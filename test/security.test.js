// Tests for the security-hardening behavior: input validation, resource
// caps, timeouts, and error-path cleanup. Everything runs offline against
// fake channels / tmp files -- no network, no SSH keys.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { readAdvertisement, serviceAdvertisementPrefix } from '../src/pktline.js';
import { createSshTransport } from '../src/transport.js';
import { createSshChannelFactory, createLocalChannelFactory } from '../src/channel.js';
import { parseSshUrl } from '../src/ssh-url.js';
import { verifyHostKey, appendKnownHost } from '../src/known-hosts.js';

async function withTmpDir(fn) {
  const dir = mkdtempSync(path.join(tmpdir(), 'jsgit-ssh-sectest-'));
  try {
    return await fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

async function* chunkSource(chunks) {
  for (const c of chunks) yield c;
}

/** A minimal fake Channel with close-tracking. */
function fakeChannel({ chunks = [], hang = false, writeThrows = false } = {}) {
  const state = { closed: false };
  const channel = {
    stdout: (async function* () {
      for (const c of chunks) yield c;
      if (hang) await new Promise(() => {}); // never yields again
    })(),
    write() {
      if (writeThrows) throw new Error('write failed');
      return true;
    },
    end() {},
    waitForExit() {
      return new Promise(() => {}); // never resolves
    },
    close() {
      state.closed = true;
    },
  };
  return { channel, state };
}

function fakeFactory(channel) {
  return { openChannel: async () => channel, dispose: async () => {} };
}

// ---------------------------------------------------------------- pktline

test('readAdvertisement parses pkt-lines across chunk boundaries and keeps residual', async () => {
  const payload = Buffer.from('0008abcd0000EXTRA');
  const { advertisement, residual } = await readAdvertisement(
    chunkSource([payload.subarray(0, 5), payload.subarray(5)])
  );
  assert.deepEqual(advertisement, payload.subarray(0, 12));
  assert.deepEqual(residual, Buffer.from('EXTRA'));
});

test('readAdvertisement rejects malformed pkt-line lengths < 4', async () => {
  await assert.rejects(readAdvertisement(chunkSource([Buffer.from('0002xx0000')])), /Invalid pkt-line length: 2/);
});

test('readAdvertisement rejects non-hex length headers', async () => {
  await assert.rejects(readAdvertisement(chunkSource([Buffer.from('zzzzabcd0000')])), /Invalid pkt-line length header/);
});

test('readAdvertisement rejects EOF before a flush-pkt', async () => {
  await assert.rejects(readAdvertisement(chunkSource([Buffer.from('0008ab')])), /Unexpected end of stream/);
});

test('readAdvertisement enforces its byte cap (hostile server cannot grow memory unboundedly)', async () => {
  const big = Buffer.alloc(1024, 0x61);
  await assert.rejects(
    readAdvertisement(chunkSource([big, big, big]), { maxBytes: 1024 }),
    /exceeded 1024 bytes/
  );
});

test('readAdvertisement times out on a stalled source', { timeout: 10000 }, async () => {
  async function* stalled() {
    yield Buffer.from('0008ab'); // partial pkt-line, then silence forever
    await new Promise(() => {});
  }
  await assert.rejects(readAdvertisement(stalled(), { timeoutMs: 100 }), /[Tt]imed out/);
});

test('serviceAdvertisementPrefix is the expected pkt-line + flush', () => {
  const prefix = serviceAdvertisementPrefix('git-upload-pack');
  assert.equal(prefix.toString('utf8'), '001e# service=git-upload-pack\n0000');
});

// --------------------------------------------------------------- transport

test('a second GET closes the channel left pending by the first (no leak)', async () => {
  const states = [];
  const factory = {
    openChannel: async () => {
      const { channel, state } = fakeChannel({ chunks: [Buffer.from('0000')] });
      states.push(state);
      return channel;
    },
    dispose: async () => {},
  };
  const transport = createSshTransport({ channelFactory: factory, repoPath: '/x' });
  await transport.request({ method: 'GET', url: 'http://shim/info/refs?service=git-upload-pack' });
  await transport.request({ method: 'GET', url: 'http://shim/info/refs?service=git-upload-pack' });
  assert.equal(states.length, 2);
  assert.equal(states[0].closed, true, 'first GET channel must be closed by the second GET');
  assert.equal(states[1].closed, false);
  await transport.dispose();
  assert.equal(states[1].closed, true, 'dispose must close the still-pending channel');
});

test('a failing request-body write closes the channel and propagates the error', async () => {
  const { channel, state } = fakeChannel({ chunks: [Buffer.from('0000')], writeThrows: true });
  const transport = createSshTransport({ channelFactory: fakeFactory(channel), repoPath: '/x' });
  await assert.rejects(
    transport.request({ method: 'POST', url: 'http://shim/git-upload-pack', body: [Buffer.from('0004')] }),
    /write failed/
  );
  assert.equal(state.closed, true, 'channel must be closed when the body write fails');
});

test('a stalled server during the advertisement fails the GET (idle timeout) and closes the channel', { timeout: 10000 }, async () => {
  const { channel, state } = fakeChannel({ chunks: [], hang: true });
  const transport = createSshTransport({ channelFactory: fakeFactory(channel), repoPath: '/x', idleTimeoutMs: 100 });
  await assert.rejects(
    transport.request({ method: 'GET', url: 'http://shim/info/refs?service=git-upload-pack' }),
    /[Tt]imed out/
  );
  assert.equal(state.closed, true);
});

// ----------------------------------------------------------------- channel

test('remote stderr is tail-capped, not accumulated unboundedly', async () => {
  const factory = createLocalChannelFactory();
  const channel = await factory.openChannel(
    `printf 'hello'; node -e "process.stderr.write('x'.repeat(200000))"`
  );
  let stdout = '';
  for await (const chunk of channel.stdout) stdout += chunk.toString('utf8');
  const info = await channel.waitForExit();
  assert.equal(info.code, 0);
  assert.equal(stdout, 'hello');
  assert.equal(info.stderr.length, 64 * 1024, 'stderr must be capped at 64 KiB');
  assert.ok(/^x+$/.test(info.stderr), 'capped stderr should be the tail of the stream');
});

test('ssh2 connect() throwing synchronously (bad private key) rejects instead of hanging', { timeout: 10000 }, async () => {
  const factory = createSshChannelFactory({
    host: '127.0.0.1',
    port: 1, // unreachable on purpose: we must fail before any network I/O
    username: 'git',
    privateKey: Buffer.from('this is not a private key'),
    hostVerifier: () => {},
  });
  await assert.rejects(factory.openChannel('git-upload-pack /x'), /Cannot parse privateKey/);
});

// ---------------------------------------------------------------- ssh-url

test('parseSshUrl accepts the normal forms (regression baseline)', () => {
  assert.deepEqual(parseSshUrl('git@github.com:org/repo.git'), {
    user: 'git',
    host: 'github.com',
    port: 22,
    path: 'org/repo.git',
  });
  assert.deepEqual(parseSshUrl('ssh://git@example.com:2222/org/repo.git'), {
    user: 'git',
    host: 'example.com',
    port: 2222,
    path: '/org/repo.git',
  });
});

test('parseSshUrl rejects out-of-range ports', () => {
  assert.throws(() => parseSshUrl('ssh://git@example.com:0/repo.git'), /port must be 1-65535/);
  assert.throws(() => parseSshUrl('ssh://git@example.com:70000/repo.git'), /port must be 1-65535/);
});

test('parseSshUrl rejects a password in the userinfo', () => {
  assert.throws(() => parseSshUrl('ssh://user:secret@example.com/repo.git'), /password in the userinfo/);
  assert.throws(() => parseSshUrl('user:secret@example.com:repo.git'), /password in the userinfo/);
});

// ------------------------------------------------------------ known-hosts

function hashedEntryLine(host, keytype, keyBuffer, { unpadded = false } = {}) {
  const salt = crypto.randomBytes(20);
  const digest = crypto.createHmac('sha1', salt).update(host).digest('base64');
  const maybeStrip = s => (unpadded ? s.replace(/=+$/, '') : s);
  return `|1|${maybeStrip(salt.toString('base64'))}|${maybeStrip(digest)} ${keytype} ${keyBuffer.toString('base64')}\n`;
}

test('hashed known_hosts entries match padding-insensitively', () =>
  withTmpDir(async dir => {
    const kh = path.join(dir, 'known_hosts');
    const key = crypto.randomBytes(32);
    writeFileSync(kh, hashedEntryLine('example.com', 'ssh-ed25519', key, { unpadded: true }));
    const result = await verifyHostKey({
      host: 'example.com',
      port: 22,
      keytype: 'ssh-ed25519',
      keyBuffer: key,
      knownHostsPath: kh,
    });
    assert.equal(result.status, 'ok');
  }));

test('a changed key on a known host is always a mismatch', () =>
  withTmpDir(async dir => {
    const kh = path.join(dir, 'known_hosts');
    writeFileSync(kh, hashedEntryLine('example.com', 'ssh-ed25519', crypto.randomBytes(32)));
    const result = await verifyHostKey({
      host: 'example.com',
      port: 22,
      keytype: 'ssh-ed25519',
      keyBuffer: crypto.randomBytes(32), // different key
      knownHostsPath: kh,
    });
    assert.equal(result.status, 'mismatch');
  }));

test('appendKnownHost refuses to follow symlinks', () =>
  withTmpDir(async dir => {
    const target = path.join(dir, 'target');
    writeFileSync(target, 'original contents\n');
    const kh = path.join(dir, 'known_hosts');
    symlinkSync(target, kh);
    await assert.rejects(
      appendKnownHost({
        host: 'example.com',
        port: 22,
        keytype: 'ssh-ed25519',
        keyBuffer: crypto.randomBytes(32),
        knownHostsPath: kh,
      }),
      /symlink/
    );
    assert.equal(readFileSync(target, 'utf8'), 'original contents\n', 'symlink target must be untouched');
  }));
