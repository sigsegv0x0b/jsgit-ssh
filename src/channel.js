// Channel abstraction: a bidirectional command execution with stdout,
// stderr, and an exit code -- shaped so a real `ssh2` exec channel and a
// local `child_process.spawn` can present an identical interface. This lets
// the wire-protocol code in transport.js be tested with zero network/keys.
//
// Channel interface:
//   stdout      - AsyncIterable<Buffer> (readable side of the command)
//   write(buf)  - write to the command's stdin
//   end()       - close stdin (signals "no more input", e.g. EOF on a pipe)
//   waitForExit() -> Promise<{ code: number|null, signal: string|null, stderr: string }>
//                 resolves once the channel fully closes; safe to call any
//                 time, including after stdout has already been consumed.
//   close()     - force-terminate/cleanup (used on error paths)

import ssh2 from 'ssh2';
const { Client } = ssh2;
import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

/**
 * Quote a single path argument the way real git does when building the
 * remote command: `git-upload-pack '<path>'`, with `'` escaped as `'\''`.
 */
export function shellQuote(arg) {
  return `'${arg.replace(/'/g, `'\\''`)}'`;
}

/**
 * Wraps a Node child_process-like object (anything with .stdout, .stderr,
 * .stdin, and an 'exit'/'close' event) into the Channel interface. Stdout
 * and stderr consumers are attached synchronously (before returning) so
 * backpressure on an unread stream can never stall the other side --
 * this matters for real SSH channels where unread stderr consumes channel
 * window and can silently stall stdout.
 */
function wrapProcessLike(proc) {
  const stderrChunks = [];
  proc.stderr.on('data', chunk => stderrChunks.push(chunk));

  let exitInfo = null;
  const exitPromise = new Promise(resolve => {
    let code = null;
    let signal = null;
    // Resolve on 'close' alone, not on both 'exit' and 'close'. 'close'
    // fires reliably once the channel is fully torn down for both a Node
    // ChildProcess and an ssh2 Channel; 'exit' does not -- it depends on the
    // remote sending an SSH exit-status request, which some servers omit.
    // Requiring both would mean waitForExit() never resolves against such a
    // server, hanging the transport on an otherwise-successful clone right
    // after the full packfile has already been received.
    proc.on('exit', (c, s) => {
      code = c;
      signal = s;
    });
    proc.on('close', (c, s) => {
      if (code === null && typeof c === 'number') code = c;
      if (signal === null && s) signal = s;
      exitInfo = { code, signal, stderr: Buffer.concat(stderrChunks).toString('utf8') };
      resolve(exitInfo);
    });
  });

  return {
    stdout: proc.stdout,
    write(buf) {
      proc.stdin.write(buf);
    },
    end() {
      proc.stdin.end();
    },
    async waitForExit() {
      return exitInfo || exitPromise;
    },
    close() {
      try {
        proc.destroy ? proc.destroy() : proc.kill();
      } catch {
        /* best effort */
      }
    },
  };
}

/**
 * Local channel factory: runs the given command via child_process.spawn.
 * Used for testing the wire protocol against a local repository with no
 * network and no SSH keys involved.
 */
export function createLocalChannelFactory() {
  return {
    async openChannel(command) {
      // Real upload-pack commands look like: git-upload-pack '/some/path'
      // Run them through /bin/sh -c so the quoting matches what a real SSH
      // server would do server-side.
      const proc = spawn('/bin/sh', ['-c', command], { stdio: ['pipe', 'pipe', 'pipe'] });
      return wrapProcessLike(proc);
    },
    async dispose() {
      /* nothing to tear down */
    },
  };
}

/**
 * ssh2-based channel factory. Opens a single ssh2 Client connection (lazily,
 * on first openChannel call) and execs commands over it.
 *
 * Auth precedence: explicit privateKey > ssh-agent (SSH_AUTH_SOCK) > default
 * ~/.ssh/id_rsa.
 */
export function createSshChannelFactory({
  host,
  port = 22,
  username,
  privateKey,
  passphrase,
  agent,
  hostVerifier,
  readyTimeout = 20000,
}) {
  let clientPromise = null;

  async function resolveAuth() {
    if (privateKey) {
      return { privateKey, passphrase };
    }
    const agentSock = agent || process.env.SSH_AUTH_SOCK;
    if (agentSock) {
      return { agent: agentSock };
    }
    const defaultKeyPath = path.join(os.homedir(), '.ssh', 'id_rsa');
    try {
      const key = await readFile(defaultKeyPath);
      return { privateKey: key, passphrase };
    } catch {
      throw new Error(
        'No SSH authentication method available: no privateKey given, no SSH_AUTH_SOCK agent, ' +
          `and no default key at ${defaultKeyPath}.`
      );
    }
  }

  function connect() {
    return new Promise(async (resolve, reject) => {
      const client = new Client();
      let authOpts;
      try {
        authOpts = await resolveAuth();
      } catch (err) {
        reject(err);
        return;
      }
      client.on('ready', () => resolve(client));
      client.on('error', err => reject(err));
      client.connect({
        host,
        port,
        username,
        readyTimeout,
        hostVerifier,
        ...authOpts,
      });
    });
  }

  return {
    async openChannel(command) {
      if (!clientPromise) clientPromise = connect();
      const client = await clientPromise;
      return new Promise((resolve, reject) => {
        client.exec(command, (err, stream) => {
          if (err) return reject(err);
          // wrapProcessLike expects .stdin/.stdout/.stderr + exit/close
          // events, which is exactly the ssh2 Channel duplex-stream shape
          // (stream itself is stdin+stdout, .stderr is the separate
          // readable). Wrapping happens synchronously right here, inside
          // the exec callback, so the stderr 'data' listener is attached
          // before control ever returns to the event loop -- an unread
          // stderr can consume channel window and stall stdout, so this
          // must not be deferred across an await.
          resolve(
            wrapProcessLike({
              stdin: stream,
              stdout: stream,
              stderr: stream.stderr,
              on: (event, cb) => stream.on(event, cb),
              destroy: () => stream.destroy(),
            })
          );
        });
      });
    },
    async dispose() {
      if (clientPromise) {
        const client = await clientPromise.catch(() => null);
        if (client) client.end();
      }
    },
  };
}
