// Minimal ~/.ssh/known_hosts parsing + verification (TOFU-capable), wired
// into ssh2's `hostVerifier`.
//
// Format reference: `man 8 sshd`, "SSH_KNOWN_HOSTS FILE FORMAT".
// Each line: [marker] hostnames keytype base64-key [comment]
//   marker    - optional "@cert-authority" or "@revoked"
//   hostnames - comma-separated patterns (glob '*'/'?', '!' negation), or a
//               single hashed entry "|1|<b64 salt>|<b64 hmac>"
//   keytype   - e.g. "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256"
//
// A changed key on an already-known host is the actual MITM signal, so
// verify() always hard-fails on 'mismatch' regardless of any TOFU setting --
// only genuinely *unknown* hosts are eligible for trust-on-first-use.

import { createHash, createHmac } from 'node:crypto';
import { readFile, appendFile, mkdir, chmod } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import ssh2 from 'ssh2';
const { utils: ssh2Utils } = ssh2;

export const DEFAULT_KNOWN_HOSTS_PATH = path.join(os.homedir(), '.ssh', 'known_hosts');

function globToRegExp(pattern) {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
  return new RegExp(`^${escaped}$`, 'i');
}

function hostCandidateStrings(host, port) {
  // OpenSSH stores the bare hostname for the default port, and the
  // "[host]:port" bracketed form for any non-default port. We check the one
  // form that matches how port 22 vs. other ports actually get written.
  const candidate = port === 22 ? host : `[${host}]:${port}`;
  return [candidate, candidate.toLowerCase()];
}

function parseLine(line) {
  const trimmed = line.trim();
  if (trimmed === '' || trimmed.startsWith('#')) return null;

  const tokens = trimmed.split(/\s+/);
  let marker = null;
  if (tokens[0] === '@cert-authority' || tokens[0] === '@revoked') {
    marker = tokens.shift();
  }
  const [hostnamesField, keytype, keydataB64] = tokens;
  if (!hostnamesField || !keytype || !keydataB64) return null; // malformed/short line

  let keyBuffer;
  try {
    keyBuffer = Buffer.from(keydataB64, 'base64');
  } catch {
    return null;
  }

  if (hostnamesField.startsWith('|1|')) {
    const parts = hostnamesField.split('|'); // ['', '1', saltB64, hashB64]
    if (parts.length !== 4) return null;
    return {
      marker,
      keytype,
      keyBuffer,
      hashed: { salt: Buffer.from(parts[2], 'base64'), hash: parts[3] },
    };
  }

  const patterns = hostnamesField.split(',').map(p => {
    const negate = p.startsWith('!');
    const pat = negate ? p.slice(1) : p;
    return { negate, regexp: globToRegExp(pat) };
  });
  return { marker, keytype, keyBuffer, patterns };
}

async function loadEntries(knownHostsPath) {
  let text;
  try {
    text = await readFile(knownHostsPath, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return [];
    throw err;
  }
  return text.split('\n').map(parseLine).filter(Boolean);
}

function lineApplies(entry, candidates) {
  if (entry.hashed) {
    return candidates.some(c => {
      const digest = createHmac('sha1', entry.hashed.salt).update(c).digest('base64');
      return digest === entry.hashed.hash;
    });
  }
  let matched = false;
  for (const { negate, regexp } of entry.patterns) {
    const hit = candidates.some(c => regexp.test(c));
    if (hit && negate) return false; // explicit negation always wins
    if (hit) matched = true;
  }
  return matched;
}

/** Standard `SHA256:<base64, no padding>` fingerprint, as printed by `ssh-keygen -lf`. */
export function fingerprint(keyBuffer) {
  return 'SHA256:' + createHash('sha256').update(keyBuffer).digest('base64').replace(/=+$/, '');
}

/**
 * Check a presented host key against known_hosts.
 * Returns { status: 'ok' | 'unknown' | 'mismatch', reason? }.
 */
export async function verifyHostKey({ host, port = 22, keytype, keyBuffer, knownHostsPath = DEFAULT_KNOWN_HOSTS_PATH }) {
  const entries = await loadEntries(knownHostsPath);
  const candidates = hostCandidateStrings(host, port);

  let exactMatch = false;
  let sameHostAndTypeDifferentKey = false;
  let revokedMatch = false;

  for (const entry of entries) {
    if (entry.keytype.toLowerCase() !== keytype.toLowerCase()) continue;
    if (!lineApplies(entry, candidates)) continue;

    const sameKey = entry.keyBuffer.equals(keyBuffer);
    if (entry.marker === '@revoked') {
      if (sameKey) revokedMatch = true;
      continue;
    }
    if (entry.marker === '@cert-authority') continue; // CA-signed cert checking is out of scope
    if (sameKey) exactMatch = true;
    else sameHostAndTypeDifferentKey = true;
  }

  if (revokedMatch) {
    return { status: 'mismatch', reason: `host key for ${host} is explicitly @revoked in ${knownHostsPath}` };
  }
  if (exactMatch) return { status: 'ok' };
  if (sameHostAndTypeDifferentKey) {
    return {
      status: 'mismatch',
      reason:
        `REMOTE HOST IDENTIFICATION HAS CHANGED for ${host}! ` +
        `A different ${keytype} key (${fingerprint(keyBuffer)}) was presented than the one in ${knownHostsPath}. ` +
        'This could indicate a man-in-the-middle attack and is never auto-trusted.',
    };
  }
  return { status: 'unknown', reason: `${host} (${keytype} ${fingerprint(keyBuffer)}) is not in ${knownHostsPath}` };
}

/** Append a newly-trusted host key entry, in plain (non-hashed) "[host]:port" form. */
export async function appendKnownHost({ host, port = 22, keytype, keyBuffer, knownHostsPath = DEFAULT_KNOWN_HOSTS_PATH }) {
  const [candidate] = hostCandidateStrings(host, port);
  const line = `${candidate} ${keytype} ${keyBuffer.toString('base64')}\n`;
  await mkdir(path.dirname(knownHostsPath), { recursive: true, mode: 0o700 });
  await appendFile(knownHostsPath, line, { mode: 0o600 });
  await chmod(knownHostsPath, 0o600);
  return line.trim();
}

/**
 * Build an ssh2 `hostVerifier` function bound to a specific host/port and
 * trust policy. ssh2 calls this synchronously with (keyBuffer) for the
 * legacy form, but also supports the async `(keyBuffer, callback)` form we
 * use here since verification/appending are async (file I/O).
 */
export function createHostVerifier({ host, port = 22, trustNewHosts = false, knownHostsPath = DEFAULT_KNOWN_HOSTS_PATH, onTrust }) {
  return function hostVerifier(keyBuffer, callback) {
    // ssh2's raw host key Buffer is the same SSH wire-format public key blob
    // stored (base64-decoded) in known_hosts. utils.parseKey() -- the
    // approach ssh2's own README recommends -- reads that format directly.
    const parsed = ssh2Utils.parseKey(keyBuffer);
    if (parsed instanceof Error) {
      console.error(`ssh host key verification error: could not parse presented host key: ${parsed.message}`);
      return callback(false);
    }
    const keytype = parsed.type;
    verifyHostKey({ host, port, keytype, keyBuffer, knownHostsPath })
      .then(async result => {
        if (result.status === 'ok') return callback(true);
        if (result.status === 'mismatch') {
          console.error(`ssh host key verification FAILED: ${result.reason}`);
          return callback(false);
        }
        // unknown
        if (!trustNewHosts) {
          console.error(
            `ssh host key verification failed: ${result.reason}. ` +
              'Pass --trust-new-hosts to accept and remember it (only for hosts not already known).'
          );
          return callback(false);
        }
        const line = await appendKnownHost({ host, port, keytype, keyBuffer, knownHostsPath });
        if (onTrust) onTrust({ host, port, keytype, fingerprint: fingerprint(keyBuffer), line });
        callback(true);
      })
      .catch(err => {
        console.error(`ssh host key verification error: ${err.message}`);
        callback(false);
      });
  };
}
