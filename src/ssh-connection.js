// Shared setup for turning an ssh:// URL + auth options into a ready-to-use
// (channelFactory, shimUrl) pair. Used identically by clone.js (fetch side)
// and push.js (receive-pack side) -- the SSH connection/host-key machinery
// doesn't care which service will run over it.

import fs from 'node:fs';
import { createSshChannelFactory } from './channel.js';
import { createHostVerifier } from './known-hosts.js';
import { parseSshUrl, buildShimUrl } from './ssh-url.js';

/**
 * @param {object} args
 * @param {string} args.url - an ssh:// or scp-like git remote URL
 * @param {string} [args.username] - overrides the URL's embedded user (default: url user, then 'git')
 * @param {string} [args.identityFile] - path to a private key file
 * @param {string} [args.passphrase]
 * @param {boolean} [args.trustNewHosts=false]
 * @param {string} [args.knownHostsPath]
 * @param {(msg: string) => void} [args.onProgress]
 * @returns {Promise<{ channelFactory: object, shimUrl: string, parsed: {user, host, port, path} }>}
 */
export async function createSshConnection({
  url,
  username,
  identityFile,
  passphrase,
  trustNewHosts = false,
  knownHostsPath,
  onProgress,
}) {
  const parsed = parseSshUrl(url);
  const user = username || parsed.user || 'git';

  let privateKey;
  if (identityFile) {
    privateKey = await fs.promises.readFile(identityFile);
  }

  const hostVerifier = createHostVerifier({
    host: parsed.host,
    port: parsed.port,
    trustNewHosts,
    knownHostsPath,
    onTrust: ({ fingerprint, line }) => {
      if (onProgress) {
        onProgress(`Trusting new host key for ${parsed.host}:${parsed.port} (${fingerprint}); added to known_hosts: ${line}`);
      }
    },
  });

  const channelFactory = createSshChannelFactory({
    host: parsed.host,
    port: parsed.port,
    username: user,
    privateKey,
    passphrase,
    hostVerifier,
  });

  return { channelFactory, shimUrl: buildShimUrl(parsed.path), parsed };
}
