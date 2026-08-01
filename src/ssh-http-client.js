// A general-purpose isomorphic-git `http` client backed by the same SSH
// transport shim jsgit's own clone/push commands use (transport.js +
// ssh-connection.js) -- for OTHER Node programs that want to drive
// isomorphic-git directly (git.clone/git.fetch/git.push/git.listServerRefs/
// ...) over SSH, without going through jsgit's CLI or its own clone()/
// push() wrappers.
//
// Connection lifecycle is per-operation, not persistent, by design: a
// GET+POST pair -- which is exactly one isomorphic-git clone/fetch/push
// operation, per transport.js's own doc comment -- opens a brand-new SSH
// connection and tears it down again once that operation's response body
// has been fully consumed (whether the consumer drains it, stops early, or
// throws), rather than keeping one connection open across multiple git.*
// calls. The SAME `http` object returned here can be reused for a later,
// unrelated clone/fetch/push (e.g. a `git.fetch()` followed later by a
// `git.push()`) -- it simply opens another fresh connection for it.
//
// That auto-close guarantee is POST-triggered, so it does NOT cover
// isomorphic-git's discover-only entry points (`git.listServerRefs`,
// `getRemoteInfo`/`getRemoteInfo2`) -- these call GET and never follow up
// with a POST, so there is no "response fully consumed" moment to hook.
// Confirmed empirically: without special-casing this, a `listServerRefs()`
// call leaves its SSH connection open indefinitely (the process never
// exits on its own). Two things cover it instead: a fresh GET always
// disposes whatever connection is still pending from a previous GET before
// opening its own (so back-to-back discover-only calls don't accumulate
// open connections), and the client exposes an explicit `dispose()` for the
// terminal case -- call it after a discover-only call if no further
// clone/fetch/push on the same client is coming.
//
// Not safe for concurrent operations on the same client instance: like
// transport.js's own `pending` state, this tracks at most one in-flight
// GET-then-POST pair at a time -- as a single `current` variable, not keyed
// per-operation. This is actively destructive, not just confusing: the
// discover-only cleanup above means a second operation's GET will dispose
// (close the SSH channel out from under) whatever the first operation's GET
// opened, and the first operation's later POST then runs against a
// transport belonging to the SECOND operation. Concurrent isomorphic-git
// calls sharing one client will corrupt or kill each other's connections,
// not just interleave oddly. Create a separate createSshHttpClient()
// instance per concurrent operation.

import { parseSshUrl, buildShimUrl } from './ssh-url.js';
import { createSshConnection } from './ssh-connection.js';
import { createSshTransport } from './transport.js';

/** GET requests carry the service isomorphic-git wants as `?service=...`
 * (added by isomorphic-git itself, from whichever git.* function is
 * calling); the POST that follows re-requests the identical service as its
 * last path segment. Deriving it from the request instead of fixing it at
 * construction time is what lets one client serve both fetch-shaped
 * (git-upload-pack) and push-shaped (git-receive-pack) operations. */
function serviceFromDiscoverUrl(url) {
  const match = url.match(/[?&]service=([^&]+)/);
  if (!match) {
    throw new Error(`ssh http shim: GET request is missing ?service=: ${url}`);
  }
  return decodeURIComponent(match[1]);
}

/** Wraps an async-iterable response body so `dispose()` runs exactly once
 * the consumer is done with it -- fully drained, stopped early, or thrown
 * through -- never before. Disposing any earlier would tear down the SSH
 * connection while isomorphic-git is still mid-stream reading the pack. */
async function* disposeAfterDrain(iterable, dispose) {
  try {
    yield* iterable;
  } finally {
    await dispose();
  }
}

/** The actual GET/POST/auto-dispose state machine, parameterized over how a
 * fresh connection gets created so it can be exercised offline in tests via
 * createLocalChannelFactory, exactly like transport.js itself is tested --
 * see test/ssh-http-client.test.js. */
function createHttpClient({ repoPath, shimUrl, createConnection }) {
  let current = null; // the transport for the in-flight GET-then-POST pair, or null between operations

  async function disposeCurrent() {
    if (current) {
      const transport = current;
      current = null;
      await transport.dispose();
    }
  }

  async function handleGet(reqUrl, body) {
    // A GET with no intervening POST (discover-only: listServerRefs/
    // getRemoteInfo, or simply two operations in a row on this client)
    // means whatever the previous GET opened was never going to be closed
    // by a POST -- close it now rather than accumulating open connections.
    await disposeCurrent();

    const service = serviceFromDiscoverUrl(reqUrl);
    const { channelFactory } = await createConnection();
    const transport = createSshTransport({ channelFactory, repoPath, service });
    try {
      const response = await transport.request({ method: 'GET', url: reqUrl, body });
      current = transport;
      return response;
    } catch (err) {
      await transport.dispose();
      throw err;
    }
  }

  async function handlePost(reqUrl, body) {
    if (!current) {
      throw new Error(
        "ssh http shim: POST with no prior GET on this client (expected isomorphic-git's own GET-then-POST sequence)"
      );
    }
    const transport = current;
    current = null;
    try {
      const response = await transport.request({ method: 'POST', url: reqUrl, body });
      return { ...response, body: disposeAfterDrain(response.body, () => transport.dispose()) };
    } catch (err) {
      await transport.dispose();
      throw err;
    }
  }

  return {
    url: shimUrl,
    http: {
      async request({ method, url: reqUrl, body }) {
        if (method === 'GET') return handleGet(reqUrl, body);
        if (method === 'POST') return handlePost(reqUrl, body);
        throw new Error(`ssh http shim: unsupported method ${method}`);
      },
    },
    // Closes a connection left open by a discover-only call (listServerRefs/
    // getRemoteInfo) that no POST will ever follow up on. A no-op if the
    // last operation on this client was a clone/fetch/push, since those
    // already close themselves. Safe to call unconditionally when done with
    // a client, and safe to call more than once.
    dispose: disposeCurrent,
  };
}

/**
 * @param {object} args
 * @param {string} args.url - an ssh:// or scp-like git remote URL
 * @param {string} [args.username] - overrides the URL's embedded user (default: url user, then 'git')
 * @param {string} [args.identityFile] - path to a private key file
 * @param {string} [args.passphrase]
 * @param {boolean} [args.trustNewHosts=false] - TOFU-accept hosts not already in known_hosts
 * @param {string} [args.knownHostsPath]
 * @param {(msg: string) => void} [args.onProgress]
 * @returns {{ http: object, url: string, dispose(): Promise<void> }} - pass
 *   `http`/`url` straight into any isomorphic-git call, e.g.
 *   `git.clone({ fs, http, url, dir, depth: 1 })`. clone/fetch/push close
 *   their own connection automatically; call `dispose()` after a
 *   discover-only call (`listServerRefs`/`getRemoteInfo`) if no further
 *   operation on this client is coming, so its connection doesn't linger.
 */
export function createSshHttpClient({ url, username, identityFile, passphrase, trustNewHosts = false, knownHostsPath, onProgress }) {
  const parsed = parseSshUrl(url);
  const connectionOptions = { url, username, identityFile, passphrase, trustNewHosts, knownHostsPath, onProgress };
  return createHttpClient({
    repoPath: parsed.path,
    shimUrl: buildShimUrl(parsed.path),
    createConnection: () => createSshConnection(connectionOptions),
  });
}

export const _internals = { createHttpClient };
