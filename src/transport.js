// isomorphic-git `HttpClient`-shaped shim that speaks the git smart
// protocol (git-upload-pack for fetch/clone, git-receive-pack for push)
// over an arbitrary Channel (see channel.js) instead of real HTTP.
//
// isomorphic-git's fetch/push flows each make exactly two requests per
// operation (index.js in isomorphic-git@1.40.0), symmetric in shape --
// only the service name and the meaning of the bytes differ:
//   GET  <url>/info/refs?service=<service>   (discover)
//   POST <url>/<service>                     (connect)
// and both are handled here by opening ONE channel for the given service
// and reusing it for both -- exactly like real git does, since a single
// `git-upload-pack`/`git-receive-pack` invocation serves the ref
// advertisement and then the negotiated pack (or push result) over the
// same pipe. Confirmed empirically that `git receive-pack` advertises refs
// with no "# service=" line either, same as `git upload-pack` -- the two
// services share the identical wire framing this module relies on.
//
// The one thing that must never happen: handing isomorphic-git's ref-ad
// parser a body that never ends. `parseRefsAdResponse` only stops on
// end-of-stream, not on the flush-pkt -- so the GET response body here is
// always a small, fully-buffered, FINITE array. Only the POST/result
// response streams from the live channel (for push, isomorphic-git demuxes
// this itself via GitSideBand.demux, which -- like parseRefsAdResponse --
// requires the body to actually reach EOF, so the same finite-vs-streaming
// split applies without any service-specific handling here).

import { readAdvertisement, serviceAdvertisementPrefix } from './pktline.js';
import { shellQuote } from './channel.js';

/** Streams an isomorphic-git request `body` (array of chunks, a single
 * chunk, or an (async) iterable of chunks) into the channel, honoring
 * backpressure. Deliberately does NOT concatenate the body first: a push
 * body can be very large, and buffering it whole on top of isomorphic-git's
 * own in-memory pack doubles peak memory for no benefit. `timed` wraps each
 * chunk write so a server that stops reading stdin can't stall us forever. */
async function writeRequestBody(channel, body, timed) {
  if (body == null) return;
  const writeOne = async chunk => {
    await timed(async () => {
      const ok = channel.write(Buffer.from(chunk));
      if (ok === false && typeof channel.drain === 'function') await channel.drain();
    }, 'writing request data');
  };
  if (Buffer.isBuffer(body) || typeof body === 'string') {
    await writeOne(body);
    return;
  }
  if (typeof body[Symbol.asyncIterator] === 'function' || typeof body[Symbol.iterator] === 'function') {
    for await (const chunk of body) await writeOne(chunk);
    return;
  }
  await writeOne(body);
}

/** Drains an async-iterable channel body into a single string, best-effort. */
async function drainStderr(channel) {
  const info = await channel.waitForExit().catch(() => null);
  return info ? info.stderr.trim() : '';
}

/**
 * @param {object} args
 * @param {{openChannel(cmd: string): Promise<Channel>, dispose(): Promise<void>}} args.channelFactory
 * @param {string} args.repoPath - the path portion to pass to `<service> '<repoPath>'`
 * @param {string} [args.service] - 'git-upload-pack' (fetch/clone, default) or 'git-receive-pack' (push)
 * @param {number} [args.idleTimeoutMs=300000] - abort the operation if the
 *   server sends no stdout bytes (or accepts no stdin) for this long.
 *   Protects against stalled/hung servers keeping the client waiting
 *   forever; 0 disables. Generous by default because a server-side
 *   `git upload-pack` counting objects on a huge repo can legitimately be
 *   silent for a while.
 */
const VALID_SERVICES = new Set(['git-upload-pack', 'git-receive-pack']);

const DEFAULT_IDLE_TIMEOUT_MS = 300000;

export function createSshTransport({ channelFactory, repoPath, service = 'git-upload-pack', idleTimeoutMs = DEFAULT_IDLE_TIMEOUT_MS }) {
  // `service` is spliced unquoted into the remote command (`${service} 'path'`),
  // so it must be allowlisted, not just defaulted. These are the only two git
  // smart-protocol services that exist; a caller passing anything else (e.g. a
  // string with shell metacharacters) would otherwise be injecting into the
  // command executed remotely via ssh2 exec. Reject before any channel opens.
  if (!VALID_SERVICES.has(service)) {
    throw new Error(
      `createSshTransport: invalid service '${service}' (must be 'git-upload-pack' or 'git-receive-pack')`
    );
  }

  /** @type {{channel: import('./channel.js').Channel, residual: Buffer} | null} */
  let pending = null;

  /** Runs fn() and rejects if it doesn't settle within idleTimeoutMs.
   * Handlers are attached to the underlying promise either way, so a late
   * rejection after a timeout can never surface as unhandled. */
  function timed(fn, what) {
    if (!(idleTimeoutMs > 0)) return fn();
    return new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error(`${service} for '${repoPath}': timed out after ${idleTimeoutMs}ms ${what} (stalled or dead server)`)),
        idleTimeoutMs
      );
      if (timer.unref) timer.unref();
      fn().then(
        v => {
          clearTimeout(timer);
          resolve(v);
        },
        e => {
          clearTimeout(timer);
          reject(e);
        }
      );
    });
  }

  async function openAndAdvertise() {
    const command = `${service} ${shellQuote(repoPath)}`;
    const channel = await channelFactory.openChannel(command);
    try {
      const { advertisement, residual } = await readAdvertisement(channel.stdout, { timeoutMs: idleTimeoutMs });
      return { channel, advertisement, residual };
    } catch (err) {
      // Best-effort stderr for the error message, but don't wait forever for
      // a server that may be wedged (that's the failure mode being handled).
      const stderrText = await timed(() => drainStderr(channel), 'waiting for the remote command to exit').catch(
        () => ''
      );
      channel.close();
      if (stderrText) {
        throw new Error(`${service} failed for '${repoPath}': ${stderrText}`);
      }
      throw err;
    }
  }

  async function handleDiscover() {
    // A GET while a previous GET's channel is still pending (no POST ever
    // consumed it -- e.g. two discover-only calls in a row) must close that
    // channel, not leak it by silently dropping the reference.
    if (pending) {
      pending.channel.close();
      pending = null;
    }
    const { channel, advertisement, residual } = await openAndAdvertise();
    pending = { channel, residual };
    const responseBody = Buffer.concat([serviceAdvertisementPrefix(service), advertisement]);
    return {
      url: `ssh-shim://${repoPath}/info/refs`,
      method: 'GET',
      statusCode: 200,
      statusMessage: 'OK',
      headers: { 'content-type': `application/x-${service}-advertisement` },
      // MUST be finite -- see module doc comment. An array literal is an
      // iterable that yields once and ends; isomorphic-git's ref-ad parser
      // requires the body to actually reach EOF.
      body: [responseBody],
    };
  }

  async function handleConnect(requestBody) {
    let channel;
    let residual = Buffer.alloc(0);
    if (pending) {
      ({ channel, residual } = pending);
      pending = null;
    } else {
      // Safety net: a POST with no prior GET on this transport instance.
      // Open fresh and discard the advertisement we're forced to read.
      const opened = await openAndAdvertise();
      channel = opened.channel;
      residual = opened.residual;
    }

    try {
      await writeRequestBody(channel, requestBody, timed);
      channel.end();
    } catch (err) {
      // A failed/interrupted write must not leave the channel open -- nobody
      // else owns it now that `pending` has been consumed.
      channel.close();
      throw err;
    }

    async function* responseGenerator() {
      let sawAnyBytes = false;
      if (residual.length > 0) {
        sawAnyBytes = true;
        yield residual;
      }
      const it = channel.stdout[Symbol.asyncIterator]();
      try {
        while (true) {
          const { value, done } = await timed(() => it.next(), 'waiting for response data');
          if (done) break;
          sawAnyBytes = true;
          yield value;
        }
      } finally {
        if (it.return) await it.return().catch(() => {});
      }
      // stdout reached EOF, so the response bytes are complete. A wedged
      // server that never closes the channel afterwards is tolerated (treat
      // like the no-exit-status case) but must not be left running.
      const info = await timed(() => channel.waitForExit(), 'waiting for the remote command to exit').catch(() => {
        channel.close();
        return null;
      });
      // info.code may legitimately be null: 'close' resolves waitForExit()
      // even when the remote never sent an SSH exit-status message (see
      // channel.js). Only a stream error or definitely-nonzero code is a
      // real failure.
      if (info && (info.error || (info.code != null && info.code !== 0))) {
        const stderrText = info.stderr.trim();
        const detail = info.error
          ? info.error.message
          : stderrText || `exited with code ${info.code}${info.signal ? ` (signal ${info.signal})` : ''}`;
        throw new Error(
          `${service} for '${repoPath}' failed${sawAnyBytes ? ' mid-stream' : ''}: ${detail}`
        );
      }
    }

    return {
      url: `ssh-shim://${repoPath}/${service}`,
      method: 'POST',
      statusCode: 200,
      statusMessage: 'OK',
      headers: { 'content-type': `application/x-${service}-result` },
      body: responseGenerator(),
    };
  }

  return {
    async request({ method, url, body }) {
      if (method === 'GET') return handleDiscover();
      if (method === 'POST') return handleConnect(body);
      throw new Error(`ssh transport shim: unsupported method ${method} for ${url}`);
    },
    async dispose() {
      if (pending) {
        pending.channel.close();
        pending = null;
      }
      await channelFactory.dispose();
    },
  };
}
