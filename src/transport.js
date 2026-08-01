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

/** Collects an isomorphic-git request `body` (array of chunks, a single
 * chunk, or an (async) iterable of chunks) into one Buffer. */
async function collectBody(body) {
  if (body == null) return Buffer.alloc(0);
  if (Buffer.isBuffer(body)) return body;
  if (Array.isArray(body)) return Buffer.concat(body.map(c => Buffer.from(c)));
  const chunks = [];
  if (typeof body[Symbol.asyncIterator] === 'function' || typeof body[Symbol.iterator] === 'function') {
    for await (const chunk of body) chunks.push(Buffer.from(chunk));
    return Buffer.concat(chunks);
  }
  return Buffer.from(body);
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
 */
export function createSshTransport({ channelFactory, repoPath, service = 'git-upload-pack' }) {
  /** @type {{channel: import('./channel.js').Channel, residual: Buffer} | null} */
  let pending = null;

  async function openAndAdvertise() {
    const command = `${service} ${shellQuote(repoPath)}`;
    const channel = await channelFactory.openChannel(command);
    try {
      const { advertisement, residual } = await readAdvertisement(channel.stdout);
      return { channel, advertisement, residual };
    } catch (err) {
      const stderrText = await drainStderr(channel);
      channel.close();
      if (stderrText) {
        throw new Error(`${service} failed for '${repoPath}': ${stderrText}`);
      }
      throw err;
    }
  }

  async function handleDiscover() {
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

    const buf = await collectBody(requestBody);
    channel.write(buf);
    channel.end();

    async function* responseGenerator() {
      if (residual.length > 0) yield residual;
      let sawAnyBytes = residual.length > 0;
      for await (const chunk of channel.stdout) {
        sawAnyBytes = true;
        yield chunk;
      }
      const info = await channel.waitForExit().catch(() => null);
      // info.code may legitimately be null: 'close' resolves waitForExit()
      // even when the remote never sent an SSH exit-status message (see
      // channel.js). Only a definitely-nonzero code is a real failure.
      if (info && info.code != null && info.code !== 0) {
        const stderrText = info.stderr.trim();
        const detail = stderrText || `exited with code ${info.code}${info.signal ? ` (signal ${info.signal})` : ''}`;
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
