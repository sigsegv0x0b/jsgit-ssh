// Minimal pkt-line helpers.
//
// A pkt-line is a 4-byte hex-ascii length prefix (length includes the 4
// prefix bytes themselves) followed by that many bytes of payload.
// Two special lengths carry no payload:
//   "0000"  flush-pkt
//   "0001"  delim-pkt (protocol v2 only; we don't use it here)
//
// See: https://git-scm.com/docs/gitprotocol-pack (readAdvertisement)

/**
 * Build the synthetic "# service=git-upload-pack\n" pkt-line + flush that
 * smart-HTTP git servers prepend to the ref advertisement, and that a real
 * SSH `git-upload-pack` invocation never sends. isomorphic-git's
 * `parseRefsAdResponse` requires this exact line as the first pkt-line.
 *
 * "# service=git-upload-pack\n" is 26 bytes; + 4 length-prefix bytes = 30 =
 * 0x1e, so the pkt-line length header is "001e".
 */
export function serviceAdvertisementPrefix(service = 'git-upload-pack') {
  const line = `# service=${service}\n`;
  const len = (line.length + 4).toString(16).padStart(4, '0');
  return Buffer.concat([Buffer.from(len, 'ascii'), Buffer.from(line, 'utf8'), Buffer.from('0000', 'ascii')]);
}

/**
 * Reads pkt-lines from `source` (an async-iterable of Buffer/Uint8Array
 * chunks, e.g. a Node Readable) until the first flush-pkt (0000) is seen.
 *
 * Returns:
 *   advertisement - Buffer containing every byte read, INCLUDING the
 *                    terminating flush-pkt itself. This is exactly the body
 *                    a smart-HTTP server would have sent for `/info/refs`
 *                    (minus the "# service=" prefix line).
 *   residual       - Buffer containing any bytes that were already pulled
 *                     out of the source past the flush-pkt boundary (in
 *                     practice this is usually empty, since a well-behaved
 *                     upload-pack process blocks after sending the
 *                     advertisement until it receives `want` lines -- but we
 *                     must not assume that and must not drop bytes).
 *
 * The source is NOT closed/ended by this function; the caller keeps whatever
 * channel it came from open and reuses it for the subsequent request.
 *
 * Safety limits (both configurable; the bytes being read here are controlled
 * by the remote server, so they must be bounded):
 *   maxBytes  - abort if more than this many bytes arrive without a
 *               flush-pkt (default 64 MiB -- far beyond any real ref
 *               advertisement, small enough to stop a hostile server from
 *               exhausting client memory).
 *   timeoutMs - abort if no bytes arrive for this long (default 0 = no
 *               timeout; the transport layer passes its idle timeout).
 */
export async function readAdvertisement(source, { maxBytes = 64 * 1024 * 1024, timeoutMs = 0 } = {}) {
  const parts = []; // every chunk read, in order -- assembled once at the end
  let total = 0;
  let carry = Buffer.alloc(0); // bytes read but not yet consumed by the pkt-line parser
  let flushEnd = -1; // absolute offset (into the concatenation of `parts`) just past the flush-pkt

  const iterator = getAsyncIterator(source);

  const next = () => {
    if (!(timeoutMs > 0)) return iterator.next();
    const read = iterator.next();
    // If the timeout below wins the race, this read stays pending; swallow a
    // late rejection so it can't surface as an unhandled rejection.
    read.catch(() => {});
    let timer;
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(
        () =>
          reject(
            new Error(`Timed out after ${timeoutMs}ms waiting for ref advertisement data (stalled or dead server)`)
          ),
        timeoutMs
      );
      if (timer.unref) timer.unref();
    });
    return Promise.race([read, timeout]).finally(() => clearTimeout(timer));
  };

  while (flushEnd < 0) {
    const { value, done } = await next();
    if (done) {
      // Stream ended before we ever saw a flush-pkt.
      throw new Error(
        'Unexpected end of stream while reading ref advertisement (no flush-pkt seen). ' +
          'This usually means the remote command failed or the repository path is wrong.'
      );
    }
    const chunk = Buffer.from(value);
    parts.push(chunk);
    total += chunk.length;
    if (total > maxBytes) {
      throw new Error(
        `Ref advertisement exceeded ${maxBytes} bytes without a flush-pkt; aborting. ` +
          'This indicates a misbehaving or hostile server.'
      );
    }
    carry = carry.length === 0 ? chunk : Buffer.concat([carry, chunk]);

    // Consume as many complete pkt-lines as possible out of `carry`. Only the
    // unconsumed tail is re-copied on the next read, so total copying stays
    // ~O(n) instead of the O(n^2) of re-concatenating the whole buffer.
    let offset = 0;
    while (carry.length - offset >= 4) {
      const lenHex = carry.slice(offset, offset + 4).toString('ascii');
      const len = parseInt(lenHex, 16);
      if (Number.isNaN(len)) {
        throw new Error(`Invalid pkt-line length header: ${JSON.stringify(lenHex)}`);
      }
      if (len === 0) {
        // flush-pkt: we're done. Everything up to and including this point
        // is the advertisement; anything after is residual.
        flushEnd = total - carry.length + offset + 4;
        offset += 4;
        break;
      }
      if (len < 4) {
        // A length of 1-3 is malformed (the length field includes its own 4
        // bytes); accepting it would misalign every subsequent parse.
        throw new Error(`Invalid pkt-line length: ${len} (must be 0 or >= 4)`);
      }
      if (carry.length - offset < len) break; // haven't received the full payload yet
      offset += len; // consume this pkt-line, keep scanning for more
    }
    carry = carry.subarray(offset);
  }

  const all = Buffer.concat(parts);
  return {
    advertisement: all.subarray(0, flushEnd),
    residual: all.subarray(flushEnd),
  };
}

function getAsyncIterator(source) {
  if (typeof source[Symbol.asyncIterator] === 'function') {
    return source[Symbol.asyncIterator]();
  }
  if (typeof source[Symbol.iterator] === 'function') {
    return source[Symbol.iterator]();
  }
  throw new TypeError('readAdvertisement() source must be an (async) iterable');
}
