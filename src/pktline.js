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
 */
export async function readAdvertisement(source) {
  let buf = Buffer.alloc(0);
  let offset = 0; // how much of `buf` we've already parsed as complete pkt-lines

  const iterator = getAsyncIterator(source);

  while (true) {
    // Try to parse as many complete pkt-lines as we can out of what we have.
    while (true) {
      if (buf.length - offset < 4) break; // need more bytes for the length header
      const lenHex = buf.slice(offset, offset + 4).toString('ascii');
      const len = parseInt(lenHex, 16);
      if (Number.isNaN(len)) {
        throw new Error(`Invalid pkt-line length header: ${JSON.stringify(lenHex)}`);
      }
      if (len === 0) {
        // flush-pkt: we're done. Everything up to and including this point
        // is the advertisement; anything after is residual.
        const advEnd = offset + 4;
        return {
          advertisement: buf.slice(0, advEnd),
          residual: buf.slice(advEnd),
        };
      }
      if (buf.length - offset < len) break; // haven't received the full payload yet
      offset += len; // consume this pkt-line, keep scanning for more
    }

    const { value, done } = await iterator.next();
    if (done) {
      // Stream ended before we ever saw a flush-pkt.
      throw new Error(
        'Unexpected end of stream while reading ref advertisement (no flush-pkt seen). ' +
          'This usually means the remote command failed or the repository path is wrong.'
      );
    }
    buf = buf.length === 0 ? Buffer.from(value) : Buffer.concat([buf, Buffer.from(value)]);
  }
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
