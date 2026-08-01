// SSH git URL parsing, shared by clone.js and push.js.

/**
 * Parses an SSH git remote URL in either form:
 *   ssh://[user@]host[:port]/path/to/repo.git
 *   [user@]host:path/to/repo.git            (the scp-like shorthand)
 * Returns { user, host, port, path }. `path` retains whatever leading slash
 * (or lack of one) the input had -- that distinction matters server-side.
 */
export function parseSshUrl(url) {
  if (!url.includes('://')) {
    const m = url.match(/^(?:([^@\s]+)@)?([^:\s]+):(.+)$/);
    if (m) {
      rejectUserinfoColon(m[1], url);
      return { user: m[1], host: m[2], port: 22, path: m[3] };
    }
  }
  const m = url.match(/^ssh:\/\/(?:([^@/]+)@)?([^:/]+)(?::(\d+))?(\/.*)$/);
  if (m) {
    rejectUserinfoColon(m[1], url);
    const port = m[3] ? parseInt(m[3], 10) : 22;
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new Error(`Unsupported SSH git URL: ${url} (port must be 1-65535)`);
    }
    return { user: m[1], host: m[2], port, path: m[4] };
  }
  throw new Error(`Unsupported SSH git URL: ${url} (expected ssh://[user@]host[:port]/path or [user@]host:path)`);
}

/** SSH has no password-in-URL form. Without this check, `user:pass@host`
 * would be sent to the server verbatim as the login name -- leaking the
 * "password" half into the username field and into error messages. */
function rejectUserinfoColon(user, url) {
  if (user && user.includes(':')) {
    throw new Error(`Unsupported SSH git URL: ${url} (a password in the userinfo is not supported for SSH)`);
  }
}

/**
 * Builds the http:// shim URL isomorphic-git is given in place of the real
 * ssh:// address (its scheme-based remote-helper dispatch only accepts
 * http/https; our custom `http` client does the actual SSH work). Exactly
 * one slash always joins the shim host to `path`, regardless of whether
 * `path` came from the ssh:// form (leading slash) or the scp-like
 * shorthand (no leading slash).
 *
 * No '@' is allowed in the result: isomorphic-git's extractAuthFromUrl()
 * treats anything before an '@' in an http(s) URL as embedded basic-auth
 * credentials and strips it.
 */
export function buildShimUrl(path) {
  return `http://ssh-shim${path.startsWith('/') ? '' : '/'}${path}`;
}
