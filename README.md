# jsgit-ssh

An **SSH transport for [`isomorphic-git`](https://isomorphic-git.org/)**. isomorphic-git only ships HTTP(S) transports out of the box; this package adds the SSH one.

It's an isomorphic-git-compatible `http` client shim that speaks `git-upload-pack`/`git-receive-pack` over an [`ssh2`](https://github.com/mscdex/ssh2) exec channel instead of real HTTP. All the git logic (object storage, refs, index/working-tree handling, packing, protocol framing) is delegated to isomorphic-git — this package contributes exactly the SSH connection and wire framing.

Pure JavaScript: no native modules, no `git` binary required. (`ssh2` is pure JS; its optional native helpers are never built.)

## Usage

```js
import fs from 'node:fs';
import git from 'isomorphic-git';
import { createSshHttpClient } from 'jsgit-ssh';

const { http, url, dispose } = createSshHttpClient({ url: 'git@github.com:org/repo.git' });

await git.clone({ fs, http, url, dir: './repo', depth: 1 });   // closes its own connection when done
await git.push({ fs, http, url, dir: './repo', ref: 'main' }); // same client, a brand-new connection

const refs = await git.listServerRefs({ http, url });          // discover-only: no POST, so...
await dispose();                                                // ...call this or the connection lingers
```

`createSshHttpClient()` accepts the same connection options as any `ssh` command: `username`, `identityFile`, `passphrase`, `trustNewHosts`, `knownHostsPath`, `onProgress`.

## Connection lifecycle

Connections are **per-operation, not persistent** — deliberately, so nothing needs to be tracked or closed across a whole program's lifetime the way a normal `http` client's keep-alive connection would be:

- `git.clone`/`git.fetch`/`git.push` each open a fresh SSH connection and close it automatically once that operation's response has been fully read — success or failure, it doesn't linger.
- The same `http`/`url` pair can be reused for as many separate operations as you like; each one gets its own connection, not a shared/persistent one.
- **Exception:** isomorphic-git's discover-only calls (`git.listServerRefs`, `getRemoteInfo`/`getRemoteInfo2`) issue a request but never a follow-up, so there's no "operation finished" moment to hook a close onto. Call the client's `dispose()` after one of these if no further clone/fetch/push on the same client is coming — otherwise that connection is left open indefinitely. A subsequent GET on the same client (another discover-only call, or the start of a clone/fetch/push) also closes it automatically, so this only matters for the last operation on a client.
- Not safe for concurrent operations on one client instance — it tracks a single in-flight connection, and a second concurrent operation will tear down the first's. Create a separate `createSshHttpClient()` call per concurrent operation.

## Host key verification

Host keys are verified against `~/.ssh/known_hosts` (hashed and plaintext entries, `[host]:port` form supported). By default, an unknown host is refused. Pass `trustNewHosts: true` for trust-on-first-use: the key is verified and appended to `known_hosts`. A host whose key **changed** from what's on record is always a hard failure — `trustNewHosts` never overrides that, since a changed key on an already-known host is the actual thing TOFU exists to catch.

## Auth

Auth precedence: explicit `identityFile` > `ssh-agent` (`SSH_AUTH_SOCK`) > default `~/.ssh/id_rsa`.

## License

MIT
