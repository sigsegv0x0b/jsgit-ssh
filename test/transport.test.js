// Self-contained offline tests for the jsgit-ssh transport: the "remote" is a
// scratch git repo made in a tmp dir (seeded with the real `git` binary -- only
// to have something for git-upload-pack to serve), and the clone runs through
// createLocalChannelFactory (child_process, no network, no SSH keys), exactly
// the no-SSH testing approach the transport itself was designed for.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import git from 'isomorphic-git';

import { createLocalChannelFactory } from '../src/channel.js';
import { createSshTransport } from '../src/transport.js';

function makeSourceRepo() {
  const dir = mkdtempSync(path.join(tmpdir(), 'jsgit-ssh-source-'));
  execFileSync('git', ['init', '-q', dir]);
  writeFileSync(path.join(dir, 'hello.txt'), 'hello from jsgit-ssh\n');
  execFileSync('git', ['-C', dir, 'add', 'hello.txt']);
  execFileSync('git', ['-C', dir, 'commit', '-q', '-m', 'initial commit']);
  execFileSync('git', ['-C', dir, 'branch', '-m', 'main']);
  return dir;
}

function withTmpDir(fn) {
  const dir = mkdtempSync(path.join(tmpdir(), 'jsgit-ssh-test-'));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('clone via the SSH transport shim (local channel) produces a working repo', async () => {
  const sourceRepo = makeSourceRepo();
  try {
    await withTmpDir(async dir => {
      const channelFactory = createLocalChannelFactory();
      const transport = createSshTransport({ channelFactory, repoPath: sourceRepo });
      try {
        await git.clone({ fs, http: transport, dir, url: 'http://local-shim/repo', singleBranch: true, depth: 1 });
      } finally {
        await transport.dispose();
      }

      assert.equal(readFileSync(path.join(dir, 'hello.txt'), 'utf8'), 'hello from jsgit-ssh\n');
      assert.ok(readdirSync(dir).includes('.git'), 'expected a .git directory');
      const headOid = await git.resolveRef({ fs, dir, ref: 'HEAD' });
      assert.match(headOid, /^[0-9a-f]{40}$/, 'HEAD should resolve to a 40-char oid');
    });
  } finally {
    rmSync(sourceRepo, { recursive: true, force: true });
  }
});

test('clone from the shim is acceptable to canonical git (fsck parity)', async () => {
  const sourceRepo = makeSourceRepo();
  try {
    await withTmpDir(async root => {
      const shimDir = path.join(root, 'via-shim');
      const baselineDir = path.join(root, 'via-real-git');
      fs.mkdirSync(shimDir);

      const channelFactory = createLocalChannelFactory();
      const transport = createSshTransport({ channelFactory, repoPath: sourceRepo });
      try {
        await git.clone({ fs, http: transport, dir: shimDir, url: 'http://local-shim/repo', singleBranch: true, depth: 1 });
      } finally {
        await transport.dispose();
      }
      execFileSync('git', ['clone', '--depth', '1', `file://${sourceRepo}`, baselineDir], { stdio: 'pipe' });

      const fsckShim = execFileSync('git', ['-C', shimDir, 'fsck'], { encoding: 'utf8' });
      const fsckBaseline = execFileSync('git', ['-C', baselineDir, 'fsck'], { encoding: 'utf8' });
      assert.equal(fsckShim, fsckBaseline, 'fsck output should match a real git shallow clone (expected: both empty)');
    });
  } finally {
    rmSync(sourceRepo, { recursive: true, force: true });
  }
});
