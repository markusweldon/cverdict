import { existsSync, mkdirSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { BatchOutputParser, catFileBatch, lsTree, resolveCommit, syncShallowClone, type TreeEntry } from '../../src/util/git';
import { captureLogger, commitFiles, repoWithClone, runGit, tempDir } from './helpers';

const BIG = Buffer.alloc(300_000, 'x'); // spans many 64 KB pipe chunks
const BINARY = Buffer.from([0x00, 0x0a, 0xff, 0x0a, 0x0d, 0x00]);

const FILES = {
  'a.json': '{"a":1}\n',
  'dir/empty.txt': '',
  'dir/binary.bin': BINARY,
  'dir/big.txt': BIG,
  'dir/naïve name with spaces.json': '"unicode path"',
};

async function collect<T>(iterable: AsyncIterable<T>): Promise<T[]> {
  const out: T[] = [];
  for await (const item of iterable) out.push(item);
  return out;
}

describe('lsTree', () => {
  it('streams every blob with its path, including unicode and spaces, on a --no-checkout clone', async () => {
    const { clone, commit } = repoWithClone(FILES);
    expect(readdirSync(clone)).toEqual(['.git']); // no working tree
    const entries = await collect(lsTree(clone, commit));
    expect(entries.map((e) => e.path).sort()).toEqual(Object.keys(FILES).sort());
    expect(entries.every((e) => e.type === 'blob' && /^[0-9a-f]{40}$/.test(e.sha) && e.mode === '100644')).toBe(true);
    expect((await collect(lsTree(clone, 'HEAD', ['dir/']))).map((e) => e.path).sort()).toEqual(
      ['dir/big.txt', 'dir/binary.bin', 'dir/empty.txt', 'dir/naïve name with spaces.json'],
    );
  });

  it('fails clearly on an unknown revision', async () => {
    const { clone } = repoWithClone({ 'a.txt': 'a' });
    await expect(collect(lsTree(clone, 'no-such-rev'))).rejects.toThrow(/git ls-tree .* failed/);
  });
});

describe('catFileBatch', () => {
  it('returns exact contents in request order through one process, fed lazily from lsTree', async () => {
    const { clone, commit } = repoWithClone(FILES);
    const results = await collect(catFileBatch(clone, lsTree(clone, commit), (e: TreeEntry) => e.sha));
    const byPath = new Map(results.map((r) => [r.item.path, r.data]));
    expect(byPath.size).toBe(5);
    expect(byPath.get('a.json')?.toString()).toBe('{"a":1}\n');
    expect(byPath.get('dir/empty.txt')?.length).toBe(0);
    expect(byPath.get('dir/binary.bin')?.equals(BINARY)).toBe(true);
    expect(byPath.get('dir/big.txt')?.equals(BIG)).toBe(true);
    expect(byPath.get('dir/naïve name with spaces.json')?.toString()).toBe('"unicode path"');
  });

  it('reports missing objects as null and keeps going', async () => {
    const { clone, commit } = repoWithClone({ 'a.txt': 'alpha', 'b.txt': 'beta' });
    const [a, b] = await collect(lsTree(clone, commit));
    const missing = 'f'.repeat(40);
    const results = await collect(catFileBatch(clone, [a.sha, missing, b.sha], (sha) => sha));
    expect(results.map((r) => r.data?.toString() ?? null)).toEqual(['alpha', null, 'beta']);
  });

  it('stops git cleanly when the consumer breaks early', async () => {
    const files = Object.fromEntries(Array.from({ length: 300 }, (_, i) => [`f${i}.txt`, `file ${i}`]));
    const { clone, commit } = repoWithClone(files);
    let seen = 0;
    for await (const { data } of catFileBatch(clone, lsTree(clone, commit), (e: TreeEntry) => e.sha)) {
      expect(data).not.toBeNull();
      if (++seen === 3) break;
    }
    expect(seen).toBe(3);
    // The repository is still usable afterwards (no stuck processes or locks).
    expect(await collect(lsTree(clone, commit))).toHaveLength(300);
  });

  it('handles an empty request list', async () => {
    const { clone } = repoWithClone({ 'a.txt': 'a' });
    expect(await collect(catFileBatch(clone, [], (s: string) => s))).toEqual([]);
  });
});

describe('BatchOutputParser', () => {
  it('parses output split at every byte boundary', () => {
    const body = Buffer.from('hello\nworld');
    const stream = Buffer.concat([
      Buffer.from(`${'a'.repeat(40)} blob ${body.length}\n`),
      body,
      Buffer.from(`\n${'b'.repeat(40)} missing\n${'c'.repeat(40)} blob 0\n\n`),
    ]);
    const parser = new BatchOutputParser();
    const objects = [];
    for (let i = 0; i < stream.length; i++) objects.push(...parser.push(stream.subarray(i, i + 1)));
    expect(objects.map((o) => [o.name[0], o.type, o.data?.toString() ?? null])).toEqual([
      ['a', 'blob', 'hello\nworld'],
      ['b', 'missing', null],
      ['c', 'blob', ''],
    ]);
    expect(parser.idle).toBe(true);
  });

  it('rejects garbage headers', () => {
    expect(() => new BatchOutputParser().push(Buffer.from('not a header\n'))).toThrow(/unexpected cat-file header/);
  });
});

describe('syncShallowClone', () => {
  const accept = async () => null;

  it('clones without a checkout, then fetches and adopts new commits', async () => {
    const root = tempDir();
    const origin = path.join(root, 'origin');
    const first = commitFiles(origin, { 'a.txt': '1' });
    const dir = path.join(root, 'cache', 'git', 'repo');
    const log = captureLogger();
    const spec = { remote: `file://${origin}`, branch: 'main', dir, offline: false, log, timeoutMs: 60_000, accept };

    const cloned = await syncShallowClone(spec);
    expect(cloned).toEqual({ dir, commit: first, stale: false, error: null });
    expect(readdirSync(dir)).toEqual(['.git']);
    expect(runGit(dir, 'rev-parse', '--is-shallow-repository')).toBe('true');

    const second = commitFiles(origin, { 'a.txt': '2' });
    const fetched = await syncShallowClone(spec);
    expect(fetched).toEqual({ dir, commit: second, stale: false, error: null });
    expect(await resolveCommit(dir, 'HEAD')).toBe(second);

    // Offline: uses what is there, marked stale.
    expect(await syncShallowClone({ ...spec, offline: true })).toEqual({ dir, commit: second, stale: true, error: null });
  });

  it('clones into a relative cache directory (as CI passes --cache .cache)', async () => {
    const root = tempDir();
    const origin = path.join(root, 'origin');
    const first = commitFiles(origin, { 'a.txt': '1' });
    const dir = path.relative(process.cwd(), path.join(root, 'cache', 'git', 'repo'));
    expect(path.isAbsolute(dir)).toBe(false);
    const spec = { remote: `file://${origin}`, branch: 'main', dir, offline: false, log: captureLogger(), timeoutMs: 60_000, accept };

    expect(await syncShallowClone(spec)).toEqual({ dir, commit: first, stale: false, error: null });
    expect(readdirSync(dir)).toEqual(['.git']);
  });

  it('keeps the previous commit when the new one fails the sanity check', async () => {
    const root = tempDir();
    const origin = path.join(root, 'origin');
    const good = commitFiles(origin, { 'a.txt': 'good' });
    const dir = path.join(root, 'clone');
    const spec = { remote: `file://${origin}`, branch: 'main', dir, offline: false, log: captureLogger(), timeoutMs: 60_000, accept };
    await syncShallowClone(spec);
    commitFiles(origin, { 'a.txt': 'bad' });

    const result = await syncShallowClone({ ...spec, accept: async () => 'too small' });
    expect(result).toEqual({ dir, commit: good, stale: true, error: 'too small' });
    expect(await resolveCommit(dir, 'HEAD')).toBe(good);
  });

  it('falls back to the cached clone when the remote is unreachable, and fails without one', async () => {
    const root = tempDir();
    const origin = path.join(root, 'origin');
    const commit = commitFiles(origin, { 'a.txt': 'x' });
    const dir = path.join(root, 'clone');
    const spec = { remote: `file://${origin}`, branch: 'main', dir, offline: false, log: captureLogger(), timeoutMs: 60_000, accept };
    await syncShallowClone(spec);
    runGit(dir, 'remote', 'set-url', 'origin', `file://${root}/gone`);

    const result = await syncShallowClone(spec);
    expect(result).toMatchObject({ commit, stale: true });
    expect(result.error).toMatch(/git fetch/);

    await expect(syncShallowClone({ ...spec, dir: path.join(root, 'fresh'), remote: `file://${root}/gone` })).rejects.toThrow(/git clone/);
    expect(existsSync(path.join(root, `fresh.tmp-${process.pid}`))).toBe(false);
  });

  it('never mistakes an enclosing repository for the clone', async () => {
    const root = tempDir();
    commitFiles(root, { 'project.txt': 'outer repo' });
    const dir = path.join(root, '.cache', 'git', 'repo');
    mkdirSync(dir, { recursive: true });
    const spec = { remote: 'file:///nonexistent', branch: 'main', dir, offline: true, log: captureLogger(), timeoutMs: 60_000, accept };
    await expect(syncShallowClone(spec)).rejects.toThrow(/no usable clone/);
  });
});
