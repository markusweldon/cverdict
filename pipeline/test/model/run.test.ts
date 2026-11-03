import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { BRAND } from '../../../shared/brand';
import type { Meta } from '../../../shared/contract';
import { ingest } from '../../src/ingest';
import { ValidationFailedError, run, siteUrl } from '../../src/run';
import { NOW, cohort, makeCve, makeIngest, makeKev, msf } from '../fixtures/model/builders';

const control = vi.hoisted(() => ({ failValidation: false }));

vi.mock('../../src/ingest', () => ({ ingest: vi.fn() }));
vi.mock('../../src/validate', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../src/validate')>();
  return {
    ...real,
    validateOutput: (root: string) => {
      const result = real.validateOutput(root);
      return control.failValidation ? { ...result, ok: false, errors: ['forced failure'] } : result;
    },
  };
});

const ingestMock = vi.mocked(ingest);
const fixture = () =>
  makeIngest([...cohort(50), makeCve({ id: 'CVE-2026-100001', published: '2026-10-26T19:45:00.000Z' })], {
    kev: [makeKev('CVE-2026-200001')],
    metasploit: { 'CVE-2026-200002': [msf('exploit/x')] },
  });

let root: string;
let out: string;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'run-'));
  out = join(root, 'public', 'data');
  control.failValidation = false;
  ingestMock.mockReset();
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});
afterEach(() => {
  rmSync(root, { recursive: true, force: true });
  vi.restoreAllMocks();
});

const opts = () => ({ out, previous: null, cache: join(root, 'cache'), now: NOW, windowDays: 30, offline: true });
const siblings = () => readdirSync(join(root, 'public')).sort();

describe('run', () => {
  it('ingests with the run context, writes and validates the tree, and returns a summary', async () => {
    ingestMock.mockResolvedValue(fixture());
    const summary = await run({ ...opts(), cvelistDir: '/clones/cvelist', pocDir: '/clones/poc' });

    const [ctx, ingestOpts] = ingestMock.mock.calls[0];
    expect(ctx).toMatchObject({ now: NOW, windowDays: 30, offline: true, cacheDir: join(root, 'cache') });
    expect(ctx.windowStart.toISOString()).toBe('2026-09-26T19:30:00.000Z');
    expect(ingestOpts).toMatchObject({ cvelistDir: '/clones/cvelist', pocDir: '/clones/poc', previousState: { status: 'missing' } });

    expect(summary.validation.ok).toBe(true);
    expect(summary.meta.counts.window_published).toBe(50); // the record published after --now is dropped
    expect(summary.meta.counts.window_by_tier.exploited).toBe(1);
    expect(summary.top.map((r) => r.id)).toEqual(['CVE-2026-200001', 'CVE-2026-200002']);
    expect(summary.batches).toHaveLength(1);

    const meta = JSON.parse(readFileSync(join(out, 'v1', 'meta.json'), 'utf8')) as Meta;
    expect(meta.generated_at).toBe(NOW.toISOString());
    expect(meta.knob_default).toBe(50);
    expect(existsSync(join(out, 'feeds', 'kev-due.ics'))).toBe(true);
    expect(siblings()).toEqual(['data']);
  });

  it('replaces the previous output atomically', async () => {
    mkdirSync(out, { recursive: true });
    writeFileSync(join(out, 'stale.txt'), 'old');
    ingestMock.mockResolvedValue(fixture());
    await run({ ...opts(), knob: 40 });
    expect(existsSync(join(out, 'stale.txt'))).toBe(false);
    expect(JSON.parse(readFileSync(join(out, 'v1', 'meta.json'), 'utf8')).knob_default).toBe(40);
    expect(siblings()).toEqual(['data']);
  });

  it('leaves the output untouched when ingest fails', async () => {
    mkdirSync(out, { recursive: true });
    writeFileSync(join(out, 'stale.txt'), 'old');
    ingestMock.mockRejectedValue(new Error('cvelist unreadable'));
    await expect(run(opts())).rejects.toThrow('cvelist unreadable');
    expect(readFileSync(join(out, 'stale.txt'), 'utf8')).toBe('old');
    expect(siblings()).toEqual(['data']);
  });

  it('leaves the output untouched and cleans up when validation fails', async () => {
    mkdirSync(out, { recursive: true });
    writeFileSync(join(out, 'stale.txt'), 'old');
    ingestMock.mockResolvedValue(fixture());
    control.failValidation = true;
    const err = await run(opts()).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ValidationFailedError);
    expect((err as ValidationFailedError).result.errors).toEqual(['forced failure']);
    expect(readFileSync(join(out, 'stale.txt'), 'utf8')).toBe('old');
    expect(siblings()).toEqual(['data']);
  });

  it('rejects bad options before ingesting', async () => {
    await expect(run({ ...opts(), knob: 95 })).rejects.toThrow(/knob/);
    await expect(run({ ...opts(), windowDays: 0 })).rejects.toThrow(/windowDays/);
    expect(ingestMock).not.toHaveBeenCalled();
  });
});

describe('siteUrl', () => {
  it('defaults to the brand deployment and normalises SITE_URL', () => {
    expect(siteUrl({})).toBe(BRAND.siteUrl);
    expect(siteUrl({ SITE_URL: ' https://example.org/triage/ ' })).toBe('https://example.org/triage');
    expect(() => siteUrl({ SITE_URL: 'javascript:alert(1)' })).toThrow(/http/);
    expect(() => siteUrl({ SITE_URL: 'not a url' })).toThrow();
  });
});
