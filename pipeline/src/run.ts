/**
 * Pipeline orchestration: ingest → build the output tree in memory (emit/build.ts) → write it
 * to `<out>.tmp-<pid>` → validate → swap into `<out>`. On failure nothing under `<out>` changes.
 */
import { existsSync } from 'node:fs';
import { mkdir, rename, rm } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { BRAND } from '../../shared/brand';
import { KNOB_DEFAULT, KNOB_MAX, KNOB_MIN, type Batch, type Meta, type Row } from '../../shared/contract';
import { SCORE_MODEL } from '../../shared/model';
import { buildOutput } from './emit/build';
import { writeFiles } from './emit/json';
import { ingest } from './ingest';
import type { RunContext } from './types';
import { DAY_MS } from './util/dates';
import { createLogger } from './util/log';
import { validateOutput, type ValidationResult } from './validate';

export interface RunOptions {
  out: string;
  previous: string | null;
  cache: string;
  cvelistDir?: string;
  pocDir?: string;
  now?: Date;
  windowDays: number;
  offline: boolean;
  /** Default knob for Row.tier / meta.knob_default (KNOB_MIN…KNOB_MAX). */
  knob?: number;
}

export interface RunSummary {
  out: string;
  meta: Meta;
  batches: Batch[];
  /** Exploited first, then likely; highest score first. */
  top: Row[];
  validation: ValidationResult;
  durationMs: number;
}

/** Thrown when the emitted tree fails validation; `<out>` is left untouched. */
export class ValidationFailedError extends Error {
  constructor(readonly result: ValidationResult) {
    super(`output validation failed: ${result.errors.length} error(s); first: ${result.errors[0]}`);
    this.name = 'ValidationFailedError';
  }
}

/** Public site base for feed links: $SITE_URL, else the default Vercel deployment. */
export function siteUrl(env: NodeJS.ProcessEnv = process.env): string {
  const raw = env.SITE_URL?.trim() || `https://${BRAND.slug}.vercel.app`;
  const url = new URL(raw);
  if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new Error(`SITE_URL must be http(s): ${raw}`);
  return url.href.replace(/\/+$/, '');
}

/** Replace `out` with `tmp` using renames; the previous tree is restored if the swap fails. */
async function swapInto(tmp: string, out: string): Promise<void> {
  await mkdir(dirname(out), { recursive: true });
  const old = `${out}.old-${process.pid}`;
  const hadOut = existsSync(out);
  if (hadOut) await rename(out, old);
  try {
    await rename(tmp, out);
  } catch (e) {
    if (hadOut) await rename(old, out);
    throw e;
  }
  if (hadOut) await rm(old, { recursive: true, force: true });
}

export async function run(opts: RunOptions): Promise<RunSummary> {
  const started = Date.now();
  const now = opts.now ?? new Date();
  const knob = opts.knob ?? KNOB_DEFAULT;
  if (!Number.isInteger(opts.windowDays) || opts.windowDays < 1) throw new Error(`windowDays must be a positive integer, got ${opts.windowDays}`);
  if (!Number.isFinite(knob) || knob < KNOB_MIN || knob > KNOB_MAX) throw new Error(`knob must be within ${KNOB_MIN}–${KNOB_MAX}, got ${knob}`);
  const log = createLogger();
  const windowStart = new Date(now.getTime() - opts.windowDays * DAY_MS);
  const ctx: RunContext = { now, windowDays: opts.windowDays, windowStart, cacheDir: opts.cache, offline: opts.offline, log };
  const base = siteUrl();

  log.info(`${BRAND.slug} pipeline · model ${SCORE_MODEL} · now ${now.toISOString()} · window ${opts.windowDays}d · knob ${knob}`);
  const ing = await ingest(ctx, { cvelistDir: opts.cvelistDir, pocDir: opts.pocDir });
  const built = buildOutput({ ingest: ing, now, windowDays: opts.windowDays, knob, previous: opts.previous, siteUrl: base });
  log.info(`scored ${built.scored.length} records (${built.meta.counts.window_published} in window), ${built.batches.length} batches`);

  const out = resolve(opts.out);
  const tmp = `${out}.tmp-${process.pid}`;
  await rm(tmp, { recursive: true, force: true });
  let validation: ValidationResult;
  try {
    await writeFiles(tmp, built.files);
    validation = validateOutput(tmp, log);
    if (!validation.ok) throw new ValidationFailedError(validation);
    await swapInto(tmp, out);
  } catch (e) {
    await rm(tmp, { recursive: true, force: true });
    throw e;
  }
  log.info(`wrote ${validation.files} files to ${out}`);
  return { out, meta: built.meta, batches: built.batches, top: built.top, validation, durationMs: Date.now() - started };
}
