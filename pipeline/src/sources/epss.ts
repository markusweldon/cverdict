/** EPSS daily scores (current file, then the dated GitHub archive for today and yesterday, then cache). */
import { gunzipSync } from 'node:zlib';
import { EPSS, type SanityLimits } from '../config';
import type { EpssTable } from '../types';
import { addDays, normalizeYmd, ymd } from '../util/dates';
import type { HttpClient, Parsed } from '../util/http';
import { normalizeCveId, sanitizeLine } from '../util/text';
import { requireAtLeast, statusFromFetch, type SourceResult } from './source';

/** `#model_version:v2026.06.15,score_date:2026-10-26T12:03:00Z` → key/value pairs. */
export function parseEpssHeader(line: string): Map<string, string> {
  const fields = new Map<string, string>();
  for (const pair of line.replace(/^#/, '').split(',')) {
    const colon = pair.indexOf(':');
    if (colon > 0) fields.set(pair.slice(0, colon).trim().toLowerCase(), pair.slice(colon + 1).trim());
  }
  return fields;
}

/**
 * Parse an EPSS CSV: optional `#key:value,…` comment line(s), a column header containing `cve`,
 * `epss` and `percentile` (any order, extra columns allowed), then one row per CVE.
 */
export function parseEpssCsv(text: string): EpssTable & { rows: number } {
  let model: string | null = null;
  let scoreDate: string | null = null;
  let columns: { cve: number; epss: number; percentile: number } | null = null;
  const scores: EpssTable['scores'] = new Map();
  let rows = 0;

  let start = text.charCodeAt(0) === 0xfeff ? 1 : 0;
  while (start < text.length) {
    let end = text.indexOf('\n', start);
    if (end === -1) end = text.length;
    const line = text.slice(start, text.charCodeAt(end - 1) === 0x0d ? end - 1 : end);
    start = end + 1;
    if (line === '') continue;

    if (line.startsWith('#')) {
      const header = parseEpssHeader(line);
      model = sanitizeLine(header.get('model_version'), 64) || model;
      scoreDate = normalizeYmd(header.get('score_date')) ?? scoreDate;
      continue;
    }
    const cells = line.split(',');
    if (!columns) {
      const names = cells.map((c) => c.trim().toLowerCase());
      const cve = names.indexOf('cve');
      const epss = names.indexOf('epss');
      const percentile = names.indexOf('percentile');
      if (cve === -1 || epss === -1 || percentile === -1) throw new Error(`EPSS: unexpected header "${sanitizeLine(line, 80)}"`);
      columns = { cve, epss, percentile };
      continue;
    }
    const id = normalizeCveId(cells[columns.cve]);
    const epss = Number(cells[columns.epss]);
    const percentile = Number(cells[columns.percentile]);
    if (!id || !(epss >= 0 && epss <= 1) || !(percentile >= 0 && percentile <= 1)) continue;
    scores.set(id, { epss, percentile });
    rows++;
  }
  if (!columns) throw new Error('EPSS: no column header');
  return { model, scoreDate, scores, rows };
}

/** Bodies are gzip; tolerate an already-decompressed body (served with Content-Encoding: gzip). */
export function parseEpssBody(body: Buffer, limits: SanityLimits): Parsed<EpssTable> {
  const raw = body[0] === 0x1f && body[1] === 0x8b ? gunzipSync(body) : body;
  const { rows, ...table } = parseEpssCsv(raw.toString('utf8'));
  requireAtLeast(rows, limits.epssRows, 'EPSS rows');
  return { value: table, records: rows, version: [table.model, table.scoreDate].filter(Boolean).join(' ') || null };
}

export async function loadEpss(http: HttpClient, now: Date, limits: SanityLimits, signal?: AbortSignal): Promise<SourceResult<EpssTable>> {
  const fetched = await http.getSource({
    key: 'epss',
    ext: 'csv.gz',
    urls: [EPSS.current, EPSS.daily(ymd(now)), EPSS.daily(ymd(addDays(now, -1)))],
    parse: (body) => parseEpssBody(body, limits),
    signal,
  });
  return { data: fetched.value, status: statusFromFetch(EPSS.info, fetched) };
}

/** The score dates a cached or downloaded EPSS file may carry for `loadEpssOn` to accept it. */
export function parseEpssBodyOn(body: Buffer, dates: readonly string[], limits: SanityLimits): Parsed<EpssTable> {
  const parsed = parseEpssBody(body, limits);
  if (!parsed.value.scoreDate || !dates.includes(parsed.value.scoreDate)) {
    throw new Error(`EPSS: file is for ${parsed.value.scoreDate ?? 'an unknown date'}, wanted ${dates.join(' or ')}`);
  }
  return parsed;
}

/**
 * EPSS scores of a past day (the first of `dates` that the archive has), from the dated
 * archive, then the EPSS host, then the cache. A past day never changes, so a cached copy for
 * one of `dates` is reused without a request; a cached copy of another day is not used.
 * Never throws: `data` is null and `error` says why when no copy of those days could be read.
 */
export async function loadEpssOn(
  http: HttpClient,
  dates: readonly string[],
  limits: SanityLimits,
  signal?: AbortSignal,
): Promise<{ data: EpssTable | null; error: string | null }> {
  const fetched = await http.getSource({
    key: 'epss-past',
    ext: 'csv.gz',
    urls: dates.flatMap((d) => [EPSS.daily(d), EPSS.dated(d)]),
    parse: (body) => parseEpssBodyOn(body, dates, limits),
    minIntervalMs: 30 * 86_400_000,
    signal,
  });
  return { data: fetched.value, error: fetched.value ? null : fetched.error };
}
