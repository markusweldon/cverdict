/**
 * Ingest stage: fetch every source (primary → fallback → cache, SPEC §2), stream the whole CVE
 * List once, and return normalised window ∪ KEV records with History counters, enrichment data
 * restricted to those records, and a SourceStatus per source.
 */
import { SANITY, type SanityLimits } from './config';
import { cvelistStatuses, openCvelist, scanCvelist, type CvelistRepo, type CvelistScan } from './sources/cvelist';
import { loadEpss } from './sources/epss';
import { loadExploitDb } from './sources/exploitdb';
import { loadKev } from './sources/kev';
import { loadMetasploit } from './sources/metasploit';
import { loadNuclei } from './sources/nuclei';
import { openPoc, readPocRepos } from './sources/poc';
import type { EpssTable, ExploitIndex, IngestOptions, IngestResult, KevCatalog, RunContext } from './types';
import { HttpClient } from './util/http';
import { since } from './util/log';

export interface IngestDeps {
  http: HttpClient;
  limits: SanityLimits;
}

export async function ingest(ctx: RunContext, opts: IngestOptions): Promise<IngestResult> {
  const http = new HttpClient({ cacheDir: ctx.cacheDir, offline: ctx.offline, log: ctx.log });
  return ingestWith(ctx, opts, { http, limits: SANITY });
}

/** Keep only the entries for `ids`. */
function restrict<V>(map: Map<string, V> | null, ids: ReadonlySet<string>): Map<string, V> {
  const out = new Map<string, V>();
  if (!map) return out;
  for (const id of ids) {
    const value = map.get(id);
    if (value !== undefined) out.set(id, value);
  }
  return out;
}

/** ingest() with injectable HTTP client and sanity limits (tests, tools). */
export async function ingestWith(ctx: RunContext, opts: IngestOptions, deps: IngestDeps): Promise<IngestResult> {
  const { log } = ctx;
  const { http, limits } = deps;
  const started = performance.now();
  const abort = new AbortController();
  const { signal } = abort;

  // Independent downloads run while the CVE List streams; none of them ever throws.
  const kevP = loadKev(http, limits, signal);
  const epssP = loadEpss(http, ctx.now, limits, signal);
  const metasploitP = loadMetasploit(http, limits, signal);
  const nucleiP = loadNuclei(http, limits, signal);
  const exploitDbP = loadExploitDb(http, limits, signal);
  const pocP = openPoc(ctx, opts.pocDir, limits, signal);
  const pending = [kevP, epssP, metasploitP, nucleiP, exploitDbP, pocP];

  let repo: CvelistRepo;
  let scan: CvelistScan;
  try {
    repo = await openCvelist(ctx, opts.cvelistDir, limits, signal);
    log.info(`cvelist: reading ${repo.dir} at ${repo.commit.slice(0, 12)}${repo.stale ? ' (stale)' : ''}`);
    scan = await scanCvelist(repo, {
      windowStart: ctx.windowStart,
      now: ctx.now,
      kevIds: kevP.then((kev) => new Set(kev.data?.entries.keys())),
      minRecords: limits.cvelistRecords,
      log,
      signal,
    });
  } catch (err) {
    // The CVE List is the one fatal source: stop the other downloads before failing.
    abort.abort();
    await Promise.allSettled(pending);
    throw err;
  }

  const ids = new Set(scan.cves.map((c) => c.id));
  const [kev, epss, metasploit, nuclei, exploitDb, pocTree] = await Promise.all([kevP, epssP, metasploitP, nucleiP, exploitDbP, pocP]);
  const poc = await readPocRepos(pocTree, ids, log, signal);

  const epssTable: EpssTable = {
    model: epss.data?.model ?? null,
    scoreDate: epss.data?.scoreDate ?? null,
    scores: restrict(epss.data?.scores ?? null, ids),
  };
  const exploits: ExploitIndex = {
    metasploit: restrict(metasploit.data, ids),
    nuclei: restrict(nuclei.data, ids),
    exploitdb: restrict(exploitDb.data, ids),
    poc: poc.repos,
  };
  const kevCatalog: KevCatalog = kev.data ?? { version: null, dateReleased: null, entries: new Map() };
  const sources = [...cvelistStatuses(repo, scan), kev.status, epss.status, metasploit.status, nuclei.status, exploitDb.status, poc.status];

  const kevInWindow = scan.cves.filter((c) => c.inWindow && (kevCatalog.entries.has(c.id) || c.adpKev)).length;
  log.info(
    `ingest: ${scan.cves.length.toLocaleString('en-US')} records (${scan.windowPublished.toLocaleString('en-US')} in window, ` +
      `${kevInWindow} of them KEV) · EPSS ${epssTable.scores.size} · Metasploit ${exploits.metasploit.size} · ` +
      `Nuclei ${exploits.nuclei.size} · Exploit-DB ${exploits.exploitdb.size} · PoC ${exploits.poc.size} · ${since(started)}`,
  );
  for (const s of sources) {
    if (!s.ok || s.stale) log.warn(`ingest: source ${s.id} ${s.ok ? 'stale' : 'unavailable'}${s.error ? ` — ${s.error}` : ''}`);
  }

  return {
    cves: scan.cves,
    history: scan.history,
    rejectedInWindow: scan.rejectedInWindow,
    kev: kevCatalog,
    epss: epssTable,
    exploits,
    sources,
    cvelistCommit: repo.commit,
  };
}
