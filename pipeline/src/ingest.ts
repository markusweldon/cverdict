/**
 * Ingest stage: fetch every source (primary → fallback → cache, SPEC §2), stream the whole CVE
 * List once, and return normalised window ∪ KEV records with History counters, enrichment data
 * restricted to those records, and a SourceStatus per source.
 */
import { SANITY, type SanityLimits } from './config';
import { cvelistStatuses, openCvelist, scanCvelist, type CvelistRepo, type CvelistScan } from './sources/cvelist';
import { loadEpss, loadEpssOn } from './sources/epss';
import { loadExploitDb } from './sources/exploitdb';
import { loadKev } from './sources/kev';
import { loadMetasploit } from './sources/metasploit';
import { loadNuclei } from './sources/nuclei';
import { openPoc, readPocRepos } from './sources/poc';
import { loadEpssAsOf, type BacktestInputs } from './backtest';
import { EMPTY_STATE, readSection } from './state';
import type { EpssTable, ExploitIndex, IngestOptions, IngestResult, KevCatalog, RunContext } from './types';
import { HttpClient } from './util/http';
import { since } from './util/log';
import { detectWakes, epssPastDates, failedWakeDetection, WOKE_SECTION, type WakeDetection } from './woke';

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
  // Every PoC file is read (wake detection needs each CVE's first repo); the scan keeps its own.
  const pocReadP = pocP.then((tree) => readPocRepos(tree, tree.data?.files.keys() ?? [], log, signal));
  // EPSS from WAKE_DAYS before the current score date, for EPSS jumps.
  const epssPastP = epssP.then((e) =>
    e.data?.scoreDate ? loadEpssOn(http, epssPastDates(e.data.scoreDate), limits, signal) : { data: null, error: 'no current EPSS score date' },
  );
  // Wake detection runs as soon as its inputs are in, while the CVE List is still streaming, so
  // old CVEs that woke up are recognised in the pass (or looked up by path right after it).
  const previousState = opts.previousState ?? EMPTY_STATE;
  const previousWoke = readSection(previousState, WOKE_SECTION, log);
  const wakeP: Promise<WakeDetection> = Promise.all([kevP, exploitDbP, metasploitP, nucleiP, pocReadP, epssP, epssPastP]).then(
    ([kev, exploitDb, metasploit, nuclei, pocRead, epss, epssPast]) => {
      const t0 = performance.now();
      const wake = detectWakes({
        now: ctx.now,
        kev: kev.data,
        exploitdb: exploitDb.data,
        metasploit: metasploit.data?.byCve ?? null,
        nuclei: nuclei.data,
        poc: pocRead.status.ok ? pocRead.repos : null,
        epss: epss.data,
        epssPast: epssPast.data,
        epssPastError: epssPast.error,
        previous: previousWoke,
        previousAt: previousState.generatedAt,
      });
      for (const note of wake.notes) log.info(`woke: ${note}`);
      for (const s of wake.skipped) log.warn(`woke: ${s.kind} skipped: ${s.reason}`);
      log.info(`woke: ${wake.signals.size} CVEs with a wake signal in the period (${since(t0)})`);
      return wake;
    },
  ).catch((err: unknown) => {
    // Never fatal: keep the previous state and say every signal was skipped.
    const message = err instanceof Error ? err.message : String(err);
    log.error(`woke: detection failed (${message})`);
    return failedWakeDetection(previousWoke, message);
  });
  // Backtest refresh only: EPSS of the days before recent KEV listings, downloaded while the CVE List streams.
  const plan = opts.backtest;
  const epssAsOfP = plan ? kevP.then((kev) => loadEpssAsOf(http, kev.data, ctx.now, plan.reuse, limits, log, signal)) : Promise.resolve(null);
  const pending = [kevP, epssP, metasploitP, nucleiP, exploitDbP, pocP, pocReadP, epssPastP, wakeP, epssAsOfP];

  let repo: CvelistRepo;
  let scan: CvelistScan;
  try {
    repo = await openCvelist(ctx, opts.cvelistDir, limits, signal);
    log.info(`cvelist: reading ${repo.dir} at ${repo.commit.slice(0, 12)}${repo.stale ? ' (stale)' : ''}`);
    scan = await scanCvelist(repo, {
      windowStart: ctx.windowStart,
      now: ctx.now,
      kevIds: kevP.then((kev) => new Set(kev.data?.entries.keys())),
      extraIds: wakeP.then((w) => new Set(w.signals.keys())),
      keepFrom: plan?.volumeFrom,
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
  const [kev, epss, metasploit, nuclei, exploitDb, pocRead, wake, epssAsOf] = await Promise.all([kevP, epssP, metasploitP, nucleiP, exploitDbP, pocReadP, wakeP, epssAsOfP]);

  const epssTable: EpssTable = {
    model: epss.data?.model ?? null,
    scoreDate: epss.data?.scoreDate ?? null,
    scores: restrict(epss.data?.scores ?? null, ids),
  };
  const exploits: ExploitIndex = {
    metasploit: restrict(metasploit.data?.byCve ?? null, ids),
    nuclei: restrict(nuclei.data, ids),
    exploitdb: restrict(exploitDb.data?.byCve ?? null, ids),
    poc: restrict(pocRead.repos, ids),
  };
  const kevCatalog: KevCatalog = kev.data ?? { version: null, dateReleased: null, entries: new Map() };
  const sources = [...cvelistStatuses(repo, scan), kev.status, epss.status, metasploit.status, nuclei.status, exploitDb.status, pocRead.status];

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
    wake,
    ...(plan && epssAsOf
      ? {
          backtest: {
            epss: epssAsOf,
            reuse: plan.reuse,
            metasploitModified: restrict(metasploit.data?.firstModified ?? null, ids),
            exploitdbAdded: exploitDb.data?.added ?? new Map(),
            volumeFrom: plan.volumeFrom.toISOString(),
          } satisfies BacktestInputs,
        }
      : {}),
  };
}
