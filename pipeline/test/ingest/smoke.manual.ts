/**
 * Manual end-to-end smoke test of the ingest stage against real data (not run by vitest).
 *
 *   npx tsx pipeline/test/ingest/smoke.manual.ts --cvelist-dir <cvelistV5 clone> --poc-dir <PoC-in-GitHub clone> \
 *     [--now 2026-10-26T19:30:00Z] [--cache <dir>] [--window-days 30] [--offline]
 *
 * Logs go to stderr; a JSON summary (counts, timings, peak memory, every SourceStatus) to stdout.
 */
import { mkdtempSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { DEFAULT_WINDOW_DAYS } from '../../src/config';
import { ingest } from '../../src/ingest';
import type { RunContext } from '../../src/types';
import { addDays, parseIsoDate } from '../../src/util/dates';
import { createLogger } from '../../src/util/log';

const { values } = parseArgs({
  options: {
    'cvelist-dir': { type: 'string' },
    'poc-dir': { type: 'string' },
    now: { type: 'string' },
    cache: { type: 'string' },
    'window-days': { type: 'string' },
    offline: { type: 'boolean', default: false },
  },
});

const now = values.now ? parseIsoDate(values.now) : new Date();
if (!now) throw new Error(`invalid --now: ${values.now}`);
const windowDays = Number(values['window-days'] ?? DEFAULT_WINDOW_DAYS);
const cacheDir = values.cache ?? mkdtempSync(path.join(os.tmpdir(), 'ingest-smoke-'));
const ctx: RunContext = { now, windowDays, windowStart: addDays(now, -windowDays), cacheDir, offline: values.offline ?? false, log: createLogger() };

let peakRss = 0;
const sampler = setInterval(() => (peakRss = Math.max(peakRss, process.memoryUsage().rss)), 200);
const started = performance.now();
const result = await ingest(ctx, { cvelistDir: values['cvelist-dir'], pocDir: values['poc-dir'] });
const seconds = (performance.now() - started) / 1000;
clearInterval(sampler);
peakRss = Math.max(peakRss, process.memoryUsage().rss);

const kevIds = result.kev.entries;
const isKev = (id: string, adpKev: unknown) => kevIds.has(id) || adpKev !== null;
const window = result.cves.filter((c) => c.inWindow);
const sum = (m: Map<string, number>) => [...m.values()].reduce((a, b) => a + b, 0);
const mb = (bytes: number) => Math.round(bytes / (1024 * 1024));

console.log(
  JSON.stringify(
    {
      now: now.toISOString(),
      windowStart: ctx.windowStart.toISOString(),
      cacheDir,
      cvelistCommit: result.cvelistCommit,
      seconds: Math.round(seconds * 10) / 10,
      peakRssMb: mb(peakRss),
      heapUsedMbAfter: mb(process.memoryUsage().heapUsed),
      counts: {
        totalRecords: result.history.totalRecords,
        publishedAllTime: sum(result.history.published),
        rejectedAllTime: sum(result.history.rejected),
        aiCreditedAllTime: sum(result.history.ai),
        kept: result.cves.length,
        windowPublished: window.length,
        kevInWindow: window.filter((c) => isKev(c.id, c.adpKev)).length,
        kevOutsideWindow: result.cves.filter((c) => !c.inWindow).length,
        kevCatalogMissingFromList: [...kevIds.keys()].filter((id) => !result.cves.some((c) => c.id === id)).length,
        rejectedInWindow: result.rejectedInWindow,
        aiCreditedInWindow: window.filter((c) => c.aiCredit).length,
        vendorInTheWildInWindow: window.filter((c) => c.vendorInTheWild).length,
        noCvssInWindow: window.filter((c) => !c.cvss).length,
        ssvcMissingInWindow: window.filter((c) => !c.ssvc).length,
        published2026: [...result.history.published].filter(([m]) => m.startsWith('2026-')).reduce((a, [, n]) => a + n, 0),
        publishedOct2026: result.history.published.get('2026-10') ?? 0,
      },
      enrichment: {
        epssScored: result.epss.scores.size,
        epssModel: result.epss.model,
        epssDate: result.epss.scoreDate,
        metasploit: result.exploits.metasploit.size,
        nuclei: result.exploits.nuclei.size,
        exploitdb: result.exploits.exploitdb.size,
        poc: result.exploits.poc.size,
      },
      sources: result.sources,
    },
    null,
    2,
  ),
);
