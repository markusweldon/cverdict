/**
 * Real-data check for the MCP server: answer sizes of every tool on the published data, at the
 * defaults and at the worst case its bounds allow, against the token budget agents work with
 * (Claude Code warns at 10,000 tokens and cuts tool results at 25,000 by default).
 *
 *   npx tsx scripts/mcp-measure.ts [base URL ending in /v1/]     (default: the live data branch)
 *
 * Worst cases are found, not guessed: every shard is read to find the 15 largest verdicts (and the
 * 5 largest with detail), and pages are built from the 50 largest rows or woke items, which no
 * filter can exceed, and from 50 copies of the largest KEV entry (kev.json can hold more after a
 * large CISA batch than it does today). Also checks, for every CVE in every shard, that score_math
 * adds up: base plus the chip points equals the score for an exploited CVE and raw for any other.
 * Exits 1 when a worst case passes 20,000 estimated tokens (3.5 bytes of JSON per token) or the
 * math fails.
 */
import { InMemoryTransport } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { Client } from '@modelcontextprotocol/client';
import { MCP_DATA_BASES } from '../shared/mcp';
import { BASE_POINTS } from '../shared/model';
import { SHARD_COUNT } from '../shared/shard';
import type { CveDetail, McpRow } from '../shared/contract';
import { DataClient, parse } from '../mcp/src/data';
import { createServer } from '../mcp/src/server';
import { getVerdict, kevDue, listSignal, mcpRow, receipts, searchCves, verdictOf, wokeUp } from '../mcp/src/tools';

const BUDGET_TOKENS = 20_000;
const BYTES_PER_TOKEN = 3.5;
const base = process.argv[2] ?? MCP_DATA_BASES[0];
const dc = new DataClient({ bases: [base], callTimeoutMs: 300_000, maxShards: SHARD_COUNT });
const now = Date.now();
const size = (v: unknown) => Buffer.byteLength(JSON.stringify(v));
const tokens = (bytes: number) => Math.round(bytes / BYTES_PER_TOKEN);

interface Line {
  call: string;
  items: number | string;
  bytes: number;
  worst: boolean;
}
const lines: Line[] = [];
const record = (call: string, v: object, worst = false) => lines.push({ call, items: (v as { items?: unknown[] }).items?.length ?? '', bytes: size(v), worst });

const t0 = performance.now();
const meta = await dc.run((c) => c.meta());
console.log(`data ${base}  generated_at ${meta.generated_at}  window ${meta.counts.window_published} CVEs`);

// Defaults, as an agent calls them first.
record('get_verdict, 1 ID (first exploited in signal.json)', await dc.run(async (c) => getVerdict(c, { ids: [(await c.file('signal.json', parse.rows)).rows[0].id] }, now)));
record('list_signal, defaults', await dc.run((c) => listSignal(c, {}, now)));
record('kev_due, defaults (7 + 7 days)', await dc.run((c) => kevDue(c, {}, now)));
record('woke_up, defaults', await dc.run((c) => wokeUp(c, {}, now)));
record('receipts, summary', await dc.run((c) => receipts(c, {}, now)));
record('search_cves "fortinet"', await dc.run((c) => searchCves(c, { query: 'fortinet' }, now)));

// Every shard: the largest verdicts, and the score math of every CVE.
const names = Array.from({ length: SHARD_COUNT }, (_, i) => i.toString(16).padStart(2, '0'));
const shards = await dc.run((c) => c.shards(names));
const details: { d: CveDetail; url: string }[] = [];
for (const { shard, url } of shards.values()) for (const d of Object.values(shard.items)) details.push({ d, url });
let mathFailures = 0;
for (const { d } of details) {
  const sum = BASE_POINTS + d.reasons.reduce((s, r) => s + r.points, 0);
  if (sum !== (d.score.tier === 'exploited' ? d.score.value : d.score.raw)) {
    if (mathFailures++ < 5) console.log(`score_math does not add up for ${d.id}: ${sum} vs ${d.score.tier === 'exploited' ? d.score.value : d.score.raw}`);
  }
}
const largest = (detail: boolean, n: number) =>
  details
    .map(({ d, url }) => ({ id: d.id, bytes: size(verdictOf(d, 50, url, detail)) }))
    .sort((a, b) => b.bytes - a.bytes)
    .slice(0, n)
    .map((x) => x.id);
record('get_verdict, 15 largest of all CVEs', await dc.run((c) => getVerdict(c, { ids: largest(false, 15) }, now)), true);
record('get_verdict, 5 largest with detail: true', await dc.run((c) => getVerdict(c, { ids: largest(true, 5), detail: true }, now)), true);

// Pages: no filter can pick rows larger than the 50 largest rows of index.json.
const index = await dc.run((c) => c.file('index.json', parse.rows));
const biggestRows = index.rows.map((r) => mcpRow(r, 50)).sort((a, b) => size(b) - size(a));
const page = await dc.run((c) => listSignal(c, { tiers: ['exploited', 'likely', 'watch', 'quiet'], knob: 30, limit: 50 }, now));
record('list_signal / search_cves page of the 50 largest rows', { ...page, items: biggestRows.slice(0, 50) as McpRow[] }, true);
record('search_cves "cve", every tier, limit 50', await dc.run((c) => searchCves(c, { query: 'cve', limit: 50, tiers: ['exploited', 'likely', 'watch', 'quiet'], knob: 30 }, now)));
const wokeCount = (await dc.run((c) => c.file('woke.json', parse.woke))).items.length;
const wokePages = [];
for (let offset = 0; offset < Math.max(1, wokeCount); offset += 50) wokePages.push(await dc.run((c) => wokeUp(c, { since: '2000-01-01', limit: 50, offset }, now)));
const wokeBiggest = wokePages.flatMap((p) => p.items).sort((a, b) => size(b) - size(a));
record('woke_up page of the 50 largest items', { ...wokePages[0], items: wokeBiggest.slice(0, 50) }, true);
const kevWide = await dc.run((c) => kevDue(c, { within_days: 60, overdue_days: 14 }, now));
record('kev_due, 60 days ahead and 14 overdue', kevWide);
// kev.json can hold far more entries after a large CISA batch: a full page of the largest one.
const kevBiggest = [...kevWide.items].sort((a, b) => size(b) - size(a))[0];
record('kev_due page of 50 copies of its largest entry', { ...kevWide, items: kevBiggest ? Array(50).fill(kevBiggest) : [] }, true);

// receipts with the id whose entries are largest.
const rf = await dc.run((c) => c.file('receipts.json', parse.receipts));
const rids = [...new Set([...rf.forward.items.map((i) => i.id), ...rf.forward.uncounted.map((i) => i.id), ...(rf.backtest?.items.map((i) => i.id) ?? [])])];
let worstReceipt = await dc.run((c) => receipts(c, {}, now));
for (const id of rids) {
  const r = await dc.run((c) => receipts(c, { id }, now));
  if (size(r) > size(worstReceipt)) worstReceipt = r;
}
record(`receipts, the largest single CVE (${worstReceipt.cve?.id ?? 'none'})`, worstReceipt, true);

// tools/list, as a client receives it.
const [cs, ss] = InMemoryTransport.createLinkedPair();
const handle = serveStdio(() => createServer(dc), { transport: ss });
const client = new Client({ name: 'measure', version: '0' });
await client.connect(cs);
const toolsBytes = size(await client.listTools());
await client.close();
await handle.close();

console.log(`\n${'call'.padEnd(58)} ${'items'.padStart(5)} ${'bytes'.padStart(8)} ${'~tokens'.padStart(8)}`);
for (const l of lines) console.log(`${(l.worst ? '* ' : '  ') + l.call.padEnd(56)} ${String(l.items).padStart(5)} ${String(l.bytes).padStart(8)} ${String(tokens(l.bytes)).padStart(8)}`);
console.log(`  ${'tools/list'.padEnd(56)} ${''.padStart(5)} ${String(toolsBytes).padStart(8)} ${String(tokens(toolsBytes)).padStart(8)}`);
const worst = Math.max(...lines.map((l) => tokens(l.bytes)));
console.log(`\n* = worst case at the maximum bounds. Largest: ~${worst} tokens (budget ${BUDGET_TOKENS}). Tokens are estimated at ${BYTES_PER_TOKEN} bytes of JSON each.`);
console.log(`score_math checked on ${details.length} CVEs in ${shards.size} shards: ${mathFailures} failures. ${dc.requests} requests, ${Math.round(performance.now() - t0)} ms.`);
if (worst > BUDGET_TOKENS || mathFailures > 0) {
  console.log('MCP MEASURE FAILED');
  process.exit(1);
}
console.log('MCP MEASURE PASSED');
