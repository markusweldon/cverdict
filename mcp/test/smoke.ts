/**
 * CI smoke test of the built server: starts the bundle over stdio the way an MCP client does,
 * against a data tree on disk served from localhost, and calls every tool.
 *
 *   npx tsx mcp/test/smoke.ts mcp/dist/cverdict-mcp.mjs <data dir with v1/>
 */
import { MCP_TOOLS } from '../../shared/mcp';
import { call, connectStdio, fromDir, serveData } from './harness';

const [bundle, dir] = process.argv.slice(2);
if (!bundle || !dir) {
  console.error('usage: smoke.ts <bundle> <data dir>');
  process.exit(2);
}

const data = await serveData(fromDir(dir));
const s = await connectStdio(process.execPath, [bundle], { CVERDICT_DATA_BASE: data.base });
let failed = false;
try {
  const tools = (await s.client.listTools()).tools.map((t) => t.name);
  if (tools.join() !== MCP_TOOLS.map((t) => t.name).join()) throw new Error(`tools/list: ${tools.join(', ')}`);
  console.log(`connected (${s.client.getNegotiatedProtocolVersion()}), tools: ${tools.join(', ')}`);
  const signal = await call(s.client, 'list_signal', { limit: 3 });
  const ids = (signal.value.items as { id: string }[]).map((i) => i.id);
  const calls: [string, Record<string, unknown>][] = [
    ['get_verdict', { ids: [...ids, 'CVE-1999-0001'] }],
    ['get_verdict', { ids: ids.slice(0, 1), detail: true }],
    ['kev_due', { within_days: 60, overdue_days: 14 }],
    ['woke_up', { since: '2000-01-01', limit: 5 }],
    ['receipts', {}],
    ['search_cves', { query: 'microsoft', limit: 5 }],
  ];
  console.log(`list_signal: total ${signal.value.total}, ${signal.result.content[0].text.length} B`);
  for (const [name, args] of calls) {
    const { value, result } = await call(s.client, name, args);
    const items = value.items as { found?: boolean }[] | undefined;
    console.log(`${name} ${JSON.stringify(args)}: ${items ? `${items.length} items` : 'summary'}, ${result.content[0].text.length} B`);
  }
  if (!ids.length) throw new Error('list_signal returned no rows');
  if (!s.stderr().includes('cverdict-mcp')) throw new Error('no start-up line on stderr');
} catch (e) {
  failed = true;
  console.error(`MCP SMOKE FAILED: ${e instanceof Error ? e.message : String(e)}\n${s.stderr()}`);
} finally {
  await s.close();
  await data.close();
}
if (failed) process.exit(1);
console.log(`MCP SMOKE PASSED (${data.requests.length} data requests)`);
