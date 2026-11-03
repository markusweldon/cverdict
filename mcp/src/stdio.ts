/**
 * The local MCP server: stdio transport, one process per client. stdout carries only JSON-RPC, so
 * everything else goes to stderr. Configuration (all optional): CVERDICT_DATA_BASE, and for a proxy
 * NODE_USE_ENV_PROXY=1 with HTTPS_PROXY (Node 22.21 or later); see mcp/README.md.
 */
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { MCP_SERVER } from '../../shared/mcp';
import { dataClientFromEnv, type DataClient } from './data';
import { createServer } from './server';

let dc: DataClient;
try {
  dc = dataClientFromEnv(process.env);
} catch (e) {
  process.stderr.write(`${MCP_SERVER.npm}: ${e instanceof Error ? e.message : String(e)}\n`);
  process.exit(2);
}

// Older Node ignores NODE_USE_ENV_PROXY without a warning, so say what this process sees.
const proxy = process.env.HTTPS_PROXY || process.env.https_proxy ? `HTTPS_PROXY set, NODE_USE_ENV_PROXY=${process.env.NODE_USE_ENV_PROXY ?? 'unset'}` : 'no proxy';
process.stderr.write(`${MCP_SERVER.npm} ${MCP_SERVER.version} on Node ${process.version} (${proxy}); data from ${dc.bases.join(', ')}\n`);

serveStdio(() => createServer(dc), { onerror: (e) => process.stderr.write(`${MCP_SERVER.npm}: ${e.message}\n`) });
