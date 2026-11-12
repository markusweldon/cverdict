/**
 * The MCP server factory: one McpServer with the six read-only tools over a DataClient. It knows
 * nothing about transports, so the same factory serves stdio (mcp/src/stdio.ts) and would serve a
 * web-standard handler (createMcpHandler) unchanged. Inputs are bounded by zod schemas; every
 * failure comes back as a tool result with isError: true, never as a thrown protocol error.
 */
import { McpServer } from '@modelcontextprotocol/server';
import { z } from 'zod';
import { KNOB_DEFAULT, KNOB_MAX, KNOB_MIN, TIERS, WAKE_KINDS, type Tier, type WakeKind } from '../../shared/contract';
import { MCP_INSTRUCTIONS, MCP_SERVER, MCP_TOOLS, type McpToolName } from '../../shared/mcp';
import { DataError, type DataCall, type DataClient } from './data';
import { DATE_RE, InputError, LIMITS, getVerdict, kevDue, listSignal, parseUtc, receipts, searchCves, wokeUp } from './tools';

/** Every tool reads one published dataset and changes nothing. */
export const ANNOTATIONS = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false } as const;

const tier = z.enum(TIERS as [Tier, ...Tier[]]);
const tiers = z.array(tier).min(1).max(4);
const knob = z
  .number()
  .int()
  .min(KNOB_MIN)
  .max(KNOB_MAX)
  .optional()
  .describe(`The evidence bar: the score out of 100 a CVE needs to be Likely next, ${KNOB_MIN} to ${KNOB_MAX}. Default ${KNOB_DEFAULT}, as on the site.`);
const limit = (def: number) => z.number().int().min(1).max(LIMITS.page).optional().describe(`Items per page, 1 to ${LIMITS.page}. Default ${def}.`);
const offset = z.number().int().min(0).max(LIMITS.offset).optional().describe('Items to skip: next_offset of the previous page.');
const date = (what: string) =>
  z
    .string()
    .max(30)
    .regex(DATE_RE, 'expected a UTC date (2026-10-01) or date-time (2026-10-01T06:00Z)')
    .refine((s) => !Number.isNaN(parseUtc(s)), 'not a real date')
    .optional()
    .describe(what);
const cveId = z.string().min(1).max(32);

const SCHEMAS = {
  get_verdict: z.object({
    ids: z.array(cveId).min(1).max(LIMITS.ids).describe('CVE IDs, e.g. ["CVE-2026-96951"].'),
    knob,
    detail: z.boolean().optional().describe(`Also return the description, affected products, CWE, SSVC, exploit links, timeline and references. At most ${LIMITS.detailIds} IDs.`),
  }),
  list_signal: z.object({
    tiers: tiers.optional().describe('Default ["exploited","likely"].'),
    knob,
    vendor: z.string().max(100).optional().describe('Case-insensitive text in the vendor or product name.'),
    published_since: date('Only CVEs published on or after this UTC date or date-time.'),
    kev_only: z.boolean().optional().describe('Only CVEs in CISA KEV.'),
    limit: limit(25),
    offset,
  }),
  kev_due: z.object({
    within_days: z.number().int().min(0).max(LIMITS.withinDays).optional().describe(`Due today or in the next N days, 0 to ${LIMITS.withinDays}. Default 7.`),
    overdue_days: z.number().int().min(0).max(LIMITS.overdueDays).optional().describe(`Also overdue by up to N days, 0 to ${LIMITS.overdueDays}. Default 7.`),
    limit: limit(LIMITS.page),
    offset,
  }),
  woke_up: z.object({
    since: date('Woke up on or after this UTC date or date-time. Default: 7 days before the data was generated.'),
    kinds: z
      .array(z.enum(WAKE_KINDS as [WakeKind, ...WakeKind[]]))
      .min(1)
      .max(WAKE_KINDS.length)
      .optional()
      .describe('Only CVEs with a signal of these kinds.'),
    limit: limit(25),
    offset,
  }),
  receipts: z.object({ id: cveId.optional().describe('One CVE: its forward-log entry and its backtest entry.') }),
  search_cves: z.object({
    query: z
      .string()
      .min(2)
      .max(100)
      .refine((q) => q.trim().split(/\s+/).length <= LIMITS.queryWords, `at most ${LIMITS.queryWords} words`)
      .describe(`Words that must all occur (case-insensitive), at most ${LIMITS.queryWords}.`),
    tiers: tiers.optional().describe('Only these tiers at the evidence bar.'),
    knob,
    limit: limit(20),
    offset,
  }),
} satisfies Record<McpToolName, z.ZodType>;

type Args<N extends McpToolName> = z.infer<(typeof SCHEMAS)[N]>;
type Handler<N extends McpToolName> = (call: DataCall, args: Args<N>, now: number) => Promise<object>;

const HANDLERS: { [N in McpToolName]: Handler<N> } = {
  get_verdict: getVerdict,
  list_signal: listSignal,
  kev_due: kevDue,
  woke_up: wokeUp,
  receipts,
  search_cves: searchCves,
};

/** structuredContent plus the same JSON as one text block (spec: SHOULD), or an isError text. */
function answer(value: object) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(value) }], structuredContent: value as Record<string, unknown> };
}
function failure(message: string) {
  return { content: [{ type: 'text' as const, text: message }], isError: true };
}

export function createServer(dc: DataClient): McpServer {
  const server = new McpServer(
    { name: MCP_SERVER.name, title: MCP_SERVER.title, version: MCP_SERVER.version },
    {
      capabilities: { tools: { listChanged: false } },
      instructions: MCP_INSTRUCTIONS,
      cacheHints: { 'tools/list': { ttlMs: 3_600_000, cacheScope: 'public' }, 'server/discover': { ttlMs: 3_600_000, cacheScope: 'public' } },
    },
  );
  for (const { name, title, description } of MCP_TOOLS) {
    const handler = HANDLERS[name] as Handler<McpToolName>;
    server.registerTool(name, { title, description, inputSchema: SCHEMAS[name], annotations: ANNOTATIONS }, async (args: unknown) => {
      try {
        return answer(await dc.run((call) => handler(call, args as Args<McpToolName>, dc.now())));
      } catch (e) {
        if (e instanceof DataError || e instanceof InputError) return failure(e.message);
        return failure(`${MCP_SERVER.title} could not answer: ${e instanceof Error ? e.message : String(e)}`);
      }
    });
  }
  return server;
}
