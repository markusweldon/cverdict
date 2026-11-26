import { describe, expect, it } from 'vitest';
import { BRAND, RAW_DATA_URL } from './brand';
import { llmsTxt } from './llms';
import { MCP_TOOLS } from './mcp';

describe('llmsTxt', () => {
  const text = llmsTxt('https://cverdict.example', '/');

  it('follows the llms.txt shape: one H1, a blockquote summary, then link sections', () => {
    const lines = text.split('\n');
    expect(lines[0]).toBe(`# ${BRAND.name}`);
    expect(lines[2]).toBe(`> ${BRAND.pitch}`);
    expect(lines.filter((l) => l.startsWith('# '))).toHaveLength(1);
    expect(lines.filter((l) => l.startsWith('## ')).map((l) => l.slice(3))).toEqual(['MCP server', 'Open data', 'Feeds', 'Docs', 'Optional']);
  });

  it('lists every MCP tool, and the data and feeds on the data branch', () => {
    for (const t of MCP_TOOLS) expect(text).toContain(`\`${t.name}\``);
    expect(text).toContain(`${RAW_DATA_URL}/v1/signal.json`);
    expect(text).toContain(`${RAW_DATA_URL}/feeds/kev-due.ics`);
  });

  it('links pages on the origin it is served from, under a sub-path too', () => {
    expect(text).toContain('https://cverdict.example/method');
    expect(llmsTxt('https://me.github.io', '/cverdict/')).toContain('https://me.github.io/cverdict/check');
    expect(text).not.toMatch(/https:\/\/[^\s)]*\/\/[a-z]/);
  });

  it('tells agents that upstream text is untrusted and Quiet is not safe', () => {
    expect(text).toMatch(/untrusted/);
    expect(text).toMatch(/Quiet never means safe/);
  });
});
