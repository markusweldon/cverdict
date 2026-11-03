/**
 * Copy, docs and packaging stay in step with the server: no em dash in new text, the site cannot
 * pull in the SDK, the package and the docs name the same version, scripts and tools.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { MCP_INSTRUCTIONS, MCP_MSG, MCP_SERVER, MCP_SNIPPETS, MCP_TOOLS, VERDICT } from '../../shared/mcp';
import { LIMITS } from '../src/tools';

const ROOT = resolve(import.meta.dirname, '../..');
const read = (p: string) => readFileSync(resolve(ROOT, p), 'utf8');
const EM_DASH = '\u2014';

/** The text of a Markdown section: from its heading to the next heading of the same level. */
function section(md: string, heading: string): string {
  const level = heading.match(/^#+/)![0];
  const start = md.indexOf(`\n${heading}\n`);
  if (start < 0) throw new Error(`no section ${heading}`);
  const rest = md.slice(start + heading.length + 2);
  const end = rest.search(new RegExp(`\\n${level} `));
  return end < 0 ? rest : rest.slice(0, end);
}

describe('copy', () => {
  it('has no em dash in the server copy or the new docs', () => {
    const strings = [
      MCP_INSTRUCTIONS,
      ...MCP_TOOLS.flatMap((t) => [t.title, t.description]),
      ...Object.values(VERDICT),
      ...MCP_SNIPPETS.flat(),
      MCP_MSG.notFound,
      MCP_MSG.notCveId,
      MCP_MSG.detailTooMany(5),
      MCP_MSG.notPublished('woke.json'),
      MCP_MSG.schema(2, 1),
      MCP_MSG.allFailed(['a: HTTP 503']),
      MCP_MSG.deadline(['a: timed out']),
      MCP_MSG.refreshFailed(['a: HTTP 429'], '2026-11-03T06:50:00.000Z'),
    ];
    for (const s of strings) expect(s, s).not.toContain(EM_DASH);
    expect(read('shared/mcp.ts')).not.toContain(EM_DASH);
    for (const f of ['mcp/README.md', 'mcp/src/data.ts', 'mcp/src/tools.ts', 'mcp/src/server.ts', 'mcp/src/stdio.ts']) expect(read(f), f).not.toContain(EM_DASH);
    expect(section(read('README.md'), '## Ask from an AI agent (MCP)')).not.toContain(EM_DASH);
    expect(section(read('docs/DATA.md'), '## MCP server')).not.toContain(EM_DASH);
    const feeds = read('site/src/pages/Feeds.tsx');
    expect(feeds.slice(feeds.indexOf('id="mcp"'))).not.toContain(EM_DASH);
  });

  it('keeps zod and the SDK out of the site: shared/mcp.ts imports only brand strings and types', () => {
    const imports = [...read('shared/mcp.ts').matchAll(/^import .*$/gm)].map((m) => m[0]);
    expect(imports).toEqual(["import { BRAND, RAW_DATA_URL, REPO_URL } from './brand';", "import type { Tier } from './contract';"]);
    for (const f of ['site/src/pages/Feeds.tsx', 'site/src/app.tsx']) expect(read(f)).not.toMatch(/@modelcontextprotocol|from 'zod'|mcp\/src/);
  });

  it('tells the agent about the bounds it enforces', () => {
    const verdict = MCP_TOOLS.find((t) => t.name === 'get_verdict')!.description;
    expect(verdict).toContain(`1 to ${LIMITS.ids} CVE IDs (at most ${LIMITS.detailIds} with detail: true)`);
    for (const t of MCP_TOOLS) expect(t.description, t.name).toContain('untrusted');
  });
});

describe('package and docs', () => {
  const pkg = JSON.parse(read('mcp/package.json'));
  const root = JSON.parse(read('package.json'));

  it('prepares cverdict-mcp without publishing it', () => {
    expect(pkg.name).toBe(MCP_SERVER.npm);
    expect(pkg.name).toBe('cverdict-mcp');
    expect(pkg.version).toBe(MCP_SERVER.version);
    expect(pkg.private).toBe(true);
    expect(pkg.bin).toEqual({ 'cverdict-mcp': 'dist/cverdict-mcp.mjs' });
    expect(pkg.files).toEqual(['dist', 'LICENSE', 'LICENSE-THIRD-PARTY', 'README.md']);
    expect(pkg.dependencies).toBeUndefined();
    expect(pkg.engines.node).toBe(root.engines.node);
    const third = read('mcp/LICENSE-THIRD-PARTY');
    for (const name of ['@modelcontextprotocol/server', 'zod', 'ajv', 'ajv-formats', 'fast-uri', 'fast-deep-equal', 'json-schema-traverse', 'content-type', 'Apache License', 'MIT License']) expect(third).toContain(name);
  });

  it('pins the SDK and zod exactly as dev dependencies, with the scripts the docs use', () => {
    expect(root.dependencies).toEqual({ preact: expect.any(String) });
    for (const dep of ['@modelcontextprotocol/server', '@modelcontextprotocol/client', 'zod']) expect(root.devDependencies[dep], dep).toMatch(/^\d+\.\d+\.\d+$/);
    expect(root.scripts.mcp).toBe('tsx mcp/src/stdio.ts');
    expect(root.scripts['build:mcp']).toBe('vite build --config mcp/vite.config.ts');
    expect(MCP_SNIPPETS[0][1]).toContain('npm --prefix "$PWD" run -s mcp');
    // The JSON snippet is valid JSON, with -s so npm's banner stays off stdout.
    expect(JSON.parse(MCP_SNIPPETS[1][1]).mcpServers.cverdict).toEqual({ command: 'npm', args: ['--prefix', '/path/to/cverdict', 'run', '-s', 'mcp'] });
    expect(JSON.parse(`{${MCP_SNIPPETS[2][1]}}`).env).toEqual({ NODE_USE_ENV_PROXY: '1', HTTPS_PROXY: 'http://proxy.example:3128' });
  });

  it('documents every tool and the same clone command everywhere', () => {
    const docs = { readme: section(read('README.md'), '## Ask from an AI agent (MCP)'), data: section(read('docs/DATA.md'), '## MCP server'), mcp: read('mcp/README.md') };
    for (const [where, text] of Object.entries(docs)) for (const t of MCP_TOOLS) expect(text, `${t.name} in ${where}`).toContain(`\`${t.name}\``);
    for (const text of [docs.readme, docs.mcp]) expect(text).toContain('claude mcp add cverdict -- npm --prefix "$PWD" run -s mcp');
    expect(docs.readme).toContain(`1 to ${LIMITS.ids} CVE IDs`);
    expect(docs.data).toContain(`1 to ${LIMITS.ids} CVE IDs (${LIMITS.detailIds} with \`detail\`)`);
    expect(docs.mcp).toContain(`1 to ${LIMITS.ids} IDs, at most ${LIMITS.detailIds} with \`detail\``);
    expect(read('site/src/pages/Feeds.tsx')).toContain('id="mcp"');
  });
});
