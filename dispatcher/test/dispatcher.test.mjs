import { mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';
import { COMMANDS, VERSION, help, resolveTool, route, versions } from '../lib.mjs';

const read = (p) => JSON.parse(readFileSync(new URL(p, import.meta.url), 'utf8'));
const own = read('../package.json');

describe('route', () => {
  it('hands the rest of the line to the named tool, its own --help included', () => {
    expect(route(['check', 'package-lock.json', '--fail-on', 'likely'])).toEqual({ kind: 'run', pkg: 'cverdict-check', args: ['package-lock.json', '--fail-on', 'likely'] });
    expect(route(['check', '--help'])).toEqual({ kind: 'run', pkg: 'cverdict-check', args: ['--help'] });
    expect(route(['mcp'])).toEqual({ kind: 'run', pkg: 'cverdict-mcp', args: [] });
  });

  it('answers help and version itself, and refuses anything else', () => {
    for (const a of [[], ['-h'], ['--help'], ['help']]) expect(route(a)).toEqual({ kind: 'help' });
    for (const a of [['-v'], ['--version']]) expect(route(a)).toEqual({ kind: 'version' });
    expect(route(['scan'])).toMatchObject({ kind: 'error', message: expect.stringContaining('Unknown command: scan') });
    expect(route(['__proto__'])).toMatchObject({ kind: 'error' });
    expect(route(['constructor'])).toMatchObject({ kind: 'error' });
  });

  it('lists every command in the help', () => {
    for (const name of Object.keys(COMMANDS)) expect(help()).toContain(`  ${name}`);
    expect(help()).toContain('npx -y cverdict mcp');
  });
});

describe('the tools', () => {
  it('depends on each tool at its current minor version in this repository', () => {
    expect(own.dependencies).toEqual({ 'cverdict-check': `^${read('../../cli/package.json').version}`, 'cverdict-mcp': `^${read('../../mcp/package.json').version}` });
    expect(VERSION).toBe(own.version);
  });

  it('finds each tool\'s bin from where it is installed', () => {
    const root = mkdtempSync(join(tmpdir(), 'cverdict-dispatch-'));
    mkdirSync(join(root, 'node_modules'));
    symlinkSync(new URL('../../cli', import.meta.url).pathname, join(root, 'node_modules', 'cverdict-check'));
    symlinkSync(new URL('../../mcp', import.meta.url).pathname, join(root, 'node_modules', 'cverdict-mcp'));
    writeFileSync(join(root, 'here.mjs'), '');
    const from = pathToFileURL(join(root, 'here.mjs')).href;
    const check = resolveTool('cverdict-check', from);
    expect(check.version).toBe(read('../../cli/package.json').version);
    expect(check.bin.endsWith(join('dist', 'cverdict-check.mjs'))).toBe(true);
    expect(resolveTool('cverdict-mcp', from).bin.endsWith(join('dist', 'cverdict-mcp.mjs'))).toBe(true);
    expect(() => resolveTool('cverdict-nope', from)).toThrow();
  });

  it('prints its version and each tool\'s, or says one is missing', () => {
    const fake = (pkg) => {
      if (pkg === 'cverdict-mcp') throw new Error('missing');
      return { version: '0.1.0', bin: '/x' };
    };
    expect(versions(fake)).toBe(`cverdict ${VERSION}\ncverdict-check 0.1.0\ncverdict-mcp not installed\n`);
  });
});
