/**
 * The `cverdict` command: one name for the two tools, which stay their own packages.
 *
 *   cverdict check [paths...] [options]   runs cverdict-check (the dependency check)
 *   cverdict mcp                          runs cverdict-mcp (the MCP server, over stdio)
 *
 * Nothing is reimplemented here: the named package's own `bin` is loaded in this process with
 * process.argv set as if it had been started directly, so stdin, stdout (the MCP server's JSON-RPC
 * channel) and the exit code are exactly the tool's. Plain JavaScript with no build step and no
 * dependency beyond the two tools.
 */
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';

export const COMMANDS = {
  check: { pkg: 'cverdict-check', about: 'Check lockfiles and SBOMs: which dependencies have CVEs, most exploited first' },
  mcp: { pkg: 'cverdict-mcp', about: 'Run the read-only MCP server for AI agents (stdio)' },
};

const own = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));
export const VERSION = own.version;

export function help() {
  const width = Math.max(...Object.keys(COMMANDS).map((c) => c.length));
  const lines = Object.entries(COMMANDS).map(([name, c]) => `  ${name.padEnd(width)}  ${c.about}`);
  return `cverdict ${VERSION}: CVE verdicts with receipts, from open CISA KEV, EPSS and exploit data

Usage: cverdict <command> [options]

Commands:
${lines.join('\n')}

  cverdict check --help    options of the dependency check
  cverdict --version       versions of cverdict and both tools

In an MCP client: claude mcp add cverdict -- npx -y cverdict mcp
Site: https://cverdict.dev  ·  Docs: https://github.com/markusweldon/cverdict
`;
}

/**
 * What a command line asks for: { kind: 'run', pkg, args } hands off to a tool; 'help', 'version'
 * and 'error' are answered here. Only the first argument is read: everything after the command
 * belongs to the tool, `--help` included.
 */
export function route(argv) {
  const [first, ...rest] = argv;
  if (first === undefined || first === '-h' || first === '--help' || first === 'help') return { kind: 'help' };
  if (first === '-v' || first === '--version') return { kind: 'version' };
  const c = Object.prototype.hasOwnProperty.call(COMMANDS, first) ? COMMANDS[first] : null;
  if (!c) return { kind: 'error', message: `Unknown command: ${first}. Commands: ${Object.keys(COMMANDS).join(', ')}. Run cverdict --help.` };
  return { kind: 'run', pkg: c.pkg, args: rest };
}

/** A tool's package.json and the absolute path of its bin, resolved from this package (or `from`). */
export function resolveTool(pkg, from = import.meta.url) {
  const require = createRequire(from);
  const manifestPath = require.resolve(`${pkg}/package.json`);
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  const bin = typeof manifest.bin === 'string' ? manifest.bin : manifest.bin?.[pkg];
  if (typeof bin !== 'string') throw new Error(`${pkg} has no bin named ${pkg}`);
  return { version: manifest.version, bin: join(dirname(manifestPath), bin) };
}

/** `cverdict --version`: this package's version, then each tool's (or why it cannot be found). */
export function versions(resolve = resolveTool) {
  const out = [`cverdict ${VERSION}`];
  for (const { pkg } of Object.values(COMMANDS)) {
    try {
      out.push(`${pkg} ${resolve(pkg).version}`);
    } catch {
      out.push(`${pkg} not installed`);
    }
  }
  return `${out.join('\n')}\n`;
}
