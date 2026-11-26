#!/usr/bin/env node
// `cverdict`: hands off to cverdict-check or cverdict-mcp (see ../lib.mjs).
import { pathToFileURL } from 'node:url';
import { help, resolveTool, route, versions } from '../lib.mjs';

const r = route(process.argv.slice(2));
if (r.kind === 'help') process.stdout.write(help());
else if (r.kind === 'version') process.stdout.write(versions());
else if (r.kind === 'error') {
  process.stderr.write(`${r.message}\n`);
  process.exitCode = 2;
} else {
  let tool;
  try {
    tool = resolveTool(r.pkg);
  } catch (e) {
    process.stderr.write(`cverdict: cannot find ${r.pkg} (${e instanceof Error ? e.message : String(e)}). Reinstall cverdict, or run npx -y ${r.pkg}.\n`);
    process.exit(2);
  }
  // The tool reads its arguments from process.argv, as if started directly.
  process.argv = [process.argv[0], tool.bin, ...r.args];
  await import(pathToFileURL(tool.bin).href);
}
