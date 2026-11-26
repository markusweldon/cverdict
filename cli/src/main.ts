/** `cverdict-check`: the command line. See args.ts for the options and run.ts for what a run does. */
import { HELP, parseCli } from './args';
import { run } from './run';
import { VERSION } from './version';

// `cverdict-check | head` closes the pipe early: stop quietly instead of throwing EPIPE.
for (const stream of [process.stdout, process.stderr]) {
  stream.on('error', (e: NodeJS.ErrnoException) => {
    if (e.code === 'EPIPE') process.exit(process.exitCode ?? 0);
    throw e;
  });
}

async function main(): Promise<number> {
  const parsed = parseCli(process.argv.slice(2));
  if (parsed.kind === 'help') {
    process.stdout.write(HELP);
    return 0;
  }
  if (parsed.kind === 'version') {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }
  if (parsed.kind === 'error') {
    process.stderr.write(`${parsed.message}\nRun with --help for the options.\n`);
    return 2;
  }
  const { code } = await run({ ...parsed.options, cwd: process.cwd() }, { out: (s) => process.stdout.write(s), err: (s) => process.stderr.write(s), fetch });
  return code;
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (e: unknown) => {
    process.stderr.write(`${e instanceof Error ? (e.stack ?? e.message) : String(e)}\n`);
    process.exitCode = 2;
  },
);
