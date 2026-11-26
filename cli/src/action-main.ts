/** Entry of the GitHub Action bundle (action/dist/index.mjs): runs action.ts with the real environment. */
import { runAction } from './action';
import { data as escapeData } from './report';

runAction(process.env, { out: (s) => process.stdout.write(s), err: (s) => process.stderr.write(s), fetch }).then(
  (code) => {
    process.exitCode = code;
  },
  (e: unknown) => {
    process.stdout.write(`::error title=cverdict-check::${escapeData(e instanceof Error ? e.message : String(e))}\n`);
    process.exitCode = 2;
  },
);
