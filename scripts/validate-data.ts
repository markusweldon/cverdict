/**
 * Run the pipeline's own output checks (pipeline/src/validate.ts) on a data tree, for example the
 * mock data, so it cannot drift from what a real run writes.
 *
 *   npx tsx scripts/validate-data.ts <dir>
 */
import { validateOutput } from '../pipeline/src/validate';

const dir = process.argv[2];
if (!dir) {
  console.error('usage: validate-data.ts <dir>');
  process.exit(2);
}
const result = validateOutput(dir);
for (const w of result.warnings) console.warn(`warning: ${w}`);
for (const e of result.errors) console.error(`error: ${e}`);
console.log(`${dir}: ${result.files} files, ${result.errors.length} errors, ${result.warnings.length} warnings`);
process.exit(result.ok ? 0 : 1);
