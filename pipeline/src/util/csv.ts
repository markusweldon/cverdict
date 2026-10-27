/**
 * RFC 4180 CSV parser.
 *
 * - Fields may be enclosed in double quotes; inside quotes `""` is a literal quote and commas,
 *   CR and LF are data.
 * - Records end at CRLF, LF or a lone CR. Empty lines are skipped and a trailing line break does
 *   not produce an empty record.
 * - A leading UTF-8 BOM is ignored.
 * - Lenient where RFC 4180 is silent: a quote inside an unquoted field is kept literally, and
 *   characters between a closing quote and the next delimiter are appended to the field.
 * - Strict where it matters: an unterminated quoted field throws, so a truncated download can
 *   never parse as a shorter, valid file.
 */

const QUOTE = 0x22;
const COMMA = 0x2c;
const LF = 0x0a;
const CR = 0x0d;

export class CsvError extends Error {
  override name = 'CsvError';
}

function isRecordEnd(code: number): boolean {
  return code === COMMA || code === LF || code === CR;
}

/** Yield one array of fields per record. */
export function* parseCsv(text: string): Generator<string[]> {
  const n = text.length;
  let i = text.charCodeAt(0) === 0xfeff ? 1 : 0;

  while (i < n) {
    // Skip empty lines between records.
    const first = text.charCodeAt(i);
    if (first === LF || first === CR) {
      i += first === CR && text.charCodeAt(i + 1) === LF ? 2 : 1;
      continue;
    }

    const record: string[] = [];
    for (;;) {
      let field: string;
      if (text.charCodeAt(i) === QUOTE) {
        const opening = i;
        let start = i + 1;
        field = '';
        for (;;) {
          const q = text.indexOf('"', start);
          if (q === -1) throw new CsvError(`unterminated quoted field starting on line ${lineOf(text, opening)}`);
          if (text.charCodeAt(q + 1) === QUOTE) {
            field += text.slice(start, q + 1);
            start = q + 2;
            continue;
          }
          field += text.slice(start, q);
          i = q + 1;
          break;
        }
        let j = i;
        while (j < n && !isRecordEnd(text.charCodeAt(j))) j++;
        if (j > i) field += text.slice(i, j);
        i = j;
      } else {
        let j = i;
        while (j < n && !isRecordEnd(text.charCodeAt(j))) j++;
        field = text.slice(i, j);
        i = j;
      }
      record.push(field);

      if (i >= n) break;
      const code = text.charCodeAt(i);
      i++;
      if (code === COMMA) continue;
      if (code === CR && text.charCodeAt(i) === LF) i++;
      break;
    }
    yield record;
  }
}

/** 1-based physical line number of `pos` (for error messages only). */
function lineOf(text: string, pos: number): number {
  let line = 1;
  for (let k = 0; k < pos; k++) {
    const c = text.charCodeAt(k);
    if (c === LF || (c === CR && text.charCodeAt(k + 1) !== LF)) line++;
  }
  return line;
}
