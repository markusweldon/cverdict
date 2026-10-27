import { describe, expect, it } from 'vitest';
import { CsvError, parseCsv } from '../../src/util/csv';

const parse = (text: string) => [...parseCsv(text)];

describe('parseCsv (RFC 4180)', () => {
  it('parses simple records with LF, CRLF and lone CR line breaks', () => {
    expect(parse('a,b,c\n1,2,3\n')).toEqual([['a', 'b', 'c'], ['1', '2', '3']]);
    expect(parse('a,b\r\n1,2\r\n')).toEqual([['a', 'b'], ['1', '2']]);
    expect(parse('a,b\r1,2')).toEqual([['a', 'b'], ['1', '2']]);
  });

  it('does not create a record for a trailing line break, and skips blank lines', () => {
    expect(parse('a\n')).toEqual([['a']]);
    expect(parse('a\n\n\r\nb\n\n')).toEqual([['a'], ['b']]);
    expect(parse('')).toEqual([]);
    expect(parse('\n')).toEqual([]);
  });

  it('handles quoted fields containing commas, escaped quotes and line breaks', () => {
    const text = 'id,description\n1,"Foo, Bar ""Pro"" 2.0"\n2,"line one\nline two\r\nline three"\n3,"ends with quote """\n';
    expect(parse(text)).toEqual([
      ['id', 'description'],
      ['1', 'Foo, Bar "Pro" 2.0'],
      ['2', 'line one\nline two\r\nline three'],
      ['3', 'ends with quote "'],
    ]);
  });

  it('keeps empty fields, empty quoted fields and trailing delimiters', () => {
    expect(parse(',a,,\n"",""""\n')).toEqual([['', 'a', '', ''], ['', '"']]);
    expect(parse('a,b,')).toEqual([['a', 'b', '']]);
  });

  it('ignores a leading UTF-8 BOM', () => {
    expect(parse(`${String.fromCharCode(0xfeff)}id,file\n1,x`)).toEqual([['id', 'file'], ['1', 'x']]);
  });

  it('is lenient about stray quotes in unquoted fields and text after a closing quote', () => {
    expect(parse('5" screen,x\n')).toEqual([['5" screen', 'x']]);
    expect(parse('"a"b,c\n')).toEqual([['ab', 'c']]);
  });

  it('throws on an unterminated quoted field (truncated download) with its line number', () => {
    expect(() => parse('id,desc\n1,ok\n2,"never closed\nmore')).toThrow(CsvError);
    expect(() => parse('id,desc\n1,ok\n2,"never closed\nmore')).toThrow(/line 3/);
  });

  it('parses a real Exploit-DB row with a quoted, comma-bearing description', () => {
    const row =
      '16929,exploits/aix/dos/16929.rb,"AIX Calendar Manager Service Daemon (rpc.cmsd) Opcode 21 - Buffer Overflow (Metasploit)",' +
      '2010-11-11,Metasploit,dos,aix,,2010-11-11,2011-03-06,1,CVE-2009-3699;OSVDB-58726,"Metasploit Framework (MSF)",,,,http://aix.software.ibm.com/aix/efixes/security/cmsd_advisory.asc';
    const [fields] = parse(row);
    expect(fields).toHaveLength(17);
    expect(fields[2]).toBe('AIX Calendar Manager Service Daemon (rpc.cmsd) Opcode 21 - Buffer Overflow (Metasploit)');
    expect(fields[11]).toBe('CVE-2009-3699;OSVDB-58726');
    expect(fields[16]).toBe('http://aix.software.ibm.com/aix/efixes/security/cmsd_advisory.asc');
  });

  it('parses large inputs in linear time', () => {
    const rows = Array.from({ length: 50_000 }, (_, i) => `${i},"desc, ${i} ""q""\nnext",CVE-2026-${10_000 + i}`);
    const started = performance.now();
    let count = 0;
    let last: string[] = [];
    for (const record of parseCsv(rows.join('\r\n'))) {
      if (record.length !== 3) throw new Error(`record ${count} has ${record.length} fields`);
      last = record;
      count++;
    }
    expect(count).toBe(50_000);
    expect(last).toEqual(['49999', 'desc, 49999 "q"\nnext', 'CVE-2026-59999']);
    // Generous bound: only a pathological (e.g. quadratic) parser gets near it.
    expect(performance.now() - started).toBeLessThan(5_000);
  });
});
