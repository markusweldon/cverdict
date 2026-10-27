import { readFileSync } from 'node:fs';
import path from 'node:path';
import { gzipSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { SANITY, type SanityLimits } from '../../src/config';
import { parseEpssBody, parseEpssCsv, parseEpssHeader } from '../../src/sources/epss';
import { parseExploitDb, parseExploitDbBody } from '../../src/sources/exploitdb';
import { parseKevBody, parseKevCatalog } from '../../src/sources/kev';
import { parseMetasploit, parseMetasploitBody } from '../../src/sources/metasploit';
import { parseNuclei } from '../../src/sources/nuclei';
import { parsePocFile } from '../../src/sources/poc';
import { SanityError } from '../../src/sources/source';
import type { CacheMeta } from '../../src/util/http';
import { FIXTURES } from './helpers';

const read = (name: string) => readFileSync(path.join(FIXTURES, name));
const LOOSE: SanityLimits = { ...SANITY, kevEntries: 1, epssRows: 1, metasploitModules: 1, nucleiTemplates: 1, exploitdbRows: 1, pocFiles: 1 };
const cachedMeta = (records: number): CacheMeta => ({
  url: 'https://example.com/kev.json',
  etag: null,
  last_modified: null,
  fetched_at: '2026-10-26T00:00:00.000Z',
  bytes: 1,
  records,
  upstream_version: null,
});

describe('KEV', () => {
  it('parses a real catalog subset, including entries from before forensicTriage existed', () => {
    const catalog = parseKevCatalog(JSON.parse(read('kev-sample.json').toString()));
    expect(catalog.version).toBe('2026.10.23');
    expect(catalog.dateReleased).toBe('2026-10-23T19:30:18.920Z');
    expect([...catalog.entries.keys()]).toEqual(['CVE-2026-114625', 'CVE-2026-110447', 'CVE-2026-58644', 'CVE-2026-0257', 'CVE-2021-43890']);
    const arista = catalog.entries.get('CVE-2026-114625');
    expect(arista).toMatchObject({
      vendorProject: 'Arista',
      product: 'VeloCloud Orchestrator',
      dateAdded: '2026-10-23',
      dueDate: '2026-10-26',
      knownRansomwareCampaignUse: 'Unknown',
      forensicTriage: 'Yes',
      cwes: ['CWE-89'],
    });
    const old = catalog.entries.get('CVE-2021-43890');
    expect(old?.forensicTriage).toBeUndefined();
    expect(old?.cwes).toBeUndefined();
  });

  it('skips invalid and duplicate entries and tolerates odd fields', () => {
    const catalog = parseKevCatalog({
      catalogVersion: 7,
      vulnerabilities: [
        { cveID: 'cve-2026-0001', dateAdded: '2026-10-01', vendorProject: ' Acme\n', product: null, extra: true },
        { cveID: 'CVE-2026-0001', dateAdded: '2026-10-02' },
        { cveID: 'not-a-cve', dateAdded: '2026-10-01' },
        { cveID: 'CVE-2026-0002' },
        'junk',
      ],
    });
    expect(catalog.version).toBeNull();
    expect([...catalog.entries.keys()]).toEqual(['CVE-2026-0001']);
    expect(catalog.entries.get('CVE-2026-0001')).toMatchObject({ vendorProject: 'Acme', product: '', dateAdded: '2026-10-01', dueDate: '' });
  });

  it('sanity: minimum size, and never shrinking below 98% of the cached copy', () => {
    const body = read('kev-sample.json');
    expect(parseKevBody(body, null, LOOSE).records).toBe(5);
    expect(() => parseKevBody(body, null, SANITY)).toThrow(SanityError);
    expect(() => parseKevBody(body, cachedMeta(100), LOOSE)).toThrow(/shrank to 5 entries from 100/);
    expect(parseKevBody(body, cachedMeta(5), LOOSE).version).toBe('2026.10.23');
    expect(() => parseKevBody(Buffer.from('{"vulnerabilities": 3}'), null, LOOSE)).toThrow(/vulnerabilities/);
    expect(() => parseKevBody(Buffer.from('<html>'), null, LOOSE)).toThrow(/invalid JSON/);
  });
});

describe('EPSS', () => {
  it('parses the header comment', () => {
    const header = parseEpssHeader('#model_version:v2026.06.15,score_date:2026-10-26T12:03:22Z');
    expect(Object.fromEntries(header)).toEqual({ model_version: 'v2026.06.15', score_date: '2026-10-26T12:03:22Z' });
  });

  it('parses a real gzip file', () => {
    const { value, records, version } = parseEpssBody(read('epss-sample.csv.gz'), LOOSE);
    expect(records).toBe(8);
    expect(version).toBe('v2026.06.15 2026-10-26');
    expect(value.model).toBe('v2026.06.15');
    expect(value.scoreDate).toBe('2026-10-26');
    expect(value.scores.get('CVE-2026-0257')).toEqual({ epss: 0.95012, percentile: 0.99861 });
  });

  it('tolerates CRLF, a BOM, reordered and extra columns, no comment line, and bad rows', () => {
    const bom = String.fromCharCode(0xfeff);
    const text = `${bom}percentile,cve,epss,extra\r\n0.5,CVE-2026-0001,0.25,x\r\nbad,CVE-2026-0002,0.1,x\r\n0.2,CVE-2026-0003,2,x\r\n0.1,nope,0.1,x\r\n`;
    const table = parseEpssCsv(text);
    expect(table.model).toBeNull();
    expect(table.scoreDate).toBeNull();
    expect(table.rows).toBe(1);
    expect(table.scores.get('CVE-2026-0001')).toEqual({ epss: 0.25, percentile: 0.5 });
  });

  it('accepts an already-decompressed body and rejects files without a header or with too few rows', () => {
    const plain = Buffer.from('#score_date:2026-10-25T12:00:00Z,model_version:v1\ncve,epss,percentile\nCVE-2026-0001,0.1,0.2\n');
    expect(parseEpssBody(plain, LOOSE).value.scoreDate).toBe('2026-10-25');
    expect(() => parseEpssCsv('CVE-2026-0001,0.1,0.2\n')).toThrow(/unexpected header/);
    expect(() => parseEpssBody(gzipSync(plain), SANITY)).toThrow(SanityError);
  });
});

describe('Metasploit', () => {
  it('indexes real modules by referenced CVE, exploits and higher ranks first', () => {
    const { value: byCve, records, version } = parseMetasploitBody(read('msf-sample.json'), LOOSE);
    expect(records).toBe(6);
    expect(version).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    const log4shell = byCve.get('CVE-2021-44228') ?? [];
    expect(log4shell.length).toBeGreaterThanOrEqual(4);
    expect(log4shell[0].type).toBe('exploit');
    expect(log4shell[0].rank).toBe(600);
    expect(log4shell.at(-1)?.fullname).toBe('auxiliary/scanner/http/log4shell_scanner');
    expect(log4shell[0].url).toMatch(/^https:\/\/github\.com\/rapid7\/metasploit-framework\/blob\/master\/modules\/exploits\//);
    expect(byCve.get('CVE-2007-4387')?.[0]).toMatchObject({
      name: '2Wire Cross-Site Request Forgery Password Reset Vulnerability',
      fullname: 'auxiliary/admin/2wire/xslt_password_reset',
      type: 'auxiliary',
      url: 'https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/2wire/xslt_password_reset.rb',
    });
  });

  it('ignores non-CVE references and malformed modules; links to Rapid7 when the path is unusable', () => {
    const { byCve, modules } = parseMetasploit({
      a: { fullname: 'exploit/x/y', references: ['URL-https://x', 'cve-2026-0001', 'CVE-2026-0001'], path: '../../etc/passwd', rank: 'high' },
      b: { name: 'no fullname' },
      c: 'junk',
    });
    expect(modules).toBe(1);
    expect(byCve.get('CVE-2026-0001')).toEqual([
      { name: 'exploit/x/y', fullname: 'exploit/x/y', rank: null, type: '', url: 'https://www.rapid7.com/db/modules/exploit/x/y/' },
    ]);
    expect(() => parseMetasploit([])).toThrow(/expected an object/);
  });
});

describe('Nuclei', () => {
  it('indexes NDJSON templates by ID, skipping bad lines, duplicates and unsafe paths', () => {
    const text = [
      read('nuclei-sample.json').toString().trim(),
      '{not json',
      '{"ID":"CVE-2026-0001","Info":{"Severity":"HIGH"},"file_path":"../evil.yaml"}',
      '{"ID":"CVE-2021-44228","Info":{"Severity":"critical"},"file_path":"http/cves/2021/CVE-2021-44228.yaml"}',
      '',
    ].join('\n');
    const { byCve, templates } = parseNuclei(text);
    expect(templates).toBe(4);
    expect(byCve.get('CVE-2021-44228')).toEqual([
      { path: 'http/cves/2021/CVE-2021-44228.yaml', severity: 'critical', url: 'https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-44228.yaml' },
    ]);
    expect(byCve.get('CVE-2026-0257')?.[0].path).toBe('javascript/cves/2026/CVE-2026-0257.yaml');
    expect(byCve.has('CVE-2026-0001')).toBe(false);
  });
});

describe('Exploit-DB', () => {
  it('indexes real rows by the CVEs in `codes`', () => {
    const { value: byCve, records, version } = parseExploitDbBody(read('exploitdb-sample.csv'), LOOSE);
    expect(records).toBe(4);
    expect(version).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    expect(byCve.get('CVE-2009-3699')).toEqual([{ id: '16929', verified: true, url: 'https://www.exploit-db.com/exploits/16929', date: '2010-11-11' }]);
    expect(byCve.get('CVE-2021-44228')?.map((e) => e.id)).toHaveLength(3);
  });

  it('handles quoted descriptions with commas, quotes and newlines, and multiple CVEs per row', () => {
    const csv = [
      'id,file,description,date_published,author,type,platform,port,date_added,date_updated,verified,codes,tags',
      '1,exploits/a.txt,"Foo, ""Bar"" 1.0\nmulti-line",2026-10-01,"Doe, J.",webapps,php,,2026-10-02,2026-10-02,0,"CVE-2026-0001;CVE-2026-0002;OSVDB-1",',
      '2,exploits/b.txt,No CVE,2026-10-01,x,dos,linux,,2026-10-03,2026-10-03,1,OSVDB-2,',
      'garbage-id,exploits/c.txt,x,2026-10-01,x,dos,linux,,2026-10-01,2026-10-01,1,CVE-2026-0003,',
    ].join('\r\n');
    const { byCve, rows, newest } = parseExploitDb(csv);
    expect(rows).toBe(2);
    expect(newest).toBe('2026-10-03');
    expect(byCve.get('CVE-2026-0001')).toEqual([{ id: '1', verified: false, url: 'https://www.exploit-db.com/exploits/1', date: '2026-10-01' }]);
    expect(byCve.get('CVE-2026-0002')?.[0].id).toBe('1');
    expect(byCve.has('CVE-2026-0003')).toBe(false);
  });

  it('rejects files missing required columns', () => {
    expect(() => parseExploitDb('id,file,description\n1,a,b\n')).toThrow(/missing columns date_published, verified, codes/);
    expect(() => parseExploitDb('')).toThrow(/empty/);
  });
});

describe('PoC-in-GitHub files', () => {
  it('drops forks, invalid URLs and duplicates; sorts by stars', () => {
    const repos = parsePocFile(
      JSON.stringify([
        { html_url: 'https://github.com/a/poc', stargazers_count: 3, created_at: '2026-10-20T10:00:00Z', fork: false },
        { html_url: 'https://github.com/b/poc-fork', stargazers_count: 99, created_at: '2026-10-20T10:00:00Z', fork: true },
        { html_url: 'https://github.com/c/poc', stargazers_count: 30, created_at: '2026-10-21T10:00:00Z', fork: false },
        { html_url: 'https://github.com/a/poc', stargazers_count: 3, created_at: '2026-10-20T10:00:00Z', fork: false },
        { html_url: 'javascript:alert(1)', stargazers_count: 1, created_at: '2026-10-20T10:00:00Z' },
        { html_url: 'https://evil.example/x/y', stargazers_count: 1, created_at: '2026-10-20T10:00:00Z' },
        { html_url: 'https://github.com/d/no-date', stargazers_count: 1 },
        { html_url: 'https://github.com/e/neg', stargazers_count: -4, created_at: '2026-10-22T10:00:00Z' },
      ]),
    );
    expect(repos).toEqual([
      { url: 'https://github.com/c/poc', stars: 30, created: '2026-10-21T10:00:00.000Z', fork: false },
      { url: 'https://github.com/a/poc', stars: 3, created: '2026-10-20T10:00:00.000Z', fork: false },
      { url: 'https://github.com/e/neg', stars: 0, created: '2026-10-22T10:00:00.000Z', fork: false },
    ]);
  });

  it('returns nothing for invalid JSON or non-arrays', () => {
    expect(parsePocFile('not json')).toEqual([]);
    expect(parsePocFile('{"a":1}')).toEqual([]);
  });
});
