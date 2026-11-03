import { readFileSync } from 'node:fs';
import path from 'node:path';
import { gzipSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { EPSS, SANITY, type SanityLimits } from '../../src/config';
import { loadEpssOn, parseEpssBody, parseEpssBodyOn, parseEpssCsv, parseEpssHeader } from '../../src/sources/epss';
import { HttpClient, type FetchLike } from '../../src/util/http';
import { parseExploitDb, parseExploitDbBody } from '../../src/sources/exploitdb';
import { parseKevBody, parseKevCatalog } from '../../src/sources/kev';
import { parseMetasploit, parseMetasploitBody } from '../../src/sources/metasploit';
import { parseNuclei } from '../../src/sources/nuclei';
import { parsePocFile } from '../../src/sources/poc';
import { SanityError } from '../../src/sources/source';
import type { CacheMeta } from '../../src/util/http';
import { captureLogger, FIXTURES, tempDir } from './helpers';
import { loadEpssAsOf } from '../../src/backtest';
import { makeKev, makeKevCatalog } from '../fixtures/model/builders';

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
    // Upstream bytes quoted in the error stay on one line (a lone CR would start a new log line).
    expect(() => parseEpssCsv('cve,epss\r::warning title=Forged::x,percentile\n')).toThrow(/^EPSS: unexpected header "cve,epss ::warning[^\r\n]*"$/);
    expect(() => parseEpssBody(gzipSync(plain), SANITY)).toThrow(SanityError);
  });
});

describe('EPSS for a past day', () => {
  const day = (date: string) => gzipSync(`#model_version:v2026.06.15,score_date:${date}T12:00:21Z\ncve,epss,percentile\nCVE-2026-0001,0.02,0.5\n`);

  it('accepts only a file for one of the wanted days', () => {
    expect(parseEpssBodyOn(day('2026-10-03'), ['2026-10-03', '2026-10-02'], LOOSE).value.scoreDate).toBe('2026-10-03');
    expect(() => parseEpssBodyOn(day('2026-11-02'), ['2026-10-03'], LOOSE)).toThrow(/is for 2026-11-02, wanted 2026-10-03/);
  });

  it('tries the archive, then the EPSS host, then the day before, and reuses only the cached first day without a request', async () => {
    const cacheDir = tempDir();
    const requested: string[] = [];
    const routes: Record<string, () => Response> = {
      [EPSS.daily('2026-10-03')]: () => new Response('nope', { status: 404 }),
      [EPSS.dated('2026-10-03')]: () => new Response('nope', { status: 404 }),
      [EPSS.daily('2026-10-02')]: () => new Response(new Uint8Array(day('2026-10-02')), { status: 200 }),
    };
    const fetch: FetchLike = async (url) => {
      requested.push(url);
      return routes[url]?.() ?? new Response('nope', { status: 404 });
    };
    const http = new HttpClient({ cacheDir, offline: false, log: captureLogger(), fetch, sleep: async () => {} });
    const first = await loadEpssOn(http, ['2026-10-03', '2026-10-02'], LOOSE);
    expect(first.data?.scoreDate).toBe('2026-10-02');
    expect(requested).toEqual([EPSS.daily('2026-10-03'), EPSS.dated('2026-10-03'), EPSS.daily('2026-10-02')]);

    // A cached fallback day is not reused while the wanted day may exist: it is tried again first.
    requested.length = 0;
    expect((await loadEpssOn(http, ['2026-10-03', '2026-10-02'], LOOSE)).data?.scoreDate).toBe('2026-10-02');
    expect(requested.slice(0, 2)).toEqual([EPSS.daily('2026-10-03'), EPSS.dated('2026-10-03')]);

    // Once the wanted day is out and cached, it is reused without a request.
    routes[EPSS.daily('2026-10-03')] = () => new Response(new Uint8Array(day('2026-10-03')), { status: 200 });
    expect((await loadEpssOn(http, ['2026-10-03', '2026-10-02'], LOOSE)).data?.scoreDate).toBe('2026-10-03');
    requested.length = 0;
    expect((await loadEpssOn(http, ['2026-10-03', '2026-10-02'], LOOSE)).data?.scoreDate).toBe('2026-10-03');
    expect(requested).toEqual([]);
    // The next day, yesterday's first day is today's fallback: today's first day is fetched instead
    // of measuring the jump over 31 days.
    routes[EPSS.daily('2026-10-04')] = () => new Response(new Uint8Array(day('2026-10-04')), { status: 200 });
    expect((await loadEpssOn(http, ['2026-10-04', '2026-10-03'], LOOSE)).data?.scoreDate).toBe('2026-10-04');
    expect(requested).toEqual([EPSS.daily('2026-10-04')]);
    // While the fallback day is all the archive has, its cached copy still serves when the host is down.
    const down = new HttpClient({ cacheDir, offline: false, log: captureLogger(), fetch: async () => new Response('down', { status: 404 }), sleep: async () => {} });
    expect((await loadEpssOn(down, ['2026-10-05', '2026-10-04'], LOOSE)).data?.scoreDate).toBe('2026-10-04');

    // Other dates: the cached file does not stand in for them.
    const next = await loadEpssOn(down, ['2026-10-06', '2026-10-05'], LOOSE);
    expect(next.data).toBeNull();
    expect(next.error).toMatch(/cached copy unusable: EPSS: file is for 2026-10-04/);
  });
});

describe('Metasploit', () => {
  it('indexes real modules by referenced CVE, exploits and higher ranks first', () => {
    const {
      value: { byCve, firstModified },
      records,
      version,
    } = parseMetasploitBody(read('msf-sample.json'), LOOSE);
    // The earliest mod_time of the modules that reference a CVE: they existed by then.
    expect(firstModified.get('CVE-2021-44228')).toMatch(/^\d{4}-\d{2}-\d{2}T/);
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
      date: '2007-08-15',
      url: 'https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/2wire/xslt_password_reset.rb',
    });
  });

  it('ignores non-CVE references and malformed modules; links to Rapid7 when the path is unusable', () => {
    const { byCve, modules } = parseMetasploit({
      a: { fullname: 'exploit/x/y', references: ['URL-https://x', 'cve-2026-0001', 'CVE-2026-0001'], path: '../../etc/passwd', rank: 'high', disclosure_date: '2026-02-30' },
      b: { name: 'no fullname' },
      c: 'junk',
    });
    expect(modules).toBe(1);
    expect(byCve.get('CVE-2026-0001')).toEqual([
      { name: 'exploit/x/y', fullname: 'exploit/x/y', rank: null, type: '', url: 'https://www.rapid7.com/db/modules/exploit/x/y/', date: null },
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
    const { value, records, version } = parseExploitDbBody(read('exploitdb-sample.csv'), LOOSE);
    const { byCve, firstAdded } = value;
    expect(records).toBe(4);
    expect(version).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    expect(byCve.get('CVE-2009-3699')).toEqual([{ id: '16929', verified: true, url: 'https://www.exploit-db.com/exploits/16929', date: '2010-11-11' }]);
    expect(byCve.get('CVE-2021-44228')?.map((e) => e.id)).toHaveLength(3);
    expect(firstAdded.get('CVE-2009-3699')).toEqual({ date: '2010-11-11', id: '16929', url: 'https://www.exploit-db.com/exploits/16929' });
  });

  it('keeps the entry Exploit-DB added first per CVE, by date_added', () => {
    const csv = [
      'id,file,description,date_published,author,type,platform,port,date_added,date_updated,verified,codes',
      '20,exploits/a.txt,a,2019-01-01,x,webapps,php,,2026-10-20,2026-10-20,1,CVE-2019-0001',
      '10,exploits/b.txt,b,2026-10-25,x,webapps,php,,2026-10-25,2026-10-25,1,CVE-2019-0001;CVE-2019-0002',
      '11,exploits/c.txt,c,2018-05-05,x,webapps,php,,,,1,CVE-2019-0003',
    ].join('\n');
    const { firstAdded } = parseExploitDb(csv);
    expect(firstAdded.get('CVE-2019-0001')).toMatchObject({ date: '2026-10-20', id: '20' });
    expect(firstAdded.get('CVE-2019-0002')).toMatchObject({ date: '2026-10-25', id: '10' });
    // No date_added: date_published stands in.
    expect(firstAdded.get('CVE-2019-0003')).toMatchObject({ date: '2018-05-05', id: '11' });
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
        { html_url: 'https://github.com/c/poc', stargazers_count: 30, created_at: '2026-10-21T10:00:00Z', pushed_at: '2026-10-23T08:00:00Z', fork: false },
        { html_url: 'https://github.com/a/poc', stargazers_count: 3, created_at: '2026-10-20T10:00:00Z', fork: false },
        { html_url: 'javascript:alert(1)', stargazers_count: 1, created_at: '2026-10-20T10:00:00Z' },
        { html_url: 'https://evil.example/x/y', stargazers_count: 1, created_at: '2026-10-20T10:00:00Z' },
        { html_url: 'https://github.com/d/no-date', stargazers_count: 1 },
        { html_url: 'https://github.com/e/neg', stargazers_count: -4, created_at: '2026-10-22T10:00:00Z' },
      ]),
    );
    expect(repos).toEqual([
      { url: 'https://github.com/c/poc', stars: 30, created: '2026-10-21T10:00:00.000Z', fork: false, pushed: '2026-10-23T08:00:00.000Z' },
      { url: 'https://github.com/a/poc', stars: 3, created: '2026-10-20T10:00:00.000Z', fork: false, pushed: null },
      { url: 'https://github.com/e/neg', stars: 0, created: '2026-10-22T10:00:00.000Z', fork: false, pushed: null },
    ]);
  });

  it('returns nothing for invalid JSON or non-arrays', () => {
    expect(parsePocFile('not json')).toEqual([]);
    expect(parsePocFile('{"a":1}')).toEqual([]);
  });
});

describe('EPSS for the backtest', () => {
  const file = (date: string, rows: Record<string, number>) =>
    gzipSync(`#model_version:v2026.06.15,score_date:${date}T12:00:21Z\ncve,epss,percentile\n${Object.entries(rows).map(([id, e]) => `${id},${e},0.5`).join('\n')}\n`);

  it('downloads the day before each listing once, keeps only the listed CVEs, and skips what it already knows', async () => {
    const now = new Date('2026-11-03T03:17:00Z');
    const kev = makeKevCatalog([
      makeKev('CVE-2026-0001', { dateAdded: '2026-10-20' }),
      makeKev('CVE-2026-0002', { dateAdded: '2026-10-20' }),
      makeKev('CVE-2026-0003', { dateAdded: '2026-10-22' }), // already known
      makeKev('CVE-2026-0004', { dateAdded: '2026-10-25' }), // published after its listing last time
      makeKev('CVE-2026-0005', { dateAdded: '2026-10-28' }), // no file for that day
      makeKev('CVE-2020-0001', { dateAdded: '2026-01-02' }), // outside the 180 days
    ]);
    const requested: string[] = [];
    const routes: Record<string, Buffer> = { [EPSS.daily('2026-10-19')]: file('2026-10-19', { 'CVE-2026-0001': 0.3, 'CVE-2026-0009': 0.9 }) };
    const fetch: FetchLike = async (url) => {
      requested.push(url);
      const body = routes[url];
      return body ? new Response(new Uint8Array(body), { status: 200 }) : new Response('nope', { status: 404 });
    };
    const http = new HttpClient({ cacheDir: tempDir(), offline: false, log: captureLogger(), fetch, sleep: async () => {} });
    const plan = { reuse: new Map([['CVE-2026-0003@2026-10-22', { date: '2026-10-21', score: 0.01 }]]), skip: new Set(['CVE-2026-0004']) };
    const out = await loadEpssAsOf(http, kev, now, plan, LOOSE, captureLogger());
    expect([...out.keys()].sort()).toEqual(['2026-10-19', '2026-10-27']);
    expect([...out.get('2026-10-19')!]).toEqual([['CVE-2026-0001', 0.3]]); // 0002 had no score that day; 0009 was not listed
    expect(out.get('2026-10-27')).toBeNull();
    expect(requested.filter((u) => u.includes('2026-10-19'))).toHaveLength(1);
    expect(requested.some((u) => u.includes('2026-10-21') || u.includes('2026-10-24') || u.includes('2026-01-01'))).toBe(false);
  });
});
