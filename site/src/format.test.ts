import { describe, expect, it } from 'vitest';
import {
  cnaName,
  cveListUrl,
  fmtAge,
  fmtCountdown,
  fmtDate,
  fmtDateTime,
  fmtPct,
  fmtRelative,
  isHttpUrl,
  kevDeadline,
  oneIn,
  signed,
  toMs,
  vendorProduct,
} from './format';

const NOW = Date.parse('2026-10-26T19:30:00Z');

describe('numbers', () => {
  it('formats percentages with sensible precision', () => {
    expect(fmtPct(297 / 15_960)).toBe('1.9%');
    expect(fmtPct(0.0004)).toBe('0.04%');
    expect(fmtPct(0.142)).toBe('14%');
    expect(fmtPct(0.02)).toBe('2%');
    expect(fmtPct(0.0029)).toBe('0.29%');
    expect(fmtPct(0.00004)).toBe('0.004%');
    expect(fmtPct(0)).toBe('0%');
    expect(fmtPct(Number.NaN)).toBe('—');
  });

  it('says how many CVEs to skim per one that matters', () => {
    expect(oneIn(297, 15_960)).toBe('1 in 54');
    expect(oneIn(0, 100)).toBe('—');
  });

  it('signs points with a real minus', () => {
    expect(signed(34)).toBe('+34');
    expect(signed(-14)).toBe('−14');
    expect(signed(0)).toBe('0');
  });
});

describe('dates (UTC)', () => {
  it('treats bare dates as UTC midnight', () => {
    expect(toMs('2026-10-13')).toBe(Date.UTC(2026, 9, 13));
  });

  it('adds the year only when it differs', () => {
    expect(fmtDate('2026-10-13', 2026)).toBe('Oct 13');
    expect(fmtDate('2025-10-06', 2026)).toBe('Oct 6, 2025');
    expect(fmtDate('not a date')).toBe('—');
  });

  it('formats a timestamp in UTC', () => {
    expect(fmtDateTime('2026-10-13T17:04:59Z')).toBe('Oct 13, 2026 · 17:04 UTC');
  });

  it('gives compact ages', () => {
    expect(fmtAge('2026-10-26T19:29:40Z', NOW)).toBe('now');
    expect(fmtAge('2026-10-26T19:05:00Z', NOW)).toBe('25m');
    expect(fmtAge('2026-10-26T01:30:00Z', NOW)).toBe('18h');
    expect(fmtAge('2026-10-20T19:30:00Z', NOW)).toBe('6d');
    expect(fmtAge('2026-09-01T00:00:00Z', NOW)).toBe('7w');
    expect(fmtAge('2024-01-01T00:00:00Z', NOW)).toBe('2y');
  });

  it('gives relative phrases both ways', () => {
    expect(fmtRelative('2026-10-26T14:30:00Z', NOW)).toBe('5 hours ago');
    expect(fmtRelative('2026-10-29T19:30:00Z', NOW)).toBe('in 3 days');
  });

  it('counts KEV deadlines to the end of the due date', () => {
    expect(kevDeadline('2026-10-26')).toBe(Date.UTC(2026, 9, 27));
  });

  it('formats countdowns', () => {
    expect(fmtCountdown(5_000)).toBe('00:00:05');
    expect(fmtCountdown((4 * 3600 + 12 * 60 + 9) * 1000)).toBe('04:12:09');
    expect(fmtCountdown((2 * 86_400 + 4 * 3600) * 1000)).toBe('2d 04h');
    expect(fmtCountdown((2 * 86_400 + 4 * 3600 + 61) * 1000, true)).toBe('2d 04:01:01');
    expect(fmtCountdown(-3_600_000)).toBe('01:00:00');
  });
});

describe('names and links', () => {
  it('prettifies CNA short names', () => {
    expect(cnaName('microsoft')).toBe('Microsoft');
    expect(cnaName('GitHub_M')).toBe('GitHub');
    expect(cnaName('VulnCheck')).toBe('VulnCheck');
    expect(cnaName('someone')).toBe('Someone');
  });

  it('joins vendor and product without repeating', () => {
    expect(vendorProduct('Fortinet', 'FortiSandbox')).toBe('Fortinet · FortiSandbox');
    expect(vendorProduct('Linux', 'Linux')).toBe('Linux');
    expect(vendorProduct('Microsoft', 'Microsoft Exchange Server 2019')).toBe('Microsoft Exchange Server 2019');
    expect(vendorProduct('Unknown', 'GiveWP')).toBe('GiveWP');
    expect(vendorProduct('', '')).toBe('');
  });

  it('only accepts absolute http(s) URLs', () => {
    expect(isHttpUrl('https://www.cisa.gov/kev')).toBe(true);
    expect(isHttpUrl('http://example.com')).toBe(true);
    expect(isHttpUrl('javascript:alert(1)')).toBe(false);
    expect(isHttpUrl('data:text/html,<script>alert(1)</script>')).toBe(false);
    expect(isHttpUrl('//evil.example/x')).toBe(false);
    expect(isHttpUrl('/relative')).toBe(false);
  });

  it('points at the record in the CVE List repository', () => {
    expect(cveListUrl('CVE-2024-12345')).toBe('https://github.com/CVEProject/cvelistV5/blob/main/cves/2024/12xxx/CVE-2024-12345.json');
    expect(cveListUrl('CVE-2019-0708')).toBe('https://github.com/CVEProject/cvelistV5/blob/main/cves/2019/0xxx/CVE-2019-0708.json');
    expect(cveListUrl('nope')).toBeNull();
  });
});
