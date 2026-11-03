import { describe, expect, it } from 'vitest';
import type { CveDetail } from '../../shared/contract';
import { feedbackIssueUrl, mdCode, mdEscape, ticketMarkdown } from './ticket';
import { detailTier, verdict } from './tiers';

const detail: CveDetail = {
  id: 'CVE-2026-112850',
  state: 'PUBLISHED',
  published: '2026-10-25T08:00:00Z',
  reserved: '2026-10-01T00:00:00Z',
  updated: null,
  cna: 'VulDB',
  title: 'Shop 1.0 search.php "><script>alert(document.domain)</script> [click](javascript:alert(1)) cross site scripting',
  description: 'The manipulation leads to <img src=x onerror=alert(1)>.',
  cvss: { version: '4.0', score: 9.3, severity: 'CRITICAL', vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`', source: 'cna' },
  cwe: ['CWE-79'],
  affected: [{ vendor: 'code-projects', product: 'Shop', purl: null }],
  ssvc: null,
  kev: { date_added: '2026-10-25', due_date: '2026-10-28', ransomware: 'Known', forensic_triage: true, name: 'x', required_action: 'Apply mitigations.', notes: '' },
  epss: { score: 0.123, percentile: 0.991, date: '2026-10-26', model: 'v2026.06.15' },
  exploits: { metasploit: [], nuclei: [], exploitdb: [], poc: { count: 0, vetted: 0, hype: false, top: [] } },
  ai_credit: null,
  tags: [],
  batch: null,
  score: { value: 100, tier: 'exploited', raw: 30, model: 'v0.1.0' },
  reasons: [
    { id: 'kev.listed', label: 'CISA KEV · added Oct 25 · due Oct 28', polarity: 'up', family: 'E', points: 70, source: 'kev', url: 'https://www.cisa.gov/kev' },
    { id: 'sev.crit_net', label: 'Critical 9.3 · network (v4.0)', polarity: 'up', family: 'SEV', points: 13, source: 'cvelist', url: 'javascript:alert(1)' },
    { id: 'x.too_new', label: 'Too new', polarity: 'unknown', family: 'X', points: 0, source: 'computed' },
    { id: 'prior.none', label: 'Never in KEV: code-projects', polarity: 'down', family: 'PRIOR', points: -6, source: 'kev' },
  ],
  unknowns: ['No CISA SSVC assessment yet'],
  timeline: [],
  references: [],
  woke: null,
};

describe('mdEscape', () => {
  it('neutralises links, HTML, code and emphasis, and flattens newlines', () => {
    expect(mdEscape('[x](javascript:1) <b>*hi*</b> `c`\nnext')).toBe('\\[x\\](javascript:1) \\<b\\>\\*hi\\*\\</b\\> \\`c\\` next');
    expect(mdEscape('# heading')).toBe('\\# heading');
  });

  it('defuses @mentions with a zero-width space', () => {
    expect(mdEscape('Never in KEV: Tobias @Saleswonder.biz')).toBe('Never in KEV: Tobias @\u200bSaleswonder.biz');
    expect(mdEscape('@fastify/jwt')).not.toMatch(/@[a-z]/i);
  });
});

describe('mdCode', () => {
  it('drops backticks and newlines so the span cannot be closed or split', () => {
    expect(mdCode('a`b\n- c')).toBe('`ab - c`');
  });
});

describe('feedbackIssueUrl', () => {
  const hostile: CveDetail = {
    ...detail,
    reasons: [
      ...detail.reasons,
      { id: 'prior.none', label: 'Never in KEV: [Official fix](https://evil.example) <!-- @maintainer', polarity: 'down', family: 'PRIOR', points: -6, source: 'kev' },
    ],
  };
  const body = new URL(feedbackIssueUrl(hostile, 'exploited', 50)).searchParams.get('body')!;
  const chips = body.split('\n').filter((l) => l.startsWith('- '));

  it('quotes every counted chip label as inline code', () => {
    expect(chips).toContain('- −6 `prior.none`: `Never in KEV: [Official fix](https://evil.example) <!-- @maintainer`');
    expect(chips).toHaveLength(4);
    expect(chips.every((l) => /^- \S+ `[a-z._]+`: `[^`]*`$/.test(l))).toBe(true);
    expect(chips.join()).not.toContain('Too new');
  });

  it('keeps the template outside the quoted text', () => {
    expect(body).toMatch(/^\*\*CVE:\*\* CVE-2026-112850\n/);
    expect(body).toContain('**What looks wrong?**');
  });
});

describe('ticketMarkdown', () => {
  const md = ticketMarkdown(detail, detailTier(detail, 50), 50, 'https://site.example/cve/CVE-2026-112850');

  it('leads with the verdict, deadline and score', () => {
    expect(md).toContain('### CVE-2026-112850 · code-projects · Shop');
    expect(md).toContain('**Verdict:** Patch now — exploited, KEV due Oct 28 · score 100/100');
    expect(md).toContain('due **2026-10-28**');
    expect(md).toContain('forensic triage required');
  });

  it('lists counted chips with points, skipping unknown chips', () => {
    expect(md).toContain('- +70 · CISA KEV · added Oct 25 · due Oct 28 (https://www.cisa.gov/kev)');
    expect(md).toContain('- −6 · Never in KEV: code-projects');
    expect(md).not.toContain('Too new');
    expect(md).toContain('- No CISA SSVC assessment yet');
  });

  it('never carries live markup or non-http links from CVE text', () => {
    // Every bracket and angle bracket that came from CVE text is backslash-escaped.
    expect(md).not.toMatch(/(^|[^\\])[[<]/m);
    expect(md).toContain('\\<script\\>');
    expect(md).not.toContain('network (v4.0) (javascript:');
    expect(md).toContain('`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`');
  });
});

describe('verdict', () => {
  it('explains each tier in words', () => {
    expect(verdict(detail, 'exploited', 50)).toEqual({ head: 'Patch now', reason: 'exploited, KEV due Oct 28' });
    expect(verdict({ ...detail, kev: null, score: { ...detail.score, value: 38 } }, 'watch', 50).reason).toBe('score 38, below the default knob (50)');
    expect(verdict({ ...detail, kev: null, score: { ...detail.score, value: 38 } }, 'watch', 60).reason).toBe('score 38, below the knob (60)');
    // Quiet is never "no evidence" while a counted chip raised the score.
    expect(verdict({ ...detail, score: { ...detail.score, value: 20 } }, 'quiet', 50).reason).toBe('score 20, below the watch floor (25), and quiet is not safe');
    expect(verdict({ ...detail, reasons: [] }, 'quiet', 50).reason).toBe('no evidence yet, and quiet is not safe');
  });

  it('names the strongest artifact for Likely, including a vendor-declared working exploit', () => {
    const functional = { id: 'vendor.functional', label: 'Acme CVSS vector: functional exploit code exists (E:F)', polarity: 'up', family: 'X', points: 24, source: 'cvelist' } as const;
    const likely = { ...detail, kev: null, reasons: [functional, ...detail.reasons.slice(1)], score: { ...detail.score, value: 62, tier: 'likely' as const } };
    expect(verdict(likely, 'likely', 50).reason).toBe('vendor CVSS says a working exploit exists');
  });

  it('re-tiers a detail at another knob', () => {
    const likely = { ...detail, kev: null, score: { ...detail.score, value: 55, tier: 'likely' as const } };
    expect(detailTier(likely, 50)).toBe('likely');
    expect(detailTier(likely, 60)).toBe('watch');
    expect(detailTier(detail, 80)).toBe('exploited');
  });
});
