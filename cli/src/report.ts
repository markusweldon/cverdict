/**
 * The report in each output form: text for a terminal, Markdown for a GitHub job summary, JSON,
 * SARIF 2.1.0 for code scanning, and GitHub workflow annotations.
 *
 * Package names and versions come from the user's files, and CVE titles from upstream records:
 * both are untrusted. Markdown escapes them (a job summary renders HTML), annotations escape the
 * workflow-command syntax, so a package named "x\n::set-env" stays a name.
 */
import { createHash } from 'node:crypto';
import { BRAND, REPO_URL } from '../../shared/brand';
import { TIER_NAMES } from '../../shared/verdict';
import type { Group } from '../../site/src/check/match';
import { countByGroup, failing, formatLabel, type FailOn, type Finding, type Report } from './check';

export const GROUP_NAMES: Readonly<Record<Group, string>> = { ...TIER_NAMES, possible: 'Possibly affected, not confirmed' };
export const GROUPS: readonly Group[] = ['exploited', 'likely', 'watch', 'quiet', 'possible'];
export const cveUrl = (id: string) => `${BRAND.siteUrl}/cve/${encodeURIComponent(id)}`;
/** Where a finding's CVE is explained: its CVE page when tracked, else its record on cve.org (older CVEs have no page). */
export const findingUrl = (f: Pick<Finding, 'row' | 'tracked'>) => (f.tracked ? cveUrl(f.row.id) : `https://www.cve.org/CVERecord?id=${encodeURIComponent(f.row.id)}`);

const fmtTime = (iso: string) => `${iso.slice(0, 16).replace('T', ' ')} UTC`;
const plural = (n: number, one: string, many = `${one}s`) => `${n.toLocaleString('en-US')} ${n === 1 ? one : many}`;
const pkgText = (f: Finding) => `${f.pkg.named ?? f.pkg.name}${f.pkg.version ? ` ${f.pkg.version}` : ''}`;
const where = (f: Finding) => `${f.file}${f.line ? `:${f.line}` : ''}`;
const who = (f: Finding) => [f.row.v, f.row.p].filter(Boolean).join(' · ');

/** What a finding needs: a fixed version, or why it is only possibly affected. */
function action(f: Finding): string {
  if (f.group === 'possible') return f.pkg.version ? 'version could not be compared' : 'no exact version in the file';
  return f.fixedIn ? `fixed in ${f.fixedIn}` : 'no fixed version named';
}

/** The verdict line: pass or fail, and why. */
export function verdictLine(report: Report, failOn: FailOn): string {
  const bad = failing(report, failOn);
  if (failOn === 'never') return 'Result: reported only (--fail-on never).';
  if (!bad.length) return `Result: pass. No confirmed CVE at ${TIER_NAMES[failOn]}${failOn === 'exploited' ? '' : ' or above'}.`;
  const n = new Set(bad.map((f) => f.row.id)).size;
  return `Result: fail. ${plural(n, 'CVE')} at ${TIER_NAMES[failOn]}${failOn === 'exploited' ? '' : ' or above'} (--fail-on ${failOn}).`;
}

function scopeLine(report: Report): string {
  const c = report.coverage;
  const against = c.olderError === null ? `the ${plural(c.tracked + c.older, 'CVE')} OSV.dev advisories tie to package versions` : `${plural(c.tracked, 'tracked CVE')} only`;
  return `Checked ${plural(report.checked, 'package')} in ${plural(report.files.filter((f) => f.result).length, 'file')} against ${against} (data of ${fmtTime(report.generatedAt)}, evidence bar ${report.knob}).`;
}

/** The line for a run with no finding: what "nothing found" covers. */
function cleanLine(report: Report): string {
  return report.coverage.olderError === null
    ? 'None of the CVEs OSV.dev advisories tie to package versions affects these packages.'
    : 'No tracked CVE affects these packages. Older CVEs were not checked (see below), so this is not a clean result.';
}

/** Plain text for a terminal. */
export function toText(report: Report, failOn: FailOn): string {
  const out: string[] = [`${BRAND.name} check`, scopeLine(report), ''];
  const by = groupFindings(report.findings);
  const counts = countByGroup(report.findings);
  for (const g of GROUPS) {
    const list = by.get(g) ?? [];
    if (!list.length) continue;
    out.push(`${GROUP_NAMES[g].toUpperCase()} (${counts[g]})`);
    for (const [id, fs] of byCve(list)) {
      const r = fs[0].row;
      out.push(`  ${id}  score ${r.s}${r.kd ? `  KEV due ${r.kd}` : ''}  ${clip(who(fs[0]) || r.t, 60)}`);
      for (const f of fs) out.push(`    ${clip(pkgText(f), 70)}  ${action(f)}  ${where(f)}`);
    }
    out.push('');
  }
  if (!report.findings.length) out.push(cleanLine(report), '');
  out.push(...footer(report).map((l) => l.text));
  out.push('', verdictLine(report, failOn));
  return `${out.join('\n')}\n`;
}

/** Markdown for $GITHUB_STEP_SUMMARY: counts, then a table per group (possibly affected collapsed). */
export function toMarkdown(report: Report, failOn: FailOn): string {
  const counts = countByGroup(report.findings);
  const out: string[] = [`### ${md(BRAND.name)} check`, '', md(scopeLine(report)), ''];
  out.push(`| ${GROUPS.map((g) => md(GROUP_NAMES[g])).join(' | ')} |`, `|${GROUPS.map(() => '--:').join('|')}|`, `| ${GROUPS.map((g) => counts[g]).join(' | ')} |`, '');
  const by = groupFindings(report.findings);
  for (const g of GROUPS) {
    const list = by.get(g) ?? [];
    if (!list.length) continue;
    const table = ['| CVE | Score | Package | Fix | File |', '|---|--:|---|---|---|'];
    for (const f of list) table.push(`| [${md(f.row.id)}](${findingUrl(f)}) | ${f.row.s} | ${md(pkgText(f))} | ${md(action(f))} | \`${code(where(f))}\` |`);
    if (g === 'possible' || g === 'quiet') out.push(`<details><summary>${md(GROUP_NAMES[g])} (${counts[g]})</summary>`, '', ...table, '', '</details>', '');
    else out.push(`#### ${md(GROUP_NAMES[g])} (${counts[g]})`, '', ...table, '');
  }
  if (!report.findings.length) out.push(md(cleanLine(report)), '');
  for (const l of footer(report)) out.push(`- ${md(l.text)}`);
  out.push('', `**${md(verdictLine(report, failOn))}**`, '');
  return `${out.join('\n')}\n`;
}

/** The report as JSON: stable field names, for scripts. */
export function toJson(report: Report, failOn: FailOn): string {
  const bad = new Set(failing(report, failOn));
  return `${JSON.stringify(
    {
      tool: BRAND.slug,
      data_generated_at: report.generatedAt,
      evidence_bar: report.knob,
      fail_on: failOn,
      failed: bad.size > 0,
      counts: countByGroup(report.findings),
      packages_checked: report.checked,
      tracked_cves: report.coverage.tracked,
      older_cves: report.coverage.older,
      advisories: report.coverage.advisories,
      older_error: report.coverage.olderError,
      files: report.files.map((f) => ({ path: f.path, format: f.format, error: f.error, packages: f.result?.distinct ?? 0 })),
      findings: report.findings.map((f) => ({
        cve: f.row.id,
        group: f.group,
        score: f.row.s,
        in_kev: f.row.k === 1,
        kev_due: f.row.kd,
        ecosystem: f.pkg.eco,
        package: f.pkg.name,
        named: f.pkg.named ?? null,
        version: f.pkg.version,
        fixed_in: f.fixedIn,
        advisories: f.pkg.advisories.map((a) => a.id),
        file: f.file,
        line: f.line,
        fails: bad.has(f),
        tracked: f.tracked,
        url: findingUrl(f),
      })),
      ecosystems_down: report.ecosystemsDown,
      notes: report.notes,
    },
    null,
    2,
  )}\n`;
}

/** SARIF severity buckets for code scanning: Exploited critical, Likely next high, Watch medium. */
const SARIF: Partial<Record<Group, { level: 'error' | 'warning' | 'note'; severity: string }>> = {
  exploited: { level: 'error', severity: '9.5' },
  likely: { level: 'warning', severity: '8.0' },
  watch: { level: 'note', severity: '5.0' },
};

/** SARIF 2.1.0: one rule per CVE, one result per (CVE, package, file). Quiet and possibly affected are left out. */
export function toSarif(report: Report, version: string): string {
  const shown = report.findings.filter((f) => SARIF[f.group]);
  const rules = new Map<string, Finding>();
  for (const f of shown) if (!rules.has(f.row.id)) rules.set(f.row.id, f);
  const ruleIds = [...rules.keys()];
  const doc = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: BRAND.name,
            informationUri: REPO_URL,
            version,
            rules: [...rules.values()].map((f) => ({
              id: f.row.id,
              name: f.row.id.replace(/-/g, ''),
              shortDescription: { text: clip(`${f.row.id}: ${f.row.t || who(f)}`, 200) },
              fullDescription: { text: clip(f.row.t || f.row.id, 1000) },
              helpUri: findingUrl(f),
              help: { text: `${TIER_NAMES[f.row.tier]} at the default evidence bar, score ${f.row.s}/100. ${f.tracked ? `Why: ${cveUrl(f.row.id)}` : `An older CVE with no ${BRAND.name} page: ${findingUrl(f)}`}` },
              properties: { 'security-severity': SARIF[f.group]!.severity, tags: ['security', 'dependency', BRAND.slug, f.group] },
            })),
          },
        },
        results: shown.map((f) => ({
          ruleId: f.row.id,
          ruleIndex: ruleIds.indexOf(f.row.id),
          level: SARIF[f.group]!.level,
          message: { text: clip(`${pkgText(f)} is affected by ${f.row.id} (${GROUP_NAMES[f.group]}, score ${f.row.s}). ${action(f)[0].toUpperCase()}${action(f).slice(1)}.`, 1000) },
          locations: [{ physicalLocation: { artifactLocation: { uri: f.file }, region: { startLine: f.line ?? 1 } } }],
          partialFingerprints: { [`${BRAND.slug}/v1`]: fingerprint(f) },
        })),
        properties: { dataGeneratedAt: report.generatedAt, evidenceBar: report.knob },
      },
    ],
  };
  return `${JSON.stringify(doc, null, 2)}\n`;
}

/** GitHub workflow annotations: an error per Exploited finding, a warning per Likely next one, a notice per Watch one. */
export function toAnnotations(report: Report): string[] {
  const kind: Partial<Record<Group, string>> = { exploited: 'error', likely: 'warning', watch: 'notice' };
  return report.findings
    .filter((f) => kind[f.group])
    .map((f) => {
      const props = [`file=${prop(f.file)}`, ...(f.line ? [`line=${f.line}`] : []), `title=${prop(`${f.row.id} · ${GROUP_NAMES[f.group]}`)}`].join(',');
      return `::${kind[f.group]} ${props}::${data(`${pkgText(f)} is affected by ${f.row.id} (score ${f.row.s}), ${action(f)}. ${findingUrl(f)}`)}`;
    });
}

// ── helpers ──

function groupFindings(findings: readonly Finding[]): Map<Group, Finding[]> {
  const by = new Map<Group, Finding[]>();
  for (const f of findings) {
    const list = by.get(f.group);
    if (list) list.push(f);
    else by.set(f.group, [f]);
  }
  return by;
}

function byCve(findings: readonly Finding[]): Map<string, Finding[]> {
  const by = new Map<string, Finding[]>();
  for (const f of findings) {
    const list = by.get(f.row.id);
    if (list) list.push(f);
    else by.set(f.row.id, [f]);
  }
  return by;
}

function footer(report: Report): { text: string }[] {
  const out: { text: string }[] = [];
  for (const f of report.files) if (f.error) out.push({ text: `${f.path}: ${f.error}` });
  for (const e of report.ecosystemsDown) out.push({ text: `${e} packages were not checked: the advisory data could not be loaded in the last run.` });
  const notChecked = report.packages - report.checked;
  if (notChecked > 0) out.push({ text: `${plural(notChecked, 'package')} not checked (outside the eight ecosystems, or no usable package URL).` });
  for (const n of report.notes) out.push({ text: `${n.file}: ${n.text}` });
  const c = report.coverage;
  if (c.olderError === null) {
    out.push({
      text: `Covered: every CVE that one of ${c.advisories.toLocaleString('en-US')} OSV.dev advisories ties to a package version, ranked by exploitation evidence. Not covered: advisories without a CVE ID (malware reports among them), other ecosystems (deb, rpm, apk, containers) and bugs no advisory names yet.`,
    });
  } else {
    out.push({ text: `Older CVEs were not checked (${c.olderError}): only CVEs published in the last 30 days, in CISA KEV, listed as exploited or woken up. Run a scanner such as osv-scanner for the rest.` });
  }
  return out;
}

const clip = (s: string, n: number) => {
  const t = s.replace(/[\u0000-\u001f\u007f]+/g, ' ').trim();
  return t.length > n ? `${t.slice(0, n - 1)}…` : t;
};

/** Markdown and HTML inert: escapes the characters that make links, emphasis, tables and tags. */
export function md(s: string): string {
  return clip(s, 300)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/([\\`*_{}[\]()#+!|~])/g, '\\$1');
}

/** Text for inline code: no backticks or pipes to break out of it or the table. */
const code = (s: string) => clip(s, 300).replace(/[`|]/g, '?');

/** Workflow command message: %, CR and LF escaped (GitHub's own escaping). */
export const data = (s: string) => s.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
/** Workflow command property: as `data`, plus : and , that separate properties. */
export const prop = (s: string) => data(s).replace(/:/g, '%3A').replace(/,/g, '%2C');

function fingerprint(f: Finding): string {
  return createHash('sha256').update([f.row.id, f.pkg.eco, f.pkg.name, f.pkg.version ?? '', f.file].join('\u0000')).digest('hex').slice(0, 32);
}
