/** Method: how the score works, the full chip table (from shared/model.ts), sources and blind spots. */
import type { ComponentChildren } from 'preact';
import { KNOB_DEFAULT, KNOB_MAX, KNOB_MIN, SIGNAL_MIN_SCORE, WATCH_FLOOR } from '../../../shared/contract';
import { BRAND, REPO_URL } from '../../../shared/brand';
import { BASE_POINTS, BATCH_MIN, CHIPS, COLD_START_DAYS, EXPLOITED_BONUS, EXPLOITED_FLOOR, RANSOMWARE_BONUS, SCORE_MODEL } from '../../../shared/model';
import { Chip } from '../components/Chip';
import { ExtLink } from '../components/ExtLink';
import { IconAlert, IconCheck } from '../components/icons';
import { ErrorState, Loading } from '../components/States';
import { TierPill } from '../components/Tier';
import { data } from '../data';
import { fmtAge, fmtDateTime, fmtInt, signed } from '../format';
import { useData, useNow, useTitle } from '../hooks';
import { href } from '../router';
import { SITE_KNOB_MAX, SITE_KNOB_MIN } from '../state';
import { FAMILY_META, FAMILY_ORDER, SOURCE_NAMES, TIER_META } from '../tiers';

const FORMULA = `raw   = ${BASE_POINTS} + X + SEV + SSVC + PRIOR + NOISE
score = exploited ? min(100, max(raw + ${EXPLOITED_BONUS}, ${EXPLOITED_FLOOR}) + ransomware·${RANSOMWARE_BONUS})
                  : clamp(raw, 0, 100)

X      strongest exploit signal (Metasploit, Nuclei, Exploit-DB, EPSS, PoC…)
       EPSS and "no exploit yet" only after ${COLD_START_DAYS} days
SSVC   automatable + technical impact (they add)
NOISE  only when nothing exploits it: hobby code, disputed, WordPress, kernel`;

const STEPS: readonly [string, string][] = [
  ['Read every CVE', 'One streaming pass over the full CVE List V5 git repository each hour — CNA records plus CISA’s ADP enrichment. NVD is not used: it stopped enriching most CVEs in April 2026.'],
  ['Join public evidence', 'CISA KEV, FIRST EPSS, Metasploit modules, Nuclei templates, Exploit-DB and PoC-in-GitHub, matched by CVE ID.'],
  ['Score with chips', 'Each piece of evidence is a chip worth a fixed number of points. Within a family only the strongest counts; across families points add.'],
  ['Set the evidence bar', `Exploited CVEs always pass. Weaponized ones (Metasploit or Nuclei) are always at least Likely. Everything else passes when its score reaches the evidence bar (default ${KNOB_DEFAULT}).`],
  ['Publish static files', 'JSON, Atom and iCalendar files on a git branch. AI agents can read the same files through a read-only MCP server that runs on your machine. No accounts or API keys. Fork it and run your own.'],
];

const BLIND_SPOTS: readonly [string, ComponentChildren][] = [
  [
    'Old CVEs drop out',
    <>
      We score CVEs published in the last 30 days and every CVE in CISA KEV. An older CVE comes back only when it gains new exploitation evidence, and then it shows on <a href={href('woke')}>Woke Up</a>. Any other
      old CVE is not in this data.
    </>,
  ],
  ['Not in KEV ≠ not exploited', 'KEV lists only exploitation CISA can confirm, often weeks late. Plenty of exploited bugs never appear.'],
  ['Quiet ≠ safe', 'Quiet means no public evidence yet. A brand-new CVE in an internet-facing product you run can matter before anyone writes an exploit.'],
  ['Exposure is yours', 'We can’t see your assets. A Likely CVE in software you don’t run is noise; a Watch CVE on your perimeter may not be.'],
  ['Feeds lag', `Exploit feeds and EPSS need about ${COLD_START_DAYS} days to catch up, so new CVEs show “Too new” instead of a penalty.`],
  ['PoCs are unverified', 'Proof-of-concept repos are counted, never run. Fake PoCs that carry malware are common — treat every link as hostile.'],
  ['Vendor text is data', 'Descriptions are written by CNAs and sometimes contain hostile markup. Everything is shown as plain text.'],
  [
    'Check Deps knows only what we track',
    <>
      The <a href={href('check')}>Check Deps</a> page compares an SBOM or lockfile with the CVEs in this data that an OSV.dev advisory ties to a package version, in eight package ecosystems. A clean result there is
      not a full audit, and “affected” means the version is in the advisory’s range, not that your code reaches the vulnerable part.
    </>,
  ],
];

const ATTRIBUTIONS: readonly [string, string, string][] = [
  ['CVE List V5', 'https://github.com/CVEProject/cvelistV5', 'CVE Program Terms of Use; MITRE’s notice below'],
  ['CISA KEV and Vulnrichment (ADP)', 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', 'CC0 1.0; no CISA endorsement implied'],
  ['EPSS', 'https://www.first.org/epss', 'FIRST.org — free use with attribution'],
  ['Metasploit Framework', 'https://github.com/rapid7/metasploit-framework', 'BSD-3-Clause, Rapid7'],
  ['Nuclei templates', 'https://github.com/projectdiscovery/nuclei-templates', 'MIT, ProjectDiscovery'],
  ['Exploit-DB', 'https://www.exploit-db.com', 'OffSec; only IDs, flags and links are used'],
  ['PoC-in-GitHub', 'https://github.com/nomi-sec/PoC-in-GitHub', 'nomi-sec; linked repos are third-party and unverified'],
  [
    'OSV.dev advisories (Check Deps page only)',
    'https://osv.dev/',
    'GitHub Advisory Database, PyPI and Go databases (CC-BY-4.0), RustSec (CC0-1.0), Drupal (MIT, Ackama); never part of a score',
  ],
];

function Sources() {
  const meta = useData(data.meta);
  const now = useNow(60_000);
  if (meta.status === 'error') return <ErrorState error={meta.error} onRetry={meta.retry} />;
  if (meta.status !== 'ready') return <Loading label="Loading source status" lines={4} height="56px" />;
  return (
    <ul class="sources">
      {meta.data.sources.map((s) => {
        const state = !s.ok ? 'down' : s.stale ? 'stale' : 'fresh';
        return (
          <li key={s.id} class={`source source--${state}`}>
            <div class="source__head">
              <span class={`source__state source__state--${state}`}>
                {state === 'fresh' ? <IconCheck size={12} /> : <IconAlert size={12} />}
                {state}
              </span>
              <ExtLink href={s.url} class="source__name">
                {s.name}
              </ExtLink>
            </div>
            <dl class="source__facts">
              <div>
                <dt>Fetched</dt>
                <dd>{s.fetched_at ? `${fmtAge(s.fetched_at, now)} ago` : 'never'}</dd>
              </div>
              <div>
                <dt>Records</dt>
                <dd class="mono">{s.records === null ? '—' : fmtInt(s.records)}</dd>
              </div>
              <div>
                <dt>Version</dt>
                <dd class="mono">{s.upstream_version ? (s.upstream_version.length > 16 ? s.upstream_version.slice(0, 12) : s.upstream_version) : '—'}</dd>
              </div>
            </dl>
            {s.error && <p class="source__error">{s.error}</p>}
            <p class="source__license">{s.license}</p>
          </li>
        );
      })}
    </ul>
  );
}

export default function Method() {
  useTitle('Method');
  const meta = useData(data.meta);
  return (
    <div class="page page--method">
      <header class="page__head">
        <p class="eyebrow">Explainable by construction</p>
        <h1 class="page__title" tabIndex={-1}>
          Method
        </h1>
        <p class="page__lede">
          Every score is a sum of chips you can read, each linked to its source. No machine learning, no generated text, no imputed values. Model <span class="mono">{SCORE_MODEL}</span>.
        </p>
        <nav class="toc" aria-label="On this page">
          <a href="#how">How it works</a>
          <a href="#formula">The formula</a>
          <a href="#tiers">Tiers</a>
          <a href="#chips">Chips</a>
          <a href="#sources">Sources</a>
          <a href="#checking">Checking our work</a>
          <a href="#blind-spots">Blind spots</a>
          <a href="#attributions">Attributions</a>
        </nav>
      </header>

      <section id="how" class="prose-section">
        <h2 class="section__title">How it works</h2>
        <ol class="steps">
          {STEPS.map(([title, text], i) => (
            <li key={title} class="step">
              <span class="step__n mono">{String(i + 1).padStart(2, '0')}</span>
              <div>
                <h3 class="step__title">{title}</h3>
                <p>{text}</p>
              </div>
            </li>
          ))}
        </ol>
      </section>

      <section id="formula" class="prose-section">
        <h2 class="section__title">The formula</h2>
        <pre class="code">
          <code>{FORMULA}</code>
        </pre>
        <p class="muted">
          Points are roughly 20·log₁₀ of how much each signal raises the odds of a later KEV listing, shrunk for look-ahead bias — so +20 points is about ten times the odds. Batches are {BATCH_MIN}+ CVEs from one CNA on one UTC day — a vendor patch day or an aggregator’s bulk release.
        </p>
      </section>

      <section id="tiers" class="prose-section">
        <h2 class="section__title">Tiers</h2>
        <div class="tablewrap">
          <table class="table">
            <thead>
              <tr>
                <th scope="col">Tier</th>
                <th scope="col">Rule</th>
                <th scope="col">Meaning</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>
                  <TierPill tier="exploited" />
                </td>
                <td>any Exploitation chip</td>
                <td>{TIER_META.exploited.blurb}</td>
              </tr>
              <tr>
                <td>
                  <TierPill tier="likely" />
                </td>
                <td>
                  Metasploit/Nuclei, or score ≥ the evidence bar ({SITE_KNOB_MIN} to {SITE_KNOB_MAX} here, {KNOB_MIN} to {KNOB_MAX} in the API, default {KNOB_DEFAULT})
                </td>
                <td>{TIER_META.likely.blurb}</td>
              </tr>
              <tr>
                <td>
                  <TierPill tier="watch" />
                </td>
                <td>score ≥ {WATCH_FLOOR}</td>
                <td>{TIER_META.watch.blurb}</td>
              </tr>
              <tr>
                <td>
                  <TierPill tier="quiet" />
                </td>
                <td>everything else</td>
                <td>{TIER_META.quiet.blurb}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <p class="muted">The signal feed ships every CVE with score ≥ {SIGNAL_MIN_SCORE} or confirmed/weaponized, so the evidence bar works offline in your browser.</p>
      </section>

      <section id="chips" class="prose-section">
        <h2 class="section__title">Chips</h2>
        <p class="muted">Generated from the scoring model the pipeline runs. Within a family only the strongest chip counts, except SSVC, whose two decision points add.</p>
        {FAMILY_ORDER.map((f) => (
          <div key={f} class="chipfamily">
            <h3 class="chipfamily__title">
              {FAMILY_META[f].label} <span class="muted">{FAMILY_META[f].blurb}</span>
            </h3>
            <div class="tablewrap">
              <table class="table table--chips">
                <thead>
                  <tr>
                    <th scope="col">Chip</th>
                    <th scope="col" class="num">Points</th>
                    <th scope="col">Source</th>
                    <th scope="col">What it means</th>
                  </tr>
                </thead>
                <tbody>
                  {CHIPS.filter((c) => c.family === f).map((c) => (
                    <tr key={c.id}>
                      <td>
                        <Chip id={c.id} />
                        <code class="chipid">{c.id}</code>
                      </td>
                      <td class="num mono">{c.polarity === 'info' || c.polarity === 'unknown' ? '0' : signed(c.points)}</td>
                      <td>{SOURCE_NAMES[c.source]}</td>
                      <td>{c.explain}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ))}
      </section>

      <section id="sources" class="prose-section">
        <h2 class="section__title">Sources</h2>
        <p class="muted">
          Every source falls back to its last good copy when a fetch fails; stale sources are marked here and never stop a run.
          {meta.status === 'ready' && <> Last run {fmtDateTime(meta.data.generated_at)}.</>}
        </p>
        <Sources />
      </section>

      <section id="checking" class="prose-section">
        <h2 class="section__title">Checking our work</h2>
        <p>
          A score only earns trust when it is checked. <a href={href('receipts')}>Receipts</a> shows how often {BRAND.name} flagged a CVE before CISA added it to KEV, next to “CVSS 7 or more” and “EPSS 10%
          or more”, with every hit and every miss. The live record notes each run, to the minute. A backtest of the last 180 days is shown apart and marked as hindsight.
        </p>
      </section>

      <section id="blind-spots" class="prose-section">
        <h2 class="section__title">Blind spots</h2>
        <ul class="blind">
          {BLIND_SPOTS.map(([title, text]) => (
            <li key={title}>
              <h3>{title}</h3>
              <p>{text}</p>
            </li>
          ))}
        </ul>
      </section>

      <section id="attributions" class="prose-section">
        <h2 class="section__title">Attributions</h2>
        <ul class="attrib">
          {ATTRIBUTIONS.map(([name, url, note]) => (
            <li key={name}>
              <ExtLink href={url}>{name}</ExtLink>
              <span class="muted">{note}</span>
            </li>
          ))}
        </ul>
        {/* The CVE Terms of Use license requires this notice in every copy of CVE text, and this site shows CVE descriptions. */}
        <p class="muted">
          Copyright © 1999-{new Date().getUTCFullYear()}, The MITRE Corporation. CVE is a trademark and the CVE logo is a registered trademark of The MITRE Corporation.{' '}
          <strong>CVE Usage:</strong> MITRE hereby grants you a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable copyright license to reproduce, prepare derivative works of, publicly
          display, publicly perform, sublicense, and distribute Common Vulnerabilities and Exposures (CVE™). Any copy you make for such purposes is authorized provided that you reproduce MITRE's copyright
          designation and this license in any such copy. <ExtLink href="https://www.cve.org/Legal/TermsOfUse">CVE Terms of Use</ExtLink>
        </p>
        <p class="muted">
          {BRAND.name} is open source (MIT). <ExtLink href={REPO_URL}>Read the code</ExtLink>, file an issue when a score looks wrong, or fork it to run your own.
        </p>
      </section>
    </div>
  );
}
