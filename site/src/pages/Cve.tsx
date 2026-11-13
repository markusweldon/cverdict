/** One CVE: verdict, the score arithmetic, every chip with its evidence, facts and references. */
import type { ComponentChildren } from 'preact';
import { useEffect } from 'preact/hooks';
import type { CveDetail, Reason } from '../../../shared/contract';
import { BRAND } from '../../../shared/brand';
import { BASE_POINTS } from '../../../shared/model';
import { shareDescription, shareTitle } from '../../../shared/share';
import { absoluteUrl, copyLink, copyTicket } from '../actions';
import { Chip } from '../components/Chip';
import { ExtLink } from '../components/ExtLink';
import {
  IconAlert,
  IconArrowLeft,
  IconClock,
  IconCopy,
  IconDown,
  IconDownload,
  IconExternal,
  IconEye,
  IconEyeOff,
  IconInfo,
  IconLayers,
  IconLink,
  IconSparkle,
  IconStar,
  IconUnknown,
  IconUp,
} from '../components/icons';
import { Countdown, KevFlags } from '../components/Kev';
import { ScoreDial } from '../components/ScoreDial';
import { EmptyState, ErrorState, Loading } from '../components/States';
import { TierIcon, TierPill } from '../components/Tier';
import { data, normalizeCveId } from '../data';
import { batchKind, batchLabel, cnaName, cveListUrl, cveOrgUrl, fmtAge, fmtDate, fmtDateTime, fmtPct, signed, vendorProduct } from '../format';
import { useData, useMetaDescription, useNow, useTitle } from '../hooks';
import { cveHref, href } from '../router';
import { keyTargets, knob, normalizeName, toggleWatch, useStore, watchlist } from '../state';
import { feedbackIssueUrl } from '../ticket';
import { chipDef, chipTone, detailTier, FAMILY_META, FAMILY_ORDER, SOURCE_NAMES, verdict } from '../tiers';
import { wakeSentence } from '../woke';

const MSF_RANK: Readonly<Record<number, string>> = { 600: 'excellent', 500: 'great', 400: 'good', 300: 'normal', 200: 'average', 100: 'low', 0: 'manual' };

function ToneIcon({ r }: { r: Reason }) {
  const def = chipDef(r.id);
  const tone = def ? chipTone(def) : r.polarity;
  if (tone === 'down') return <IconDown size={14} />;
  if (tone === 'ai') return <IconSparkle size={14} />;
  if (tone === 'info') return <IconInfo size={14} />;
  if (tone === 'unknown') return <IconUnknown size={14} />;
  return <IconUp size={14} />;
}

function Ledger({ d }: { d: CveDetail }) {
  const counted = d.reasons.filter((r) => r.points !== 0);
  const sum = BASE_POINTS + counted.reduce((a, r) => a + r.points, 0);
  const exploited = d.score.tier === 'exploited';
  return (
    <section class="ledger" aria-labelledby="ledger-h">
      <h2 id="ledger-h" class="ledger__title">
        How the score adds up
      </h2>
      <ol class="ledger__list">
        <li class="ledger__row">
          <span class="ledger__what">Base</span>
          <span class="ledger__pts">{BASE_POINTS}</span>
        </li>
        {counted.map((r) => (
          <li key={r.id} class={`ledger__row ledger__row--${chipDef(r.id) ? chipTone(chipDef(r.id)!) : r.polarity}`}>
            <span class="ledger__what">
              <Chip id={r.id} />
            </span>
            <span class="ledger__pts">{signed(r.points)}</span>
          </li>
        ))}
        <li class="ledger__row ledger__row--total">
          <span class="ledger__what">Score</span>
          <span class="ledger__pts">{d.score.value}</span>
        </li>
      </ol>
      {exploited ? (
        <p class="ledger__note">
          Raw evidence score {d.score.raw}. Confirmed exploitation adds 75 and floors the result at 90, so exploited CVEs always sort first.
        </p>
      ) : (
        sum !== d.score.value && (
          <p class="ledger__note">
            The chips add up to {sum}; scores are clamped to 0–100.
          </p>
        )
      )}
    </section>
  );
}

function Evidence({ d }: { d: CveDetail }) {
  return (
    <section class="evidence" aria-labelledby="ev-h">
      <h2 id="ev-h" class="section__title">
        Evidence
      </h2>
      {FAMILY_ORDER.map((f) => {
        const rs = d.reasons.filter((r) => r.family === f && r.polarity !== 'unknown');
        if (rs.length === 0) return null;
        const pts = rs.reduce((a, r) => a + r.points, 0);
        return (
          <section key={f} class="family" aria-label={FAMILY_META[f].label}>
            <header class="family__head">
              <h3 class="family__title">{FAMILY_META[f].label}</h3>
              {f !== 'INFO' && <span class="family__pts mono">{signed(pts)}</span>}
            </header>
            <p class="family__blurb">{FAMILY_META[f].blurb}</p>
            <ul class="reasons">
              {rs.map((r) => {
                const def = chipDef(r.id);
                const lost = r.points === 0 && r.polarity !== 'info' && f !== 'E';
                return (
                  <li key={r.id} class={`reason reason--${def ? chipTone(def) : r.polarity}${lost ? ' is-lost' : ''}`}>
                    <span class="reason__icon">
                      <ToneIcon r={r} />
                    </span>
                    <div class="reason__body">
                      <p class="reason__label">{r.label}</p>
                      <p class="reason__meta">
                        <a class="reason__chip" href={`${href('explore')}?chip=${encodeURIComponent(r.id)}`} data-tip={def?.explain}>
                          {def?.short ?? r.id}
                        </a>
                        <span>{SOURCE_NAMES[r.source] ?? r.source}</span>
                        {r.at && <span>{fmtDate(r.at)}</span>}
                        {r.url && <ExtLink href={r.url}>evidence</ExtLink>}
                        {lost && <span class="reason__lost">counted 0: a stronger chip in this family won</span>}
                      </p>
                    </div>
                    {r.polarity !== 'info' && <span class="reason__pts mono">{signed(r.points)}</span>}
                  </li>
                );
              })}
            </ul>
          </section>
        );
      })}
      {d.unknowns.length > 0 && (
        <section class="family family--unknown" aria-label="Unknowns">
          <header class="family__head">
            <h3 class="family__title">Unknowns</h3>
          </header>
          <p class="family__blurb">Evidence we could not see. Missing data is shown, never imputed.</p>
          <ul class="reasons">
            {d.unknowns.map((u) => (
              <li key={u} class="reason reason--unknown">
                <span class="reason__icon">
                  <IconUnknown size={14} />
                </span>
                <div class="reason__body">
                  <p class="reason__label">{u}</p>
                </div>
              </li>
            ))}
          </ul>
        </section>
      )}
    </section>
  );
}

function Exploits({ d }: { d: CveDetail }) {
  const x = d.exploits;
  if (!x.metasploit.length && !x.nuclei.length && !x.exploitdb.length && !x.poc.count) return null;
  return (
    <section class="panel" aria-labelledby="xp-h">
      <header class="panel__head">
        <h2 id="xp-h" class="panel__title">
          Public exploit artifacts
        </h2>
      </header>
      <ul class="artifacts">
        {x.metasploit.map((m) => (
          <li key={m.fullname}>
            <span class="artifacts__kind">Metasploit</span>
            <ExtLink href={m.url}>
              <span class="mono">{m.fullname}</span>
            </ExtLink>
            <span class="muted">{m.rank !== null ? (MSF_RANK[m.rank] ?? m.rank) : ''}</span>
          </li>
        ))}
        {x.nuclei.map((n) => (
          <li key={n.path}>
            <span class="artifacts__kind">Nuclei</span>
            <ExtLink href={n.url}>
              <span class="mono">{n.path}</span>
            </ExtLink>
            <span class="muted">{n.severity ?? ''}</span>
          </li>
        ))}
        {x.exploitdb.map((e) => (
          <li key={e.id}>
            <span class="artifacts__kind">Exploit-DB</span>
            <ExtLink href={e.url}>
              <span class="mono">EDB-{e.id}</span>
            </ExtLink>
            <span class="muted">
              {e.verified ? 'verified' : 'unverified'}
              {e.date ? ` · ${fmtDate(e.date)}` : ''}
            </span>
          </li>
        ))}
      </ul>
      {x.poc.count > 0 && (
        <div class="poc">
          <p class="poc__warn">
            <IconAlert size={14} /> {x.poc.count} PoC repo{x.poc.count === 1 ? '' : 's'} on GitHub ({x.poc.vetted} vetted{x.poc.hype ? ', hype burst' : ''}). Unverified third-party code. Fake PoCs often carry malware. Never run them outside an
            isolated lab.
          </p>
          <ul class="artifacts">
            {x.poc.top.map((p) => (
              <li key={p.url}>
                <span class="artifacts__kind">GitHub</span>
                <ExtLink href={p.url}>
                  <span class="mono">{p.url.replace(/^https:\/\/github\.com\//, '')}</span>
                </ExtLink>
                <span class="muted">
                  <IconStar size={12} /> {p.stars} · {fmtDate(p.created)}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}

function Facts({ d }: { d: CveDetail }) {
  const now = useNow(60_000);
  const rows: [string, ComponentChildren][] = [
    ['CNA', cnaName(d.cna)],
    ['Published', `${fmtDateTime(d.published)} · ${fmtAge(d.published, now)} ago`],
  ];
  if (d.reserved) rows.push(['Reserved', fmtDate(d.reserved)]);
  if (d.updated) rows.push(['Updated', fmtDateTime(d.updated)]);
  if (d.cvss) {
    const metrics = d.cvss.vector.split('/').slice(1);
    rows.push([
      `CVSS ${d.cvss.version}`,
      <>
        <span class="mono">{d.cvss.score.toFixed(1)}</span> {d.cvss.severity?.toLowerCase()} · {d.cvss.source === 'cna' ? 'from the CNA' : 'from CISA-ADP'}
        <span class="vector">
          {metrics.map((m) => (
            <code key={m}>{m}</code>
          ))}
        </span>
      </>,
    ]);
  } else rows.push(['CVSS', <span class="muted">none published</span>]);
  if (d.cwe.length) {
    rows.push([
      'Weakness',
      <span class="list-inline">
        {d.cwe.map((c) => {
          const n = /^CWE-(\d+)$/.exec(c)?.[1];
          return n ? (
            <ExtLink key={c} href={`https://cwe.mitre.org/data/definitions/${n}.html`}>
              {c}
            </ExtLink>
          ) : (
            <span key={c}>{c}</span>
          );
        })}
      </span>,
    ]);
  }
  if (d.affected.length) {
    rows.push([
      'Affected',
      <ul class="affected">
        {d.affected.map((a, i) => (
          <li key={i}>
            {vendorProduct(a.vendor, a.product)}
            {a.purl && <code class="purl">{a.purl}</code>}
          </li>
        ))}
      </ul>,
    ]);
  }
  rows.push([
    'CISA SSVC',
    d.ssvc ? (
      <>
        exploitation <strong>{d.ssvc.exploitation}</strong> · automatable <strong>{d.ssvc.automatable}</strong> · impact <strong>{d.ssvc.technical_impact}</strong>
        {d.ssvc.timestamp && <span class="muted"> · {fmtDate(d.ssvc.timestamp)}</span>}
      </>
    ) : (
      <span class="muted">not assessed yet</span>
    ),
  ]);
  rows.push([
    'EPSS',
    d.epss ? (
      <>
        <span class="mono">{fmtPct(d.epss.score)}</span> · {Math.floor(d.epss.percentile * 100)}th percentile <span class="muted">· {d.epss.date} · {d.epss.model}</span>
      </>
    ) : (
      <span class="muted">not scored yet</span>
    ),
  ]);
  if (d.kev) {
    rows.push([
      'CISA KEV',
      <>
        added {fmtDate(d.kev.date_added)} · due <strong>{fmtDate(d.kev.due_date)}</strong> · ransomware {d.kev.ransomware.toLowerCase()}
        <KevFlags e={d.kev} />
        {d.kev.required_action && <span class="facts__note">{d.kev.required_action}</span>}
      </>,
    ]);
  }
  if (d.ai_credit) rows.push(['AI credit', <span class="ai">“{d.ai_credit}”</span>]);
  if (d.tags.length) rows.push(['CNA tags', d.tags.join(', ')]);
  if (d.batch) {
    rows.push([
      'Batch',
      <a href={href(`batches#${d.batch}`)}>
        <IconLayers size={12} /> {batchLabel(d.batch, d.cna)} <span class="muted">({batchKind(d.cna)})</span>
      </a>,
    ]);
  }
  return (
    <section class="panel" aria-labelledby="facts-h">
      <header class="panel__head">
        <h2 id="facts-h" class="panel__title">
          Facts
        </h2>
      </header>
      <dl class="facts">
        {rows.map(([k, v]) => (
          <div key={k} class="facts__row">
            <dt>{k}</dt>
            <dd>{v}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

function downloadJson(d: CveDetail) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(d, null, 2)], { type: 'application/json' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = `${d.id}.json`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function Detail({ d }: { d: CveDetail }) {
  const level = useStore(knob);
  const watch = useStore(watchlist);
  const tier = detailTier(d, level);
  const v = verdict(d, tier, level);
  const a = d.affected[0];
  const who = a ? vendorProduct(a.vendor, a.product) : '';
  const watchNames = [a?.vendor, a?.product].filter((n, i, all): n is string => !!n && !/^(unknown|n\/a)$/i.test(n) && all.findIndex((m) => m && normalizeName(m) === normalizeName(n)) === i);
  const page = absoluteUrl(cveHref(d.id));
  const summary = d.title ?? d.description.split(/(?<=\.)\s/)[0];
  const timeline = [...d.timeline].sort((x, y) => Date.parse(x.at) - Date.parse(y.at));

  return (
    <article class={`cve cve--${tier}`}>
      <header class="cve__head">
        <div class="cve__idline">
          <TierPill tier={tier} size="lg" />
          <h1 class="cve__id" tabIndex={-1}>
            {d.id}
          </h1>
          <button type="button" class="iconbtn" onClick={() => void copyLink(d.id, 'CVE ID')} aria-label="Copy the CVE ID" data-tip="Copy ID">
            <IconCopy size={14} />
          </button>
        </div>
        {who && <p class="cve__who">{who}</p>}
        <p class="cve__title">{summary}</p>
        <p class="cve__meta">
          Published {fmtDate(d.published)} by {cnaName(d.cna)}
          {d.batch && (
            <>
              {' '}
              · <a href={href(`batches#${d.batch}`)}>part of a {batchKind(d.cna)}</a>
            </>
          )}
        </p>
      </header>

      {d.woke && (
        <p class="cve__woke">
          <IconClock size={14} />
          <span>
            {wakeSentence(d.woke)}{' '}
            <a href={href('woke')}>Old CVEs that woke up</a>
          </span>
        </p>
      )}

      <div class={`verdict verdict--${tier}`} role="status">
        <TierIcon tier={tier} size={18} />
        <p class="verdict__text">
          <strong>{v.head}</strong>: {v.reason}
        </p>
        {tier === 'exploited' && d.kev && <Countdown due={d.kev.due_date} class="verdict__clock" />}
      </div>

      <div class="cve__grid">
        <div class="cve__main">
          <div class="cve__actions" role="group" aria-label="Actions">
            <button type="button" class="btn btn--primary" onClick={() => void copyTicket(d.id)} aria-keyshortcuts="c">
              <IconCopy size={14} /> Copy as ticket <kbd class="kbd kbd--on-accent">c</kbd>
            </button>
            <button type="button" class="btn" onClick={() => void copyLink(page)}>
              <IconLink size={14} /> Copy link
            </button>
            <button type="button" class="btn" onClick={() => downloadJson(d)}>
              <IconDownload size={14} /> JSON
            </button>
            <a class="btn" href={cveOrgUrl(d.id)} target="_blank" rel="noopener noreferrer nofollow">
              cve.org <IconExternal size={12} />
            </a>
            <a class="btn btn--ghost" href={feedbackIssueUrl(d, tier, level)} target="_blank" rel="noopener noreferrer nofollow">
              Disagree? <IconExternal size={12} />
            </a>
          </div>

          <Evidence d={d} />

          <section class="panel" aria-labelledby="desc-h">
            <header class="panel__head">
              <h2 id="desc-h" class="panel__title">
                Description
              </h2>
              <span class="panel__sub">from {cnaName(d.cna)}, shown as plain text</span>
            </header>
            <p class="prose">{d.description || 'No description.'}</p>
          </section>

          <Exploits d={d} />

          <section class="panel" aria-labelledby="tl-h">
            <header class="panel__head">
              <h2 id="tl-h" class="panel__title">
                Timeline
              </h2>
            </header>
            <ol class="timeline">
              {timeline.map((t, i) => (
                <li key={`${t.at}-${i}`} class={`timeline__item timeline__item--${t.source}`}>
                  <time dateTime={t.at}>{fmtDate(t.at)}</time>
                  <span class="timeline__event">{t.event}</span>
                  <span class="timeline__src">{SOURCE_NAMES[t.source] ?? t.source}</span>
                </li>
              ))}
            </ol>
          </section>

          {d.references.length > 0 && (
            <section class="panel" aria-labelledby="ref-h">
              <header class="panel__head">
                <h2 id="ref-h" class="panel__title">
                  References
                </h2>
                <span class="panel__sub">third-party links, unvetted</span>
              </header>
              <ul class="refs">
                {d.references.map((r) => (
                  <li key={r}>
                    <ExtLink href={r}>{r}</ExtLink>
                  </li>
                ))}
              </ul>
            </section>
          )}
        </div>

        <aside class="cve__side" aria-label="Score">
          <section class="panel scorecard">
            <ScoreDial score={d.score.value} tier={tier} knob={level} />
            <Ledger d={d} />
          </section>
          {watchNames.length > 0 && (
            <section class="panel" aria-label="Watchlist">
              <p class="panel__sub">Watched vendors and products always show on Today, whatever the evidence bar.</p>
              <div class="watchbtns">
                {watchNames.map((n) => {
                  const on = watch.includes(normalizeName(n));
                  return (
                    <button key={n} type="button" class={`btn btn--sm${on ? ' is-on' : ''}`} aria-pressed={on ? 'true' : 'false'} onClick={() => toggleWatch(n)} data-tip={n.length > 30 ? n : undefined}>
                      {on ? <IconEyeOff size={14} /> : <IconEye size={14} />}
                      <span class="watchbtns__name">
                        {on ? 'Unwatch' : 'Watch'} {n}
                      </span>
                    </button>
                  );
                })}
              </div>
            </section>
          )}
          <Facts d={d} />
        </aside>
      </div>
    </article>
  );
}

function OutsideWindow({ id }: { id: string }) {
  const raw = cveListUrl(id);
  return (
    <div class="notice">
      <EmptyState heading title={`${id} is outside the 30-day window`}>
        We keep every CVE published in the last 30 days, everything in CISA KEV, and old CVEs that <a href={href('woke')}>woke up</a> in the last 30 days (a CISA KEV listing, an EPSS jump, or their first
        public exploit). Other records are not scored here. That says nothing about whether they matter.
      </EmptyState>
      <div class="notice__links">
        <a class="btn" href={cveOrgUrl(id)} target="_blank" rel="noopener noreferrer nofollow">
          Record on cve.org <IconExternal size={12} />
        </a>
        {raw && (
          <a class="btn" href={raw} target="_blank" rel="noopener noreferrer nofollow">
            Raw CVE JSON <IconExternal size={12} />
          </a>
        )}
        <a class="btn btn--ghost" href={`${href('explore')}?q=${encodeURIComponent(id)}`}>
          Search Explore
        </a>
      </div>
    </div>
  );
}

export default function CvePage({ id }: { id: string }) {
  const norm = normalizeCveId(id);
  const detail = useData(norm ? data.detail(norm) : null);
  const meta = useData(data.meta);
  const level = useStore(knob);
  // Once the record is in, the title and description say what a link preview says, at this page's evidence bar.
  const d = detail.status === 'ready' ? detail.data : null;
  const tier = d ? detailTier(d, level) : null;
  useTitle(d && tier ? shareTitle(d, tier) : (norm ?? 'Not a CVE ID'));
  useMetaDescription(d && tier ? shareDescription(d, tier, level, meta.status === 'ready' ? meta.data.generated_at : null) : null);
  useEffect(() => {
    if (!norm) return;
    const copy = () => void copyTicket(norm);
    keyTargets.copy = copy;
    return () => {
      if (keyTargets.copy === copy) keyTargets.copy = null;
    };
  }, [norm]);

  return (
    <div class="page page--cve">
      <nav class="crumbs" aria-label="Breadcrumb">
        <a href={href('')}>
          <IconArrowLeft size={12} /> Today
        </a>
        <span aria-hidden="true">/</span>
        <span aria-current="page" class="mono">
          {norm ?? id}
        </span>
      </nav>
      {!norm ? (
        <EmptyState heading title="That doesn’t look like a CVE ID">
          CVE IDs look like CVE-2026-12345. {BRAND.name} covers the last 30 days, everything in CISA KEV and old CVEs that <a href={href('woke')}>woke up</a>.
        </EmptyState>
      ) : detail.status === 'ready' ? (
        detail.data ? (
          <Detail d={detail.data} />
        ) : (
          <OutsideWindow id={norm} />
        )
      ) : detail.status === 'error' ? (
        <ErrorState error={detail.error} onRetry={detail.retry} />
      ) : (
        <div class="cve-skel">
          <Loading label={`Loading ${norm}`} lines={2} height="36px" />
          <Loading label="" lines={6} height="20px" />
        </div>
      )}
    </div>
  );
}
