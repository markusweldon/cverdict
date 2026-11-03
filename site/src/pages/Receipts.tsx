/** Receipts: how often CVErdict flagged a CVE before CISA listed it in KEV, against two common rules. */
import { RECEIPT_METHODS, type BacktestItem, type BacktestReceipts, type BacktestSignal, type ForwardReceipts, type MethodScore, type ReceiptItem, type ReceiptMethod } from '../../../shared/contract';
import { REPO_URL } from '../../../shared/brand';
import { Fragment } from 'preact';
import { ExtLink } from '../components/ExtLink';
import { IconCode, IconTerminal } from '../components/icons';
import { CveRow } from '../components/Row';
import { EmptyState, ErrorState, Loading } from '../components/States';
import { DataError, data, DATA_BASE } from '../data';
import { tierAt } from '../filters';
import { fmtDate, fmtDateTime, fmtInt, plural, vendorProduct } from '../format';
import { useData, useKnobUrl, useNow, useTitle } from '../hooks';
import {
  backtestMark,
  countOf,
  filterBacktest,
  flagText,
  forwardHeadline,
  isBacktestFilter,
  isBefore,
  leadText,
  methodScore,
  METHOD_LABEL,
  METHOD_NOTE,
  MIN_N_FOR_PCT,
  type BacktestFilter,
} from '../receipts';
import { cveHref, href, setQuery, useLocation } from '../router';
import { knob, useStore } from '../state';

const SCRIPT_URL = `${REPO_URL}/blob/main/scripts/backtest.ts`;
const ENGINE_URL = `${REPO_URL}/blob/main/pipeline/src/backtest.ts`;
const LOG_URL = `${REPO_URL}/blob/main/pipeline/src/receipts.ts`;

function MethodName({ m }: { m: ReceiptMethod }) {
  return (
    <th scope="row">
      <span class="rcpt__method">{METHOD_LABEL[m]}</span>
      <span class="rcpt__note">{METHOD_NOTE[m]}</span>
    </th>
  );
}

function ForwardTable({ f }: { f: ForwardReceipts }) {
  return (
    <div class="tablewrap">
      <table class="table rcpt__table rcpt__stack">
        <caption class="sr-only">Each method on the KEV additions the live record counts</caption>
        <thead>
          <tr>
            <th scope="col">Method</th>
            <th scope="col" class="num">Flagged before KEV</th>
            <th scope="col" class="num">Of those, same day</th>
            <th scope="col" class="num">Median lead (quartiles)</th>
            <th scope="col" class="num">Alert volume</th>
          </tr>
        </thead>
        <tbody>
          {RECEIPT_METHODS.map((m) => {
            const s = methodScore(f.methods, m);
            const v = f.volume.find((x) => x.method === m);
            return (
              <tr key={m}>
                <MethodName m={m} />
                <td class="num" data-label="Flagged before KEV">
                  {s ? countOf(s.before, s.n) : '—'}
                </td>
                <td class="num" data-label="Of those, same day">
                  {s ? fmtInt(s.same_day) : '—'}
                </td>
                <td class="num" data-label="Median lead (quartiles)">
                  {s ? leadText(s.lead, s.before) : '—'}
                </td>
                <td class="num" data-label="Alert volume">
                  {v ? countOf(v.flagged, v.n) : '—'}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function Forward({ f }: { f: ForwardReceipts }) {
  const [first, second] = forwardHeadline(f);
  const older = f.uncounted.filter((u) => u.reason === 'older').length;
  const listedFirst = f.uncounted.filter((u) => u.reason === 'listed_first').length;
  const noRecord = f.uncounted.length - older - listedFirst;
  const notCounted = [
    older > 0 && (
      <>
        {plural(older, 'listing')} of CVEs older than our {f.watch_days}-day window (<a href={href('woke')}>Woke up</a> shows the recent ones)
      </>
    ),
    listedFirst > 0 && `${plural(listedFirst, 'CVE')} that CISA listed before we first saw ${listedFirst === 1 ? 'it' : 'them'}`,
    noRecord > 0 && `${plural(noRecord, 'CVE')} with no published record yet`,
  ].filter(Boolean);
  // Every gap since the start (the list keeps only the most recent ones).
  const gaps = f.gap_total ?? { n: f.gaps.length, hours: f.gaps.reduce((a, g) => a + (Date.parse(g.to) - Date.parse(g.from)) / 3_600_000, 0) };
  return (
    <section id="live" class="prose-section" aria-labelledby="live-title">
      <h2 class="section__title" id="live-title">
        The live record
      </h2>
      <p class="rcpt__headline">
        {first} {second && <strong>{second}</strong>}
      </p>
      {f.eligible < MIN_N_FOR_PCT && <p class="rcpt__young">The log is young, so this page shows counts only. Percentages appear once {MIN_N_FOR_PCT} listings are counted.</p>}
      <ForwardTable f={f} />
      <p class="muted">
        Logging since {fmtDateTime(f.since)}. {plural(f.runs, 'hourly run')} so far
        {gaps.n > 0 ? `, with ${plural(gaps.n, 'gap')} longer than 3 hours (${fmtInt(Math.round(gaps.hours))} hours in all)` : ', no gaps longer than 3 hours'}. Alert volume counts the{' '}
        {fmtInt(f.volume[0]?.n ?? 0)} CVEs watched so far.
      </p>
      {notCounted.length > 0 && (
        <p class="muted">
          Not counted above:{' '}
          {notCounted.map((part, i) => (
            <Fragment key={i}>
              {i > 0 && (i === notCounted.length - 1 ? ' and ' : ', ')}
              {part}
            </Fragment>
          ))}
          . All are in the list below.
        </p>
      )}
    </section>
  );
}

function HowMeasured({ watchDays }: { watchDays: number }) {
  return (
    <section id="how" class="prose-section" aria-labelledby="how-title">
      <h2 class="section__title" id="how-title">
        How this is measured
      </h2>
      <ul class="rcpt__rules">
        <li>Every hour, the pipeline notes when it first sees each new CVE, and when each method first flags it.</li>
        <li>
          <strong>CVErdict</strong> flags a CVE when it is Exploited or Likely next at the default knob. <strong>CVSS 7 or more</strong> flags it when the score the site shows reaches 7.0.{' '}
          <strong>EPSS 10% or more</strong> flags it when its EPSS score reaches 0.1.
        </li>
        <li>When CISA adds one of those CVEs to KEV, we compare. It counts as flagged before KEV when an earlier hourly run flagged it, on or before the KEV date. A flag that came with the listing does not count.</li>
        <li>
          Lead time is the KEV date minus the day of the first flag, in whole days. A flag on the listing day counts as 0 days and is shown apart: it can come from CISA's own update to the CVE
          record, made as it lists the CVE.
        </li>
        <li>We watch each CVE for its first {watchDays} days, while it is in the window. A flag after that does not count, for any method.</li>
        <li>Only CVEs we saw before the listing count. Older CVEs and CVEs listed before we saw them are left out, and listed below.</li>
        <li>Alert volume is the share of watched CVEs a method flagged at least once. Catching the same listings with fewer alerts means less work.</li>
        <li>The record starts with the first run that kept it. Nothing before that is filled in. Times are the hour of the run.</li>
      </ul>
      <p class="muted">
        <ExtLink href={LOG_URL}>Read the code that keeps the log</ExtLink>.
      </p>
    </section>
  );
}

function BacktestTable({ strict, upper, volume, label }: { strict: MethodScore[]; upper: MethodScore[]; volume: BacktestReceipts['volume'] | null; label: string }) {
  return (
    <div class="tablewrap">
      <table class="table rcpt__table rcpt__stack">
        <caption class="sr-only">{label}</caption>
        <thead>
          <tr>
            <th scope="col">Method</th>
            <th scope="col" class="num">Flagged before KEV</th>
            <th scope="col" class="num">With undated evidence</th>
            {volume && <th scope="col" class="num">Alert volume</th>}
          </tr>
        </thead>
        <tbody>
          {RECEIPT_METHODS.map((m) => {
            const s = methodScore(strict, m);
            const u = methodScore(upper, m);
            const v = volume?.methods.find((x) => x.method === m);
            return (
              <tr key={m}>
                <MethodName m={m} />
                <td class="num" data-label="Flagged before KEV">
                  {s ? countOf(s.before, s.n) : '—'}
                </td>
                <td class="num" data-label="With undated evidence">
                  {u ? countOf(u.before, u.n) : '—'}
                </td>
                {volume && (
                  <td class="num" data-label="Alert volume">
                    {v ? countOf(v.flagged, v.n) : '—'}
                  </td>
                )}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/** "38 CVEs were published on or after the listing day…", with the ids behind a toggle. */
function Excluded({ e }: { e: BacktestReceipts['excluded'][number] }) {
  const one = e.ids.length === 1;
  const text =
    e.code === 'not_public'
      ? `${plural(e.ids.length, 'CVE')} ${one ? 'was' : 'were'} published on or after the listing day, so no method could have flagged ${one ? 'it' : 'them'} first.`
      : e.code === 'no_record'
        ? `${plural(e.ids.length, 'CVE')} ${one ? 'has' : 'have'} no published CVE record.`
        : `${plural(e.ids.length, 'CVE')}: ${e.reason}.`;
  return (
    <details class="rcpt__excluded">
      <summary>{text}</summary>
      <span class="rcpt__ids">
        {e.ids.map((id) => (
          <a key={id} href={cveHref(id)} class="mono">
            {id}
          </a>
        ))}
      </span>
    </details>
  );
}

function Backtest({ b }: { b: BacktestReceipts }) {
  const recent = b.sets.find((s) => s.key === 'recent');
  const old = b.sets.find((s) => s.key === 'old');
  const judged = b.items.length;
  const hits = b.items.filter((i) => i.strict.cverdict);
  const viaSsvc = hits.filter((i) => i.chips.includes('ssvc.active')).length;
  const ssvcOut = b.items.filter((i) => i.left_out.includes('ssvc') || i.left_out.includes('ssvc_exploitation')).length;
  const hindsight = b.signals.filter((s) => s.treatment === 'hindsight');
  const excluded = b.signals.filter((s) => s.treatment === 'excluded');
  const matched = b.signals.filter((s) => s.treatment === 'time_matched');
  const asToday = b.signals.filter((s) => s.treatment === 'today');
  return (
    <section id="backtest" class="prose-section rcpt__back" aria-labelledby="backtest-title">
      <h2 class="section__title" id="backtest-title">
        Backtest <span class="rcpt__hindsight">Hindsight</span>
      </h2>
      <p class="rcpt__warn">
        This part is not a real-time record. It was rebuilt after the fact, so treat it as an estimate. The live record above is the one that counts.
      </p>
      <p>
        CISA added {plural(b.listed, 'CVE')} to KEV from {fmtDate(b.from, Number.NaN)} to {fmtDate(b.to, Number.NaN)}. We scored {fmtInt(judged)} of them again, with the evidence from the day
        before each listing, wherever the source says when its evidence appeared.
      </p>
      {recent && (
        <>
          <h3 class="rcpt__sub">
            Published up to {b.old_years} years before the listing <span class="muted">{plural(recent.n, 'CVE')}</span>
          </h3>
          <BacktestTable strict={recent.strict} upper={recent.upper} volume={b.volume} label="Backtest, hindsight: each method on recent CVEs that CISA added to KEV" />
        </>
      )}
      {old && old.n > 0 && (
        <>
          <h3 class="rcpt__sub">
            Published more than {b.old_years} years before the listing <span class="muted">{plural(old.n, 'CVE')}</span>
          </h3>
          <BacktestTable strict={old.strict} upper={old.upper} volume={null} label="Backtest, hindsight: each method on old CVEs that CISA added to KEV" />
        </>
      )}
      {b.volume && (
        <p class="muted">
          Alert volume: of the {fmtInt(b.volume.n)} CVEs published since {fmtDate(b.volume.from, Number.NaN)}, how many each method flags with today's evidence.
        </p>
      )}
      <h3 class="rcpt__sub">What to keep in mind</h3>
      <ul class="rcpt__rules">
        <li>
          “Flagged before KEV” uses only evidence dated before the listing day, plus the vendor, product and description as they read today. Evidence without a usable date is left out and
          treated as unknown, never as absent. “With undated evidence” adds what
          that evidence says today, as if it had all been there already. Most of it is exploits, so this is usually the higher figure. The truth is likely between the two.
        </li>
        {ssvcOut > 0 && (
          <li>
            For {plural(ssvcOut, 'CVE')}, “flagged before KEV” leaves out CISA's own SSVC view of exploitation. CISA updates it when it lists a CVE, and often dates it the day before, so it cannot show
            what CISA said before the listing.
          </li>
        )}
        {viaSsvc > 0 && (
          <li>
            Of the {fmtInt(hits.length)} CVEs CVErdict flagged first (both groups), {fmtInt(viaSsvc)} were flagged because CISA's own SSVC assessment said exploitation was active before the KEV listing. That
            is public and dated, but it is CISA's view.
          </li>
        )}
        <li>Alert volume uses today's evidence, so it is hindsight too. It shows how many CVEs each rule would ask you to patch.</li>
        <li>The backtest only says yes or no. It does not measure lead time: that needs the hour each method first flagged a CVE, which only the live record has.</li>
        <li>
          Left out of every figure: {b.excluded.length === 0 ? 'nothing.' : b.excluded.map((e) => <Excluded key={e.code} e={e} />)}
          {b.epss_missing.length > 0 &&
            ` EPSS files could not be loaded for ${plural(b.epss_missing.length, 'day')}. For those CVEs, CVErdict treats EPSS as unknown and “EPSS 10% or more” counts them as not flagged. The backtest tries again the next day.`}
        </li>
        <li>
          Computed {fmtDateTime(b.computed_at)} and refreshed about once a week. Run it yourself with <code>npm run backtest</code>: <ExtLink href={SCRIPT_URL}>scripts/backtest.ts</ExtLink>, which runs{' '}
          <ExtLink href={ENGINE_URL}>the backtest code</ExtLink>.
        </li>
      </ul>
      <h3 class="rcpt__sub">Which evidence was used</h3>
      <div class="tablewrap">
        <table class="table table--compact rcpt__signals rcpt__stack">
          <caption class="sr-only">How the backtest used each kind of evidence</caption>
          <thead>
            <tr>
              <th scope="col">Evidence</th>
              <th scope="col">How it was used</th>
              <th scope="col" class="num">Left out for</th>
            </tr>
          </thead>
          <tbody>
            {[...matched, ...hindsight, ...asToday, ...excluded].map((s) => (
              <tr key={s.key}>
                <th scope="row">{s.label}</th>
                <td data-label="How it was used">
                  <span class={`rcpt__use rcpt__use--${s.treatment}`}>{USE_LABEL[s.treatment] ?? s.treatment}</span> {s.note}
                </td>
                <td class="num" data-label="Left out for">
                  {s.treatment === 'today' || s.affected === 0 ? '—' : s.affected >= judged ? 'all' : plural(s.affected, 'CVE')}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function ForwardList({ items, level, now }: { items: ReceiptItem[]; level: number; now: number }) {
  if (items.length === 0) return <EmptyState title="No listings to judge yet">When CISA adds a CVE we have already seen to KEV, it shows up here with each method's result, hit or miss.</EmptyState>;
  return (
    <div class="rows">
      {items.map((it) => {
        const note = (
          <ul class="rcpt__flags" aria-label="Each method">
            <li>
              <span class="muted">Added to KEV</span> {fmtDate(it.kev_added)}
            </li>
            {RECEIPT_METHODS.map((m) => (
              <li key={m} class={isBefore(it.flags[m]) ? 'rcpt__flag--hit' : 'rcpt__flag--miss'}>
                <span class="muted">{METHOD_LABEL[m]}:</span> {flagText(it.flags[m])}
              </li>
            ))}
          </ul>
        );
        return it.row ? (
          <CveRow key={it.id} row={it.row} tier={tierAt(it.row, level)} knob={level} now={now} note={note} />
        ) : (
          <div key={it.id} class="rcpt__bare">
            <a href={cveHref(it.id)} class="mono">
              {it.id}
            </a>
            {note}
          </div>
        );
      })}
    </div>
  );
}

const MARK_TEXT = { yes: 'Yes', upper: 'Only with undated evidence', no: 'No' } as const;
const USE_LABEL: Readonly<Record<BacktestSignal['treatment'], string>> = { time_matched: 'Dated', hindsight: 'Not always dated', today: 'As it is today', excluded: 'Never used' };

function BacktestList({ items, filter }: { items: BacktestItem[]; filter: BacktestFilter }) {
  const shown = filterBacktest(items, filter);
  const hits = items.filter((i) => i.strict.cverdict).length;
  return (
    <>
      <div class="wokefilter" role="group" aria-label="Show">
        <div class="seg">
          {(
            [
              ['all', 'All', items.length],
              ['hit', 'CVErdict flagged first', hits],
              ['miss', 'CVErdict missed', items.length - hits],
            ] as const
          ).map(([key, label, count]) => (
            <button key={key} type="button" class="seg__btn" aria-pressed={filter === key ? 'true' : 'false'} onClick={() => setQuery({ bt: key === 'all' ? null : key })}>
              {label} <span class="seg__count">{fmtInt(count)}</span>
            </button>
          ))}
        </div>
      </div>
      <div class="tablewrap">
        <table class="table table--compact rcpt__cves rcpt__stack">
          <caption class="sr-only">Backtest result per CVE (hindsight)</caption>
          <thead>
            <tr>
              <th scope="col">CVE</th>
              <th scope="col">Added to KEV</th>
              {RECEIPT_METHODS.map((m) => (
                <th key={m} scope="col">
                  {METHOD_LABEL[m]}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {shown.map((i) => (
              <tr key={i.id}>
                <th scope="row">
                  <a href={cveHref(i.id)} class="mono">
                    {i.id}
                  </a>
                  {i.row && (i.row.v || i.row.p) && <span class="rcpt__who">{vendorProduct(i.row.v, i.row.p)}</span>}
                  {i.old && <span class="rcpt__old">published {fmtDate(i.published, Number.NaN)}</span>}
                </th>
                <td class="mono" data-label="Added to KEV">
                  {fmtDate(i.kev_added, Number.NaN)}
                </td>
                {RECEIPT_METHODS.map((m) => {
                  const mark = backtestMark(i, m);
                  return (
                    <td key={m} data-label={METHOD_LABEL[m]}>
                      <span class={`rcpt__mark rcpt__mark--${mark}`}>{MARK_TEXT[mark]}</span>
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

export default function Receipts() {
  useTitle('Receipts');
  useKnobUrl();
  const level = useStore(knob);
  const now = useNow(60_000);
  const loc = useLocation();
  const receipts = useData(data.receipts);
  const btParam = loc.search.get('bt');
  const filter: BacktestFilter = isBacktestFilter(btParam) ? btParam : 'all';
  const json = new URL(`${DATA_BASE}receipts.json`, window.location.origin).href;
  const r = receipts.status === 'ready' ? receipts.data : null;

  return (
    <div class="page page--receipts">
      <header class="page__head">
        <p class="eyebrow">Checked against CISA KEV</p>
        <h1 class="page__title" tabIndex={-1}>
          Receipts
        </h1>
        <p class="page__lede">
          How often CVErdict flagged a CVE before CISA confirmed it as exploited, next to two common rules: patch everything with a CVSS score of 7 or more, and patch everything with an EPSS score of 10% or
          more. The misses are listed too.
        </p>
        <nav class="toc" aria-label="On this page">
          <a href="#live">The live record</a>
          <a href="#how">How this is measured</a>
          <a href="#backtest">Backtest (hindsight)</a>
          <a href="#cves">Every CVE</a>
        </nav>
        <div class="page__actions">
          <a class="btn btn--ghost" href={json} target="_blank" rel="noopener noreferrer">
            <IconCode size={14} /> JSON
          </a>
          <a class="btn btn--ghost" href={SCRIPT_URL} target="_blank" rel="noopener noreferrer">
            <IconTerminal size={14} /> Backtest script
          </a>
        </div>
      </header>

      {receipts.status === 'error' ? (
        receipts.error instanceof DataError && receipts.error.status === 404 ? (
          <EmptyState title="Not published yet">The first pipeline run with this page has not finished. Check back after the next hourly run.</EmptyState>
        ) : (
          <ErrorState error={receipts.error} onRetry={receipts.retry} />
        )
      ) : !r ? (
        <Loading label="Loading the receipts" lines={6} height="56px" />
      ) : (
        <>
          <Forward f={r.forward} />
          <HowMeasured watchDays={r.forward.watch_days} />
          {r.backtest ? (
            <Backtest b={r.backtest} />
          ) : (
            <section id="backtest" class="prose-section">
              <h2 class="section__title">
                Backtest <span class="rcpt__hindsight">Hindsight</span>
              </h2>
              <p class="muted">The backtest has not run yet. It runs about once a week.</p>
            </section>
          )}
          <section id="cves" class="prose-section" aria-labelledby="cves-title">
            <h2 class="section__title" id="cves-title">
              Every CVE
            </h2>
            <h3 class="rcpt__sub">
              Live record <span class="muted">{plural(r.forward.items.length, 'CVE')}</span>
            </h3>
            <ForwardList items={r.forward.items} level={level} now={now} />
            {r.forward.uncounted.length > 0 && (
              <>
                <h3 class="rcpt__sub">
                  Listed since {fmtDate(r.forward.since, Number.NaN)} but not counted <span class="muted">{plural(r.forward.uncounted.length, 'CVE')}</span>
                </h3>
                <div class="tablewrap">
                  <table class="table table--compact">
                    <caption class="sr-only">KEV additions since the log started that it does not count, and why</caption>
                    <thead>
                      <tr>
                        <th scope="col">CVE</th>
                        <th scope="col">Added to KEV</th>
                        <th scope="col">Why not counted</th>
                      </tr>
                    </thead>
                    <tbody>
                      {r.forward.uncounted.map((u) => (
                        <tr key={u.id}>
                          <th scope="row">
                            <a href={cveHref(u.id)} class="mono">
                              {u.id}
                            </a>
                          </th>
                          <td class="mono">{fmtDate(u.kev_added, Number.NaN)}</td>
                          <td>{u.reason === 'older' ? `Older than our ${r.forward.watch_days}-day window` : u.reason === 'listed_first' ? 'Listed before we first saw it' : 'No published CVE record yet'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            )}
            {r.backtest && (
              <>
                <h3 class="rcpt__sub">
                  Backtest <span class="rcpt__hindsight">Hindsight</span> <span class="muted">{plural(r.backtest.items.length, 'CVE')}</span>
                </h3>
                <p class="muted">
                  “Yes” means flagged with evidence dated before the listing. “Only with undated evidence” means flagged only once today's evidence without a usable date is added.
                </p>
                <BacktestList items={r.backtest.items} filter={filter} />
              </>
            )}
          </section>
        </>
      )}
    </div>
  );
}
