/** Today: the noise meter, evidence bar, waterfall, signal feed, batches, KEV Clock and what changed. */
import { Fragment } from 'preact';
import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { KNOB_DEFAULT, SIGNAL_MIN_SCORE, type Batch, type Meta, type Row, type Tier } from '../../../shared/contract';
import { copyTicket, watchVendorOf } from '../actions';
import { BatchCard } from '../components/BatchCard';
import { Changes } from '../components/Changes';
import { freshness } from '../components/Chrome';
import { FilterBar } from '../components/FilterBar';
import { IconArrowRight, IconLayers } from '../components/icons';
import { kevUrgency, KevStrip } from '../components/Kev';
import { Knob } from '../components/Knob';
import { CveRow } from '../components/Row';
import { EmptyState, ErrorState, Loading } from '../components/States';
import { TierBar, TierIcon } from '../components/Tier';
import { Waterfall, type Annotation } from '../components/Waterfall';
import { WokeCard } from '../components/WokeCard';
import { data } from '../data';
import { exploreDayHref } from '../drill';
import {
  batchCounts,
  byScore,
  countTiers,
  DEFAULT_FEED_FILTER,
  emptyCounts,
  FEED_PARAMS,
  feedFilterQuery,
  feedRows,
  groupByBatch,
  hasChip,
  hourlyAt,
  isPassed,
  pubMs,
  readFeedFilter,
  retier,
  tierAt,
  type FeedFilter,
  type TierCounts,
} from '../filters';
import { cnaName, DAY_MS, fmtAge, fmtDate, fmtInt, fmtPct, fmtSlot, HOUR_MS, oneIn, plural } from '../format';
import { prefersReducedMotion, useCountUp, useData, useDebounced, useKnobUrl, useListController, useMediaQuery, useNow, useTitle } from '../hooks';
import { cveHref, historyValue, href, navigate, setHistoryValue, setQuery, useLocation } from '../router';
import { backtestAt } from '../receipts';
import { KNOB_PRESETS, knob, previousVisit, SITE_KNOB_MAX, SITE_KNOB_MIN, useStore, watchlist } from '../state';
import { TIER_META } from '../tiers';

const PAGE = 40;

/** Count-up number; mono digits with tightened thousands separators. */
function CountUp({ value, class: cls }: { value: number; class?: string }) {
  const shown = useCountUp(value);
  const digits = fmtInt(shown)
    .split(',')
    .map((p, i) => (
      <Fragment key={i}>
        {i > 0 && <span class="hero__comma">,</span>}
        {p}
      </Fragment>
    ));
  if (shown === value) return <span class={cls}>{digits}</span>;
  // Mid count, assistive tech gets the real number: the hero heading takes focus on arrival and
  // would otherwise be announced as "0 new CVEs published".
  return (
    <span class={cls}>
      <span aria-hidden="true">{digits}</span>
      <span class="sr-only">{fmtInt(value)}</span>
    </span>
  );
}

function Ticker({ meta, passed24h, kevSoon, batchesWeek }: { meta: Meta; passed24h: number; kevSoon: number | null; batchesWeek: number | null }) {
  const now = useNow(30_000);
  const state = freshness(meta, now);
  const items: { label: string; value: string; tone?: string; to?: string; tip: string }[] = [
    { label: 'Published 24h', value: fmtInt(meta.counts.published_24h), tip: meta.definitions.published_24h ?? '' },
    { label: 'Passed 24h', value: fmtInt(passed24h), tone: passed24h ? 'lit' : undefined, tip: 'Published in the last 24 hours and Exploited or Likely at the current evidence bar. Most CVEs clear the bar days after they are published.' },
    { label: 'KEV due ≤ 72h', value: kevSoon === null ? '…' : fmtInt(kevSoon), tone: kevSoon ? 'warn' : undefined, to: 'kev', tip: 'CISA KEV deadlines in the next three days' },
    { label: 'Batches this week', value: batchesWeek === null ? '…' : fmtInt(batchesWeek), to: 'batches', tip: 'Patch-day cohorts (50+ CVEs from one CNA in a day) in the last 7 days' },
    { label: 'Data age', value: fmtAge(meta.generated_at, now), tone: state === 'fresh' ? 'ok' : state === 'late' ? 'warn' : 'bad', to: 'method#sources', tip: 'Time since the last hourly pipeline run' },
  ];
  return (
    <ul class="ticker" aria-label="At a glance">
      {items.map((it) => {
        const body = (
          <>
            <span class="ticker__label">{it.label}</span>
            <span class={`ticker__value${it.tone ? ` is-${it.tone}` : ''}`}>{it.value}</span>
          </>
        );
        return (
          <li key={it.label} class="ticker__item" data-tip={it.tip}>
            {it.to ? (
              <a class="ticker__link" href={href(it.to)}>
                {body}
              </a>
            ) : (
              body
            )}
          </li>
        );
      })}
    </ul>
  );
}

function Hero({ meta, counts, level }: { meta: Meta; counts: TierCounts; level: number }) {
  const total = meta.counts.window_published;
  const passed = counts.exploited + counts.likely;
  return (
    <section class="hero" aria-labelledby="hero-h">
      <p class="eyebrow">
        Last {meta.window.days} days · {fmtDate(meta.window.from)} – {fmtDate(meta.window.to)}
      </p>
      <h1 class="hero__line" id="hero-h" tabIndex={-1}>
        <a class="hero__group hero__link" href={href('surge')} aria-label={`${fmtInt(total)} new CVEs published. See The Surge.`}>
          <CountUp class="hero__noise" value={total} />
          <span class="hero__unit">new CVEs published</span>
        </a>
        <span class="hero__arrow" aria-label="of which">
          →
        </span>
        <span class="hero__group">
          <CountUp class="hero__signal" value={passed} />
          <span class="hero__unit">worth your time</span>
        </span>
      </h1>
      <p class="hero__sub">
        <strong>{fmtPct(passed / Math.max(1, total))}</strong> of the flood · <strong>{oneIn(passed, total)}</strong> · evidence bar at <span class="mono">{level}</span>
      </p>
      <TierBar counts={counts} total={total} />
      <ul class="legend" aria-label="By tier">
        {(['exploited', 'likely', 'watch', 'quiet'] as const).map((t) => (
          <li key={t} class={`legend__item legend__item--${t}`} data-tip={TIER_META[t].blurb}>
            <TierIcon tier={t} size={12} />
            <span>{TIER_META[t].label}</span>
            <span class="legend__num">{fmtInt(counts[t])}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}

/** Average CVEs a day, rounded: "about 10 a day", "about 4 a day", or "under 1 a day". Null while the count is not known yet. */
function perDay(passed: number | null, days: number): { about: string; n: string } | null {
  if (passed === null) return null;
  const n = passed / Math.max(1, days);
  return n < 1 ? { about: 'under', n: '1' } : { about: 'about', n: fmtInt(Math.round(n)) };
}

/** Screen reader value for the dial: "50 of 100, about 11 CVEs a day pass", "under 1 CVE a day passes", or "counting". */
function dialText(level: number, day: { about: string; n: string } | null): string {
  if (!day) return `${level} of 100, counting`;
  return day.about === 'under' ? `${level} of 100, under 1 CVE a day passes` : `${level} of 100, about ${day.n} CVEs a day pass`;
}
const cap = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

/** "about 4 CVEs a day", "under 1 CVE a day", or null while not counted. */
const dayWords = (day: { about: string; n: string } | null): string | null => (day ? `${day.about} ${day.n} ${day.about === 'under' ? 'CVE' : 'CVEs'} a day` : null);

function PresetCount({ day }: { day: { about: string; n: string } | null }) {
  // Not counted yet: an empty line of the same height, so the buttons do not change size when counts arrive.
  if (!day) return <span class="seg__count" aria-hidden="true">{'\u00a0'}</span>;
  return (
    <span class="seg__count" aria-hidden="true">
      {/* Phones drop "about" to fit; "under" stays. */}
      <span class={day.about === 'about' ? 'seg__about' : undefined}>{day.about} </span>
      {day.n} a day
    </span>
  );
}

/**
 * The backtest at the current bar: "Flagged 40 of 125 recent KEV additions before CISA did."
 * `undefined` while receipts.json loads and `null` when it failed or has no backtest: both keep an
 * empty line of the same height, so nothing below moves once the file settles (it shows on phones,
 * where the panel does not stretch to the hero).
 */
function TrackRecord({ level, track }: { level: number; track: { flagged: number; n: number } | null | undefined }) {
  if (!track) return <p class="knobpanel__track" aria-hidden="true">{'\u00a0'}</p>;
  return (
    <p class="knobpanel__track">
      <a
        href={href('receipts#backtest')}
        data-tip={`Backtest, in hindsight: recent CVEs that CISA added to KEV, scored with the evidence from the day before each listing, at evidence bar ${level}`}
      >
        Flagged {fmtInt(track.flagged)} of {fmtInt(track.n)} recent KEV additions before CISA did.
      </a>
    </p>
  );
}

function KnobPanel({
  level,
  passed,
  days,
  presetPassed,
  track,
}: {
  level: number;
  passed: number | null;
  days: number;
  presetPassed: (value: number) => number | null;
  track: { flagged: number; n: number } | null | undefined;
}) {
  const day = perDay(passed, days);
  // The full-size dial fits beside the hero (two columns from 1,181 px); stacked and on phones it stays compact.
  const wide = useMediaQuery('(min-width: 1181px)');
  return (
    <section class="knobpanel" aria-label="Evidence bar">
      <Knob
        value={level}
        min={SITE_KNOB_MIN}
        max={SITE_KNOB_MAX}
        defaultValue={KNOB_DEFAULT}
        marks={KNOB_PRESETS.map((p) => p.value)}
        onChange={(v) => knob.set(v)}
        size={wide ? 136 : 122}
        label="Evidence bar"
        valueText={dialText(level, day)}
      />
      <div class="knobpanel__body">
        <div>
          <p class="eyebrow">Evidence bar</p>
          <p class="knobpanel__desc">Minimum score (out of 100) to flag a CVE as likely exploited next.</p>
        </div>
        {day && passed !== null ? (
          <p class="knobpanel__read">
            <span class={day.about === 'about' ? 'knobpanel__about' : undefined}>{cap(day.about)} </span>
            <span class="knobpanel__num">{day.n}</span> {day.about === 'under' ? 'CVE' : 'CVEs'} a day
            <span class="sr-only">, </span>
            <span class="knobpanel__pct">
              <span class="mono">{fmtInt(passed)}</span> in {days} days
            </span>
          </p>
        ) : (
          // Same lines as the readout, so nothing jumps when the count arrives.
          <p class="knobpanel__read">
            <span class="knobpanel__num">…</span>
            <span class="knobpanel__pct">Counting</span>
          </p>
        )}
      </div>
      <p class="knobpanel__hint">Raise it for a shorter list with stronger evidence. Exploited CVEs and those with a Metasploit module or Nuclei template always show.</p>
      <div class="seg seg--presets" role="group" aria-label={`Evidence bar presets: ${KNOB_PRESETS.map((p) => p.label).join(', ')}`}>
        {KNOB_PRESETS.map((p) => {
          const pd = perDay(presetPassed(p.value), days);
          const words = dayWords(pd);
          return (
            <button
              key={p.value}
              type="button"
              class="seg__btn"
              aria-pressed={level === p.value ? 'true' : 'false'}
              aria-label={`${p.label}, ${words ? `${words}, ` : ''}evidence bar at ${p.value}`}
              onClick={() => knob.set(p.value)}
              data-tip={`${p.label}: evidence bar at ${p.value}`}
            >
              <span class="seg__label">{p.label}</span>
              <PresetCount day={pd} />
            </button>
          );
        })}
      </div>
      <TrackRecord level={level} track={track} />
    </section>
  );
}

/** Largest patch days, merged per date: "Oracle 1,076 + Chrome 353". */
function annotationsFor(batches: readonly Batch[], hourly: { start: string; counts: readonly number[][] }): Annotation[] {
  const byDate = new Map<string, Batch[]>();
  for (const b of batches) byDate.set(b.date, [...(byDate.get(b.date) ?? []), b]);
  const start = Date.parse(hourly.start);
  return [...byDate.entries()]
    .map(([date, list]) => ({ date, list: list.sort((a, b) => b.count - a.count), total: list.reduce((a, b) => a + b.count, 0) }))
    .sort((a, b) => b.total - a.total)
    .slice(0, 4)
    .map(({ date, list }) => {
      const day = Date.parse(`${date}T00:00:00Z`);
      let peak = day + 12 * HOUR_MS;
      let best = -1;
      for (let h = 0; h < 24; h++) {
        const i = Math.floor((day + h * HOUR_MS - start) / HOUR_MS);
        const c = hourly.counts[i];
        if (!c) continue;
        const sum = c[0] + c[1] + c[2] + c[3];
        if (sum > best) {
          best = sum;
          peak = day + h * HOUR_MS;
        }
      }
      const named = list.filter((b) => b.count >= 300).slice(0, 2);
      // Each name links to its card on /batches (the card's id is the batch id).
      return { at: peak, parts: (named.length ? named : list.slice(0, 1)).map((b) => ({ text: `${cnaName(b.cna)} ${fmtInt(b.count)}`, href: href(`batches#${b.id}`) })) };
    });
}

export default function Today() {
  useTitle(null);
  useKnobUrl();
  const level = useStore(knob);
  const watch = useStore(watchlist);
  const loc = useLocation();
  // The feed filter lives in the URL so Back from a CVE restores it; the search box writes it debounced.
  const filterKey = FEED_PARAMS.map((k) => loc.search.get(k) ?? '').join('|');
  const filter = useMemo(() => readFeedFilter(loc.search), [filterKey]);
  const [q, setQ] = useState(filter.query);
  const debounced = useDebounced(q, 180);
  useEffect(() => setQuery({ q: debounced.trim() || null }), [debounced]);
  useEffect(() => {
    if (filter.query !== debounced.trim()) setQ(filter.query);
  }, [filter.query]);
  const setFilter = (next: FeedFilter) => {
    if (next.query !== q) setQ(next.query);
    const { q: _typed, ...rest } = feedFilterQuery(next);
    setQuery(rest);
  };

  const meta = useData(data.meta);
  const signal = useData(data.signal);
  const stats = useData(data.stats);
  const batches = useData(data.batches);
  const kev = useData(data.kev);
  const changes = useData(data.changes);
  // Every row is needed below the signal floor (scores under 35 are not in signal.json), for the Watch tier
  // (scores 25–34) and for watched quiet CVEs.
  const needIndex = level < SIGNAL_MIN_SCORE || watch.length > 0 || filter.tiers.has('watch');
  const index = useData(needIndex && signal.status === 'ready' ? data.index : null);
  const complete = index.status === 'ready';
  const rows: readonly Row[] = complete ? index.data : signal.status === 'ready' ? signal.data : [];
  const now = useNow(60_000);

  // "Show more" survives a trip to a CVE and back, so the restored scroll position still exists.
  const [limit, setLimit] = useState(() => {
    const saved = historyValue('feedLimit');
    return typeof saved === 'number' && saved > PAGE ? saved : PAGE;
  });
  useEffect(() => setHistoryValue('feedLimit', limit), [limit]);
  const [sel, setSel] = useState(-1);
  // Each waterfall column covers 1+ hours depending on its width: the caption says which.
  const [binHours, setBinHours] = useState(1);
  const slot = fmtSlot(binHours);

  const counts = useMemo<TierCounts | null>(() => {
    if (meta.status !== 'ready' || rows.length === 0) return null;
    return complete ? countTiers(rows, level) : retier(meta.data.counts.window_by_tier, rows, level);
  }, [meta.status, rows, level, complete]);

  // What each preset would pass, for the per-day counts on the preset buttons.
  const presetCounts = useMemo(() => {
    const out = new Map<number, number>();
    if (meta.status !== 'ready' || rows.length === 0) return out;
    for (const p of KNOB_PRESETS) {
      const c = complete ? countTiers(rows, p.value) : retier(meta.data.counts.window_by_tier, rows, p.value);
      out.set(p.value, c.exploited + c.likely);
    }
    return out;
  }, [meta.status, rows, complete]);
  const presetPassed = (v: number) => presetCounts.get(v) ?? null;
  // The track-record line: receipts.json (about 150 kB, 23 kB gzipped) loads once the signal is in,
  // so it never competes with the rest of Today. Missing or without a backtest: the line hides.
  const receipts = useData(signal.status === 'ready' ? data.receipts : null);
  const track = useMemo(
    () => {
      if (receipts.status === 'error') return null;
      if (receipts.status !== 'ready') return undefined;
      // A side line must never break the evidence bar: any surprise in the file hides it.
      try {
        return backtestAt(receipts.data?.backtest, level);
      } catch {
        return null;
      }
    },
    [receipts, level],
  );

  const feed = useMemo(() => feedRows(rows, filter, level, watch).sort(byScore), [rows, filter, level, watch]);
  // Tier toggle counts: everything the other filters let through, whatever the toggles say.
  const feedCounts = useMemo(() => {
    const c = emptyCounts();
    for (const fr of feedRows(rows, { ...filter, tiers: new Set<Tier>(['exploited', 'likely', 'watch']), watchOnly: false }, level, [])) c[fr.tier]++;
    return c;
  }, [rows, filter, level]);
  // Without every row, the Watch toggle can only count scores ≥ 35. Unfiltered, the hero's count is
  // exact; filtered, it is unknown until the index arrives.
  const narrowed = filter.query.trim() !== '' || filter.hideWordpress || filter.hideKernel || filter.hideAi || filter.chip !== null;
  const toggleCounts = complete || !counts ? feedCounts : { ...feedCounts, watch: narrowed ? null : counts.watch };
  const visible = feed.slice(0, limit);

  // Keyboard moves focus the row; hover and tab only mark it. Selecting prefetches the shard so
  // "c" (copy as ticket) can write to the clipboard without waiting. selRef is the latest
  // selection, updated synchronously: several key presses can land before a render.
  const focusNext = useRef(false);
  const selRef = useRef(-1);
  const selected = useRef<string | null>(null);
  const select = (i: number) => {
    selRef.current = i;
    selected.current = feed[i]?.row.id ?? null;
    setSel(i);
  };
  // A new filter or bar starts the list over (but remounting on Back keeps the restored limit).
  const shape = useRef({ filterKey, level });
  useEffect(() => {
    if (shape.current.filterKey !== filterKey) select(-1);
    if (shape.current.filterKey !== filterKey || shape.current.level !== level) setLimit(PAGE);
    shape.current = { filterKey, level };
  }, [filterKey, level]);

  const hourly = useMemo(() => (stats.status === 'ready' && rows.length > 0 ? hourlyAt(stats.data.hourly, rows, level, complete) : []), [stats, rows, level, complete]);
  const annotations = useMemo(() => (stats.status === 'ready' && batches.status === 'ready' ? annotationsFor(batches.data.batches, stats.data.hourly) : []), [stats, batches]);
  const batchMembers = useMemo(() => groupByBatch(rows), [rows]);

  const generated = meta.status === 'ready' ? Date.parse(meta.data.generated_at) : now;
  const passed24h = useMemo(() => rows.filter((r) => pubMs(r) >= generated - DAY_MS && isPassed(tierAt(r, level))).length, [rows, level, generated]);
  const kevSoon = kev.status === 'ready' ? kev.data.entries.filter((e) => kevUrgency(e, now) === 'soon').length : null;
  const weekBatches = batches.status === 'ready' ? batches.data.batches.filter((b) => Date.parse(`${b.date}T00:00:00Z`) >= generated - 7 * DAY_MS) : null;
  const rowById = useMemo(() => new Map(rows.map((r) => [r.id, r])), [rows]);

  useEffect(() => {
    const r = feed[sel]?.row;
    if (!r) return;
    if (sel >= limit - 2) setLimit((l) => Math.max(l, sel + PAGE));
    void data.detail(r.id).load().catch(() => undefined);
    // Several quick presses can land before a frame: always focus the latest selection.
    requestAnimationFrame(() => {
      if (!focusNext.current || !selected.current) return;
      focusNext.current = false;
      document.querySelector<HTMLElement>(`[data-row-link="${selected.current}"]`)?.focus();
    });
  }, [sel]);
  useListController({
    move: (d) => {
      if (feed.length === 0) return;
      focusNext.current = true;
      select(Math.min(feed.length - 1, Math.max(0, selRef.current + d)));
    },
    open: () => feed[selRef.current] && navigate(cveHref(feed[selRef.current].row.id)),
    watch: () => feed[selRef.current] && watchVendorOf(feed[selRef.current].row),
    copy: () => feed[selRef.current] && void copyTicket(feed[selRef.current].row.id),
  });

  const onChip = (id: string) => {
    setFilter({ ...filter, query: q, chip: filter.chip === id ? null : id });
    document.getElementById('feed')?.scrollIntoView({ block: 'start', behavior: prefersReducedMotion() ? 'auto' : 'smooth' });
  };

  if (meta.status === 'error') return <ErrorState error={meta.error} onRetry={meta.retry} />;
  if (signal.status === 'error') return <ErrorState error={signal.error} onRetry={signal.retry} />;
  const ready = meta.status === 'ready' && counts !== null;

  return (
    <div class="today">
      {ready ? <Ticker meta={meta.data} passed24h={passed24h} kevSoon={kevSoon} batchesWeek={weekBatches?.length ?? null} /> : <Loading label="Loading today’s numbers" lines={1} height="28px" class="ticker-skel" />}

      <div class="today__grid">
        <div class="today__hero">
          {ready ? (
            <Hero meta={meta.data} counts={counts} level={level} />
          ) : (
            <div class="hero">
              <Loading label="Loading" lines={3} height="48px" />
            </div>
          )}
        </div>
        <div class="today__knob">
          <KnobPanel level={level} passed={counts ? counts.exploited + counts.likely : null} days={meta.status === 'ready' ? meta.data.window.days : 30} presetPassed={presetPassed} track={track} />
        </div>

        <section class="panel today__wf" aria-labelledby="wf-h">
          <header class="panel__head">
            <div>
              <h2 id="wf-h" class="panel__title">Signal waterfall</h2>
              <p class="panel__sub">Every CVE in the window, {slot}. Grey is noise; lit ticks cleared the bar. Pick a column to see that day’s CVEs in Explore.</p>
            </div>
            <ul class="legend legend--inline" aria-hidden="true">
              {(['exploited', 'likely', 'watch', 'quiet'] as const).map((t) => (
                <li key={t} class={`legend__item legend__item--${t}`}>
                  <span class={`wf__key wf__key--${t}`} />
                  {TIER_META[t].label}
                </li>
              ))}
            </ul>
          </header>
          {stats.status === 'error' ? (
            <ErrorState error={stats.error} onRetry={stats.retry} />
          ) : hourly.length > 0 && stats.status === 'ready' && counts ? (
            <Waterfall
              counts={hourly}
              start={Date.parse(stats.data.hourly.start)}
              annotations={annotations}
              onBinHours={setBinHours}
              dayHref={(day) => exploreDayHref(day, level)}
              summary={`Signal waterfall: ${fmtInt(meta.status === 'ready' ? meta.data.counts.window_published : 0)} CVEs over ${stats.data.hourly.hours} hours, ${slot}; ${fmtInt(counts.exploited)} exploited and ${fmtInt(counts.likely)} likely with the evidence bar at ${level}.`}
            />
          ) : (
            <Loading label="Drawing the waterfall" lines={1} height="176px" />
          )}
        </section>

        <section class="today__feed" id="feed" aria-labelledby="feed-h">
          <header class="section__head">
            <h2 id="feed-h" class="section__title">
              Signal <span class="section__count">{fmtInt(feed.length)}</span>
            </h2>
            <span class="section__links">
              <a class="section__more" href={href('check')}>
                Check your dependencies <IconArrowRight size={12} />
              </a>
              <a class="section__more" href={href('explore')}>
                Explore all <IconArrowRight size={12} />
              </a>
            </span>
          </header>
          <FilterBar filter={{ ...filter, query: q }} onChange={setFilter} counts={toggleCounts} shown={feed.length} />
          {signal.status !== 'ready' ? (
            <Loading label="Loading the signal" lines={6} height="56px" />
          ) : feed.length === 0 ? (
            <EmptyState
              title="Nothing passes these filters"
              action={
                <button type="button" class="btn" onClick={() => setFilter({ ...filter, query: '', chip: null, watchOnly: false, tiers: DEFAULT_FEED_FILTER.tiers })}>
                  Reset filters
                </button>
              }
            >
              Quiet is not the same as safe. Try a lower bar or fewer filters.
            </EmptyState>
          ) : (
            <>
              <div class="rows" key={`${filter.chip ?? ''}-${[...filter.tiers].join()}`}>
                {visible.map((fr, i) => (
                  <CveRow
                    key={fr.row.id}
                    row={fr.row}
                    tier={fr.tier}
                    knob={level}
                    now={now}
                    watched={fr.watched}
                    isNew={previousVisit !== null && pubMs(fr.row) > previousVisit}
                    selected={i === sel}
                    activeChip={filter.chip}
                    onChip={onChip}
                    onSelect={() => i !== selRef.current && select(i)}
                  />
                ))}
              </div>
              {feed.length > visible.length && (
                <button type="button" class="btn btn--block" onClick={() => setLimit(limit + PAGE * 2)}>
                  Show {fmtInt(Math.min(PAGE * 2, feed.length - visible.length))} more <span class="muted">of {fmtInt(feed.length - visible.length)}</span>
                </button>
              )}
            </>
          )}
        </section>

        <aside class="today__side" aria-label="Deadlines and changes">
          <section class="panel" aria-labelledby="kev-h">
            <header class="panel__head">
              <h2 id="kev-h" class="panel__title">KEV Clock</h2>
              <a class="section__more" href={href('kev')}>
                All deadlines <IconArrowRight size={12} />
              </a>
            </header>
            {kev.status === 'ready' ? (
              kev.data.entries.length ? <KevStrip entries={kev.data.entries} limit={6} /> : <EmptyState title="No KEV deadlines in range" />
            ) : kev.status === 'error' ? (
              <ErrorState error={kev.error} onRetry={kev.retry} />
            ) : (
              <Loading label="Loading KEV deadlines" lines={4} height="44px" />
            )}
          </section>
          <WokeCard level={level} />
          <section class="panel" aria-labelledby="chg-h">
            <header class="panel__head">
              <h2 id="chg-h" class="panel__title">What changed</h2>
              <span class="panel__sub">last 7 days</span>
            </header>
            {changes.status === 'ready' ? (
              <Changes items={changes.data.items} rows={rowById} />
            ) : changes.status === 'error' ? (
              <ErrorState error={changes.error} onRetry={changes.retry} />
            ) : (
              <Loading label="Loading recent changes" lines={5} height="32px" />
            )}
          </section>
        </aside>

        <section class="today__batches" aria-labelledby="bat-h">
          <header class="section__head">
            <h2 id="bat-h" class="section__title">
              <IconLayers size={16} /> Batches <span class="section__count">largest in {meta.status === 'ready' ? meta.data.window.days : 30} days</span>
            </h2>
            <a class="section__more" href={href('batches')}>
              All {batches.status === 'ready' ? plural(batches.data.batches.length, 'batch', 'batches') : 'batches'} <IconArrowRight size={12} />
            </a>
          </header>
          {batches.status === 'ready' && signal.status === 'ready' ? (
            batches.data.batches.length ? (
              <div class="batchgrid">
                {[...batches.data.batches]
                  .sort((a, b) => b.count - a.count)
                  .slice(0, 6)
                  .map((b) => {
                    const members = batchMembers.get(b.id) ?? [];
                    const { counts: bc, exact } = batchCounts(b.by_tier, members, level, complete);
                    return <BatchCard key={b.id} batch={b} counts={bc} exact={exact} pocs={members.filter((r) => hasChip(r, 'x.poc')).length} topTier={(r) => tierAt(r, level)} compact />;
                  })}
              </div>
            ) : (
              <EmptyState title="No patch-day batches in the window" />
            )
          ) : (
            <Loading label="Loading batches" lines={2} height="120px" />
          )}
        </section>
      </div>
    </div>
  );
}
