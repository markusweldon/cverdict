/** Batches: patch-day cohorts (50+ CVEs from one CNA in one UTC day), with tier bars. */
import { useEffect, useMemo, useState } from 'preact/hooks';
import { SIGNAL_MIN_SCORE, type Batch } from '../../../shared/contract';
import { BatchCard } from '../components/BatchCard';
import { ErrorState, Loading } from '../components/States';
import { data } from '../data';
import { batchCounts, emptyCounts, groupByBatch, hasChip, tierAt, type TierCounts } from '../filters';
import { cnaName, DAY_MS, fmtDate, fmtInt, fmtPct, plural } from '../format';
import { useData, useKnobUrl, useTitle } from '../hooks';
import { useLocation } from '../router';
import { knob, useStore } from '../state';

/** Monday (UTC) of the week containing `date`, as YYYY-MM-DD. */
function weekOf(date: string): string {
  const t = Date.parse(`${date}T00:00:00Z`);
  const dow = (new Date(t).getUTCDay() + 6) % 7;
  return new Date(t - dow * DAY_MS).toISOString().slice(0, 10);
}

/** Batches grouped by week, newest week first, biggest batch first within a week. */
function weeks(list: readonly Batch[]): [string, Batch[]][] {
  const m = new Map<string, Batch[]>();
  for (const b of list) m.set(weekOf(b.date), [...(m.get(weekOf(b.date)) ?? []), b]);
  return [...m.entries()].sort((a, b) => b[0].localeCompare(a[0])).map(([w, g]) => [w, g.sort((x, y) => y.count - x.count || y.date.localeCompare(x.date))]);
}

export default function Batches() {
  useTitle('Batches');
  useKnobUrl();
  const level = useStore(knob);
  const loc = useLocation();
  const batches = useData(data.batches);
  const signal = useData(data.signal);
  // Below a bar of 35 the signal rows cannot tell which members pass (scores 30–34): count every row.
  const index = useData(level < SIGNAL_MIN_SCORE || data.index.peek() ? data.index : null);
  const complete = index.status === 'ready';
  const meta = useData(data.meta);
  const [open, setOpen] = useState<ReadonlySet<string>>(() => new Set(loc.hash ? [decodeURIComponent(loc.hash.slice(1))] : []));
  const [cna, setCna] = useState('');

  // Deep links (#microsoft-2026-10-13) open and reveal their card once the data is in.
  useEffect(() => {
    const id = loc.hash ? decodeURIComponent(loc.hash.slice(1)) : '';
    if (!id || batches.status !== 'ready') return;
    setOpen((s) => new Set([...s, id]));
    requestAnimationFrame(() => document.getElementById(id)?.scrollIntoView({ block: 'start' }));
  }, [loc.hash, batches.status]);

  const members = useMemo(() => groupByBatch(complete ? index.data : signal.status === 'ready' ? signal.data : []), [complete, index, signal]);

  if (batches.status === 'error') return <ErrorState error={batches.error} onRetry={batches.retry} />;
  const list = batches.status === 'ready' ? batches.data.batches : [];
  const cnas = [...new Set(list.map((b) => b.cna))].sort((a, b) => cnaName(a).localeCompare(cnaName(b)));
  const shown = cna ? list.filter((b) => b.cna === cna) : list;
  const countsOf = (id: string, d: TierCounts) => batchCounts(d, members.get(id) ?? [], level, complete).counts;
  const exact = complete || level >= SIGNAL_MIN_SCORE;
  const total = list.reduce((a, b) => a + b.count, 0);
  const passed = list.reduce((a, b) => {
    const c = countsOf(b.id, b.by_tier);
    return a + c.exploited + c.likely;
  }, 0);
  const windowTotal = meta.status === 'ready' ? meta.data.counts.window_published : 0;
  const all = list.reduce((acc, b) => {
    const c = countsOf(b.id, b.by_tier);
    for (const k of Object.keys(acc) as (keyof TierCounts)[]) acc[k] += c[k];
    return acc;
  }, emptyCounts());

  return (
    <div class="page">
      <header class="page__head">
        <p class="eyebrow">Patch-day cohorts</p>
        <h1 class="page__title" tabIndex={-1}>
          Batches
        </h1>
        <p class="page__lede">
          {list.length ? (
            <>
              {plural(list.length, 'batch', 'batches')} in 30 days carried <strong>{fmtInt(total)}</strong> CVEs
              {windowTotal ? <> ({fmtPct(total / windowTotal)} of the window)</> : null}.{' '}
              {exact ? (
                <>
                  With the evidence bar at {level}, <strong>{fmtInt(passed)}</strong> of them pass, {fmtInt(all.exploited)} of them exploited.
                </>
              ) : (
                <>With the evidence bar at {level}, counting which of them pass…</>
              )}
            </>
          ) : (
            'A batch is 50 or more CVEs from one CNA on one UTC day: Patch Tuesday, Oracle’s CPU, Chrome releases, kernel dumps.'
          )}
        </p>
        {cnas.length > 1 && (
          <label class="select">
            <span>CNA</span>
            <select value={cna} onChange={(e) => setCna(e.currentTarget.value)}>
              <option value="">All CNAs</option>
              {cnas.map((c) => (
                <option key={c} value={c}>
                  {cnaName(c)}
                </option>
              ))}
            </select>
          </label>
        )}
      </header>
      {batches.status !== 'ready' ? (
        <Loading label="Loading batches" lines={4} height="140px" />
      ) : (
        weeks(shown).map(([week, group]) => (
          <section key={week} class="batchday" aria-labelledby={`week-${week}`}>
            <header class="batchday__head">
              <h2 class="batchday__date" id={`week-${week}`}>
                Week of {fmtDate(week)}
              </h2>
              <span class="batchday__sum">
                {plural(group.length, 'batch', 'batches')} · {fmtInt(group.reduce((a, b) => a + b.count, 0))} CVEs
              </span>
            </header>
            <div class="batchgrid batchgrid--page">
              {group.map((b) => {
                const ms = members.get(b.id) ?? [];
                return (
                  <BatchCard
                    key={b.id}
                    batch={b}
                    counts={countsOf(b.id, b.by_tier)}
                    exact={exact}
                    pocs={ms.filter((r) => hasChip(r, 'x.poc')).length}
                    topTier={(r) => tierAt(r, level)}
                    expanded={open.has(b.id)}
                    onToggle={() =>
                      setOpen((s) => {
                        const n = new Set(s);
                        if (n.has(b.id)) n.delete(b.id);
                        else n.add(b.id);
                        return n;
                      })
                    }
                  />
                );
              })}
            </div>
          </section>
        ))
      )}
    </div>
  );
}
