/**
 * "More from CVErdict" on Today: one live card for each page that Today does not already show,
 * each with a real number from the current data run and a way in. The Check card takes a
 * repository right here and hands it to the Check page in the URL fragment (never sent to a
 * server). receipts.json and woke.json load only when the cards come near the screen.
 */
import { useEffect, useRef, useState } from 'preact/hooks';
import { KNOB_DEFAULT, type StatsFile } from '../../../shared/contract';
import { parseRepo } from '../check/repo';
import { data } from '../data';
import { tierAt } from '../filters';
import { fmtDate, fmtInt, vendorProduct } from '../format';
import { prefersReducedMotion, useCountUp, useData } from '../hooks';
import { methodScore } from '../receipts';
import { cveHref, href, navigate } from '../router';
import { growth, kevGrowth, windowLabel } from '../surge';
import { Snippet } from './Snippet';
import { Spark } from './Spark';
import { TierIcon } from './Tier';
import { IconArrowRight, IconCode, IconLock, IconRefresh, IconShield, IconSparkle } from './icons';

/** A number that counts up from zero once its card is on screen. */
function Num({ value, format = fmtInt, on }: { value: number; format?: (v: number) => string; on: boolean }) {
  return <>{format(useCountUp(on ? value : 0, 900))}</>;
}

function More({ to, label }: { to: string; label: string }) {
  return (
    <a class="tour__more" href={href(to)}>
      {label}
      <IconArrowRight size={13} />
    </a>
  );
}

function CheckCard() {
  const [value, setValue] = useState('');
  const [bad, setBad] = useState(false);
  return (
    <article class="tour__card tour__card--check" style={{ '--i': 0 }}>
      <p class="tour__kicker">
        <IconLock size={13} /> Am I affected?
      </p>
      <h3 class="tour__title">Check your dependencies in one paste</h3>
      <p class="tour__text">A public GitHub repo, read straight from GitHub into your browser and ranked by exploitation. No SBOM, no account, no upload.</p>
      <form
        class="tour__form"
        onSubmit={(e) => {
          e.preventDefault();
          const v = value.trim();
          if (!parseRepo(v)) {
            setBad(true);
            return;
          }
          navigate(`${href('check')}#repo=${encodeURIComponent(v)}`);
        }}
      >
        <label class="sr-only" for="tour-repo">
          GitHub repository
        </label>
        <input
          id="tour-repo"
          class="input user-text"
          placeholder="owner/repo or a github.com URL"
          autocomplete="off"
          spellcheck={false}
          value={value}
          aria-invalid={bad ? 'true' : undefined}
          aria-describedby={bad ? 'tour-repo-err' : undefined}
          onInput={(e) => {
            setValue((e.currentTarget as HTMLInputElement).value);
            setBad(false);
          }}
        />
        <button type="submit" class="btn btn--primary">
          Check repo
        </button>
      </form>
      {bad && (
        <p class="tour__err" id="tour-repo-err" role="alert">
          That is not a GitHub repository. Try owner/repo, for example OWASP/NodeGoat.
        </p>
      )}
      <More to="check" label="Or drop a lockfile, or watch it in CI" />
    </article>
  );
}

function ReceiptsCard({ on }: { on: boolean }) {
  const receipts = useData(on ? data.receipts : null);
  const f = receipts.status === 'ready' ? receipts.data.forward : null;
  const cv = f ? methodScore(f.methods, 'cverdict') : undefined;
  return (
    <article class="tour__card tour__card--receipts" style={{ '--i': 1 }}>
      <p class="tour__kicker">
        <IconShield size={13} /> Receipts
      </p>
      {f && cv && f.eligible > 0 ? (
        <>
          <p class="tour__big">
            <Num value={cv.before} on={on} />
            <span class="tour__of"> of {fmtInt(f.eligible)}</span>
          </p>
          <p class="tour__text">
            CVEs CISA added to KEV since {fmtDate(f.since, Number.NaN)} that CVErdict flagged first
            {cv.lead && cv.lead.median > 0 ? `, a median of ${cv.lead.median} ${cv.lead.median === 1 ? 'day' : 'days'} earlier` : ''}.
          </p>
          <ol class="tour__dots" aria-hidden="true">
            {Array.from({ length: Math.min(f.eligible, 48) }, (_, i) => (
              <li key={i} class={i < cv.before ? 'is-lit' : ''} style={{ '--d': i }} />
            ))}
          </ol>
        </>
      ) : (
        <p class="tour__text">Every KEV listing, and whether CVErdict flagged it before CISA did: hits and misses alike.</p>
      )}
      <More to="receipts" label="See every hit and miss" />
    </article>
  );
}

function TrendsCard({ stats, on }: { stats: StatsFile | null; on: boolean }) {
  const g = stats ? growth(stats.monthly, stats.generated_at) : null;
  const kg = stats ? kevGrowth(stats.monthly, g) : null;
  return (
    <article class="tour__card tour__card--trends" style={{ '--i': 2 }}>
      <p class="tour__kicker">
        <IconSparkle size={13} /> Trends
      </p>
      {stats && g ? (
        <>
          <p class="tour__big">
            <Num value={Math.round(g.ratio * 10)} format={(v) => (v / 10).toFixed(1)} on={on} />
            <span class="tour__x">×</span>
          </p>
          <p class="tour__text">
            CVEs in {windowLabel(g.start, g.end)} against a year earlier.{kg ? ` KEV additions: ${kg.ratio.toFixed(1)}×. Volume is not risk.` : ''}
          </p>
          {on && <Spark monthly={stats.monthly} lit={g} height={56} />}
        </>
      ) : (
        <p class="tour__text">CVE volume since 1999, and why most of it is not risk.</p>
      )}
      <More to="surge" label="Read the surge" />
    </article>
  );
}

function WokeCard({ on }: { on: boolean }) {
  const woke = useData(on ? data.woke : null);
  const w = woke.status === 'ready' ? woke.data : null;
  const kinds = w
    ? ([
        ['kev', 'CISA KEV'],
        ['metasploit', 'Metasploit'],
        ['nuclei', 'Nuclei'],
      ] as const).filter(([k]) => (w.counts[k] ?? 0) > 0)
    : [];
  return (
    <article class="tour__card tour__card--woke" style={{ '--i': 3 }}>
      <p class="tour__kicker">
        <IconRefresh size={13} /> Woke Up
      </p>
      {w && w.items.length > 0 ? (
        <>
          <p class="tour__big">
            <Num value={w.items.length} on={on} />
            {w.items.length >= 500 && <span class="tour__of">+</span>}
          </p>
          <p class="tour__text">Old CVEs that gained exploitation evidence in the last {w.days} days.</p>
          {kinds.length > 0 && (
            <p class="tour__chips">
              {kinds.map(([k, label]) => (
                <span key={k} class="tour__chip">
                  {fmtInt(w.counts[k])} {label}
                </span>
              ))}
            </p>
          )}
          <ul class="tour__list">
            {w.items.slice(0, 2).map((i) => (
              <li key={i.id}>
                <TierIcon tier={tierAt(i.row, KNOB_DEFAULT)} size={12} />
                <a href={cveHref(i.id)} class="mono">
                  {i.id}
                </a>
                <span class="muted">{vendorProduct(i.row.v, i.row.p)}</span>
              </li>
            ))}
          </ul>
        </>
      ) : (
        <p class="tour__text">Old CVEs that gained exploitation evidence recently, each with its dated proof.</p>
      )}
      <More to="woke" label="See what woke up" />
    </article>
  );
}

function AgentsCard() {
  return (
    <article class="tour__card tour__card--agents" style={{ '--i': 4 }}>
      <p class="tour__kicker">
        <IconCode size={13} /> For AI agents
      </p>
      <h3 class="tour__title">Verdicts in your agent, one command</h3>
      <p class="tour__text">A read-only MCP server: verdicts, KEV due dates and your dependencies, from the same open data.</p>
      <Snippet title="Claude Code" code="claude mcp add cverdict -- npx -y cverdict-mcp" />
      <More to="mcp" label="Other clients and the API" />
    </article>
  );
}

export function Tour({ stats }: { stats: StatsFile | null }) {
  const ref = useRef<HTMLElement>(null);
  const [on, setOn] = useState(false);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (typeof IntersectionObserver === 'undefined') {
      setOn(true);
      return;
    }
    if (!prefersReducedMotion()) el.classList.add('is-armed');
    const io = new IntersectionObserver(
      (entries) => {
        if (!entries.some((e) => e.isIntersecting)) return;
        setOn(true);
        el.classList.add('is-in');
        io.disconnect();
      },
      { rootMargin: '0px 0px -10% 0px', threshold: 0.05 },
    );
    io.observe(el);
    return () => io.disconnect();
  }, []);
  return (
    <section class="tour" aria-labelledby="tour-h" ref={ref}>
      <header class="section__head">
        <h2 id="tour-h" class="section__title">
          More from CVErdict
        </h2>
      </header>
      <div class="tour__grid">
        <CheckCard />
        <ReceiptsCard on={on} />
        <TrendsCard stats={stats} on={on} />
        <WokeCard on={on} />
        <AgentsCard />
      </div>
    </section>
  );
}
