/**
 * Today's map of CVErdict: the same three groups as the nav, with a live card for every other
 * page, each showing what that page shows right now and leading into it. Each group plays its
 * animation once it is a fifth of the way up the screen; receipts.json and woke.json start
 * loading a little before. The Check card takes a repository right here and hands it to the
 * Check page in the URL fragment (never sent to a server). On phones each group is a row of
 * cards to swipe.
 */
import type { ComponentChildren } from 'preact';
import { useEffect, useRef, useState } from 'preact/hooks';
import { BRAND, REPO_URL } from '../../../shared/brand';
import { type BatchesFile, type KevEntry, KNOB_DEFAULT, type StatsFile, type Tier } from '../../../shared/contract';
import { CHIPS } from '../../../shared/model';
import { CLI_LINE } from '../check/ci';
import { handoff } from '../check/handoff';
import { parseRepo } from '../check/repo';
import { data } from '../data';
import { tierAt } from '../filters';
import { cnaName, fmtDate, fmtInt, HOUR_MS, kevDeadline, vendorProduct } from '../format';
import { prefersReducedMotion, useCountUp, useData, useNow } from '../hooks';
import { methodScore } from '../receipts';
import { cveHref, href, navigate } from '../router';
import { growth, kevGrowth, windowLabel } from '../surge';
import { TIER_META } from '../tiers';
import { Countdown, upcomingKev } from './Kev';
import { CheckFlow, type FlowMode } from './CheckFlow';
import { McpInstall } from './McpInstall';
import { Picker } from './Picker';
import { Snippet } from './Snippet';
import { Spark } from './Spark';
import { TierBar, TierIcon } from './Tier';
import { IconArrowRight, IconClock, IconCode, IconFilter, IconLayers, IconLock, IconRefresh, IconRss, IconSearch, IconShield, IconSparkle } from './icons';

/** A number that counts up from zero once its group is on screen. */
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

function Card({ kind, i, icon, kicker, children, wide, lead }: { kind: string; i: number; icon: ComponentChildren; kicker: string; children: ComponentChildren; wide?: boolean; lead?: boolean }) {
  return (
    <article class={`tour__card tour__card--${kind}${wide ? ' tour__card--wide' : ''}${lead ? ' tour__card--lead' : ''}`} style={{ '--i': i }}>
      <p class="tour__kicker">
        {icon} {kicker}
      </p>
      {children}
    </article>
  );
}

/** The group heading, as in the menu sheet: a numbered badge, the name, a rule and what it is for. */
export function GroupLabel({ n, label, note, id }: { n: string; label: string; note?: string; id?: string }) {
  return (
    <div class="grouplabel">
      <h3 class="grouplabel__head" id={id}>
        <span class="grouplabel__n mono">{n}</span>
        <span class="grouplabel__name">{label}</span>
        <span class="grouplabel__rule" aria-hidden="true" />
      </h3>
      {note && <p class="grouplabel__note">{note}</p>}
    </div>
  );
}

/** One group of cards: plays its animations once on screen. */
function Band({ n, label, note, lead, children }: { n: string; label: string; note: string; lead?: ComponentChildren; children: (on: boolean) => ComponentChildren }) {
  const ref = useRef<HTMLDivElement>(null);
  const [on, setOn] = useState(false);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (typeof IntersectionObserver === 'undefined' || prefersReducedMotion()) {
      setOn(true);
      return;
    }
    el.classList.add('is-armed');
    const io = new IntersectionObserver(
      (entries) => {
        if (!entries.some((e) => e.isIntersecting)) return;
        setOn(true);
        el.classList.add('is-in');
        io.disconnect();
      },
      { rootMargin: '0px 0px -10% 0px', threshold: 0 },
    );
    io.observe(el);
    return () => io.disconnect();
  }, []);
  const id = `tour-g${n}`;
  return (
    <div class="tour__band" ref={ref} role="group" aria-labelledby={id}>
      <GroupLabel n={n} label={label} note={note} id={id} />
      {/* A full-width card above the row: on a phone it stays out of the swipe row. */}
      {lead}
      <div class="tour__grid">{children(on)}</div>
    </div>
  );
}

/** A public, intentionally vulnerable app with a committed lockfile: a real result in one tap. */
const TRY_REPO = 'OWASP/NodeGoat';

type CheckWay = FlowMode;

/** Same three ways as the Check page, one word each. */
const CHECK_WAYS: readonly { id: CheckWay; label: string }[] = [
  { id: 'repo', label: 'Repo' },
  { id: 'file', label: 'File' },
  { id: 'ci', label: 'CI' },
];

const CHECK_TEXT: Record<CheckWay, string> = {
  repo: 'A public GitHub repo, read straight from GitHub into your browser and ranked by exploitation. No SBOM, no account, no upload.',
  file: 'Drop a lockfile or an SBOM and see which dependencies have CVEs worth your time. No account, no upload.',
  ci: 'Check on every push, pull request and day, private repos too. The GitHub Action fails the build when a dependency is Exploited.',
};

function CheckRepo() {
  const [value, setValue] = useState('');
  const [bad, setBad] = useState(false);
  return (
    <>
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
      <p class="tour__try">
        <span class="muted">Try it:</span>
        <button type="button" class="tour__chip tour__chip--try mono" onClick={() => navigate(`${href('check')}#repo=${encodeURIComponent(TRY_REPO)}`)}>
          {TRY_REPO}
        </button>
        <span class="muted">an intentionally vulnerable app</span>
      </p>
      <p class="tour__trust">
        <IconLock size={12} /> We never see your code: the repo name goes to GitHub, and the match runs in your browser.
      </p>
      {bad && (
        <p class="tour__err" id="tour-repo-err" role="alert">
          That is not a GitHub repository. Try owner/repo, for example OWASP/NodeGoat.
        </p>
      )}
    </>
  );
}

/** The file goes to the Check page in this tab's memory (check/handoff.ts), never anywhere else. */
function CheckFile() {
  const [drag, setDrag] = useState(false);
  const open = (f: File | undefined) => {
    if (!f) return;
    handoff.put(f);
    navigate(`${href('check')}#file`);
  };
  return (
    <>
      <div
        class={`tour__drop${drag ? ' is-drag' : ''}`}
        onDragEnter={(e) => {
          e.preventDefault();
          setDrag(true);
        }}
        onDragOver={(e) => e.preventDefault()}
        onDragLeave={(e) => {
          const to = e.relatedTarget as Node | null;
          if (!to || !(e.currentTarget as HTMLElement).contains(to)) setDrag(false);
        }}
        onDrop={(e) => {
          e.preventDefault();
          setDrag(false);
          open(e.dataTransfer?.files[0]);
        }}
      >
        <span class="tour__droptitle">Drop a lockfile or SBOM</span>
        <label class="btn btn--primary">
          <input type="file" class="sr-only user-text" onChange={(e) => open((e.currentTarget as HTMLInputElement).files?.[0])} />
          Choose a file
        </label>
      </div>
      <p class="tour__trust">
        <IconLock size={12} /> We never see your file: it is read and matched in your browser.
      </p>
    </>
  );
}

function CheckCi() {
  return (
    <>
      <Snippet title="Or in a terminal, in your project folder" code={CLI_LINE} />
      <button type="button" class="btn btn--primary tour__cta" onClick={() => navigate(`${href('check')}#ci`)}>
        Add the GitHub Action
      </button>
      <p class="tour__trust">
        <IconLock size={12} /> Runs in your own runner: no token, no app, nothing sent to us.
      </p>
    </>
  );
}

function CheckCard() {
  const [way, setWay] = useState<CheckWay>('repo');
  return (
    <Card kind="check" i={0} icon={<IconLock size={13} />} kicker="Check · Am I affected?" lead>
      <div class="tour__checkgrid">
        <div class="tour__checkmain">
          <h4 class="tour__title">Am I affected? Find out in seconds</h4>
          <p class="tour__text">{CHECK_TEXT[way]}</p>
          <Picker label="How to check" options={CHECK_WAYS} value={way} onPick={setWay} />
          {way === 'repo' && <CheckRepo />}
          {way === 'file' && <CheckFile />}
          {way === 'ci' && <CheckCi />}
          <p class="tour__proof">
            {way === 'ci' ? (
              <>
                Don’t take our word for it: <a href={`${REPO_URL}/tree/main/cli`}>read the Action’s source</a>. It only downloads the public index.
              </>
            ) : (
              <>Don’t take our word for it: open your browser’s network tab while it runs. Public files come in from cverdict.dev{way === 'repo' ? ' and GitHub' : ''}, and nothing goes back.</>
            )}
          </p>
        </div>
        {/* The same diagram as the Check page, for the chosen tab. */}
        <CheckFlow mode={way} compact />
        <div class="tour__checkmore">
          <More to="check" label="How it works" />
        </div>
      </div>
    </Card>
  );
}

function KevCard({ entries }: { entries: readonly KevEntry[] | null }) {
  const now = useNow(60_000);
  const upcoming = entries ? upcomingKev(entries, now).filter((e) => kevDeadline(e.due_date) >= now) : [];
  const next = upcoming[0];
  const after = upcoming.slice(1, 4);
  const soon = entries
    ? entries.filter((e) => {
        const left = kevDeadline(e.due_date) - now;
        return left >= 0 && left <= 72 * HOUR_MS;
      }).length
    : 0;
  return (
    <Card kind="kev" i={1} icon={<IconClock size={13} />} kicker="KEV Clock">
      {next ? (
        <>
          <p class="tour__text">Next federal deadline</p>
          <Countdown due={next.due_date} class="tour__countdown" />
          <p class="tour__text">
            <a href={cveHref(next.id)} class="mono">
              {next.id}
            </a>{' '}
            <span class="muted">{vendorProduct(next.vendor, next.product)}</span>
          </p>
          {soon > 0 && <p class="tour__chips"><span class="tour__chip tour__chip--hot">{fmtInt(soon)} due within 72 hours</span></p>}
          {after.length > 0 && (
            <ul class="tour__list" aria-label="Then">
              {after.map((e) => (
                <li key={e.id}>
                  <IconClock size={12} />
                  <a href={cveHref(e.id)} class="mono">
                    {e.id}
                  </a>
                  <span class="muted">{vendorProduct(e.vendor, e.product)}</span>
                  <span class="tour__due mono">{fmtDate(e.due_date)}</span>
                </li>
              ))}
            </ul>
          )}
        </>
      ) : (
        <p class="tour__text">Every CISA KEV due date, counting down, with ransomware and forensic flags.</p>
      )}
      <More to="kev" label="All deadlines" />
    </Card>
  );
}

function WokeCard({ on, near }: { on: boolean; near: boolean }) {
  const woke = useData(near ? data.woke : null);
  const w = woke.status === 'ready' ? woke.data : null;
  const kinds = w
    ? ([
        ['kev', 'CISA KEV'],
        ['metasploit', 'Metasploit'],
        ['nuclei', 'Nuclei'],
      ] as const).filter(([k]) => (w.counts[k] ?? 0) > 0)
    : [];
  return (
    <Card kind="woke" i={2} icon={<IconRefresh size={13} />} kicker="Woke Up">
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
            {w.items.slice(0, 3).map((i) => (
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
    </Card>
  );
}

function ExploreCard({ counts, total, days, on }: { counts: Record<Tier, number> | null; total: number | null; days: number; on: boolean }) {
  return (
    <Card kind="explore" i={1} icon={<IconSearch size={13} />} kicker="Explore">
      {counts && total !== null ? (
        <>
          <p class="tour__big">
            <Num value={total} on={on} />
          </p>
          <p class="tour__text">CVEs in the last {days} days, every one searchable, by day, vendor and tier.</p>
          <div class="tour__tierbar">
            <TierBar counts={counts} />
          </div>
          <p class="tour__legend">
            {(['exploited', 'likely', 'watch'] as const).map((t) => (
              <span key={t}>
                <TierIcon tier={t} size={11} /> {fmtInt(counts[t])} {TIER_META[t].label}
              </span>
            ))}
          </p>
        </>
      ) : (
        <p class="tour__text">Every CVE of the window, searchable and filterable by day.</p>
      )}
      <More to="explore" label="Search them all" />
    </Card>
  );
}

function PatchCard({ batches, on }: { batches: BatchesFile | null; on: boolean }) {
  const b = batches?.batches.length ? [...batches.batches].sort((x, y) => y.count - x.count)[0] : null;
  const passed = b ? b.by_tier.exploited + b.by_tier.likely : 0;
  return (
    <Card kind="patch" i={2} icon={<IconLayers size={13} />} kicker="Patch days">
      {b ? (
        <>
          <p class="tour__big">
            <Num value={b.count} on={on} />
          </p>
          <p class="tour__text">
            {cnaName(b.cna)} CVEs on {fmtDate(b.date, Number.NaN)}, the largest batch of the window. <strong>{fmtInt(passed)}</strong> {passed === 1 ? 'matters' : 'matter'} now.
          </p>
          <div class="tour__tierbar">
            <TierBar counts={b.by_tier} />
          </div>
        </>
      ) : (
        <p class="tour__text">Patch days and bulk releases, and the few CVEs in each that matter.</p>
      )}
      <More to="batches" label={batches ? `All ${fmtInt(batches.batches.length)} batches` : 'All batches'} />
    </Card>
  );
}

function TrendsCard({ stats, on }: { stats: StatsFile | null; on: boolean }) {
  const g = stats ? growth(stats.monthly, stats.generated_at) : null;
  const kg = stats ? kevGrowth(stats.monthly, g) : null;
  return (
    <Card kind="trends" i={0} icon={<IconSparkle size={13} />} kicker="Trends">
      {stats && g ? (
        <>
          <p class="tour__big">
            <Num value={Math.round(g.ratio * 10)} format={(v) => (v / 10).toFixed(1)} on={on} />
            <span class="tour__x">×</span>
          </p>
          <p class="tour__text">
            CVEs in {windowLabel(g.start, g.end)} against a year earlier.{kg ? ` KEV additions: ${kg.ratio.toFixed(1)}×.` : ''}
          </p>
          {on && <Spark monthly={stats.monthly} lit={g} height={52} />}
        </>
      ) : (
        <p class="tour__text">CVE volume since 1999, and why most of it is not risk.</p>
      )}
      <More to="surge" label="See the trends" />
    </Card>
  );
}

function ReceiptsCard({ on, near }: { on: boolean; near: boolean }) {
  const receipts = useData(near ? data.receipts : null);
  const f = receipts.status === 'ready' ? receipts.data.forward : null;
  const cv = f ? methodScore(f.methods, 'cverdict') : undefined;
  return (
    <Card kind="receipts" i={3} icon={<IconShield size={13} />} kicker="Receipts">
      {f && cv && f.eligible > 0 ? (
        <>
          <p class="tour__big">
            <Num value={cv.before} on={on} />
            <span class="tour__of"> of {fmtInt(f.eligible)}</span>
          </p>
          <p class="tour__text">
            KEV listings since {fmtDate(f.since, Number.NaN)} that CVErdict flagged first
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
      <More to="receipts" label="Every hit and miss" />
    </Card>
  );
}

/** A few chips and their points, straight from the model: exploitation first, then exploit code. */
const SAMPLE_CHIPS = ['kev.listed', 'x.metasploit', 'x.nuclei', 'epss.high', 'x.poc'].flatMap((id) => CHIPS.filter((c) => c.id === id));
const SAMPLE_MAX = Math.max(1, ...SAMPLE_CHIPS.map((c) => c.points));

function MethodCard({ on }: { on: boolean }) {
  return (
    <Card kind="method" i={2} icon={<IconFilter size={13} />} kicker="Method">
      <p class="tour__big">
        <Num value={CHIPS.length} on={on} />
        <span class="tour__of"> reason chips</span>
      </p>
      <p class="tour__text">Each score is a plain sum of them, from a base of 15. No machine learning, no LLM-written text: every point links to its evidence.</p>
      <ul class="tour__pts" aria-label="Points for some of the chips">
        {SAMPLE_CHIPS.map((c) => (
          <li key={c.id} style={{ '--w': `${(c.points / SAMPLE_MAX) * 100}%` }}>
            <span class="tour__ptlabel">{c.short}</span>
            <span class="tour__ptbar" aria-hidden="true" />
            <span class="tour__ptval mono">+{c.points}</span>
          </li>
        ))}
      </ul>
      <p class="tour__legend">
        {(['exploited', 'likely', 'watch', 'quiet'] as const).map((t) => (
          <span key={t}>
            <TierIcon tier={t} size={11} /> {TIER_META[t].label}
          </span>
        ))}
      </p>
      <More to="method" label="How a score is made" />
    </Card>
  );
}

function AgentsCard() {
  return (
    <Card kind="agents" i={0} icon={<IconCode size={13} />} kicker="MCP · for AI agents" wide>
      <h4 class="tour__title">Verdicts in your agent, one command</h4>
      <p class="tour__text">A read-only MCP server: verdicts, KEV due dates and your dependencies, from the same open data.</p>
      <McpInstall />
      <p class="tour__ask">
        <span class="muted">Then ask:</span> “Which KEV deadlines are due this week?”
      </p>
      <More to="mcp" label="Other clients" />
    </Card>
  );
}

function ApiCard() {
  const files = ['signal.json', 'kev.json', 'cve/00…ff.json', 'feeds/*.xml', 'kev-due.ics', 'llms.txt'];
  return (
    <Card kind="api" i={1} icon={<IconRss size={13} />} kicker="API">
      <h4 class="tour__title">Open data, no key</h4>
      <p class="tour__text">The same files this site reads, refreshed hourly. Scores are CC0.</p>
      <p class="tour__chips">
        {files.map((f) => (
          <span key={f} class="tour__chip mono">
            {f}
          </span>
        ))}
      </p>
      <Snippet title="Try it, no key" code={`curl -s ${BRAND.siteUrl}/data/v1/meta.json`} />
      <More to="feeds" label="Feeds and files" />
    </Card>
  );
}

export interface TourProps {
  stats: StatsFile | null;
  kev: readonly KevEntry[] | null;
  batches: BatchesFile | null;
  counts: Record<Tier, number> | null;
  total: number | null;
  days: number;
}

export function Tour({ stats, kev, batches, counts, total, days }: TourProps) {
  const ref = useRef<HTMLElement>(null);
  // Load the receipts a screen ahead, so the card is ready when it shows.
  const [near, setNear] = useState(false);
  useEffect(() => {
    const el = ref.current;
    if (!el || typeof IntersectionObserver === 'undefined') {
      setNear(true);
      return;
    }
    const io = new IntersectionObserver(
      (entries) => {
        if (!entries.some((e) => e.isIntersecting)) return;
        setNear(true);
        io.disconnect();
      },
      { rootMargin: '0px 0px 100% 0px' },
    );
    io.observe(el);
    return () => io.disconnect();
  }, []);
  return (
    <section class="tour" aria-labelledby="tour-h" ref={ref}>
      <header class="tour__head">
        <h2 id="tour-h" class="section__title">
          Everything in CVErdict
        </h2>
        <p class="tour__sub">Every page, with what it shows right now. Pick what matters to you.</p>
      </header>
      <Band n="01" label="Act on it" note="What needs you now" lead={<CheckCard />}>
        {(on) => (
          <>
            <KevCard entries={kev} />
            <WokeCard on={on} near={near} />
          </>
        )}
      </Band>
      <Band n="02" label="Look into it" note="Dig into the data and the proof">
        {(on) => (
          <>
            <TrendsCard stats={stats} on={on} />
            <ExploreCard counts={counts} total={total} days={days} on={on} />
            <PatchCard batches={batches} on={on} />
            <ReceiptsCard on={on} near={near} />
          </>
        )}
      </Band>
      <Band n="03" label="Build with it" note="Bring the verdicts into your tools">
        {(on) => (
          <>
            <AgentsCard />
            <ApiCard />
            <MethodCard on={on} />
          </>
        )}
      </Band>
    </section>
  );
}
