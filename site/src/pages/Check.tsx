/**
 * Check: which of the CVEs CVErdict tracks affect the packages in an SBOM or a lockfile.
 *
 * Everything happens in this tab (check/session.ts holds the logic and its privacy rules). Text
 * from the user's file is rendered only through UserText, in the system monospace font: the Geist
 * web fonts are split by unicode-range, and rendering a character from another range would fetch a
 * font subset, a request that depends on the file. Rows here never prefetch a shard.
 */
import type { ComponentChildren } from 'preact';
import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { BRAND } from '../../../shared/brand';
import { PACKAGE_ECOSYSTEMS, type PackagesFile, type Tier } from '../../../shared/contract';
import { advisoryUrl, ATTRIBUTION, rangesText } from '../../../shared/packages';
import { copyTicket, watchVendorOf } from '../actions';
import { groupByTier, GROUP_ORDER, type CheckResult, type CveHit, type Group, type NotCheckedGroup, type PackageHit } from '../check/match';
import { FORMAT_LABEL, FORMATS, isFormatId, parseErrorText, type Component, type FormatId } from '../check/parse';
import { fileTooLarge, fmtSize, indexGlyphs, pasteTooLarge, session, type Failure, type Held } from '../check/session';
import { ExtLink } from '../components/ExtLink';
import { IconAlert, IconLock, IconRefresh } from '../components/icons';
import { CveRow } from '../components/Row';
import { TierPill } from '../components/Tier';
import { data } from '../data';
import { tierAt } from '../filters';
import { fmtDateTime, fmtInt, plural } from '../format';
import { useData, useKnobUrl, useListController, useNow, useTitle } from '../hooks';
import { cveHref, navigate } from '../router';
import { knob, useStore } from '../state';
import { TIER_META } from '../tiers';

/** Text that came from the user's file: system monospace only, never a web font (see above). */
function UserText({ children, class: cls }: { children: string; class?: string }) {
  return <span class={`user-text${cls ? ` ${cls}` : ''}`}>{children.length > 300 ? `${children.slice(0, 300)}…` : children}</span>;
}

const ECOSYSTEM_LIST = `${PACKAGE_ECOSYSTEMS.slice(0, -1).join(', ')} or ${PACKAGE_ECOSYSTEMS[PACKAGE_ECOSYSTEMS.length - 1]}`;
const GROUP_LABEL: Readonly<Record<Group, string>> = {
  exploited: TIER_META.exploited.label,
  likely: TIER_META.likely.verdict,
  watch: TIER_META.watch.label,
  quiet: TIER_META.quiet.label,
  possible: 'Possibly affected, not confirmed',
};
const NAMES_SHOWN = 1000;

type Status = { kind: 'idle' } | { kind: 'reading'; name: string } | { kind: 'checking'; packages: number } | { kind: 'waiting'; packages: number; slow: boolean };
type IndexState = 'idle' | 'loading' | 'ready' | 'error';
interface Input {
  text: string;
  file: string | null;
}

const nextFrame = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

/**
 * Load the web font subsets the index's text needs (see indexGlyphs), once, as soon as it arrives:
 * the same requests for everyone, before any file is read, never decided by which rows match.
 * Titles, vendors and ranges are set in the sans face; the mono face here only shows CVE and
 * advisory IDs, which are ASCII.
 */
let fontsWarmed = false;
function warmFonts(file: PackagesFile): void {
  if (fontsWarmed || typeof document === 'undefined' || !document.fonts?.load) return;
  fontsWarmed = true;
  const glyphs = indexGlyphs(file);
  if (glyphs !== '') void document.fonts.load('16px "Geist Variable"', glyphs).catch(() => undefined);
}

function uncheckedText(p: PackageHit): ComponentChildren {
  switch (p.unchecked) {
    case 'not-exact':
      return 'No exact version (use == in requirements.txt, or a lock file).';
    case 'no-version':
      return 'The file gives no version.';
    case 'go-local':
      return 'Replaced by a local directory in go.mod.';
    case 'version':
      return (
        <>
          Version <UserText>{p.version ?? ''}</UserText> could not be compared.
        </>
      );
    case 'range':
      return 'The advisory’s range could not be compared.';
    case 'name-case':
      return `The advisory names ${p.named ?? ''}, the same path with other capital letters. Go paths are case-sensitive, and package URLs are often written in lower case.`;
    case 'go-package':
      return `The advisory names ${p.named ?? ''}, a path inside this module: a package of it, or a separate module.`;
    default:
      return null;
  }
}

function notCheckedText(g: NotCheckedGroup): string {
  switch (g.reason) {
    case 'eco-down':
      return `${g.eco} packages were not checked: the advisory data could not be loaded in the last run.`;
    case 'ecosystem': {
      const counts = new Map<string, number>();
      for (const c of g.items) counts.set(c.type ?? 'unknown', (counts.get(c.type ?? 'unknown') ?? 0) + 1);
      const list = [...counts].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
      return `Ecosystem not covered (${list.map(([t, n]) => `${t} ${fmtInt(n)}`).join(', ')}).`;
    }
    case 'no-purl':
      return 'No package URL in the SBOM.';
    case 'bad-purl':
      return 'The package URL could not be read.';
    case 'not-registry':
      return 'Not from the public registry (git, file, path or workspace).';
    case 'dev-branch':
      return 'Development branch, no release version.';
    case 'go-stdlib':
      return 'Go standard library: go.mod does not say which Go release builds your code.';
  }
}

/** The advisory ID, linked when it has the expected form (a tampered file yields plain text). */
function Advisory({ id }: { id: string }) {
  const url = advisoryUrl(id);
  return url ? (
    <ExtLink href={url} class="checkpk__adv">
      {id}
    </ExtLink>
  ) : (
    <span class="checkpk__adv">{id}</span>
  );
}

/** Under each CVE row: which of the user's packages it affects, and the advisories that say so. */
function Packages({ packages }: { packages: readonly PackageHit[] }) {
  return (
    <ul class="checkpk" aria-label="Your packages">
      {packages.map((p) => (
        <li key={`${p.eco}:${p.name}@${p.version}`} class="checkpk__item">
          <p class="checkpk__pkg">
            <UserText class="checkpk__name">{p.name}</UserText>
            {p.version !== null && <UserText class="checkpk__ver">{p.version}</UserText>}
            <span class="checkpk__eco">{p.eco}</span>
          </p>
          {p.unchecked && <p class="checkpk__why">{uncheckedText(p)}</p>}
          <ul class="checkpk__advs">
            {p.advisories.map((a) => (
              <li key={a.id}>
                <Advisory id={a.id} />
                <span class="checkpk__range">
                  {a.listed ? (
                    <>
                      Lists <UserText>{p.version ?? ''}</UserText> as affected.
                    </>
                  ) : (
                    `${rangesText(a.ranges) || 'listed versions only'}.`
                  )}
                  {a.fixedIn && ` Fixed in ${a.fixedIn}.`}
                </span>
              </li>
            ))}
          </ul>
        </li>
      ))}
    </ul>
  );
}

/** A list of the user's package names that renders only when opened (it can be thousands long). */
function NameList({ items }: { items: readonly Component[] }) {
  const shown = [...items].sort((a, b) => a.name.localeCompare(b.name) || (a.version ?? '').localeCompare(b.version ?? '')).slice(0, NAMES_SHOWN);
  return (
    <>
      <ul class="check__names">
        {shown.map((c, i) => (
          <li key={i}>
            <UserText>{c.version ? `${c.name} ${c.version}` : c.name}</UserText>
          </li>
        ))}
      </ul>
      {items.length > NAMES_SHOWN && <p class="muted">And {fmtInt(items.length - NAMES_SHOWN)} more.</p>}
    </>
  );
}

function More({ title, count, children }: { title: string; count: number; children: () => ComponentChildren }) {
  const [open, setOpen] = useState(false);
  if (count === 0) return null;
  return (
    <details class="check__more" onToggle={(e) => setOpen((e.currentTarget as HTMLDetailsElement).open)}>
      <summary>
        {title} <span class="section__count">{fmtInt(count)}</span>
      </summary>
      {open && children()}
    </details>
  );
}

function summaryText(r: CheckResult, days: number | null): string {
  const read = `Read ${FORMAT_LABEL.get(r.format)}: ${plural(r.total, 'package')} (${fmtInt(r.distinct)} distinct).`;
  const affecting = r.cves.filter((c) => c.affected).length;
  const skipped = r.distinct - r.checked;
  if (r.checked === 0) return `${read} None of them could be checked (listed below).`;
  if (affecting === 0 && r.possiblePackages === 0) {
    const older = days === null ? 'most older CVEs are not in the index' : `most CVEs older than ${days} days are not in the index`;
    return `${read} None of the ${fmtInt(r.indexCves)} CVEs in the index affect the ${plural(r.checked, 'package')} we could check. That does not mean they have no vulnerabilities: ${older}${skipped ? `, and ${plural(skipped, 'package')} could not be checked (listed below)` : ''}.`;
  }
  const parts = [read];
  if (affecting > 0) parts.push(`${plural(affecting, 'tracked CVE')} ${affecting === 1 ? 'affects' : 'affect'} ${fmtInt(r.affectedPackages)} of them.`);
  if (r.possiblePackages > 0) parts.push(`${fmtInt(r.possiblePackages)} ${affecting > 0 ? 'more ' : ''}${r.possiblePackages === 1 ? 'is' : 'are'} possibly affected, not confirmed.`);
  return parts.join(' ');
}

function Coverage({ index, state, days }: { index: PackagesFile | undefined; state: IndexState; days: number | null }) {
  const window = days === null ? 'in the window' : `in the last ${days} days`;
  return (
    <section class="panel check__coverage" aria-labelledby="check-cov">
      <h2 class="panel__title" id="check-cov">
        What is checked
      </h2>
      {index ? (
        <p>
          The index covers <strong>{fmtInt(index.cves.rows.length)}</strong> CVEs that name a package in {ECOSYSTEM_LIST}: CVEs published {window}, CVEs in CISA KEV, and older CVEs that woke up. It was built{' '}
          {fmtDateTime(index.generated_at)}
          {index.distinct ? ` from ${fmtInt(index.distinct.advisories)} advisories that name a CVE, ${fmtInt(index.distinct.matched)} of which name a tracked CVE` : ''}.
        </p>
      ) : (
        <p>
          The index covers the CVEs that name a package in {ECOSYSTEM_LIST}: CVEs published {window}, CVEs in CISA KEV, and older CVEs that woke up.{' '}
          {state === 'loading' ? 'Loading its numbers.' : state === 'error' ? 'The index could not be loaded, so its numbers are not shown.' : 'Its numbers show once the index has loaded, when you start a check.'}
        </p>
      )}
      <p>
        Not checked: CVEs outside that set (most older CVEs), advisories without a CVE ID, and packages outside those eight ecosystems, such as deb, rpm or apk. For a full audit, also run a scanner such as
        osv-scanner, npm audit or pip-audit.
      </p>
      {index?.sources.map((s) =>
        !s.ok ? (
          <p key={s.ecosystem} class="check__warn">
            <IconAlert size={12} /> {s.ecosystem} packages were not checked: the advisory data could not be loaded in the last run.
          </p>
        ) : s.stale ? (
          <p key={s.ecosystem} class="check__warn">
            <IconAlert size={12} /> {s.ecosystem} advisories come from a copy last updated {s.fetched_at ? fmtDateTime(s.fetched_at) : 'earlier'}: OSV.dev could not be reached in the last run.
          </p>
        ) : null,
      )}
    </section>
  );
}

function FailureText({ failure }: { failure: Failure }) {
  switch (failure.kind) {
    case 'file-too-large':
      return <>This file is {fmtSize(failure.size)}. Files up to 50 MB can be checked, because everything happens in your browser.</>;
    case 'paste-too-large':
      return <>This is {fmtSize(failure.size)} of text. Paste up to 5 MB, or save it as a file and use Choose a file.</>;
    case 'parse': {
      const { kind, detail } = failure.error;
      if (kind !== 'json') return <>{parseErrorText(kind)}</>;
      return (
        <>
          This looks like JSON, but it could not be read: <UserText>{detail}</UserText>. Check that the whole file was pasted.
        </>
      );
    }
    case 'index':
      return failure.notPublished ? <>Not published yet. The first pipeline run with this feature has not finished.</> : <>The package index could not be loaded, so nothing was checked.</>;
  }
}

const tierGroups: readonly Tier[] = ['exploited', 'likely', 'watch', 'quiet'];

export default function Check() {
  useTitle('Check your dependencies');
  useKnobUrl();
  const level = useStore(knob);
  const now = useNow(60_000);
  const meta = useData(data.meta);
  const days = meta.status === 'ready' ? meta.data.window.days : null;

  const [held, setHeld] = useState<Held | null>(() => session.held());
  const [status, setStatus] = useState<Status>({ kind: 'idle' });
  const [failure, setFailure] = useState<Failure | null>(null);
  const [hint, setHint] = useState<string | null>(null);
  /** The summary of the last check, for the status region (screen readers hear it when it lands). */
  const [announce, setAnnounce] = useState<string | null>(null);
  const [indexState, setIndexState] = useState<IndexState>(() => (session.index() ? 'ready' : 'idle'));
  const [paste, setPaste] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [forced, setForced] = useState<FormatId | 'auto'>('auto');
  const [drag, setDrag] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);
  const resultsHead = useRef<HTMLHeadingElement>(null);
  const errorBox = useRef<HTMLDivElement>(null);
  const runId = useRef(0);
  const lastInput = useRef<Input | null>(null);

  const follow = (p: Promise<PackagesFile>) => {
    setIndexState(session.index() ? 'ready' : 'loading');
    p.then(
      (file) => {
        setIndexState('ready');
        warmFonts(file);
      },
      () => setIndexState('error'),
    );
  };
  /** The first interaction with the input card starts the one request for the index. */
  const touch = () => {
    if (!session.started()) follow(session.touch());
  };
  useEffect(() => {
    // Back from a CVE page: the load may still be under way.
    if (session.started() && !session.index()) follow(session.touch());
    // A file dropped next to the card must not replace the page with the file.
    const stop = (e: DragEvent) => {
      if (e.dataTransfer?.types.includes('Files')) e.preventDefault();
    };
    window.addEventListener('dragover', stop);
    window.addEventListener('drop', stop);
    return () => {
      window.removeEventListener('dragover', stop);
      window.removeEventListener('drop', stop);
    };
  }, []);

  // On a phone the message sits below the card: bring it into view (no smooth scrolling).
  useEffect(() => {
    if (failure) errorBox.current?.scrollIntoView({ block: 'nearest' });
  }, [failure]);

  // "Still loading the package index..." after 10 s.
  useEffect(() => {
    if (status.kind !== 'waiting' || status.slow) return;
    const id = window.setTimeout(() => setStatus((s) => (s.kind === 'waiting' ? { ...s, slow: true } : s)), 10_000);
    return () => window.clearTimeout(id);
  }, [status]);

  const run = async (input: Input) => {
    const id = ++runId.current;
    lastInput.current = input;
    setFailure(null);
    setHint(null);
    setAnnounce(null);
    const fmt = forced === 'auto' ? null : forced;
    let out;
    try {
      out = await session.run(input.text, input.file, {
        forced: fmt,
        onStage: (s) => id === runId.current && setStatus(s.stage === 'waiting' ? { kind: 'waiting', packages: s.packages, slow: false } : { kind: 'checking', packages: s.packages }),
      });
    } catch (e) {
      // A bug must not leave the page saying "Reading..." with Check disabled.
      if (id === runId.current) {
        setStatus({ kind: 'idle' });
        setHint('This file could not be read.');
      }
      throw e;
    }
    if (id !== runId.current) return;
    setStatus({ kind: 'idle' });
    if (!out.ok) {
      setFailure(out.failure);
      return;
    }
    lastInput.current = null;
    setHeld(out.held);
    setAnnounce(summaryText(out.held.result, days));
    requestAnimationFrame(() => resultsHead.current?.focus());
  };

  const readFile = async (f: File) => {
    touch();
    setFile(f);
    setHint(null);
    const big = fileTooLarge(f.size);
    if (big) {
      setFailure(big);
      return;
    }
    setFailure(null);
    setStatus({ kind: 'reading', name: f.name });
    await nextFrame();
    let text: string;
    try {
      text = await f.text();
    } catch {
      setStatus({ kind: 'idle' });
      setHint('The file could not be read. Try choosing it again.');
      return;
    }
    await run({ text, file: f.name });
  };

  const onCheck = () => {
    touch();
    if (paste.trim() !== '') void run({ text: paste, file: null });
    else if (file) void readFile(file);
    else setHint('Choose a file or paste one first.');
  };

  const retry = () => {
    runId.current++;
    follow(session.retry());
    const input = lastInput.current;
    if (input) void run(input);
    else setFailure(null);
  };

  const clear = () => {
    runId.current++;
    session.clear();
    lastInput.current = null;
    setHeld(null);
    setPaste('');
    setFile(null);
    setFailure(null);
    setHint(null);
    setAnnounce(null);
    setStatus({ kind: 'idle' });
    if (fileInput.current) fileInput.current.value = '';
  };

  const onPaste = (e: ClipboardEvent) => {
    touch();
    const big = pasteTooLarge(e.clipboardData?.getData('text').length ?? 0);
    if (big) {
      e.preventDefault();
      setFailure(big);
    }
  };

  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setDrag(false);
    touch();
    const f = e.dataTransfer?.files[0];
    if (f) {
      void readFile(f);
      return;
    }
    const text = e.dataTransfer?.getData('text') ?? '';
    const big = pasteTooLarge(text.length);
    if (big) setFailure(big);
    else if (text) setPaste(text);
  };

  const result = held?.result ?? null;
  const groups = useMemo(() => (result ? groupByTier(result.cves, level) : null), [result, level]);
  // Keyboard order follows the order on screen.
  const items = useMemo(() => (groups ? GROUP_ORDER.flatMap((g) => groups.get(g) ?? []) : []), [groups]);
  const position = useMemo(() => new Map(items.map((c, i) => [c.row.id, i])), [items]);

  const [sel, setSel] = useState(-1);
  const selRef = useRef(-1);
  const focusNext = useRef(false);
  useEffect(() => {
    selRef.current = -1;
    setSel(-1);
  }, [result]);
  useEffect(() => {
    const id = items[sel]?.row.id;
    if (!id || !focusNext.current) return;
    focusNext.current = false;
    requestAnimationFrame(() => document.querySelector<HTMLElement>(`[data-row-link="${id}"]`)?.focus());
  }, [sel]);
  const select = (i: number) => {
    selRef.current = i;
    setSel(i);
  };
  // Opening a CVE, copying it or watching its vendor is the user's own action, as on every page.
  // Nothing here prefetches a shard on hover or selection: which shard would depend on the file.
  useListController({
    move: (d) => {
      if (items.length === 0) return;
      focusNext.current = true;
      select(Math.min(items.length - 1, Math.max(0, selRef.current + d)));
    },
    open: () => items[selRef.current] && navigate(cveHref(items[selRef.current].row.id)),
    watch: () => items[selRef.current] && watchVendorOf(items[selRef.current].row),
    copy: () => items[selRef.current] && void copyTicket(items[selRef.current].row.id),
  });

  const tierCounts = groups ? tierGroups.map((t) => [t, groups.get(t)?.length ?? 0] as const).filter(([, n]) => n > 0) : [];
  const possible = groups?.get('possible')?.length ?? 0;
  const busy = status.kind !== 'idle';

  const renderRow = (c: CveHit) => {
    const i = position.get(c.row.id) ?? -1;
    return (
      <CveRow
        key={c.row.id}
        row={c.row}
        tier={tierAt(c.row, level)}
        knob={level}
        now={now}
        selected={i === sel}
        onSelect={() => i !== selRef.current && select(i)}
        note={<Packages packages={c.packages} />}
      />
    );
  };

  return (
    <div class="page page--check">
      <header class="page__head">
        <p class="eyebrow">Your dependencies</p>
        <h1 class="page__title" tabIndex={-1}>
          Does this affect me?
        </h1>
        <p class="page__lede">
          Drop an SBOM or a lockfile to see which of the CVEs {BRAND.name} tracks affect your packages, with each CVE’s verdict. Your file is read here in your browser and never uploaded.
        </p>
      </header>

      <section
        class={`panel check__card${drag ? ' is-drag' : ''}`}
        aria-labelledby="check-input"
        onFocusIn={touch}
        onPointerDown={touch}
        onPaste={touch}
        onDragEnter={(e) => {
          e.preventDefault();
          touch();
          setDrag(true);
        }}
        onDragOver={(e) => {
          e.preventDefault();
          if (!drag) setDrag(true);
        }}
        onDragLeave={(e) => {
          const to = e.relatedTarget as Node | null;
          if (!to || !(e.currentTarget as HTMLElement).contains(to)) setDrag(false);
        }}
        onDrop={onDrop}
      >
        <h2 class="sr-only" id="check-input">
          Your file
        </h2>
        <div class="check__drop">
          <p class="check__droptitle">Drop a file here</p>
          <label class="btn btn--primary check__pick">
            <input
              ref={fileInput}
              type="file"
              class="sr-only user-text"
              onChange={(e) => {
                const f = (e.currentTarget as HTMLInputElement).files?.[0];
                if (f) void readFile(f);
              }}
            />
            Choose a file
          </label>
          <p class="muted">or paste it below</p>
        </div>
        {file && (
          <p class="check__file">
            File: <UserText>{file.name}</UserText> <span class="muted">({fmtSize(file.size)})</span>
          </p>
        )}
        <label class="check__label" for="check-paste">
          Paste an SBOM or lockfile
        </label>
        <textarea
          id="check-paste"
          class="check__paste user-text"
          rows={7}
          spellcheck={false}
          autocomplete="off"
          autocapitalize="off"
          data-gramm="false"
          value={paste}
          onInput={(e) => setPaste((e.currentTarget as HTMLTextAreaElement).value)}
          onPaste={onPaste}
        />
        <div class="check__controls">
          <label class="select">
            <span>Read as</span>
            <select value={forced} onChange={(e) => setForced(((v) => (isFormatId(v) ? v : 'auto'))((e.currentTarget as HTMLSelectElement).value))}>
              <option value="auto">Automatic</option>
              {FORMATS.map(([id, label]) => (
                <option key={id} value={id}>
                  {label}
                </option>
              ))}
            </select>
          </label>
          <button type="button" class="btn btn--primary" onClick={onCheck} disabled={busy}>
            Check
          </button>
          <button type="button" class="btn" onClick={clear}>
            Clear
          </button>
          <span class="check__limits">Files up to 50 MB, pasted text up to 5 MB.</span>
        </div>
        <p class="check__privacy">
          <IconLock size={13} />
          <span>
            Your file stays on your device. To check it, this page downloads one public file, the package index (the same for everyone), and compares your file with it in your browser. Nothing about your
            file is uploaded, logged or stored. The results stay in this tab’s memory until you press Clear, reload or close the tab. Opening a CVE, copying it as a ticket or watching its vendor works as
            on every other page. {BRAND.name} has no analytics and no cookies.
          </span>
        </p>
      </section>

      <div class="check__status" role="status">
        {status.kind === 'reading' ? (
          <p>
            Reading <UserText>{status.name}</UserText>...
          </p>
        ) : status.kind === 'checking' ? (
          <p>Checking {plural(status.packages, 'package')}...</p>
        ) : status.kind === 'waiting' ? (
          <p>
            {status.slow ? 'Still loading the package index...' : `Read ${plural(status.packages, 'package')}. Loading the package index...`}
            {status.slow && (
              <button type="button" class="btn btn--sm check__retry" onClick={retry}>
                <IconRefresh size={12} /> Retry
              </button>
            )}
          </p>
        ) : hint ? (
          <p>{hint}</p>
        ) : announce ? (
          <p class="sr-only">{announce}</p>
        ) : null}
      </div>
      {failure && (
        <div class="check__error" role="alert" ref={errorBox}>
          <IconAlert size={16} />
          <p>
            <FailureText failure={failure} />
          </p>
          {failure.kind === 'index' && !failure.notPublished && (
            <button type="button" class="btn btn--sm" onClick={retry}>
              <IconRefresh size={12} /> Retry
            </button>
          )}
        </div>
      )}

      {result && groups && (
        <section class="check__results" aria-labelledby="check-results">
          <h2 class="section__title" id="check-results" tabIndex={-1} ref={resultsHead}>
            Results{held?.file ? <> for <UserText>{held.file}</UserText></> : null}
          </h2>
          <p class="check__summary">{summaryText(result, days)}</p>
          {(tierCounts.length > 0 || possible > 0) && (
            <p class="check__counts" aria-label="Affecting CVEs by tier">
              {tierCounts.map(([t, n]) => (
                <span key={t} class="check__count">
                  <TierPill tier={t} size="sm" /> <span class="mono">{fmtInt(n)}</span>
                </span>
              ))}
              {possible > 0 && (
                <span class="check__count check__count--possible">
                  Possibly affected <span class="mono">{fmtInt(possible)}</span>
                </span>
              )}
            </p>
          )}
          {result.notes.length > 0 && (
            <ul class="check__notes">
              {result.notes.map((n) => (
                <li key={n}>
                  <IconAlert size={12} /> {n}
                </li>
              ))}
            </ul>
          )}
          {GROUP_ORDER.map((g) => {
            const list = groups.get(g) ?? [];
            if (list.length === 0) return null;
            return (
              <section key={g} class="batchday check__group" aria-labelledby={`check-g-${g}`}>
                <header class="batchday__head">
                  <h3 class="batchday__date" id={`check-g-${g}`}>
                    {GROUP_LABEL[g]}
                  </h3>
                  <span class="batchday__sum">{plural(list.length, 'CVE')}</span>
                </header>
                {g === 'possible' && <p class="check__groupnote">A tracked CVE may affect these packages, but we could not confirm it: the reason is under each package. Check them against the advisory.</p>}
                <div class="rows">{list.map(renderRow)}</div>
              </section>
            );
          })}
          <More title="Not checked" count={result.distinct - result.checked}>
            {() =>
              result.notChecked.map((g) => (
                <div key={`${g.reason}:${g.eco ?? ''}`} class="check__skip">
                  <p class="check__skipwhy">{notCheckedText(g)}</p>
                  <NameList items={g.items} />
                </div>
              ))
            }
          </More>
          <More title="Not affected by a tracked CVE" count={result.clean.length}>
            {() => (
              <>
                <p class="check__skipwhy">A tracked CVE may name some of these packages, but not the versions you use.</p>
                <NameList items={result.clean} />
              </>
            )}
          </More>
        </section>
      )}

      <Coverage index={session.index()} state={indexState} days={days} />

      <details class="panel check__accepted" key={result ? 'after' : 'before'} open={!result}>
        <summary class="panel__title">Accepted files, and how to make an SBOM</summary>
        <ul>
          <li>
            SBOMs: CycloneDX (JSON or XML), SPDX (JSON or tag-value), or a list of package URLs (<code>pkg:npm/lodash@4.17.21</code>).
          </li>
          <li>
            Lockfiles: package-lock.json, npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml, requirements.txt (pinned with <code>==</code>), poetry.lock, uv.lock, Pipfile.lock, go.mod, go.sum, Cargo.lock,
            Gemfile.lock, composer.lock, packages.lock.json (NuGet), gradle.lockfile.
          </li>
          <li>Not read: pom.xml and build.gradle, because they do not list the versions your build resolves. Make an SBOM instead:</li>
        </ul>
        <ul class="check__cmds">
          <li>
            <code>npm sbom --sbom-format cyclonedx &gt; bom.json</code>
          </li>
          <li>
            <code>syft dir:. -o cyclonedx-json &gt; bom.json</code>
          </li>
          <li>
            <code>trivy fs --format cyclonedx --output bom.json .</code>
          </li>
          <li>
            <code>mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom</code> (writes <code>target/bom.json</code>)
          </li>
        </ul>
      </details>

      <p class="fineprint">
        “Affected” means the version is inside the advisory’s range, not that your code reaches the vulnerable part. Forks and vendored builds may not follow the registry’s version numbers, and go.sum or
        an unpinned requirement can name versions you do not run. Package and version data:{' '}
        {ATTRIBUTION.map((a, i) => (
          <span key={a.name}>
            {i > 0 && (i === ATTRIBUTION.length - 1 ? ' and ' : ', ')}
            <ExtLink href={a.url} icon={false}>
              {a.name.replace(/ \(OSV\)$/, '')}
            </ExtLink>{' '}
            ({a.license.replace(/ \((.*)\)$/, ', $1')})
          </span>
        ))}
        , through <ExtLink href="https://osv.dev/" icon={false}>OSV.dev</ExtLink>. {BRAND.name} keeps only advisory IDs, package names and version ranges for the CVEs it tracks. Verdicts are {BRAND.name}’s own
        (CC0-1.0).
      </p>
    </div>
  );
}
