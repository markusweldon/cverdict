/**
 * Version orderings for the package ecosystems of v1/packages.json, and the OSV range rule.
 *
 * Used by the pipeline (extra versions, validation) and by the site (matching an SBOM), so the
 * two can never disagree about what a range means. No Node or DOM APIs.
 *
 * One comparator per ordering: SemVer 2.0 (npm, crates.io, Go), PEP 440 (PyPI), Gem::Version
 * (RubyGems), NuGet, Maven ComparableVersion and Composer (Packagist). `parse()` returns null for
 * a string the ordering does not accept; callers treat that as "version not checked", never as
 * "not affected". Every string longer than MAX_VERSION is rejected before any regex or loop runs.
 */
import type { PackageEcosystem } from './contract';

/** No real version is longer; longer strings are not comparable (bounds every parser's work). */
export const MAX_VERSION = 128;

export interface Comparator<K = unknown> {
  /** Parsed form of `version`, or null when the ordering does not accept it. */
  parse(version: string): K | null;
  /** Negative, zero or positive, like Array.prototype.sort. */
  cmp(a: K, b: K): number;
}

const DIGITS = /^\d+$/;

/** Numeric comparison of two digit strings of any length (leading zeros allowed). */
function cmpDigits(a: string, b: string): number {
  let i = 0;
  let j = 0;
  while (i < a.length - 1 && a[i] === '0') i++;
  while (j < b.length - 1 && b[j] === '0') j++;
  const la = a.length - i;
  const lb = b.length - j;
  if (la !== lb) return la < lb ? -1 : 1;
  for (; i < a.length; i++, j++) if (a[i] !== b[j]) return a[i] < b[j] ? -1 : 1;
  return 0;
}

const cmpText = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/** Wrap a parser with the length cap and trimming every comparator shares. */
function capped<K>(parse: (v: string) => K | null): (v: string) => K | null {
  return (v) => {
    if (typeof v !== 'string' || v.length > MAX_VERSION) return null;
    const s = v.trim();
    return s === '' ? null : parse(s);
  };
}

/** SemVer 2.0 prerelease identifiers (null: a release). Numeric < alphanumeric; more identifiers win. */
function cmpPrerelease(a: readonly string[] | null, b: readonly string[] | null): number {
  if (!a || !b) return a ? -1 : b ? 1 : 0;
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i];
    const y = b[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const xn = DIGITS.test(x);
    const yn = DIGITS.test(y);
    const c = xn && yn ? cmpDigits(x, y) : xn !== yn ? (xn ? -1 : 1) : cmpText(x, y);
    if (c !== 0) return c;
  }
  return 0;
}

// ── SemVer 2.0: npm, crates.io, Go (an optional leading "v"; "+incompatible" is build metadata) ──

interface SemverKey {
  n: [string, string, string];
  pre: string[] | null;
}

const SEMVER_RE =
  /^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

export const semver: Comparator<SemverKey> = {
  parse: capped((s) => {
    const m = SEMVER_RE.exec(s);
    return m ? { n: [m[1], m[2], m[3]], pre: m[4] ? m[4].split('.') : null } : null;
  }),
  cmp(a, b) {
    for (let i = 0; i < 3; i++) {
      const c = cmpDigits(a.n[i], b.n[i]);
      if (c !== 0) return c;
    }
    return cmpPrerelease(a.pre, b.pre);
  },
};

// ── PEP 440: PyPI ──

interface Pep440Key {
  epoch: string;
  release: string[];
  /** [letter rank, number] or null. */
  pre: [number, string] | null;
  post: string | null;
  dev: string | null;
  local: string[] | null;
}

const PEP440_RE =
  /^v?(?:(\d+)!)?(\d+(?:\.\d+)*)(?:[-_.]?(alpha|beta|preview|pre|rc|a|b|c)[-_.]?(\d+)?)?(?:-(\d+)|[-_.]?(post|rev|r)[-_.]?(\d+)?)?(?:[-_.]?(dev)[-_.]?(\d+)?)?(?:\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?$/i;
const PRE_RANK: Readonly<Record<string, number>> = { a: 0, alpha: 0, b: 1, beta: 1, c: 2, rc: 2, pre: 2, preview: 2 };

/** Rank of the pre-release part: a dev-only release sorts first, then pre-releases, then none. */
function pepPreKey(k: Pep440Key): [number, number, string] {
  if (k.pre) return [1, k.pre[0], k.pre[1]];
  return k.post === null && k.dev !== null ? [0, 0, '0'] : [2, 0, '0'];
}

export const pep440: Comparator<Pep440Key> = {
  parse: capped((s) => {
    const m = PEP440_RE.exec(s);
    if (!m) return null;
    const release = m[2].split('.');
    while (release.length > 1 && /^0+$/.test(release[release.length - 1])) release.pop();
    return {
      epoch: m[1] ?? '0',
      release,
      pre: m[3] ? [PRE_RANK[m[3].toLowerCase()], m[4] ?? '0'] : null,
      post: m[5] !== undefined ? m[5] : m[6] ? (m[7] ?? '0') : null,
      dev: m[8] ? (m[9] ?? '0') : null,
      local: m[10] ? m[10].toLowerCase().split(/[-_.]/) : null,
    };
  }),
  cmp(a, b) {
    let c = cmpDigits(a.epoch, b.epoch);
    if (c !== 0) return c;
    for (let i = 0; i < Math.max(a.release.length, b.release.length); i++) {
      c = cmpDigits(a.release[i] ?? '0', b.release[i] ?? '0');
      if (c !== 0) return c;
    }
    const pa = pepPreKey(a);
    const pb = pepPreKey(b);
    c = pa[0] - pb[0] || pa[1] - pb[1] || cmpDigits(pa[2], pb[2]);
    if (c !== 0) return c;
    // No post-release sorts before any post-release.
    if ((a.post === null) !== (b.post === null)) return a.post === null ? -1 : 1;
    if (a.post !== null && b.post !== null) {
      c = cmpDigits(a.post, b.post);
      if (c !== 0) return c;
    }
    // A dev release sorts before the same version without one.
    if ((a.dev === null) !== (b.dev === null)) return a.dev === null ? 1 : -1;
    if (a.dev !== null && b.dev !== null) {
      c = cmpDigits(a.dev, b.dev);
      if (c !== 0) return c;
    }
    // No local label sorts first; numeric segments sort above alphanumeric ones.
    if ((a.local === null) !== (b.local === null)) return a.local === null ? -1 : 1;
    if (a.local && b.local) {
      for (let i = 0; i < Math.max(a.local.length, b.local.length); i++) {
        const x = a.local[i];
        const y = b.local[i];
        if (x === undefined) return -1;
        if (y === undefined) return 1;
        const xn = DIGITS.test(x);
        const yn = DIGITS.test(y);
        c = xn && yn ? cmpDigits(x, y) : xn !== yn ? (xn ? 1 : -1) : cmpText(x, y);
        if (c !== 0) return c;
      }
    }
    return 0;
  },
};

// ── Gem::Version: RubyGems ──

/** Canonical segments: numbers as digit strings, letters as strings (marked by a leading letter). */
type GemKey = string[];

const GEM_RE = /^[0-9]+(?:\.[0-9a-zA-Z]+)*(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const isNumSeg = (s: string) => s.charCodeAt(0) >= 48 && s.charCodeAt(0) <= 57;

export const rubygems: Comparator<GemKey> = {
  parse: capped((s) => {
    if (!GEM_RE.test(s)) return null;
    const segs = s.replace(/-/g, '.pre.').match(/[0-9]+|[a-z]+/gi) ?? [];
    // Gem::Version#canonical_segments: trailing zeros go from the numeric part and from the rest.
    let split = segs.findIndex((x) => !isNumSeg(x));
    if (split < 0) split = segs.length;
    const trim = (xs: string[]) => {
      while (xs.length > 0 && isNumSeg(xs[xs.length - 1]) && /^0+$/.test(xs[xs.length - 1])) xs.pop();
      return xs;
    };
    return [...trim(segs.slice(0, split)), ...trim(segs.slice(split))];
  }),
  cmp(a, b) {
    for (let i = 0; i < Math.max(a.length, b.length); i++) {
      const x = a[i] ?? '0';
      const y = b[i] ?? '0';
      const xn = isNumSeg(x);
      const yn = isNumSeg(y);
      if (xn && yn) {
        const c = cmpDigits(x, y);
        if (c !== 0) return c;
      } else if (xn !== yn) {
        return xn ? 1 : -1;
      } else if (x !== y) {
        return x < y ? -1 : 1;
      }
    }
    return 0;
  },
};

// ── NuGet: up to four numbers, case-insensitive prerelease labels, metadata ignored ──

interface NugetKey {
  n: [string, string, string, string];
  pre: string[] | null;
}

const NUGET_RE = /^v?(\d+(?:\.\d+){0,3})(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

export const nuget: Comparator<NugetKey> = {
  parse: capped((s) => {
    const m = NUGET_RE.exec(s);
    if (!m) return null;
    const parts = m[1].split('.');
    while (parts.length < 4) parts.push('0');
    return { n: parts as NugetKey['n'], pre: m[2] ? m[2].toLowerCase().split('.') : null };
  }),
  cmp(a, b) {
    for (let i = 0; i < 4; i++) {
      const c = cmpDigits(a.n[i], b.n[i]);
      if (c !== 0) return c;
    }
    return cmpPrerelease(a.pre, b.pre);
  },
};

// ── Maven ComparableVersion, as the Maven version order specification describes it ──
//
// The version is split into tokens at ".", "-" and every transition between digits and letters
// (a transition counts as "-"); each token remembers its separator. Trailing "null" tokens (0, "",
// "final", "ga", "release") are trimmed from the end, and again before every remaining "-". Tokens
// compare left to right; past the end of the shorter version, tokens compare with a null item.
// Flat and iterative: no nesting, so hostile input cannot recurse.

interface MavenToken {
  /** "." or "-". */
  sep: string;
  /** Digit string for a number; null for a qualifier. */
  num: string | null;
  /** Qualifier (lower case, aliases resolved); "" for a number. */
  qual: string;
}
type MavenKey = MavenToken[];

/** Known qualifiers in order; "" is the release. Unknown qualifiers sort after all of them. */
const MAVEN_QUALIFIERS = ['alpha', 'beta', 'milestone', 'rc', 'snapshot', '', 'sp'];
const MAVEN_ALIASES: Readonly<Record<string, string>> = { ga: '', final: '', release: '', cr: 'rc' };
const MAVEN_SHORT: Readonly<Record<string, string>> = { a: 'alpha', b: 'beta', m: 'milestone' };

function mavenQualifier(q: string): string {
  return Object.hasOwn(MAVEN_ALIASES, q) ? MAVEN_ALIASES[q] : q;
}

function cmpQualifier(a: string, b: string): number {
  const ia = MAVEN_QUALIFIERS.indexOf(a);
  const ib = MAVEN_QUALIFIERS.indexOf(b);
  if (ia >= 0 && ib >= 0) return ia - ib;
  if (ia >= 0 || ib >= 0) return ia >= 0 ? -1 : 1;
  return cmpText(a, b);
}

const isMavenNull = (t: MavenToken) => (t.num !== null ? /^0+$/.test(t.num) : t.qual === '');

/** Qualifier < "-" number < "." number; numbers by value, qualifiers by the known order. */
function cmpMavenToken(a: MavenToken, b: MavenToken): number {
  if (a.num === null && b.num === null) return cmpQualifier(a.qual, b.qual);
  if (a.num === null || b.num === null) return a.num === null ? -1 : 1;
  if (a.sep !== b.sep) return a.sep === '-' ? -1 : 1;
  return cmpDigits(a.num, b.num);
}

/**
 * A token compared with nothing (the shorter version ran out): a number with 0, a qualifier with
 * the release qualifier "", whatever the separator. So "7.2.2.v20101205" is above "7.2.2" and
 * "1-SNAPSHOT" below "1", as Maven and OSV.dev order them.
 */
function cmpMavenToNull(t: MavenToken): number {
  return t.num !== null ? (/^0+$/.test(t.num) ? 0 : 1) : cmpQualifier(t.qual, '');
}

export const maven: Comparator<MavenKey> = {
  parse: capped((raw) => {
    if (/\s/.test(raw)) return null;
    const s = raw.toLowerCase();
    const tokens: MavenToken[] = [];
    let sep = '.';
    let start = 0;
    const push = (end: number, nextSep: string, followedByDigit: boolean) => {
      const text = s.slice(start, end);
      if (text === '') tokens.push({ sep, num: '0', qual: '' });
      else if (/^\d/.test(text)) tokens.push({ sep, num: text, qual: '' });
      else {
        const q = followedByDigit && Object.hasOwn(MAVEN_SHORT, text) ? MAVEN_SHORT[text] : text;
        tokens.push({ sep, num: null, qual: mavenQualifier(q) });
      }
      sep = nextSep;
    };
    for (let i = 0; i < s.length; i++) {
      const ch = s[i];
      if (ch === '.' || ch === '-') {
        push(i, ch, false);
        start = i + 1;
      } else if (i > start) {
        const digit = ch >= '0' && ch <= '9';
        const prevDigit = s[i - 1] >= '0' && s[i - 1] <= '9';
        if (digit !== prevDigit) {
          // A transition between digits and letters counts as "-".
          push(i, '-', digit);
          start = i;
        }
      }
    }
    if (start < s.length) push(s.length, '.', false);
    else if (s.length > 0 && (s.endsWith('.') || s.endsWith('-'))) push(s.length, '.', false);
    // Trim trailing nulls, then again before each remaining "-", from the end to the start.
    let i = tokens.length - 1;
    while (i > 0) {
      if (isMavenNull(tokens[i])) {
        tokens.splice(i, 1);
        i--;
        continue;
      }
      while (i >= 0 && tokens[i].sep !== '-') i--;
      i--;
    }
    return tokens;
  }),
  cmp(a, b) {
    for (let i = 0; i < Math.max(a.length, b.length); i++) {
      const c = i >= a.length ? -cmpMavenToNull(b[i]) : i >= b.length ? cmpMavenToNull(a[i]) : cmpMavenToken(a[i], b[i]);
      if (c !== 0) return c;
    }
    return 0;
  },
};

// ── Composer: Packagist ──

interface ComposerKey {
  n: [string, string, string, string];
  /** dev 0 < alpha 1 < beta 2 < RC 3 < stable 4 < patch 5. */
  stability: number;
  numbers: string[];
  dev: boolean;
}

// The numbers after the stability are written `\d*(?:[.-]\d+)*`, not Composer's `(?:[.-]?\d+)*+`:
// JavaScript has no possessive quantifier, and that nested form splits a run of digits in
// exponentially many ways before failing (a 40-character version took minutes). Same strings matched.
const COMPOSER_RE =
  /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?(?:[._-]?(stable|beta|b|rc|alpha|a|patch|pl|p)(\d*(?:[.-]\d+)*))?([._-]?dev)?$/;
const COMPOSER_STABILITY: Readonly<Record<string, number>> = { alpha: 1, a: 1, beta: 2, b: 2, rc: 3, stable: 4, patch: 5, pl: 5, p: 5 };

export const composer: Comparator<ComposerKey> = {
  parse: capped((raw) => {
    const m = COMPOSER_RE.exec(raw.toLowerCase());
    if (!m) return null;
    const dev = m[7] !== undefined;
    const stability = m[5] ? COMPOSER_STABILITY[m[5]] : dev ? 0 : 4;
    return {
      n: [m[1], m[2] ?? '0', m[3] ?? '0', m[4] ?? '0'],
      stability,
      numbers: (m[6] ?? '').split(/[.-]/).filter((x) => x !== ''),
      // "1.0.0-dev" is the dev stability itself; "1.0.0-beta1-dev" is the dev build of beta1.
      dev: dev && m[5] !== undefined,
    };
  }),
  cmp(a, b) {
    for (let i = 0; i < 4; i++) {
      const c = cmpDigits(a.n[i], b.n[i]);
      if (c !== 0) return c;
    }
    if (a.stability !== b.stability) return a.stability - b.stability;
    for (let i = 0; i < Math.max(a.numbers.length, b.numbers.length); i++) {
      const c = cmpDigits(a.numbers[i] ?? '0', b.numbers[i] ?? '0');
      if (c !== 0) return c;
    }
    if (a.dev !== b.dev) return a.dev ? -1 : 1;
    return 0;
  },
};

export const COMPARATORS: Readonly<Record<PackageEcosystem, Comparator>> = {
  npm: semver as Comparator,
  'crates.io': semver as Comparator,
  Go: semver as Comparator,
  PyPI: pep440 as Comparator,
  RubyGems: rubygems as Comparator,
  NuGet: nuget as Comparator,
  Maven: maven as Comparator,
  Packagist: composer as Comparator,
};

// ── OSV ranges ──

export type RangeEvent = { op: '>=' | '<' | '<='; v: string } | { op: '?'; kind: string; v: string };

/** ">=V" introduced, "<V" fixed, "<=V" last affected, "?kind=V" anything else; null if malformed. */
export function parseEvent(event: string): RangeEvent | null {
  if (typeof event !== 'string') return null;
  if (event.startsWith('>=')) return { op: '>=', v: event.slice(2) };
  if (event.startsWith('<=')) return { op: '<=', v: event.slice(2) };
  if (event.startsWith('<')) return { op: '<', v: event.slice(1) };
  const m = /^\?([a-z_]{1,32})=([^\s]{0,128})$/.exec(event);
  return m ? { op: '?', kind: m[1], v: m[2] } : null;
}

/** "introduced: 0" (and RustSec's "0.0.0-0") means "from the first release". */
export const isFirstRelease = (v: string) => v === '0' || v === '0.0.0-0';

/** True affected, false not affected, null cannot say. */
export type RangeTest = (version: string) => boolean | null;

interface CompiledEvent {
  op: '>=' | '<' | '<=';
  /** null for "from the first release". */
  key: unknown;
}

/** Parse a range's events once; null when one of them cannot be evaluated. */
function compileRange(c: Comparator, events: readonly string[]): CompiledEvent[] | null {
  if (events.length === 0) return null;
  const out: CompiledEvent[] = [];
  for (const e of events) {
    const p = parseEvent(e);
    if (!p || p.op === '?') return null;
    if (p.op === '>=' && p.v === '0') {
      out.push({ op: '>=', key: null });
      continue;
    }
    const key = c.parse(p.v);
    if (key === null) return null;
    out.push({ op: p.op, key });
  }
  // Events in version order, "from the first release" first; the sort is stable.
  return out.sort((x, y) => (x.key === null ? (y.key === null ? 0 : -1) : y.key === null ? 1 : c.cmp(x.key, y.key)));
}

/**
 * The OSV evaluation of `ranges` for one ecosystem, compiled once. Per range, walk the events in
 * version order: an introduced event at or below the version turns "affected" on, a fixed event
 * at or below it turns it off, a last-affected event below it turns it off. The version is
 * affected when any range ends on; otherwise unknown (null) when a range could not be evaluated
 * (an unparseable bound or a "?" event) or the version does not parse; otherwise not affected.
 */
export function compileRanges(eco: PackageEcosystem, ranges: readonly (readonly string[])[]): RangeTest {
  const c = COMPARATORS[eco];
  const compiled = ranges.map((r) => compileRange(c, r));
  const someUnknown = compiled.includes(null);
  return (version) => {
    const v = c.parse(version);
    if (v === null) return null;
    for (const events of compiled) {
      if (!events) continue;
      let affected = false;
      for (const { op, key } of events) {
        if (op === '>=') {
          if (key === null || c.cmp(v, key) >= 0) affected = true;
        } else if (op === '<') {
          if (c.cmp(v, key) >= 0) affected = false;
        } else if (c.cmp(v, key) > 0) {
          affected = false;
        }
      }
      if (affected) return true;
    }
    return someUnknown ? null : false;
  };
}

export function inRanges(eco: PackageEcosystem, version: string, ranges: readonly (readonly string[])[]): boolean | null {
  return compileRanges(eco, ranges)(version);
}

/** Listed versions the ranges do not cover (or cannot place): they must match as exact strings. */
export function extraVersions(eco: PackageEcosystem, versions: readonly string[], ranges: readonly (readonly string[])[]): string[] {
  const test = compileRanges(eco, ranges);
  return [...new Set(versions)].filter((v) => test(v) !== true);
}

/** What one advisory entry says about one version (section 6.1 of the design). */
export type AffectVerdict = 'affected' | 'unchecked' | 'not_affected';

/**
 * `version` null means "no exact version". A listed extra version matches as an exact string, or
 * as an equal version when both parse; then the ranges decide. An entry with no range and no
 * listed version cannot be evaluated, so it is "unchecked", never "not affected".
 */
export function matchAffect(
  eco: PackageEcosystem,
  version: string | null,
  ranges: readonly (readonly string[])[],
  extra: readonly string[] = [],
): AffectVerdict {
  if (version === null || version === '') return 'unchecked';
  if (extra.includes(version)) return 'affected';
  const c = COMPARATORS[eco];
  const v = c.parse(version);
  if (v !== null && extra.some((x) => {
    const k = c.parse(x);
    return k !== null && c.cmp(v, k) === 0;
  })) return 'affected';
  if (ranges.length === 0) return extra.length > 0 && v !== null ? 'not_affected' : 'unchecked';
  const r = compileRanges(eco, ranges)(version);
  return r === true ? 'affected' : r === null ? 'unchecked' : 'not_affected';
}
