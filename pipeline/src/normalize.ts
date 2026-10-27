/**
 * CVE JSON 5.x record → NormalizedCve (SPEC §2 "Normalisation").
 *
 * Records are untrusted and loosely shaped: every field is read defensively, unknown fields are
 * ignored, and missing containers produce empty values rather than errors. All text is
 * sanitised plain text.
 */
import type { Cvss, Ssvc } from '../../shared/contract';
import { CISA_ADP } from './config';
import type { NormalizedCve } from './types';
import { normalizeIso, normalizeYmd, parseIsoDate } from './util/dates';
import { asArray, asNumber, asObject, asString, type JsonObject } from './util/json';
import { clip, normalizeCveId, sanitizeLine, sanitizeText, sanitizeUrl, truncate } from './util/text';

const MAX_DESCRIPTION = 1_000;
const MAX_TITLE = 300;
const MAX_NAME = 200;
const MAX_AFFECTED = 10;
const MAX_REFERENCES = 10;
const MAX_LIST = 10;
const MAX_AI_CREDIT = 80;
const MAX_NOISE_TEXT = 4_096;

/** The `cveMetadata` fields every record contributes (history counters, window/KEV decisions). */
export interface CveMeta {
  id: string;
  /** Upper-cased state, e.g. "PUBLISHED" or "REJECTED". */
  state: string;
  assigner: string;
  published: Date | null;
  reserved: Date | null;
  updated: Date | null;
  rejected: Date | null;
}

/** Cheap first look at a parsed record. Null when it has no valid CVE ID. */
export function readCveMeta(record: unknown): CveMeta | null {
  const root = asObject(record);
  const md = asObject(root?.cveMetadata);
  const id = normalizeCveId(md?.cveId);
  if (!md || !id) return null;
  const cnaProvider = asObject(cnaOf(root)?.providerMetadata);
  return {
    id,
    state: (asString(md.state) ?? '').trim().toUpperCase(),
    assigner: sanitizeLine(asString(md.assignerShortName) ?? cnaProvider?.shortName, 64),
    published: parseIsoDate(md.datePublished),
    reserved: parseIsoDate(md.dateReserved),
    updated: parseIsoDate(md.dateUpdated),
    rejected: parseIsoDate(md.dateRejected),
  };
}

interface Containers {
  cna: JsonObject | null;
  /** ADP containers published by CISA (normally at most one). */
  cisaAdp: JsonObject[];
}

function containersOf(record: unknown): Containers {
  const containers = asObject(asObject(record)?.containers);
  const cisaAdp: JsonObject[] = [];
  for (const entry of asArray(containers?.adp)) {
    const adp = asObject(entry);
    if (adp && isCisaAdp(adp)) cisaAdp.push(adp);
  }
  return { cna: asObject(containers?.cna), cisaAdp };
}

function cnaOf(record: unknown): JsonObject | null {
  return asObject(asObject(asObject(record)?.containers)?.cna);
}

function isCisaAdp(adp: JsonObject): boolean {
  return asString(asObject(adp.providerMetadata)?.shortName)?.trim().toUpperCase() === CISA_ADP.shortName;
}

/** Cheap per-record check: is there a CISA-ADP container, and does it carry a KEV block? */
export function cisaAdpFlags(record: unknown): { present: boolean; kev: boolean } {
  const { cisaAdp } = containersOf(record);
  return { present: cisaAdp.length > 0, kev: cisaAdp.some((adp) => adpOther(adp, 'kev') !== null) };
}

// ---------------------------------------------------------------------------------------------
// AI credit

const AI_CREDIT_RE =
  /\b(claude|anthropic|openai|gpt-?\d|codex|aardvark|big ?sleep|gemini|xbow|zeropath|depthfirst|striga|zerotrail|mythos|glasswing|llm|large language model|agentic|ai[- ](assisted|agent|powered|driven|discovered|found|security|scanner))\b/i;
/** A handle ending in `-ai` or `.ai`, e.g. "zerotrail-ai", "striga.ai". */
const AI_HANDLE_RE = /(?<![\w.-])[a-z0-9][\w.-]*[.-]ai(?![\w-])/i;

/** The first CNA credit that names an AI system or lab (≤ 80 chars), or null. */
export function findAiCredit(cna: JsonObject | null): string | null {
  for (const credit of asArray(cna?.credits)) {
    const value = sanitizeLine(asObject(credit)?.value, 1_000);
    if (value && (AI_CREDIT_RE.test(value) || AI_HANDLE_RE.test(value))) return truncate(value, MAX_AI_CREDIT);
  }
  return null;
}

/** AI credit of a whole record (used by the streaming pass for every record). */
export function recordAiCredit(record: unknown): string | null {
  return findAiCredit(cnaOf(record));
}

// ---------------------------------------------------------------------------------------------
// "Exploited in the wild" vendor text

const ITW_RE =
  /\b(exploited in the wild|exists in the wild|in the wild|aware of (a )?reports?|may have been exploited|limited,? (and )?(highly )?targeted attacks?|actively exploited|exploitation detected|has been exploited)\b/i;
/**
 * SPEC negation guard with three refinements, each needed by real records:
 * - `n't` also matches inside contractions ("isn't", "haven’t"); `\bn't\b` never can;
 * - the window is 60 characters, so "There is no evidence that this vulnerability has been
 *   exploited in the wild" (CVE-2025-43027, CVE-2026-45776…45779; 43 chars) is negated;
 * - it is applied per sentence (see mentionsInTheWild).
 */
const ITW_NEGATION_RE = /(?:\b(?:no|not|unaware|without)\b|n['’]t\b)[^.]{0,60}\b(?:exploit|in the wild)/i;
const SENTENCE_BREAK_RE = /(?<=[.!?])\s+|\n+/;

/**
 * True when some sentence says the bug is exploited in the wild and that same sentence is not
 * negated. Per-sentence scoping keeps a later, unrelated negation from cancelling a positive
 * statement, e.g. CVE-2026-48172: "…as exploited in the wild in May 2026. … If there is no
 * output, you have not been hit with exploitation".
 */
export function mentionsInTheWild(text: string): boolean {
  if (!ITW_RE.test(text)) return false;
  return text.split(SENTENCE_BREAK_RE).some((sentence) => ITW_RE.test(sentence) && !ITW_NEGATION_RE.test(sentence));
}

// ---------------------------------------------------------------------------------------------
// CVSS

const CVSS_KEYS = [
  { key: 'cvssV4_0', version: '4.0' },
  { key: 'cvssV3_1', version: '3.1' },
  { key: 'cvssV3_0', version: '3.0' },
] as const;
const CVSS_V2 = { key: 'cvssV2_0', version: '2.0' } as const;

/** Allowed exploit-maturity (`E`) values per CVSS version; `X` (not defined) is ignored. */
const EXPLOIT_MATURITY: Record<string, ReadonlySet<string>> = {
  '4.0': new Set(['U', 'P', 'A']),
  '3.1': new Set(['U', 'P', 'F', 'H']),
  '3.0': new Set(['U', 'P', 'F', 'H']),
};

const VECTOR_KEY_RE = /^[A-Za-z]{1,5}$/;
const VECTOR_VALUE_RE = /^[A-Za-z0-9]{1,10}$/;

/** "CVSS:3.1/AV:N/AC:L/…" (or a v2 "(AV:N/…)") → { AV: 'N', AC: 'L', … }. Malformed parts are skipped. */
export function parseCvssVector(vector: string): Record<string, string> {
  const metrics: Record<string, string> = {};
  for (const part of vector.trim().replace(/^\(|\)$/g, '').split('/')) {
    const colon = part.indexOf(':');
    const key = part.slice(0, colon).trim();
    const value = part.slice(colon + 1).trim();
    if (colon > 0 && key !== 'CVSS' && VECTOR_KEY_RE.test(key) && VECTOR_VALUE_RE.test(value)) metrics[key] = value;
  }
  return metrics;
}

/** First valid metric of `key` in a container's `metrics[]`. */
function cvssOf(metrics: readonly unknown[], key: string, version: string, source: Cvss['source']): Cvss | null {
  for (const entry of metrics) {
    const m = asObject(asObject(entry)?.[key]);
    const score = asNumber(m?.baseScore);
    if (!m || score === null || score < 0 || score > 10) continue;
    return {
      version,
      score,
      severity: sanitizeLine(m.baseSeverity, 16).toUpperCase() || null,
      vector: sanitizeLine(m.vectorString, 256).replace(/\s+/g, ''),
      source,
    };
  }
  return null;
}

/**
 * CVSS preference: CNA v4.0 > v3.1 > v3.0, then CISA-ADP (v4.0 > v3.1 > v3.0), and CNA v2.0 only
 * as a display-only last resort so an ADP v3.1 score is never shadowed by a legacy v2 one.
 */
function pickCvss(cnaMetrics: readonly unknown[], adpMetrics: readonly unknown[]): Cvss | null {
  for (const { key, version } of CVSS_KEYS) {
    const found = cvssOf(cnaMetrics, key, version, 'cna');
    if (found) return found;
  }
  for (const { key, version } of CVSS_KEYS) {
    const found = cvssOf(adpMetrics, key, version, 'cisa-adp');
    if (found) return found;
  }
  return cvssOf(cnaMetrics, CVSS_V2.key, CVSS_V2.version, 'cna');
}

/** Distinct `E` values from every CNA v3/v4 vector, in first-seen order. */
function exploitMaturity(cnaMetrics: readonly unknown[]): string[] {
  const values = new Set<string>();
  for (const entry of cnaMetrics) {
    for (const { key, version } of CVSS_KEYS) {
      const vector = asString(asObject(asObject(entry)?.[key])?.vectorString);
      const e = vector ? parseCvssVector(vector).E?.toUpperCase() : undefined;
      if (e && EXPLOIT_MATURITY[version].has(e)) values.add(e);
    }
  }
  return [...values];
}

// ---------------------------------------------------------------------------------------------
// CISA-ADP "other" metrics: SSVC and the KEV block

function adpOther(adp: JsonObject, type: string): JsonObject | null {
  for (const entry of asArray(adp.metrics)) {
    const other = asObject(asObject(entry)?.other);
    if (other && asString(other.type)?.trim().toLowerCase() === type) {
      const content = asObject(other.content);
      if (content) return content;
    }
  }
  return null;
}

/** SSVC `options` are single-key objects; keys are matched loosely ("Technical Impact"). */
function parseSsvc(content: JsonObject): Ssvc | null {
  const decisions = new Map<string, string>();
  for (const option of asArray(content.options)) {
    for (const [key, value] of Object.entries(asObject(option) ?? {})) {
      const text = sanitizeLine(value, 32).toLowerCase();
      if (text) decisions.set(key.toLowerCase().replace(/[^a-z]/g, ''), text);
    }
  }
  const exploitation = decisions.get('exploitation') ?? '';
  const automatable = decisions.get('automatable') ?? '';
  const technicalImpact = decisions.get('technicalimpact') ?? '';
  if (!exploitation && !automatable && !technicalImpact) return null;
  return {
    exploitation,
    automatable,
    technical_impact: technicalImpact,
    version: sanitizeLine(content.version, 16) || null,
    timestamp: normalizeIso(content.timestamp),
  };
}

// ---------------------------------------------------------------------------------------------
// Descriptive fields

/** Full sanitised English description (else the first one); callers truncate for storage. */
function englishDescription(cna: JsonObject | null): string {
  const descriptions = asArray(cna?.descriptions).map(asObject).filter((d): d is JsonObject => d !== null);
  const english = descriptions.find((d) => asString(d.lang)?.trim().toLowerCase().startsWith('en'));
  return sanitizeText((english ?? descriptions[0])?.value, Number.MAX_SAFE_INTEGER);
}

const CWE_RE = /\bCWE-\d{1,5}\b/i;

function cweIds(cna: JsonObject | null): string[] {
  const ids = new Set<string>();
  for (const problemType of asArray(cna?.problemTypes)) {
    for (const entry of asArray(asObject(problemType)?.descriptions)) {
      const d = asObject(entry);
      // Prefer the structured id; some CNAs only put "CWE-79 …" in the description text.
      const match = CWE_RE.exec(asString(d?.cweId) ?? asString(d?.description) ?? '');
      if (match) ids.add(match[0].toUpperCase());
      if (ids.size === MAX_LIST) return [...ids];
    }
  }
  return [...ids];
}

function cleanName(value: unknown): string {
  const name = sanitizeLine(value, MAX_NAME);
  return name.toLowerCase() === 'n/a' ? '' : name;
}

const PURL_RE = /^pkg:[a-z0-9.+-]+\/\S+$/i;

function affectedEntries(cna: JsonObject | null): NormalizedCve['affected'] {
  const out: NormalizedCve['affected'] = [];
  const seen = new Set<string>();
  for (const entry of asArray(cna?.affected)) {
    const a = asObject(entry);
    if (!a) continue;
    const vendor = cleanName(a.vendor);
    const product = cleanName(a.product) || cleanName(a.packageName);
    if (!vendor && !product) continue;
    const key = `${vendor}\u0000${product}`.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    const purl = sanitizeLine(a.packageURL, 512);
    out.push({ vendor, product, purl: PURL_RE.test(purl) ? purl : null });
    if (out.length === MAX_AFFECTED) break;
  }
  return out;
}

function referenceUrls(cna: JsonObject | null): string[] {
  const urls = new Set<string>();
  for (const entry of asArray(cna?.references)) {
    const url = sanitizeUrl(asObject(entry)?.url);
    if (url) urls.add(url);
    if (urls.size === MAX_REFERENCES) break;
  }
  return [...urls];
}

function cnaTags(cna: JsonObject | null): string[] {
  const tags = new Set<string>();
  for (const tag of asArray(cna?.tags)) {
    const text = sanitizeLine(tag, 64).toLowerCase();
    if (text) tags.add(text);
    if (tags.size === MAX_LIST) break;
  }
  return [...tags];
}

// ---------------------------------------------------------------------------------------------

/**
 * Normalise a PUBLISHED record. Returns null for other states or when datePublished is missing.
 * `meta` must come from readCveMeta(record).
 */
export function normalizeCve(record: unknown, meta: CveMeta, inWindow: boolean): NormalizedCve | null {
  if (meta.state !== 'PUBLISHED' || !meta.published) return null;
  const { cna, cisaAdp } = containersOf(record);
  const cnaMetrics = asArray(cna?.metrics);
  const adpMetrics = cisaAdp.flatMap((adp) => asArray(adp.metrics));

  const cvss = pickCvss(cnaMetrics, adpMetrics);
  // pickCvss only falls back to CISA-ADP or CNA v2.0 when the CNA has no v3.x/v4.0 score.
  const cnaHasCvss = cvss?.source === 'cna' && cvss.version !== CVSS_V2.version;

  let ssvc: Ssvc | null = null;
  let adpKev: NormalizedCve['adpKev'] = null;
  for (const adp of cisaAdp) {
    const ssvcContent = adpOther(adp, 'ssvc');
    ssvc ??= ssvcContent ? parseSsvc(ssvcContent) : null;
    const kevContent = adpOther(adp, 'kev');
    if (kevContent && !adpKev) {
      adpKev = { dateAdded: normalizeYmd(kevContent.dateAdded), reference: sanitizeUrl(kevContent.reference) };
    }
  }

  const title = sanitizeLine(cna?.title, MAX_TITLE) || null;
  const fullDescription = englishDescription(cna);
  const affected = affectedEntries(cna);
  const references = referenceUrls(cna);
  const noiseText = clip(
    [title ?? '', fullDescription, ...affected.map((a) => `${a.vendor} ${a.product}`), ...references].join('\n').toLowerCase(),
    MAX_NOISE_TEXT,
  );

  return {
    id: meta.id,
    published: meta.published.toISOString(),
    reserved: meta.reserved?.toISOString() ?? null,
    updated: meta.updated?.toISOString() ?? null,
    cna: meta.assigner,
    title,
    description: truncate(fullDescription, MAX_DESCRIPTION),
    cvss,
    cvssMetrics: cvss ? parseCvssVector(cvss.vector) : {},
    cnaCvssMissing: !cnaHasCvss,
    cnaExploitMaturity: meta.assigner.toLowerCase() === 'vuldb' ? [] : exploitMaturity(cnaMetrics),
    ssvc,
    adpKev,
    cwe: cweIds(cna),
    affected,
    tags: cnaTags(cna),
    references,
    aiCredit: findAiCredit(cna),
    vendorInTheWild: mentionsInTheWild(fullDescription),
    noiseText,
    inWindow,
  };
}
