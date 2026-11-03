/**
 * Reads an SBOM or a lockfile into a flat list of packages, in the browser (the Check page).
 *
 * The file is untrusted and can be large (up to 50 MB): every parser is a single pass with
 * anchored or bounded regular expressions, line-oriented formats skip lines over 64 KB, and
 * nothing builds a plain object keyed by a string from the file (only arrays, Map and Set), so a
 * package named `__proto__` is just a name. No eval, no DOMParser: CycloneDX XML is read from the
 * text of its <purl> elements only.
 */
import type { PackageEcosystem } from '../../../shared/contract';
import { ecosystemOfPurlType } from '../../../shared/packages';

export const FORMATS = [
  ['cyclonedx-json', 'CycloneDX JSON'],
  ['cyclonedx-xml', 'CycloneDX XML'],
  ['spdx-json', 'SPDX JSON'],
  ['spdx-tag', 'SPDX tag-value'],
  ['purl', 'a list of package URLs'],
  ['npm-lock', 'package-lock.json'],
  ['yarn', 'yarn.lock'],
  ['pnpm', 'pnpm-lock.yaml'],
  ['requirements', 'requirements.txt'],
  ['poetry', 'poetry.lock'],
  ['uv', 'uv.lock'],
  ['pipfile', 'Pipfile.lock'],
  ['gomod', 'go.mod'],
  ['gosum', 'go.sum'],
  ['cargo', 'Cargo.lock'],
  ['gemfile', 'Gemfile.lock'],
  ['composer', 'composer.lock'],
  ['nuget', 'packages.lock.json (NuGet)'],
  ['gradle', 'gradle.lockfile'],
] as const;

export type FormatId = (typeof FORMATS)[number][0];
export const FORMAT_LABEL: ReadonlyMap<FormatId, string> = new Map(FORMATS);
export const isFormatId = (v: string): v is FormatId => FORMAT_LABEL.has(v as FormatId);

/** Why a package is never compared ("Not checked"). */
export type SkipReason = 'ecosystem' | 'not-registry' | 'no-purl' | 'bad-purl' | 'dev-branch' | 'go-stdlib';
/** Why a package has no version to compare: a tracked CVE naming it makes it "possibly affected". */
export type NoVersionReason = 'not-exact' | 'no-version' | 'go-local';

export interface Component {
  /** null: outside the eight ecosystems (`type` says which, e.g. "deb"). */
  eco: PackageEcosystem | null;
  type?: string;
  name: string;
  version: string | null;
  skip?: SkipReason;
  noVersion?: NoVersionReason;
}

export interface Parsed {
  format: FormatId;
  components: Component[];
  /** Plain sentences about what was skipped or may be inexact. */
  notes: string[];
}

/** Why a file could not be read. `detail` quotes the file (the JSON error), so it is rendered as file text. */
export class ParseError extends Error {
  constructor(
    readonly kind: 'json' | 'unknown' | 'empty',
    readonly detail = '',
  ) {
    super(parseErrorText(kind, detail));
    this.name = 'ParseError';
  }
}

export function parseErrorText(kind: ParseError['kind'], detail = ''): string {
  if (kind === 'json') return `This looks like JSON, but it could not be read: ${detail}. Check that the whole file was pasted.`;
  if (kind === 'unknown') return 'We could not tell what kind of file this is. Pick it under Read as, or see the accepted files below.';
  return 'No packages found in this file.';
}

export const MAX_LINE = 64 * 1024;
export const MAX_NAME = 512;
const MAX_PURL = 2048;

export const GO_SUM_NOTE = 'go.sum can list module versions your build does not use, so this may show versions you do not run. go.mod is more exact.';

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => typeof v === 'object' && v !== null && !Array.isArray(v);
const str = (v: unknown): string | null => (typeof v === 'string' && v.trim() !== '' ? v.trim() : null);
const entries = (v: unknown): [string, unknown][] => (isObj(v) ? Object.entries(v) : []);

function decode(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

function unquote(s: string): string {
  const t = s.trim();
  return t.length >= 2 && (t[0] === '"' || t[0] === "'") && t[t.length - 1] === t[0] ? t.slice(1, -1) : t;
}

/** Lines of a line-oriented format; lines over MAX_LINE are skipped and counted. */
function lines(text: string, notes: string[]): string[] {
  const out: string[] = [];
  let long = 0;
  for (const raw of text.split('\n')) {
    const line = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
    if (line.length > MAX_LINE) long++;
    else out.push(line);
  }
  if (long) notes.push(`Skipped ${long === 1 ? 'a line' : `${long} lines`} longer than 64 KB.`);
  return out;
}

// ── package URLs ──

/** A package URL (`pkg:type/namespace/name@version?qualifiers#subpath`) as a component; null when malformed. */
export function purlComponent(raw: string): Component | null {
  const full = raw.trim();
  if (full.length > MAX_PURL || full.slice(0, 4).toLowerCase() !== 'pkg:') return null;
  let s = full.slice(4);
  while (s.startsWith('/')) s = s.slice(1);
  const hash = s.indexOf('#');
  if (hash >= 0) s = s.slice(0, hash);
  const query = s.indexOf('?');
  if (query >= 0) s = s.slice(0, query);
  const slash = s.indexOf('/');
  if (slash <= 0) return null;
  const type = s.slice(0, slash).toLowerCase();
  if (!/^[a-z][a-z0-9.+-]{0,31}$/.test(type)) return null;
  let rest = s.slice(slash + 1);
  while (rest.endsWith('/')) rest = rest.slice(0, -1);
  let version: string | null = null;
  const at = rest.lastIndexOf('@');
  if (at > 0 && at > rest.lastIndexOf('/')) {
    version = str(decode(rest.slice(at + 1)));
    rest = rest.slice(0, at);
  }
  const parts = rest.split('/').filter(Boolean).map(decode);
  if (parts.length === 0) return null;
  const name = parts[parts.length - 1];
  const ns = parts.slice(0, -1);
  const eco = ecosystemOfPurlType(type);
  if (!eco) return { eco: null, type, name: parts.join('/'), version, skip: 'ecosystem' };
  let pkgName: string;
  if (eco === 'npm') pkgName = ns.length ? `${ns[0].startsWith('@') ? '' : '@'}${ns.join('/')}/${name}` : name;
  else if (eco === 'Maven') pkgName = ns.length ? `${ns.join('.')}:${name}` : name;
  else pkgName = parts.join('/');
  // Syft writes the Go standard library as pkg:golang/stdlib@go1.22.5 (or 1.22.5); OSV says 1.22.5.
  if (eco === 'Go' && (pkgName === 'stdlib' || pkgName === 'toolchain') && version?.startsWith('go')) version = version.slice(2);
  return version === null ? { eco, name: pkgName, version: null, noVersion: 'no-version' } : { eco, name: pkgName, version };
}

/** An SBOM entry: its package URL when there is one, otherwise "not checked" under its own name. */
function sbomEntry(purl: unknown, name: unknown, version: unknown): Component {
  const ver = str(version);
  const p = str(purl);
  if (p) {
    const c = purlComponent(p);
    if (c) {
      if (c.version === null && c.eco && ver) return { eco: c.eco, name: c.name, version: ver };
      return c;
    }
    return { eco: null, name: str(name) ?? p, version: ver, skip: 'bad-purl' };
  }
  return { eco: null, name: str(name) ?? '(no name)', version: ver, skip: 'no-purl' };
}

function cyclonedxJson(doc: Json): Component[] {
  const out: Component[] = [];
  // Nested components, without recursion (the file decides how deep).
  const stack: unknown[] = [doc.components];
  while (stack.length) {
    const list = stack.pop();
    if (!Array.isArray(list)) continue;
    for (const c of list) {
      if (!isObj(c)) continue;
      const group = str(c.group);
      const name = str(c.name);
      out.push(sbomEntry(c.purl, group && name ? `${group}/${name}` : name, c.version));
      if (c.components) stack.push(c.components);
    }
  }
  return out;
}

function spdxJson(doc: Json): Component[] {
  const out: Component[] = [];
  if (Array.isArray(doc.packages)) {
    // SPDX 2.x
    for (const p of doc.packages) {
      if (!isObj(p)) continue;
      const refs = Array.isArray(p.externalRefs) ? p.externalRefs : [];
      const ref = refs.find((r) => isObj(r) && typeof r.referenceType === 'string' && r.referenceType.toLowerCase() === 'purl');
      out.push(sbomEntry(isObj(ref) ? ref.referenceLocator : null, p.name, p.versionInfo));
    }
  }
  if (Array.isArray(doc['@graph'])) {
    // SPDX 3.0 JSON-LD
    for (const e of doc['@graph']) {
      if (!isObj(e)) continue;
      const type = str(e.type) ?? str(e['@type']);
      if (type !== 'software_Package') continue;
      const ids = Array.isArray(e.externalIdentifier) ? e.externalIdentifier : [];
      const id = ids.find((x) => isObj(x) && x.externalIdentifierType === 'packageUrl');
      out.push(sbomEntry(e.software_packageUrl ?? (isObj(id) ? id.identifier : null), e.name, e.software_packageVersion));
    }
  }
  return out;
}

function spdxTag(text: string, notes: string[]): Component[] {
  const out: Component[] = [];
  let cur: { name: string; version: string | null; purl: string | null } | null = null;
  let inText = false;
  const flush = () => cur && out.push(sbomEntry(cur.purl, cur.name, cur.version));
  for (const line of lines(text, notes)) {
    // Multi-line <text>...</text> values can hold anything, including lines that look like tags.
    if (inText) {
      if (line.includes('</text>')) inText = false;
      continue;
    }
    const colon = line.indexOf(':');
    if (colon <= 0) continue;
    const tag = line.slice(0, colon).trim();
    const value = line.slice(colon + 1).trim();
    if (value.startsWith('<text>') && !value.includes('</text>')) {
      inText = true;
      continue;
    }
    if (tag === 'PackageName') {
      flush();
      cur = { name: value, version: null, purl: null };
    } else if (cur && tag === 'PackageVersion') cur.version = value;
    else if (cur && tag === 'ExternalRef') {
      const [, type, locator] = value.split(/\s+/);
      if (type?.toLowerCase() === 'purl' && locator) cur.purl = locator;
    }
  }
  flush();
  return out;
}

const XML_ENTITIES: ReadonlyMap<string, string> = new Map([
  ['amp', '&'],
  ['lt', '<'],
  ['gt', '>'],
  ['quot', '"'],
  ['apos', "'"],
]);

/** The five predefined XML entities and numeric references; nothing else is expanded. */
function xmlText(s: string): string {
  return s.replace(/&(#x[0-9a-fA-F]{1,6}|#[0-9]{1,7}|[a-z]{2,4});/g, (whole, ref: string) => {
    if (ref[0] !== '#') return XML_ENTITIES.get(ref) ?? whole;
    const code = ref[1] === 'x' ? parseInt(ref.slice(2), 16) : parseInt(ref.slice(1), 10);
    return code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : whole;
  });
}

function cyclonedxXml(text: string, notes: string[]): Component[] {
  const out: Component[] = [];
  // Only the text of <purl> elements: bom-ref attributes and <dependency ref> hold package URLs too.
  for (const m of text.matchAll(/<(?:[A-Za-z_][\w.-]{0,31}:)?purl>([^<]{1,2048})<\/(?:[A-Za-z_][\w.-]{0,31}:)?purl>/g)) {
    const purl = xmlText(m[1]);
    out.push(purlComponent(purl) ?? { eco: null, name: purl.trim(), version: null, skip: 'bad-purl' });
  }
  const all = text.match(/<(?:[A-Za-z_][\w.-]{0,31}:)?component[\s>]/g)?.length ?? 0;
  if (all > out.length) notes.push(`${all - out.length} of ${all} components have no package URL and were not checked.`);
  return out;
}

function purlList(text: string, notes: string[]): Component[] {
  const out: Component[] = [];
  let other = 0;
  for (const line of lines(text, notes)) {
    const t = line.trim();
    if (t === '' || t.startsWith('#')) continue;
    if (t.slice(0, 4).toLowerCase() !== 'pkg:') {
      other++;
      continue;
    }
    out.push(purlComponent(t) ?? { eco: null, name: t, version: null, skip: 'bad-purl' });
  }
  if (other) notes.push(`Ignored ${other === 1 ? 'a line' : `${other} lines`} that ${other === 1 ? 'is not a package URL' : 'are not package URLs'}.`);
  return out;
}

// ── npm ──

const isRegistryTarball = (url: string): boolean => /^https?:\/\//i.test(url) && url.split(/[?#]/)[0].toLowerCase().endsWith('.tgz');

function npmEntry(name: string, version: unknown, resolved: unknown): Component {
  const ver = str(version);
  if (ver === null) return { eco: 'npm', name, version: null, noVersion: 'no-version' };
  if (ver.startsWith('npm:')) {
    // An alias: "npm:real-name@1.2.3".
    const real = ver.slice(4);
    const at = real.lastIndexOf('@');
    if (at > 0) return npmEntry(real.slice(0, at), real.slice(at + 1), resolved);
  }
  if (/^[a-z][a-z+]*:/i.test(ver) || ver.includes('/') || (typeof resolved === 'string' && resolved !== '' && !isRegistryTarball(resolved))) {
    return { eco: 'npm', name, version: null, skip: 'not-registry' };
  }
  return { eco: 'npm', name, version: ver };
}

function npmLock(doc: Json): Component[] {
  const out: Component[] = [];
  if (isObj(doc.packages)) {
    // Lockfile v2 and v3: "node_modules/a/node_modules/b" → b; "packages/x" is a workspace folder.
    for (const [path, v] of entries(doc.packages)) {
      if (path === '' || !isObj(v) || v.link === true) continue;
      const i = path.lastIndexOf('node_modules/');
      const name = str(v.name) ?? (i >= 0 ? path.slice(i + 13) : path);
      if (i < 0) out.push({ eco: 'npm', name, version: str(v.version), skip: 'not-registry' });
      else out.push(npmEntry(name, v.version, v.resolved));
    }
    return out;
  }
  // Lockfile v1: a tree of "dependencies".
  const stack: unknown[] = [doc.dependencies];
  while (stack.length) {
    for (const [name, v] of entries(stack.pop())) {
      if (!isObj(v)) continue;
      out.push(npmEntry(name, v.version, v.resolved));
      if (v.dependencies) stack.push(v.dependencies);
    }
  }
  return out;
}

/** yarn.lock v1 ("version \"1.2.3\"") and Berry ("version: 1.2.3", "resolution: \"name@npm:1.2.3\""). */
function yarnLock(text: string, notes: string[]): Component[] {
  const out: Component[] = [];
  let head: string | null = null;
  let version: string | null = null;
  let resolution: string | null = null;
  const flush = () => {
    if (head !== null && head !== '__metadata') out.push(yarnEntry(head, version, resolution));
    head = version = resolution = null;
  };
  for (const line of lines(text, notes)) {
    if (line === '' || line.startsWith('#')) continue;
    if (line[0] !== ' ') {
      flush();
      if (line.endsWith(':')) head = line.slice(0, -1);
      continue;
    }
    if (head === null || line[2] === ' ') continue;
    const m = /^ {2}(version|resolution):? +(\S.*)$/.exec(line);
    if (!m) continue;
    if (m[1] === 'version') version = unquote(m[2]);
    else resolution = unquote(m[2]);
  }
  flush();
  return out;
}

/** "name@range" → [name, range]; the name may start with "@". */
function splitDescriptor(d: string): [string, string] {
  const at = d.indexOf('@', 1);
  return at > 0 ? [d.slice(0, at), d.slice(at + 1)] : [d, ''];
}

function yarnEntry(head: string, version: string | null, resolution: string | null): Component {
  if (resolution !== null) {
    // Berry: the resolution names the real package (aliases included) and the protocol.
    const [name, ref] = splitDescriptor(resolution);
    const registry = ref.startsWith('npm:') || (ref.startsWith('patch:') && (ref.includes('@npm%3A') || ref.includes('@npm:')));
    if (!registry) return { eco: 'npm', name, version: null, skip: 'not-registry' };
    return version ? { eco: 'npm', name, version } : { eco: 'npm', name, version: null, noVersion: 'no-version' };
  }
  let [name, range] = splitDescriptor(unquote(head.split(',')[0]));
  if (range.startsWith('npm:')) [name, range] = splitDescriptor(range.slice(4));
  if (/^[a-z][a-z+]*:/i.test(range) || range.includes('/')) return { eco: 'npm', name, version: null, skip: 'not-registry' };
  return version ? { eco: 'npm', name, version } : { eco: 'npm', name, version: null, noVersion: 'no-version' };
}

/** pnpm-lock.yaml v5 ("/name/1.0.0_peer"), v6 ("/name@1.0.0(peer)") and v9 ("name@1.0.0"). */
function pnpmLock(text: string, notes: string[]): Component[] {
  const out: Component[] = [];
  const seen = new Set<string>();
  let section = '';
  let major = 9;
  for (const line of lines(text, notes)) {
    if (line === '' || line.trimStart().startsWith('#')) continue;
    if (line[0] !== ' ') {
      section = line.trim();
      if (section.startsWith('lockfileVersion:')) major = parseFloat(unquote(section.slice(16))) || 9;
      continue;
    }
    if ((section !== 'packages:' && section !== 'snapshots:') || line[2] === ' ') continue;
    let body = line.trim();
    if (body.endsWith(' {}')) body = body.slice(0, -3);
    if (!body.endsWith(':')) continue;
    let key = unquote(body.slice(0, -1));
    const fromRegistry = major >= 9 || key.startsWith('/');
    if (key.startsWith('/')) key = key.slice(1);
    const paren = key.indexOf('(');
    if (paren > 0) key = key.slice(0, paren);
    let name: string;
    let version: string;
    if (major < 6) {
      // "name/1.0.0_peer@2.0.0" or "@scope/name/1.0.0"
      const slash = key.lastIndexOf('/');
      name = key.slice(0, Math.max(0, slash));
      version = key.slice(slash + 1);
      const u = version.indexOf('_');
      if (u > 0) version = version.slice(0, u);
    } else {
      [name, version] = splitDescriptor(key);
    }
    if (!name || !fromRegistry || /[:/]/.test(version)) {
      const id = `?${key}`;
      if (!seen.has(id)) out.push({ eco: 'npm', name: name || key, version: null, skip: 'not-registry' });
      seen.add(id);
      continue;
    }
    const id = `${name}@${version}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(version ? { eco: 'npm', name, version } : { eco: 'npm', name, version: null, noVersion: 'no-version' });
  }
  return out;
}

// ── Python ──

function requirements(text: string, notes: string[]): Component[] {
  const out: Component[] = [];
  let includes = 0;
  let ignored = 0;
  // Join "\" continuations first.
  const joined: string[] = [];
  let buf = '';
  for (const line of lines(text, notes)) {
    if (line.endsWith('\\')) {
      buf += `${line.slice(0, -1)} `;
      if (buf.length > MAX_LINE) buf = '';
      continue;
    }
    joined.push(buf + line);
    buf = '';
  }
  if (buf) joined.push(buf);
  for (const raw of joined) {
    const hash = raw.search(/(?:^|\s)#/);
    const line = (hash >= 0 ? raw.slice(0, hash) : raw).trim();
    if (line === '') continue;
    if (line.startsWith('-')) {
      if (/^(?:-r|-c|--requirement|--constraint)\b/.test(line)) includes++;
      else if (/^(?:-e|--editable)\b/.test(line)) {
        const egg = /[#&]egg=([A-Za-z0-9._-]{1,200})/.exec(raw);
        out.push({ eco: 'PyPI', name: egg ? egg[1] : line.replace(/^(?:-e|--editable)[\s=]*/, ''), version: null, skip: 'not-registry' });
      }
      continue;
    }
    const m = /^[A-Za-z0-9][A-Za-z0-9._-]*/.exec(line);
    if (!m) {
      ignored++;
      continue;
    }
    const name = m[0];
    let rest = line.slice(name.length).trimStart();
    if (rest.startsWith('[')) {
      const close = rest.indexOf(']');
      rest = close >= 0 ? rest.slice(close + 1).trimStart() : '';
    }
    if (rest !== '' && !/^[=<>!~;@]/.test(rest)) {
      ignored++;
      continue;
    }
    if (rest.startsWith('@')) {
      // "name @ https://…": a direct reference, not a registry release.
      out.push({ eco: 'PyPI', name, version: null, skip: 'not-registry' });
      continue;
    }
    const semi = rest.indexOf(';');
    let spec = semi >= 0 ? rest.slice(0, semi) : rest;
    const option = spec.search(/\s-/);
    if (option >= 0) spec = spec.slice(0, option);
    spec = spec.replace(/\s+/g, '');
    const exact = /^===?([^,*=<>!~]+)$/.exec(spec);
    out.push(exact ? { eco: 'PyPI', name, version: exact[1] } : { eco: 'PyPI', name, version: null, noVersion: 'not-exact' });
  }
  if (includes) notes.push(`${includes === 1 ? 'A line includes' : `${includes} lines include`} another requirements file (-r or -c). Check that file too.`);
  if (ignored) notes.push(`Ignored ${ignored === 1 ? 'a line' : `${ignored} lines`} that ${ignored === 1 ? 'is not a requirement' : 'are not requirements'}.`);
  return out;
}

function pipfileLock(doc: Json): Component[] {
  const out: Component[] = [];
  for (const group of ['default', 'develop']) {
    for (const [name, v] of entries(doc[group])) {
      if (!isObj(v)) continue;
      if (v.git || v.path || v.file || v.editable) out.push({ eco: 'PyPI', name, version: null, skip: 'not-registry' });
      else {
        const spec = str(v.version);
        const exact = spec && /^===?([^,*=<>!~\s]+)$/.exec(spec);
        out.push(exact ? { eco: 'PyPI', name, version: exact[1] } : { eco: 'PyPI', name, version: null, noVersion: 'not-exact' });
      }
    }
  }
  return out;
}

// ── TOML lockfiles: Cargo.lock, poetry.lock, uv.lock ──

function tomlString(v: string): string | null {
  const q = v[0];
  if (q !== '"' && q !== "'") return null;
  const end = v.indexOf(q, 1);
  return end > 0 ? v.slice(1, end) : null;
}

function tomlPackages(text: string, notes: string[], kind: 'cargo' | 'poetry' | 'uv'): Component[] {
  const eco: PackageEcosystem = kind === 'cargo' ? 'crates.io' : 'PyPI';
  const pkgs: { name: string | null; version: string | null; source: string | null; type: string | null }[] = [];
  let cur: (typeof pkgs)[number] | null = null;
  let sub = '';
  for (const line of lines(text, notes)) {
    if (line.startsWith('[')) {
      const h = line.trim();
      if (h === '[[package]]') {
        cur = { name: null, version: null, source: null, type: null };
        pkgs.push(cur);
        sub = '';
      } else if (cur && (h.startsWith('[package.') || h.startsWith('[[package.'))) sub = h;
      else cur = null;
      continue;
    }
    if (!cur) continue;
    const m = /^([A-Za-z0-9_-]+) *= *(\S.*)$/.exec(line);
    if (!m) continue;
    const value = m[2].trim();
    if (sub === '') {
      if (m[1] === 'name') cur.name = tomlString(value);
      else if (m[1] === 'version') cur.version = tomlString(value);
      else if (m[1] === 'source') cur.source = value;
    } else if (sub === '[package.source]' && m[1] === 'type') cur.type = tomlString(value);
  }
  const out: Component[] = [];
  for (const p of pkgs) {
    if (!p.name) continue;
    let registry: boolean;
    if (kind === 'cargo') {
      const src = p.source === null ? null : tomlString(p.source);
      registry = src !== null && (src.startsWith('registry+https://github.com/rust-lang/crates.io-index') || src.startsWith('sparse+https://index.crates.io/'));
    } else if (kind === 'uv') registry = p.source === null || /^\{ *registry *=/.test(p.source);
    else registry = p.type === null || p.type === 'legacy';
    if (!registry) out.push({ eco, name: p.name, version: null, skip: 'not-registry' });
    else if (!p.version) out.push({ eco, name: p.name, version: null, noVersion: 'no-version' });
    else out.push({ eco, name: p.name, version: p.version });
  }
  return out;
}

// ── Go ──

const goToken = (s: string): string => (s.length >= 2 && (s[0] === '"' || s[0] === '`') && s[s.length - 1] === s[0] ? s.slice(1, -1) : s);
const isLocalPath = (p: string): boolean => p.startsWith('./') || p.startsWith('../') || p === '.' || p === '..' || p.startsWith('/') || /^[A-Za-z]:[\\/]/.test(p);

function goMod(text: string, notes: string[]): Component[] {
  const requires: [string, string][] = [];
  const replaces: { from: string; fromVersion: string | null; to: string; toVersion: string | null }[] = [];
  let block: string | null = null;
  const handle = (verb: string, args: string[]) => {
    if (verb === 'require' && args.length >= 2) requires.push([goToken(args[0]), args[1]]);
    else if (verb === 'replace') {
      const arrow = args.indexOf('=>');
      if (arrow < 1 || arrow + 1 >= args.length) return;
      replaces.push({ from: goToken(args[0]), fromVersion: arrow > 1 ? args[1] : null, to: goToken(args[arrow + 1]), toVersion: args[arrow + 2] ?? null });
    }
  };
  for (const line of lines(text, notes)) {
    const comment = line.indexOf('//');
    const t = (comment >= 0 ? line.slice(0, comment) : line).trim();
    if (t === '') continue;
    if (block !== null) {
      if (t === ')') block = null;
      else handle(block, t.split(/\s+/));
      continue;
    }
    const [verb, ...args] = t.split(/\s+/);
    if (args.length === 1 && args[0] === '(') block = verb;
    else handle(verb, args);
  }
  const out: Component[] = requires.map(([path, version]): Component => {
    let r: (typeof replaces)[number] | undefined;
    for (const x of replaces) if (x.from === path && (x.fromVersion === null || x.fromVersion === version)) r = x;
    if (!r) return { eco: 'Go', name: path, version };
    if (isLocalPath(r.to)) return { eco: 'Go', name: path, version: null, noVersion: 'go-local' };
    return { eco: 'Go', name: r.to, version: r.toVersion ?? version };
  });
  out.push({ eco: 'Go', name: 'stdlib', version: null, skip: 'go-stdlib' });
  return out;
}

function goSum(text: string, notes: string[]): Component[] {
  const out: Component[] = [];
  const seen = new Set<string>();
  for (const line of lines(text, notes)) {
    const [path, version, hash] = line.trim().split(/\s+/);
    // "<module> <version>/go.mod h1:…" only means its go.mod was read: its code is not in the build.
    if (!path || !version || !hash || version.endsWith('/go.mod')) continue;
    const id = `${path} ${version}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push({ eco: 'Go', name: path, version });
  }
  notes.push(GO_SUM_NOTE);
  return out;
}

// ── Ruby, PHP, .NET, Gradle ──

/** Platform gems ("nokogiri (1.15.4-x86_64-linux)"): the platform is not part of the version. */
const GEM_PLATFORM = /^(?:x86_64|x86|x64|i[3-6]86|aarch64|arm64|arm|armv\d\w*|universal|java|jruby|mingw|mswin|mswin64|darwin|linux|powerpc|ppc64le|s390x|riscv64|wasm32)(?:-|$)/i;

function gemfileLock(text: string, notes: string[]): Component[] {
  const out: Component[] = [];
  let section = '';
  let specs = false;
  for (const line of lines(text, notes)) {
    if (line.trim() === '') continue;
    if (line[0] !== ' ') {
      section = line.trim();
      specs = false;
      continue;
    }
    if (line === '  specs:') {
      specs = true;
      continue;
    }
    if (line[2] !== ' ') {
      specs = false;
      continue;
    }
    if (!specs) continue;
    const m = /^ {4}([^\s(]+) \(([^)\s]+)\)$/.exec(line);
    if (!m) continue;
    let version = m[2];
    const dash = version.indexOf('-');
    if (dash > 0 && GEM_PLATFORM.test(version.slice(dash + 1))) version = version.slice(0, dash);
    out.push(section === 'GEM' ? { eco: 'RubyGems', name: m[1], version } : { eco: 'RubyGems', name: m[1], version: null, skip: 'not-registry' });
  }
  return out;
}

function composerLock(doc: Json): Component[] {
  const out: Component[] = [];
  for (const list of [doc.packages, doc['packages-dev']]) {
    if (!Array.isArray(list)) continue;
    for (const p of list) {
      if (!isObj(p)) continue;
      const name = str(p.name);
      if (!name) continue;
      const version = str(p.version);
      if (isObj(p.dist) && p.dist.type === 'path') out.push({ eco: 'Packagist', name, version: null, skip: 'not-registry' });
      else if (version && (version.startsWith('dev-') || version.endsWith('-dev'))) out.push({ eco: 'Packagist', name, version: null, skip: 'dev-branch' });
      else out.push(version ? { eco: 'Packagist', name, version } : { eco: 'Packagist', name, version: null, noVersion: 'no-version' });
    }
  }
  return out;
}

function nugetLock(doc: Json): Component[] {
  const out: Component[] = [];
  for (const [, deps] of entries(doc.dependencies)) {
    for (const [name, v] of entries(deps)) {
      if (!isObj(v)) continue;
      const version = str(v.resolved);
      if (v.type === 'Project') out.push({ eco: 'NuGet', name, version: null, skip: 'not-registry' });
      else out.push(version ? { eco: 'NuGet', name, version } : { eco: 'NuGet', name, version: null, noVersion: 'no-version' });
    }
  }
  return out;
}

function gradleLock(text: string, notes: string[]): Component[] {
  const out: Component[] = [];
  for (const line of lines(text, notes)) {
    const m = /^([^#\s:=]+):([^:=\s]+):([^:=\s]+)=/.exec(line);
    if (m) out.push({ eco: 'Maven', name: `${m[1]}:${m[2]}`, version: m[3] });
  }
  return out;
}

// ── detection ──

const BY_FILENAME: readonly [RegExp, FormatId][] = [
  [/^(?:package-lock|npm-shrinkwrap)\.json$/, 'npm-lock'],
  [/^yarn\.lock$/, 'yarn'],
  [/^pnpm-lock\.ya?ml$/, 'pnpm'],
  [/^poetry\.lock$/, 'poetry'],
  [/^uv\.lock$/, 'uv'],
  [/^pipfile\.lock$/, 'pipfile'],
  [/^go\.mod$/, 'gomod'],
  [/^go\.sum$/, 'gosum'],
  [/^cargo\.lock$/, 'cargo'],
  [/^(?:gemfile\.lock|gems\.locked)$/, 'gemfile'],
  [/^composer\.lock$/, 'composer'],
  [/^packages\.lock\.json$/, 'nuget'],
  [/\.lockfile$/, 'gradle'],
  [/^(?:requirements|constraints)[\w.-]*\.txt$/, 'requirements'],
];

const JSON_PARSERS: ReadonlyMap<FormatId, (doc: Json) => Component[]> = new Map([
  ['cyclonedx-json', cyclonedxJson],
  ['spdx-json', spdxJson],
  ['npm-lock', npmLock],
  ['pipfile', pipfileLock],
  ['composer', composerLock],
  ['nuget', nugetLock],
]);

const TEXT_PARSERS: ReadonlyMap<FormatId, (text: string, notes: string[]) => Component[]> = new Map<FormatId, (text: string, notes: string[]) => Component[]>([
  ['cyclonedx-xml', cyclonedxXml],
  ['spdx-tag', spdxTag],
  ['purl', purlList],
  ['yarn', yarnLock],
  ['pnpm', pnpmLock],
  ['requirements', requirements],
  ['poetry', (t, n) => tomlPackages(t, n, 'poetry')],
  ['uv', (t, n) => tomlPackages(t, n, 'uv')],
  ['cargo', (t, n) => tomlPackages(t, n, 'cargo')],
  ['gomod', goMod],
  ['gosum', goSum],
  ['gemfile', gemfileLock],
  ['gradle', gradleLock],
]);

function byFilename(filename: string): FormatId | null {
  const base = filename.split(/[\\/]/).pop()?.toLowerCase().slice(0, 255) ?? '';
  for (const [re, f] of BY_FILENAME) if (re.test(base)) return f;
  return null;
}

function jsonFormat(doc: unknown): FormatId | null {
  if (!isObj(doc)) return null;
  if (doc.bomFormat === 'CycloneDX') return 'cyclonedx-json';
  if (typeof doc.spdxVersion === 'string' || (Array.isArray(doc['@graph']) && JSON.stringify(doc['@context'] ?? '').includes('spdx'))) return 'spdx-json';
  if ('lockfileVersion' in doc && (isObj(doc.packages) || isObj(doc.dependencies))) return 'npm-lock';
  if (isObj(doc._meta) && (isObj(doc.default) || isObj(doc.develop))) return 'pipfile';
  if (Array.isArray(doc.packages) && ('content-hash' in doc || 'packages-dev' in doc || '_readme' in doc)) return 'composer';
  if (typeof doc.version === 'number' && isObj(doc.dependencies)) return 'nuget';
  return null;
}

/** The format of a text file, from its first 64 KB. */
function textFormat(head: string): FormatId | null {
  const t = head.trimStart();
  if (t.startsWith('<')) return /cyclonedx|<(?:[\w.-]{1,32}:)?purl>/i.test(head) ? 'cyclonedx-xml' : null;
  if (/^SPDXVersion:/m.test(head)) return 'spdx-tag';
  if (/^# yarn lockfile v1|^__metadata:/m.test(head)) return 'yarn';
  if (/^lockfileVersion:/m.test(head)) return 'pnpm';
  if (/^\[\[package\]\]/m.test(head)) {
    if (/^# This file is automatically @generated by Cargo|^source = "(?:registry|sparse|git)\+|^checksum = "/m.test(head)) return 'cargo';
    if (/^requires-python = |^source = \{ ?(?:registry|editable|virtual|path|directory|git|url) = /m.test(head)) return 'uv';
    return 'poetry';
  }
  if (/^module\s+\S/m.test(head)) return 'gomod';
  if (/^\S+ v\S+ h1:/m.test(head)) return 'gosum';
  if (/^(?:GEM|GIT|PATH)\r?$/m.test(head) && /^ {2}specs:\r?$/m.test(head)) return 'gemfile';
  if (/^[^\s#:=]+:[^\s:=]+:[^\s:=]+=/m.test(head)) return 'gradle';
  if (/^[ \t]*pkg:[a-z]/im.test(head)) return 'purl';
  if (/^(?:-[rce] |--[a-z]|[A-Za-z0-9][A-Za-z0-9._-]*[ \t]*(?:\[[^\]\n]{0,200}\][ \t]*)?(?:===?|~=|>=|<=|!=|<|>|;|@ ))/m.test(head)) return 'requirements';
  return null;
}

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch (e) {
    const why = e instanceof RangeError ? 'it is nested too deeply' : e instanceof Error ? e.message.replace(/\.$/, '').slice(0, 300) : 'unknown error';
    throw new ParseError('json', why);
  }
}

/**
 * Read `text` as the format `forced` names, or detect it from the file name and the content. Throws
 * ParseError when the format cannot be told or the file holds no packages. Names longer than
 * MAX_NAME are dropped (with a note); everything else is kept, including duplicates.
 */
export function parse(input: string, filename = '', forced: FormatId | null = null): Parsed {
  const text = input.charCodeAt(0) === 0xfeff ? input.slice(1) : input;
  if (text.trim() === '') throw new ParseError('empty');
  const head = text.slice(0, 65536);
  // No accepted JSON format is a top-level array, and TOML lockfiles start with "[[package]]".
  const looksJson = /^\s*\{/.test(head);
  let doc: unknown;
  let format = forced ?? byFilename(filename);
  if (format === null && looksJson) {
    doc = parseJson(text);
    format = jsonFormat(doc);
  } else if (format === null) format = textFormat(head);
  if (format === null) throw new ParseError('unknown');

  const notes: string[] = [];
  let components: Component[];
  const fromJson = JSON_PARSERS.get(format);
  if (fromJson) {
    doc ??= parseJson(text);
    components = fromJson(isObj(doc) ? doc : {});
  } else components = (TEXT_PARSERS.get(format) ?? gradleLock)(text, notes);
  const kept = components.filter((c) => c.name !== '' && c.name.length <= MAX_NAME);
  if (kept.length < components.length) {
    const n = components.length - kept.length;
    notes.push(`Skipped ${n === 1 ? 'an entry' : `${n} entries`} with no name or a name longer than ${MAX_NAME} characters.`);
  }
  // go.mod always adds the standard library line; on its own that is not a package from the file.
  if (kept.every((c) => c.skip === 'go-stdlib')) throw new ParseError('empty');
  return { format, components: kept, notes };
}
