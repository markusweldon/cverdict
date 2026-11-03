/**
 * Package keys, advisory IDs, licences and range wording for v1/packages.json, shared by the
 * pipeline (which builds and validates the file) and the site (which matches an SBOM against it).
 * No Node or DOM APIs.
 */
import type { PackageAttribution, PackageEcosystem } from './contract';
import { isFirstRelease, parseEvent } from './versions';

/**
 * How a package name is compared within an ecosystem, applied both to OSV names and to names from
 * the user's file. PyPI per PEP 503; crates.io treats case and "-"/"_" as equal; NuGet and
 * Packagist are case-insensitive; npm, Go module paths, Maven group:artifact and RubyGems as given.
 */
export function packageKey(eco: PackageEcosystem, name: string): string {
  switch (eco) {
    case 'PyPI':
      return name.replace(/[-_.]+/g, '-').toLowerCase();
    case 'crates.io':
      return name.toLowerCase().replace(/_/g, '-');
    case 'NuGet':
    case 'Packagist':
      return name.toLowerCase();
    default:
      return name;
  }
}

const PURL_TYPES: ReadonlyMap<string, PackageEcosystem> = new Map([
  ['npm', 'npm'],
  ['pypi', 'PyPI'],
  ['maven', 'Maven'],
  ['golang', 'Go'],
  ['cargo', 'crates.io'],
  ['gem', 'RubyGems'],
  ['composer', 'Packagist'],
  ['nuget', 'NuGet'],
]);

/** The ecosystem of a package URL type (`pkg:<type>/…`), or null when it is not covered. */
export function ecosystemOfPurlType(type: string): PackageEcosystem | null {
  return PURL_TYPES.get(type.toLowerCase()) ?? null;
}

/** OSV advisory IDs: GHSA-…, PYSEC-…, GO-…, RUSTSEC-…, DRUPAL-CORE-…, DRUPAL-CONTRIB-…. */
export const ADVISORY_ID_RE = /^[A-Z][A-Z0-9]{1,15}-[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;

/** Link to an advisory: GitHub's record for GHSA IDs, osv.dev for the rest; null for a malformed ID. */
export function advisoryUrl(id: string): string | null {
  if (!ADVISORY_ID_RE.test(id)) return null;
  const path = encodeURIComponent(id);
  return id.startsWith('GHSA-') ? `https://github.com/advisories/${path}` : `https://osv.dev/vulnerability/${path}`;
}

const DRUPAL_MIT = `The MIT License (MIT)

Copyright (c) 2025 Ackama

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.`;

/**
 * The advisory databases whose records may be published, with their licences. A record whose ID
 * prefix is not listed here is never published, so this list is always complete. Adding a
 * database means adding it here together with any notice its licence requires.
 */
export const ATTRIBUTION: readonly PackageAttribution[] = [
  { name: 'GitHub Advisory Database', url: 'https://github.com/advisories', license: 'CC-BY-4.0', prefixes: ['GHSA'], notice: null },
  { name: 'PyPI Advisory Database', url: 'https://github.com/pypa/advisory-database', license: 'CC-BY-4.0', prefixes: ['PYSEC'], notice: null },
  { name: 'Go Vulnerability Database', url: 'https://pkg.go.dev/vuln/', license: 'CC-BY-4.0', prefixes: ['GO'], notice: null },
  {
    name: 'RustSec Advisory Database',
    url: 'https://rustsec.org/',
    license: 'CC0-1.0 (content imported from the GitHub Advisory Database: CC-BY-4.0)',
    prefixes: ['RUSTSEC'],
    notice: null,
  },
  {
    name: 'Drupal security advisories (OSV)',
    url: 'https://github.com/DrupalSecurityTeam/drupal-advisory-database',
    license: 'MIT, Copyright (c) 2025 Ackama',
    prefixes: ['DRUPAL-CORE', 'DRUPAL-CONTRIB'],
    notice: DRUPAL_MIT,
  },
];

/** The database an advisory ID belongs to (longest matching prefix), or null when it is not allowed. */
export function advisoryDatabase(id: string, attribution: readonly PackageAttribution[] = ATTRIBUTION): PackageAttribution | null {
  let best: PackageAttribution | null = null;
  let bestLength = 0;
  for (const a of attribution) {
    for (const p of a.prefixes) {
      if (p.length > bestLength && id.startsWith(`${p}-`)) {
        best = a;
        bestLength = p.length;
      }
    }
  }
  return best;
}

/** The ID prefix of an advisory as written before its first "-" ("GHSA", "DRUPAL", "OSV"). */
export const advisoryPrefix = (id: string): string => id.slice(0, Math.max(0, id.indexOf('-'))) || id;

const UNKNOWN_TEXT: ReadonlyMap<string, string> = new Map([
  ['git', 'only a git commit range is given'],
  ['versions', 'too many listed versions to include'],
  ['ranges', 'too many ranges to include'],
  ['events', 'a range too long to include'],
]);

/**
 * One OSV range in words: ">=0, <1.2.3" is "before 1.2.3"; ">=1.0, <1.2.3" is "from 1.0, before
 * 1.2.3"; ">=1.0, <=1.4" is "from 1.0 up to 1.4, no fixed version listed"; ">=1.0" is "from 1.0,
 * no fixed version listed". Several pairs in one range are joined with "; ".
 */
export function rangeText(events: readonly string[]): string {
  const parts: string[] = [];
  // undefined: no pair open; null: open from the first release.
  let from: string | null | undefined;
  for (const e of events) {
    const p = parseEvent(e);
    if (!p) {
      parts.push('a range that could not be read');
      continue;
    }
    if (p.op === '?') {
      parts.push(UNKNOWN_TEXT.get(p.kind) ?? `a "${p.kind}" bound that cannot be compared`);
      continue;
    }
    if (p.op === '>=') {
      if (from !== undefined) parts.push(from === null ? 'every version, no fixed version listed' : `from ${from}, no fixed version listed`);
      from = isFirstRelease(p.v) ? null : p.v;
      continue;
    }
    const lower = from ?? null;
    if (p.op === '<') parts.push(lower === null ? `before ${p.v}` : `from ${lower}, before ${p.v}`);
    else parts.push(lower === null ? `up to ${p.v}, no fixed version listed` : `from ${lower} up to ${p.v}, no fixed version listed`);
    from = undefined;
  }
  if (from !== undefined) parts.push(from === null ? 'every version, no fixed version listed' : `from ${from}, no fixed version listed`);
  return parts.join('; ');
}

/** Every range of an entry in words, joined with "; ". */
export const rangesText = (ranges: readonly (readonly string[])[]): string => ranges.map(rangeText).filter(Boolean).join('; ');
