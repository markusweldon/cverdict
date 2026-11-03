/**
 * Recall of shared/versions.ts on real OSV.dev data.
 *
 * shared/fixtures/osv-sample.json is a frozen sample of 310 affected entries from the eight
 * OSV.dev all.zip dumps of 2026-11-03 (ranges, part of each enumerated `versions` list, and
 * "probes": versions OSV does not list as affected, namely each fixed bound and the newest known
 * version just below each introduced bound). It includes the odd records the design names:
 * PYSEC-2012-7 (Django 1.2 listed below its ranges), PYSEC-2009-17 (several last_affected events),
 * Moodle prereleases, openc3's listed versions above its fix, RustSec and Go multi-pair ranges.
 *
 * Data from OSV.dev: GitHub Advisory Database (CC-BY-4.0), PyPI Advisory Database (CC-BY-4.0), Go
 * Vulnerability Database (CC-BY-4.0), RustSec Advisory Database (CC0-1.0), Drupal security
 * advisories (MIT, Copyright (c) 2025 Ackama). Changed: only IDs, names, ranges and a sample of
 * the listed versions are kept.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { PACKAGE_ECOSYSTEMS, type PackageEcosystem } from './contract';
import { COMPARATORS, extraVersions, inRanges, matchAffect, parseEvent } from './versions';

interface SampleEntry {
  id: string;
  ecosystem: PackageEcosystem;
  package: string;
  ranges: string[][];
  versions: string[];
  probes: string[];
}

const sample = JSON.parse(readFileSync(new URL('./fixtures/osv-sample.json', import.meta.url), 'utf8')) as { entries: SampleEntry[] };
const entries = sample.entries;

/** A range with a bound the ordering cannot read, or an event of another kind. */
function hasUnreadableRange(e: SampleEntry): boolean {
  const c = COMPARATORS[e.ecosystem];
  return e.ranges.some((r) => r.some((ev) => {
    const p = parseEvent(ev);
    return !p || p.op === '?' || (p.v !== '0' && c.parse(p.v) === null);
  }));
}

describe('recall on a frozen sample of real OSV.dev records', () => {
  it('covers every ecosystem', () => {
    expect(entries.length).toBe(310);
    for (const eco of PACKAGE_ECOSYSTEMS) expect(entries.filter((e) => e.ecosystem === eco).length, eco).toBeGreaterThanOrEqual(30);
  });

  it('finds every enumerated version affected: in a range, or as an extra version', () => {
    for (const e of entries) {
      const extra = extraVersions(e.ecosystem, e.versions, e.ranges);
      for (const v of e.versions) expect(matchAffect(e.ecosystem, v, e.ranges, extra), `${e.id} ${e.package} ${v}`).toBe('affected');
    }
  });

  it('places as many enumerated versions inside the ranges as when the sample was frozen', () => {
    // Enumerated versions inside the record's own ranges, without extra versions. A comparator
    // change that moves these numbers changes what the site says about unlisted versions.
    const inside = Object.fromEntries(PACKAGE_ECOSYSTEMS.map((eco) => {
      const own = entries.filter((e) => e.ecosystem === eco);
      return [eco, [own.reduce((a, e) => a + e.versions.filter((v) => inRanges(eco, v, e.ranges) === true).length, 0), own.reduce((a, e) => a + e.versions.length, 0)]];
    }));
    expect(inside).toEqual({
      npm: [34, 34],
      PyPI: [649, 655],
      Maven: [765, 765],
      Go: [33, 34],
      'crates.io': [34, 34],
      RubyGems: [573, 581],
      Packagist: [556, 570],
      NuGet: [670, 670],
    });
  });

  it('never calls a version OSV does not list affected, and says "not affected" unless a range is unreadable', () => {
    let probes = 0;
    for (const e of entries) {
      const extra = extraVersions(e.ecosystem, e.versions, e.ranges);
      for (const p of e.probes) {
        probes++;
        const verdict = matchAffect(e.ecosystem, p, e.ranges, extra);
        expect(verdict, `${e.id} ${e.package} ${p}`).toBe(hasUnreadableRange(e) ? 'unchecked' : 'not_affected');
      }
    }
    expect(probes).toBe(513);
  });

  it('keeps the listed versions OSV names outside the ranges as extra versions', () => {
    const extraOf = (id: string, range: string) => {
      const e = entries.find((x) => x.id === id && JSON.stringify(x.ranges).includes(range));
      expect(e, `${id} ${range}`).toBeDefined();
      return extraVersions(e!.ecosystem, e!.versions, e!.ranges);
    };
    expect(extraOf('PYSEC-2012-7', '>=1.3')).toEqual(expect.arrayContaining(['1.2', '1.2.1']));
    expect(extraOf('GHSA-243v-5pff-qqfj', '>=4.0')).toEqual(expect.arrayContaining(['v4.0.0-beta', 'v4.0.0-rc1']));
    expect(extraOf('GHSA-4jvx-93h3-f45h', '>=7.0.0.pre.rc1')).toEqual(expect.arrayContaining(['7.0.0']));
    // Maven: the qualifier forms OSV puts inside the ranges need no extra versions.
    expect(extraOf('GHSA-26vr-8j45-3r4w', '>=7.2.2')).toEqual([]);
    expect(extraOf('GHSA-222w-xmc5-jhp3', '7.4.13.u92')).toEqual([]);
  });
});
