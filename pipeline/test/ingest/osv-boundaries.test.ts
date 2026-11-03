/**
 * The OSV rule at the edges of real ranges: 33 advisories across the eight ecosystems, compacted by
 * compactRecord() exactly as the pipeline writes them, then evaluated with matchAffect() as the
 * Check page does. The expectations were written by hand from each record's ranges and listed
 * versions and the ecosystem's own ordering (SemVer prereleases, PEP 440 dev and post releases,
 * Maven qualifiers, RubyGems prereleases, Composer stabilities, NuGet's fourth number), for the
 * versions just inside and just outside each range, the gaps between ranges, and versions that no
 * ordering can place, which must never come out "not affected".
 *
 * Data from OSV.dev: GitHub Advisory Database (CC-BY-4.0), PyPI Advisory Database (CC-BY-4.0), Go
 * Vulnerability Database (CC-BY-4.0), RustSec Advisory Database (CC0-1.0), Drupal security
 * advisories (MIT, Copyright (c) 2025 Ackama). Changed: one affected package per record is kept.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import type { PackageEcosystem } from '../../../shared/contract';
import { matchAffect } from '../../../shared/versions';
import { compactRecord } from '../../src/sources/osv';

interface RawRecord {
  ecosystem: PackageEcosystem;
  id: string;
  affected: { package: { name: string } }[];
}
const { records } = JSON.parse(readFileSync(new URL('../fixtures/ingest/osv-boundaries.json', import.meta.url), 'utf8')) as { records: RawRecord[] };

/** [ecosystem, advisory, package, affected, not affected, not comparable] */
type Vector = [PackageEcosystem, string, string, string[], string[], string[]];
const VECTORS: Vector[] = [
  // npm (SemVer: a prerelease sorts below its release; "2.0.0-0" is below "2.0.0-alpha")
  ['npm', 'GHSA-c2qf-rxjj-qqgw', 'semver', ['2.0.0-alpha', '2.0.0', '5.7.1', '5.7.2-rc.1', '6.0.0', '6.3.0', '7.0.0', '7.5.1', '7.5.2-0'], ['1.3.0', '2.0.0-0', '5.7.2', '6.0.0-rc.1', '6.3.1', '7.0.0-beta', '7.5.2', '7.6.0'], ['7.5', 'latest', '7.5.1.0']],
  ['npm', 'GHSA-f82v-jwr5-mffw', 'next', ['12.0.0', '12.3.4', '13.0.0', '13.5.8', '14.0.0', '14.2.24', '15.0.0', '15.2.2', '15.2.3-canary.0'], ['11.1.4', '12.0.0-canary.1', '12.3.5', '13.5.9', '14.2.25', '15.0.0-canary.1', '15.2.3', '16.0.0'], ['15.2']],
  ['npm', 'GHSA-f29h-pxvx-f335', 'eslint-config-prettier', ['8.10.1', '9.1.1', '10.1.6', '10.1.7'], ['8.10.0', '8.10.2', '9.1.0', '9.1.2', '10.1.5', '10.1.8'], []],
  ['npm', 'GHSA-p6mc-m468-83gw', 'lodash.pick', ['4.0.0', '4.4.0', '4.4.0+build'], ['3.10.1', '4.0.0-rc.1', '4.4.1', '4.4.1-0'], []],
  ['npm', 'GHSA-p6mc-m468-83gw', 'lodash', ['3.7.0', '4.17.18', '4.17.19-0'], ['3.6.0', '3.7.0-beta', '4.17.19', '4.17.21'], ['4.17']],
  // PyPI (PEP 440: dev < a < b < rc < release < post; "v" and "1!" accepted)
  ['PyPI', 'GHSA-rvmq-4x66-q7j3', 'apache-airflow', ['1.10.10', '1.10.11b1', '1.10.11rc0', '1.10.11.dev0', '1.8.2rc1'], ['1.10.11rc1', '1.10.11rc2', '1.10.11', '1.10.11.post1', '2.0.0'], ['1.10.x', 'dev-main']],
  ['PyPI', 'GHSA-jjg7-2v4v-x38h', 'idna', ['0.1', '3.6', '3.7rc1', '3.7.dev0', 'v3.6'], ['3.7', '3.7.0', '3.7.post1', '3.8', '1!0.1'], ['3.7-final-ish']],
  ['PyPI', 'GHSA-2655-q453-22f9', 'django', ['1.3', '1.3.0', '1.3.3', '1.4', '1.4.1', '1.4.2rc1'], ['1.2.7', '1.3.4', '1.3.10', '1.4rc1', '1.4.2', '1.5'], []],
  // Lists 1.0 to 1.2.1 as affected below its range: OSV's rule is "listed or in range".
  ['PyPI', 'PYSEC-2012-7', 'django', ['1.0', '1.1', '1.2', '1.2.0', '1.2.1', '1.3', '1.3.3', '1.4', '1.4.1'], ['0.96', '1.3.4', '1.4.2', '1.5'], []],
  ['PyPI', 'GHSA-3f63-hfp8-52jq', 'pillow', ['1.0', '9.5.0', '10.1.0', '10.2.0.dev0', '10.2.0rc1'], ['10.2.0', '10.2.0.post1', '11.0.0'], []],
  // Maven (ComparableVersion: alpha < beta < milestone < rc < snapshot < release; RELEASE = "")
  ['Maven', 'GHSA-jfh8-c2jp-5v3q', 'org.apache.logging.log4j:log4j-core', ['2.0-beta9', '2.0-rc1', '2.0', '2.3', '2.4', '2.12.1', '2.13.0', '2.14.1', '2.15.0-rc1'], ['2.0-alpha1', '2.0-beta8', '2.3.1', '2.3.2', '2.12.2', '2.12.4', '2.15.0', '2.17.1'], []],
  ['Maven', 'GHSA-7rjr-3q55-vv33', 'org.apache.logging.log4j:log4j-core', ['2.0-beta9', '2.3', '2.4.0', '2.12.1', '2.13.0', '2.15.0'], ['2.3.1', '2.12.2', '2.16.0', '2.17.0'], []],
  ['Maven', 'GHSA-36p3-wjmg-h94x', 'org.springframework:spring-beans', ['5.0.0.RELEASE', '5.2.19.RELEASE', '5.2.20.M1', '5.3.0', '5.3.17', '5.3.18-SNAPSHOT'], ['5.2.20.RELEASE', '5.2.20', '5.3.0-M1', '5.3.0-RC1', '5.3.18', '5.3.19', '6.0.0'], []],
  ['Maven', 'GHSA-j77q-2qqg-6989', 'org.apache.struts:struts2-core', ['2.3.5', '2.3.31', '2.5', '2.5.10'], ['2.2.3', '2.3.32', '2.3.32.1', '2.5-BETA1', '2.5.10.1', '2.5.12'], []],
  ['Maven', 'GHSA-j9h8-phrw-h4fh', 'com.thoughtworks.xstream:xstream', ['1.2', '1.4.17', '1.4.18-SNAPSHOT'], ['1.4.18', '1.4.19', '1.4.20'], []],
  // Go (SemVer with "v"; pseudo-versions are prereleases of the next patch; stdlib "1.21.0-0")
  ['Go', 'GHSA-qppj-fm5r-hxr3', 'golang.org/x/net', ['v0.16.0', '0.16.0', 'v0.0.0-20230920000000-abcdefabcdef', 'v0.16.1-0.20231001000000-abcdefabcdef', 'v0.17.0-rc.1'], ['v0.17.0', 'v0.17.1-0.20231011000000-abcdefabcdef', 'v0.18.0'], ['v0.17', 'master']],
  ['Go', 'GO-2023-2102', 'stdlib', ['1.20.9', '1.21.0-rc.2', '1.21.0', '1.21.2'], ['1.20.10', '1.20.11', '1.21.3', '1.22.0'], ['1.21']],
  ['Go', 'GO-2024-2887', 'stdlib', ['1.21.10', '1.22.0-rc.1', '1.22.3'], ['1.21.11', '1.22.4', '1.23.0'], []],
  ['Go', 'GO-2026-6433', 'code.gitea.io/gitea', ['v1.17.0', 'v1.20.0', 'v1.99.0'], ['v1.16.9', 'v1.17.0-rc1'], []],
  // crates.io (RustSec writes "from the first version" as 0.0.0-0)
  ['crates.io', 'RUSTSEC-2023-0034', 'h2', ['0.0.1', '0.1.0', '0.3.16', '0.3.17-alpha.1'], ['0.3.17', '0.4.0'], ['0.3']],
  ['crates.io', 'GHSA-j7hp-h8jx-5ppr', 'webp', ['0.1.0', '0.2.5'], ['0.2.6', '0.3.0'], []],
  ['crates.io', 'RUSTSEC-2024-0019', 'mio', ['0.7.2', '0.8.10'], ['0.7.1', '0.8.11', '0.9.0'], []],
  // Its bound "0.65" is not SemVer: no version may come out "not affected".
  ['crates.io', 'GHSA-4p9f-7p9m-5vfg', 'russh', [], [], ['0.1.0', '0.64.0', '0.65.0', '0.70.0']],
  // RubyGems (Gem::Version: "5.2.2.rc1" < "5.2.2" < "5.2.2.1")
  ['RubyGems', 'GHSA-86g5-2wh3-gc9j', 'actionview', ['4.0.0', '4.2.11', '5.0.7.1', '5.1.6.1', '5.2.0', '5.2.1', '5.2.2.rc1', '5.2.2'], ['3.2.22', '4.2.11.1', '5.0.7.2', '5.1.6.2', '5.2.0.rc1', '5.2.2.1', '5.2.3', '6.0.0'], []],
  ['RubyGems', 'GHSA-2p68-f74v-9wc6', 'activesupport', ['5.0.0', '5.2.4.rc1', '5.2.4.2', '6.0.3.rc1', '6.0.3'], ['4.2.11', '5.2.4.3', '5.2.5', '6.0.0.beta1', '6.0.3.1'], []],
  ['RubyGems', 'GHSA-crjr-9rc5-ghw8', 'nokogiri', ['1.0.0', '1.13.3', '1.13.4.rc1'], ['1.13.4', '1.13.10', '1.14.0'], []],
  // Packagist (Composer: dev < alpha < beta < RC < stable < patch; "v" accepted)
  ['Packagist', 'DRUPAL-CORE-2018-002', 'drupal/core', ['8.0.0', '8.3.8', '8.4.0', '8.4.5', '8.5.0'], ['7.57', '8.3.9', '8.4.6', '8.5.0-rc1', '8.5.1', '8.6.0'], ['dev-main']],
  // Lists the 8.0.0 betas and RCs, which sort below its ">=8.0": they match as listed versions.
  ['Packagist', 'GHSA-7fh9-933g-885p', 'drupal/core', ['7.0', '7.57', '8.0.0-beta10', '8.0.0-rc4', '8.0.0', '8.3.8', '8.5.0'], ['6.38', '7.58', '8.3.9', '8.4.6', '8.5.1'], []],
  ['Packagist', 'GHSA-r7c9-c69m-rph8', 'phpunit/phpunit', ['4.8.19', '4.8.27', '5.0.10', '5.6.2', 'v5.6.2'], ['4.8.18', '4.8.28', '5.0.9', '5.6.3', '6.0.0'], []],
  ['Packagist', 'GHSA-f3gw-9ww9-jmc3', 'craftcms/cms', ['3.0.0-RC1', '3.0.0', '3.9.14', '4.0.0-RC1', '4.14.14', '5.0.0-RC1', '5.6.9.1', '5.6.16'], ['2.9.0', '3.9.15', '4.0.0-beta.1', '4.14.15', '5.0.0-beta.1', '5.6.17'], []],
  ['Packagist', 'GHSA-4qwp-7c67-jmcc', 'facade/ignition', ['1.6.14', '1.7.0', '1.16.13', '2.0.0', '2.4.1', '2.5.0', '2.5.1'], ['1.6.15', '1.6.16', '1.16.14', '2.4.2', '2.4.3', '2.5.2'], []],
  // NuGet (a fourth number is a revision; prerelease labels case-insensitive)
  ['NuGet', 'GHSA-ghhp-997w-qr28', 'System.Text.Encodings.Web', ['4.0.0', '4.5.0-preview1-26216-02', '4.5.0', '4.5.0.1', '4.7.1', '5.0.0'], ['3.9.0', '4.5.1', '4.5.1.1', '4.7.2', '5.0.0-rc.2', '5.0.1', '6.0.0'], []],
  ['NuGet', 'GHSA-5crp-9r3c-p9vr', 'Newtonsoft.Json', ['6.0.1', '12.0.3', '13.0.0.1', '13.0.1-beta1'], ['13.0.1', '13.0.1.1', '13.0.2'], []],
  ['NuGet', 'GHSA-vv6j-ww6x-54gx', 'CefSharp.Common', ['85.0.0', '98.1.200', '98.1.210-pre'], ['98.1.210', '99.0.0'], []],
];

describe('matching at the edges of real OSV ranges', () => {
  it('covers 30 or more advisories in all eight ecosystems', () => {
    expect(new Set(VECTORS.map((v) => v[1])).size).toBeGreaterThanOrEqual(30);
    expect(new Set(VECTORS.map((v) => v[0])).size).toBe(8);
  });

  for (const [eco, id, pkg, inside, outside, odd] of VECTORS) {
    it(`${eco} ${id} ${pkg}`, () => {
      const rec = records.find((r) => r.ecosystem === eco && r.id === id && r.affected[0].package.name === pkg);
      expect(rec, 'record in the fixture').toBeDefined();
      const lite = compactRecord(rec, eco);
      expect(lite).not.toBeNull();
      const entry = lite![3].find((a) => a[0] === pkg);
      expect(entry).toBeDefined();
      const [, ranges, extra = []] = entry!;
      const verdict = (v: string) => `${v}: ${matchAffect(eco, v, ranges, extra)}`;
      expect(inside.map(verdict)).toEqual(inside.map((v) => `${v}: affected`));
      expect(outside.map(verdict)).toEqual(outside.map((v) => `${v}: not_affected`));
      expect(odd.map(verdict)).toEqual(odd.map((v) => `${v}: unchecked`));
    });
  }
});
