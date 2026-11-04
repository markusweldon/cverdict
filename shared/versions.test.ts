import { describe, expect, it } from 'vitest';
import type { PackageEcosystem } from './contract';
import { COMPARATORS, MAX_VERSION, compileRanges, extraVersions, inRanges, matchAffect, parseEvent } from './versions';

/**
 * Best of three timings of `fn`, in ms. Exponential backtracking takes seconds on these inputs; the
 * best of three keeps one garbage-collection pause or a busy test worker from failing the check.
 */
function fastest(fn: () => void): number {
  let best = Infinity;
  for (let i = 0; i < 3; i++) {
    const t0 = performance.now();
    fn();
    best = Math.min(best, performance.now() - t0);
  }
  return best;
}

/** Each version is strictly lower than the next under the ecosystem's ordering. */
function expectAscending(eco: PackageEcosystem, versions: string[]): void {
  const c = COMPARATORS[eco];
  for (let i = 0; i + 1 < versions.length; i++) {
    const a = c.parse(versions[i]);
    const b = c.parse(versions[i + 1]);
    expect(a, `${eco} parses ${versions[i]}`).not.toBeNull();
    expect(b, `${eco} parses ${versions[i + 1]}`).not.toBeNull();
    expect(Math.sign(c.cmp(a!, b!)), `${eco}: ${versions[i]} < ${versions[i + 1]}`).toBe(-1);
    expect(Math.sign(c.cmp(b!, a!)), `${eco}: ${versions[i + 1]} > ${versions[i]}`).toBe(1);
  }
}

/** All versions are equal under the ecosystem's ordering. */
function expectEqual(eco: PackageEcosystem, versions: string[]): void {
  const c = COMPARATORS[eco];
  const first = c.parse(versions[0]);
  expect(first, `${eco} parses ${versions[0]}`).not.toBeNull();
  for (const v of versions.slice(1)) {
    const k = c.parse(v);
    expect(k, `${eco} parses ${v}`).not.toBeNull();
    expect(c.cmp(first!, k!), `${eco}: ${versions[0]} == ${v}`).toBe(0);
  }
}

describe('SemVer 2.0 (npm, crates.io, Go)', () => {
  it('orders prereleases as in SemVer 2.0 §11', () => {
    for (const eco of ['npm', 'crates.io', 'Go'] as const) {
      expectAscending(eco, ['1.0.0-alpha', '1.0.0-alpha.1', '1.0.0-alpha.beta', '1.0.0-beta', '1.0.0-beta.2', '1.0.0-beta.11', '1.0.0-rc.1', '1.0.0']);
      expectAscending(eco, ['1.0.0', '2.0.0', '2.1.0', '2.1.1', '10.0.0']);
    }
  });

  it('ignores build metadata and a leading v', () => {
    expectEqual('npm', ['1.0.0', '1.0.0+20130313144700', 'v1.0.0']);
    expectEqual('Go', ['v2.0.0+incompatible', '2.0.0']);
  });

  it('orders Go pseudo-versions by time, below the release they precede', () => {
    expectAscending('Go', ['v0.0.0-20210101000000-abcdefabcdef', 'v0.0.0-20220101000000-abcdefabcdef', 'v0.1.0', 'v1.2.4-0.20230101000000-abcdefabcdef', 'v1.2.4']);
  });

  it('rejects what SemVer does not accept', () => {
    for (const v of ['1.0', '1', '01.0.0', '1.0.0-01', '1.0.0-', 'latest', '1.0.0 beta', '']) expect(COMPARATORS.npm.parse(v), v).toBeNull();
  });
});

describe('PEP 440 (PyPI)', () => {
  it("orders the specification's example list", () => {
    expectAscending(
      'PyPI',
      '1.0.dev456 1.0a1 1.0a2.dev456 1.0a12.dev456 1.0a12 1.0b1.dev456 1.0b2 1.0b2.post345.dev456 1.0b2.post345 1.0rc1.dev456 1.0rc1 1.0 1.0+abc.5 1.0+abc.7 1.0+5 1.0.post456.dev34 1.0.post456 1.0.15 1.1.dev1'.split(' '),
    );
  });

  it('normalises spellings, trailing zeros and epochs', () => {
    expectEqual('PyPI', ['1.0', '1.0.0', 'v1.0', '1.0.0.0']);
    expectEqual('PyPI', ['1.0-1', '1.0.post1', '1.0-post1', '1.0.r1', '1.0rev1']);
    expectEqual('PyPI', ['1.0a1', '1.0alpha1', '1.0.a.1', '1.0-A1']);
    expectEqual('PyPI', ['1.0rc1', '1.0c1', '1.0pre1', '1.0preview1']);
    expectAscending('PyPI', ['2013.10', '1!0.1', '1!1.0']);
  });

  it('rejects legacy versions PEP 440 does not accept', () => {
    for (const v of ['0.9-eevee', 'trunk', '2.65.2+170606_', '1.0.0-beta-2-x', 'dev']) expect(COMPARATORS.PyPI.parse(v), v).toBeNull();
  });
});

describe('Maven ComparableVersion', () => {
  it("follows Maven's version order examples", () => {
    expectAscending('Maven', ['1', '1.1']);
    expectAscending('Maven', ['1-snapshot', '1', '1-sp']);
    expectEqual('Maven', ['1', '1.0', '1.0.0', '1-ga', '1-final', '1-release', '1.ga', '1.0.0-0.0']);
    expectAscending('Maven', ['1-alpha-1', '1-beta-1', '1-milestone-1', '1-rc-1', '1-SNAPSHOT', '1']);
    expectEqual('Maven', ['1-rc-1', '1-cr-1', '1-RC1', '1rc1']);
    expectEqual('Maven', ['1-a1', '1-alpha-1', '1-alpha1']);
    expectAscending('Maven', ['1.0.0-M3', '1.0.0-M12']);
    expectAscending('Maven', ['1-foo2', '1-foo10']);
    expectAscending('Maven', ['1-1', '1.1']);
    expectEqual('Maven', ['1-ga-1', '1-1']);
    expectAscending('Maven', ['1-sp-1', '1-1']);
    expectEqual('Maven', ['2.2.10.RELEASE', '2.2.10', '2.2.10.Final']);
  });

  it('orders the log4j and xstream versions OSV names', () => {
    expectAscending('Maven', ['2.0-alpha1', '2.0-beta9', '2.0-rc1', '2.0', '2.0.1', '2.3.1', '2.12.2', '2.13.0', '2.14.1', '2.15.0', '2.17.1']);
    expectAscending('Maven', ['1.4.17', '1.4.18', '1.4.19']);
    expectAscending('Maven', ['9.4.43.v20210629', '9.4.44.v20210927', '10.0.0']);
  });
});

describe('Gem::Version (RubyGems)', () => {
  it('orders prereleases below releases, letters below numbers', () => {
    expectAscending('RubyGems', ['1.0.a', '1.0.b1', '1.0']);
    expectAscending('RubyGems', ['5.2.1.rc1', '5.2.1', '5.2.1.1', '5.2.2']);
    expectAscending('RubyGems', ['1.0.0.pre', '1.0.0.rc1', '1.0.0']);
  });

  it('drops trailing zeros and reads "-" as ".pre."', () => {
    expectEqual('RubyGems', ['1.0.0', '1', '1.0']);
    expectEqual('RubyGems', ['7.0.0-rc3', '7.0.0.pre.rc3']);
    expectEqual('RubyGems', ['1.0.a.0', '1.a']);
  });
});

describe('NuGet', () => {
  it('compares prerelease labels without case and pads to four numbers', () => {
    expectEqual('NuGet', ['1.0.0-alpha', '1.0.0-ALPHA']);
    expectEqual('NuGet', ['1.0', '1.0.0', '1.0.0.0', '1.0.0+abc']);
    expectAscending('NuGet', ['1.0.0', '1.0.0.1']);
    expectAscending('NuGet', ['11.0.0-preview.1', '11.0.0-rc.2', '11.0.0']);
    expectAscending('NuGet', ['85.0.0', '85.3.130', '86.0.241']);
  });
});

describe('Composer (Packagist)', () => {
  it('orders stabilities dev < alpha < beta < RC < stable < patch', () => {
    expectAscending('Packagist', ['1.0.0-dev', '1.0.0-alpha1', '1.0.0-beta', '1.0.0-RC1', '1.0.0', '1.0.0-p1']);
    expectAscending('Packagist', ['1.0.0-beta1-dev', '1.0.0-beta1', '1.0.0-beta2']);
    expectAscending('Packagist', ['2.4.4', '2.4.4-p9', '2.4.5']);
    expectAscending('Packagist', ['8.4.9', '8.5.0', '8.5.1']);
  });

  it('accepts a leading v and pads to four numbers', () => {
    expectEqual('Packagist', ['v6.4.3', '6.4.3', '6.4.3.0']);
    expectEqual('Packagist', ['1.0.0-patch1', '1.0.0-pl1', '1.0.0-p1']);
  });

  it('rejects branches and strings Composer would reject', () => {
    for (const v of ['dev-main', '1.x-dev', 'trunk', '1.2.3.4.5']) expect(COMPARATORS.Packagist.parse(v), v).toBeNull();
  });
});

describe('hostile input', () => {
  const inputs = ['1.0.0-' + 'a-'.repeat(50_000), '1.'.repeat(50_000) + '1', 'a'.repeat(200_000), '%'.repeat(100_000), '0'.repeat(100_000)];

  it('every comparator rejects strings over MAX_VERSION quickly', () => {
    for (const [eco, c] of Object.entries(COMPARATORS)) {
      for (const v of inputs) {
        const t0 = performance.now();
        expect(c.parse(v), `${eco} ${v.slice(0, 12)}…`).toBeNull();
        expect(performance.now() - t0).toBeLessThan(10);
      }
    }
  });

  it('every comparator handles a 128-character adversarial string quickly', () => {
    const near = ['1.0.0-' + 'a-'.repeat(61), '1.'.repeat(63) + '1', '1' + '-a1'.repeat(42), 'v'.repeat(MAX_VERSION)];
    for (const [eco, c] of Object.entries(COMPARATORS)) {
      for (const v of near) {
        expect(v.length).toBeLessThanOrEqual(MAX_VERSION);
        const t0 = performance.now();
        const k = c.parse(v);
        if (k !== null) c.cmp(k, k);
        expect(performance.now() - t0, `${eco} ${v.slice(0, 12)}`).toBeLessThan(10);
      }
    }
  });

  it('every comparator handles strings shaped for backtracking quickly (a keyword, a run, a bad last character)', () => {
    // "1.0.0-beta1111…1x" once took 2.7 s at 37 characters in the Composer ordering, doubling with each digit.
    const heads = ['1', '1.0', '1.0.0-', '1.0.0-beta', '1.0.0-p', '1.0.0-rc', '1.0a', '1.0.post', '1!1.0+a', '1-', '1.a'];
    const runs = ['1', '1.', '.1', '-1', 'a1', '1a', 'a.', '-a', '0'];
    const tails = ['', 'x', '!', '-', '.', '+'];
    for (const [eco, c] of Object.entries(COMPARATORS)) {
      let worst = 0;
      for (const h of heads) for (const r of runs) for (const t of tails) {
        const v = (h + r.repeat(MAX_VERSION)).slice(0, MAX_VERSION - t.length) + t;
        worst = Math.max(
          worst,
          fastest(() => {
            const k = c.parse(v);
            if (k !== null) c.cmp(k, k);
          }),
        );
      }
      expect(worst, eco).toBeLessThan(10);
    }
  });

  it('a backtracking-shaped Composer version is checked like any other unreadable version', () => {
    const hostile = `1.0.0-beta${'1'.repeat(100)}x`;
    expect(COMPARATORS.Packagist.parse(hostile)).toBeNull();
    expect(matchAffect('Packagist', hostile, [['>=0', '<8.5.1']])).toBe('unchecked');
    expect(fastest(() => matchAffect('Packagist', hostile, [['>=0', '<8.5.1']]))).toBeLessThan(10);
    // The same family of strings still reads when it is valid.
    expectEqual('Packagist', ['1.0.0-beta1.2', '1.0.0-beta.1.2', '1.0.0-beta-1-2']);
    expectAscending('Packagist', ['1.0.0-beta1', `1.0.0-beta1${'0'.repeat(20)}`]);
  });
});

describe('parseEvent', () => {
  it('reads the four event forms', () => {
    expect(parseEvent('>=1.0')).toEqual({ op: '>=', v: '1.0' });
    expect(parseEvent('<2.0')).toEqual({ op: '<', v: '2.0' });
    expect(parseEvent('<=2.0')).toEqual({ op: '<=', v: '2.0' });
    expect(parseEvent('?git=unknown')).toEqual({ op: '?', kind: 'git', v: 'unknown' });
    expect(parseEvent('=1.0')).toBeNull();
    expect(parseEvent('?Bad=1')).toBeNull();
  });
});

describe('inRanges (the OSV rule)', () => {
  // GHSA-jfh8-c2jp-5v3q (Log4Shell), as OSV lists its ranges.
  const log4j = [
    ['>=2.13.0', '<2.15.0'],
    ['>=2.0-beta9', '<2.3.1'],
    ['>=2.4', '<2.12.2'],
  ];

  it('matches log4j-core as the advisory says', () => {
    expect(inRanges('Maven', '2.14.1', log4j)).toBe(true);
    expect(inRanges('Maven', '2.0-beta9', log4j)).toBe(true);
    expect(inRanges('Maven', '2.12.1', log4j)).toBe(true);
    for (const v of ['2.15.0', '2.12.2', '2.3.1', '2.17.1', '2.0-beta8', '1.2.17']) expect(inRanges('Maven', v, [...log4j]), v).toBe(false);
  });

  it('handles from-the-first-release, last_affected and several pairs in one range', () => {
    expect(inRanges('npm', '0.0.1', [['>=0', '<1.2.3']])).toBe(true);
    expect(inRanges('npm', '1.2.3', [['>=0', '<1.2.3']])).toBe(false);
    expect(inRanges('crates.io', '0.1.0', [['>=0.0.0-0', '<0.2.0']])).toBe(true);
    expect(inRanges('PyPI', '1.4', [['>=1.0', '<=1.4']])).toBe(true);
    expect(inRanges('PyPI', '1.4.1', [['>=1.0', '<=1.4']])).toBe(false);
    expect(inRanges('PyPI', '9.9', [['>=1.0']])).toBe(true);
    // RustSec style: two pairs in one range, events out of order.
    const pairs = [['>=3.0.0', '<4.0.0', '>=1.0.0', '<2.0.0']];
    expect(inRanges('crates.io', '1.5.0', pairs)).toBe(true);
    expect(inRanges('crates.io', '2.5.0', pairs)).toBe(false);
    expect(inRanges('crates.io', '3.5.0', pairs)).toBe(true);
    expect(inRanges('crates.io', '4.0.0', pairs)).toBe(false);
  });

  it('never turns a range it cannot read into "not affected"', () => {
    expect(inRanges('npm', 'not-a-version', [['>=0', '<1.0.0']])).toBeNull();
    expect(inRanges('npm', '0.5.0', [['>=0', '<garbage']])).toBeNull();
    expect(inRanges('npm', '0.5.0', [['?git=unknown']])).toBeNull();
    expect(inRanges('npm', '0.5.0', [['?limit=2.0.0'], ['>=0', '<1.0.0']])).toBe(true);
    expect(inRanges('npm', '1.5.0', [['?limit=2.0.0'], ['>=0', '<1.0.0']])).toBeNull();
    expect(inRanges('npm', '1.5.0', [[]])).toBeNull();
    expect(inRanges('npm', '1.5.0', [])).toBe(false);
  });

  it('compiles once and agrees with inRanges', () => {
    const test = compileRanges('Maven', log4j);
    for (const v of ['2.14.1', '2.15.0', 'x y']) expect(test(v)).toBe(inRanges('Maven', v, log4j));
  });
});

describe('extraVersions and matchAffect', () => {
  it('keeps exactly the listed versions the ranges do not cover', () => {
    // PYSEC-2012-7 lists Django 1.2 while its range starts at 1.3.
    expect(extraVersions('PyPI', ['1.2', '1.3', '1.3.1', '1.3.1', 'trunk'], [['>=1.3', '<1.3.2']])).toEqual(['1.2', 'trunk']);
  });

  it('applies the per-entry rule of the design (6.1)', () => {
    const ranges = [['>=1.0.0', '<1.2.0']];
    expect(matchAffect('npm', null, ranges)).toBe('unchecked');
    expect(matchAffect('npm', '1.1.0', ranges)).toBe('affected');
    expect(matchAffect('npm', '1.2.0', ranges)).toBe('not_affected');
    expect(matchAffect('npm', 'banana', ranges)).toBe('unchecked');
    expect(matchAffect('npm', 'banana', ranges, ['banana'])).toBe('affected');
    expect(matchAffect('Go', 'v1.5.0', ranges, ['1.5.0'])).toBe('affected');
    expect(matchAffect('npm', '1.5.0', [], ['1.4.0'])).toBe('not_affected');
    expect(matchAffect('npm', '1.5.0', [])).toBe('unchecked');
    expect(matchAffect('npm', '1.5.0', [['?versions=capped'], ...ranges], ['0.1.0'])).toBe('unchecked');
  });
});
