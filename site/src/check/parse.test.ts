import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { FORMATS, GO_SUM_NOTE, MAX_LINE, parse, ParseError, purlComponent, type Component, type FormatId } from './parse';

const fixture = (name: string) => readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8');

/** "eco:name@version", "eco:name (why)" for no version, "eco:name !skip" for not checked. */
function brief(c: Component): string {
  const who = `${c.eco ?? c.type ?? '?'}:${c.name}`;
  if (c.skip) return `${who} !${c.skip}`;
  if (c.noVersion) return `${who} (${c.noVersion})`;
  return `${who}@${c.version}`;
}
const read = (text: string, filename = '', forced: FormatId | null = null) => {
  const p = parse(text, filename, forced);
  return { format: p.format, items: p.components.map(brief), notes: p.notes };
};

describe('fixtures (one per format, detected from the file name)', () => {
  const cases: [string, FormatId, string[]][] = [
    [
      'shop.cdx.json',
      'cyclonedx-json',
      [
        'Maven:org.apache.logging.log4j:log4j-core@2.14.1',
        'npm:Łódź-utils@1.0.0',
        'PyPI:жук@0.1',
        'crates.io:thạch@2.0.0',
        'PyPI:brotli@1.1.0',
        '?:shop !no-purl',
        '?:no-purl-lib !no-purl',
        '?:broken !bad-purl',
        '?:debian !no-purl',
        'deb:debian/openssl !ecosystem',
        'Maven:org.apache.logging.log4j:log4j-api@2.14.1',
      ],
    ],
    [
      'bom.xml',
      'cyclonedx-xml',
      ['?:shop !no-purl', 'Maven:org.apache.logging.log4j:log4j-core@2.14.1', 'npm:@pkgr/core@0.2.8', 'crates.io:webp@0.2.6', 'crates.io:libwebp-sys@0.9.5', '?:vendored-thing !no-purl'],
    ],
    ['app.spdx.json', 'spdx-json', ['Maven:org.apache.logging.log4j:log4j-core@2.14.1', 'Maven:com.thoughtworks.xstream:xstream@1.4.18', 'deb:debian/libc6 !ecosystem', '?:internal-tool !no-purl']],
    ['app.spdx3.json', 'spdx-json', ['PyPI:brotli@1.1.0', 'Maven:com.thoughtworks.xstream:xstream@1.4.17']],
    ['app.spdx', 'spdx-tag', ['Maven:org.apache.logging.log4j:log4j-core@2.14.1', 'RubyGems:actionview@5.2.1', 'apk:alpine/zlib !ecosystem', '?:in-house !no-purl']],
    [
      'purls.txt',
      'purl',
      ['npm:lodash@4.17.21', 'npm:@pkgr/core@0.2.8', 'Go:stdlib@1.22.5', 'Go:github.com/gin-gonic/gin@v1.9.0', 'deb:debian/openssl !ecosystem', 'rpm:redhat/bash !ecosystem', 'NuGet:Newtonsoft.Json@13.0.1'],
    ],
    ['package-lock.json', 'npm-lock', ['npm:@pkgr/core@0.2.8', 'npm:rollup@4.58.0', 'npm:vite@8.3.1', 'npm:forked !not-registry', 'npm:shop-ui !not-registry']],
    ['yarn.lock', 'yarn', ['npm:@pkgr/core@0.2.8', 'npm:follow-redirects@1.16.0']],
    ['yarn-berry.lock', 'yarn', ['npm:rollup@4.58.0', 'npm:vite@8.3.3', 'npm:app !not-registry']],
    ['pnpm-lock.yaml', 'pnpm', ['npm:vite@8.3.1', 'npm:@pkgr/core@0.2.9']],
    ['requirements.txt', 'requirements', ['PyPI:Brotli@1.1.0', 'PyPI:pillow@12.0.0', 'PyPI:requests@2.32.3', 'PyPI:apache_airflow@1.10.10', 'PyPI:flask (not-exact)']],
    ['poetry.lock', 'poetry', ['PyPI:brotli@1.2.1', 'PyPI:apache-superset@2.0.1', 'PyPI:forked-lib !not-registry']],
    ['uv.lock', 'uv', ['PyPI:shop !not-registry', 'PyPI:brotli@1.1.0', 'PyPI:apache-superset@2.0.1', 'PyPI:internal !not-registry']],
    ['Pipfile.lock', 'pipfile', ['PyPI:brotli@1.0.9', 'PyPI:pytest@8.0.0']],
    [
      'go.mod',
      'gomod',
      ['Go:code.gitea.io/gitea@v1.20.0', 'Go:github.com/corazawaf/coraza/v3@v3.7.0', 'Go:golang.org/x/text@v0.0.0-20210101000000-abcdefabcdef', 'Go:github.com/radius-project/radius (go-local)', 'Go:stdlib !go-stdlib'],
    ],
    ['go.sum', 'gosum', ['Go:code.gitea.io/gitea@v1.20.0', 'Go:golang.org/x/text@v0.3.7', 'Go:golang.org/x/text@v0.14.0']],
    ['Cargo.lock', 'cargo', ['crates.io:app !not-registry', 'crates.io:webp@0.2.5', 'crates.io:ammonia@4.0.1', 'crates.io:forked !not-registry']],
    ['Gemfile.lock', 'gemfile', ['RubyGems:private_gem !not-registry', 'RubyGems:actionview@5.2.1', 'RubyGems:jquery-rails@4.4.0', 'RubyGems:nokogiri@1.15.4']],
    ['composer.lock', 'composer', ['Packagist:drupal/core@8.5.0', 'Packagist:craftcms/cms@5.5.1', 'Packagist:acme/thing !dev-branch', 'Packagist:components/jquery@v3.5.0']],
    ['packages.lock.json', 'nuget', ['NuGet:CefSharp.Common@85.0.0', 'NuGet:MyLib !not-registry']],
    ['gradle.lockfile', 'gradle', ['Maven:com.thoughtworks.xstream:xstream@1.4.17', 'Maven:org.apache.logging.log4j:log4j-core@2.17.1']],
  ];
  for (const [file, format, items] of cases) {
    it(file, () => {
      const r = read(fixture(file), file);
      expect(r.format).toBe(format);
      expect([...r.items].sort()).toEqual([...items].sort());
    });
    it(`${file} without its name (pasted)`, () => {
      expect(read(fixture(file)).format).toBe(format);
    });
  }

  it('reads a real CycloneDX SBOM of this repository (cyclonedx-npm 6.0.1)', () => {
    const p = parse(fixture('cverdict.cdx.json'), 'bom.json');
    expect(p.format).toBe('cyclonedx-json');
    // The 162 dependencies, one listed twice, and the SBOM's subject.
    expect(p.components.length).toBe(164);
    expect(new Set(p.components.map((c) => `${c.name}@${c.version}`)).size).toBe(163);
    expect(p.components.filter((c) => c.name === 'cverdict').map((c) => c.version)).toEqual(['0.1.0']);
    expect(p.components.every((c) => c.eco === 'npm' && c.version && !c.skip)).toBe(true);
  });

  it('notes what it could not read', () => {
    expect(read(fixture('bom.xml')).notes).toEqual([]);
    expect(read(fixture('purls.txt')).notes).toEqual(['Ignored a line that is not a package URL.']);
    expect(read(fixture('requirements.txt')).notes).toEqual(['A line includes another requirements file (-r or -c). Check that file too.']);
    expect(read(fixture('go.sum')).notes).toEqual([GO_SUM_NOTE]);
  });
});

describe('one SBOM in three formats', () => {
  it('gives the same packages as CycloneDX JSON, CycloneDX XML and SPDX JSON: the subject in, tools and build components out', () => {
    const want = [
      'Maven:com.example:order-service@1.4.0',
      'Maven:org.apache.logging.log4j:log4j-core@2.14.1',
      'Maven:org.apache.logging.log4j:log4j-api@2.14.1',
      '?:com.example/internal-utils !no-purl',
      'deb:debian/libssl3 !ecosystem',
    ].sort();
    for (const file of ['same.cdx.json', 'same.cdx.xml', 'same.spdx.json']) {
      const r = read(fixture(file), file);
      expect([file, [...r.items].sort(), r.notes]).toEqual([file, want, []]);
    }
  });

  it('reads CycloneDX XML fields of the component itself, never of its license, supplier or a comment', () => {
    const xml =
      '<bom xmlns="http://cyclonedx.org/schema/bom/1.6"><components><component><supplier><name>Acme</name></supplier><name>a</name><licenses><license><name>MIT</name></license></licenses>' +
      '<version>1.0.0</version></component><!-- <component><name>hidden</name></component> --><component/><component><name>b<b>bold</b></name></component></components></bom>';
    expect(read(xml).items).toEqual(['?:a !no-purl', '?:(no name) !no-purl']);
    // An unclosed comment or a file cut off mid-way ends the reading; what came before is kept.
    expect(read('<bom xmlns="http://cyclonedx.org/schema/bom/1.6"><components><component><purl>pkg:npm/x@1.0.0</purl></component><!-- <component>').items).toEqual(['npm:x@1.0.0']);
    expect(read('<bom xmlns="http://cyclonedx.org/schema/bom/1.6"><components><component><purl>pkg:npm/y@2.0.0</purl>').items).toEqual(['npm:y@2.0.0']);
  });
});

describe('package URLs', () => {
  it.each([
    ['pkg:npm/%40angular/core@17.0.0', 'npm:@angular/core@17.0.0'],
    ['pkg:npm/@angular/core@17.0.0', 'npm:@angular/core@17.0.0'],
    ['pkg:npm/lodash', 'npm:lodash (no-version)'],
    ['pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar&classifier=x#sub/path', 'Maven:org.apache.logging.log4j:log4j-core@2.14.1'],
    ['pkg:golang/github.com/gin-gonic/gin@v1.9.0', 'Go:github.com/gin-gonic/gin@v1.9.0'],
    ['pkg:golang/stdlib@go1.22.5', 'Go:stdlib@1.22.5'],
    ['pkg:golang/stdlib@1.22.5', 'Go:stdlib@1.22.5'],
    ['pkg:composer/drupal/core@8.5.0', 'Packagist:drupal/core@8.5.0'],
    ['PKG:PyPI/Django@4.2.0', 'PyPI:Django@4.2.0'],
    ['pkg://cargo/webp@0.2.5', 'crates.io:webp@0.2.5'],
    ['pkg:gem/rails@7.1.0%2B1', 'RubyGems:rails@7.1.0+1'],
    ['pkg:deb/debian/curl@7.88.1-10', 'deb:debian/curl !ecosystem'],
  ])('%s', (purl, want) => {
    const c = purlComponent(purl);
    expect(c && brief(c)).toBe(want);
  });

  it.each(['npm/lodash@1', 'pkg:', 'pkg:npm', 'pkg:/lodash@1', 'pkg:1npm/lodash@1', `pkg:npm/${'a'.repeat(3000)}@1`])('rejects %s', (purl) => {
    expect(purlComponent(purl)).toBeNull();
  });
});

describe('npm lockfiles', () => {
  it('reads v1 trees, aliases and non-registry versions', () => {
    const lock = {
      lockfileVersion: 1,
      dependencies: {
        a: { version: '1.0.0', resolved: 'https://registry.npmjs.org/a/-/a-1.0.0.tgz', dependencies: { b: { version: '2.0.0' } } },
        old: { version: 'npm:new-name@3.0.0' },
        g: { version: 'git+https://github.com/x/g.git#abc' },
        f: { version: 'file:../f' },
      },
    };
    expect(read(JSON.stringify(lock), 'npm-shrinkwrap.json').items.sort()).toEqual(['npm:a@1.0.0', 'npm:b@2.0.0', 'npm:f !not-registry', 'npm:g !not-registry', 'npm:new-name@3.0.0']);
  });

  it('prefers packages over dependencies in v2', () => {
    const lock = { lockfileVersion: 2, packages: { '': {}, 'node_modules/x': { version: '1.0.0' } }, dependencies: { y: { version: '9.9.9' } } };
    expect(read(JSON.stringify(lock)).items).toEqual(['npm:x@1.0.0']);
  });
});

describe('yarn and pnpm', () => {
  it('reads yarn v1 aliases and non-registry ranges', () => {
    const text = [
      '# yarn lockfile v1',
      '',
      '"old@npm:new-name@^1.0.0":',
      '  version "1.2.0"',
      '',
      'g@git+https://github.com/x/g.git#abc:',
      '  version "0.0.1"',
      '',
      'f@file:../f:',
      '  version "0.0.2"',
      '',
      'gh@user/repo#v1:',
      '  version "0.0.3"',
      '',
      '__proto__@^1.0.0, constructor@^1.0.0:',
      '  version "1.0.0"',
      '  dependencies:',
      '    version "9.9.9"',
    ].join('\n');
    expect(read(text).items).toEqual(['npm:new-name@1.2.0', 'npm:g !not-registry', 'npm:f !not-registry', 'npm:gh !not-registry', 'npm:__proto__@1.0.0']);
    expect(({} as Record<string, unknown>).version).toBeUndefined();
  });

  it('reads Berry patch, workspace and alias resolutions', () => {
    const text = [
      '__metadata:',
      '  version: 8',
      '',
      '"resolve@patch:resolve@npm%3A^1.20.0#~builtin<compat/resolve>":',
      '  version: 1.22.1',
      '  resolution: "resolve@patch:resolve@npm%3A1.22.1#~builtin<compat/resolve>::version=1.22.1&hash=c3c19d"',
      '',
      '"old@npm:new-name@^2":',
      '  version: 2.1.0',
      '  resolution: "new-name@npm:2.1.0"',
      '',
      '"lib@portal:../lib::locator=app%40workspace%3A.":',
      '  version: 0.0.0-use.local',
      '  resolution: "lib@portal:../lib::locator=app%40workspace%3A."',
    ].join('\n');
    expect(read(text).items).toEqual(['npm:resolve@1.22.1', 'npm:new-name@2.1.0', 'npm:lib !not-registry']);
  });

  it('reads pnpm v5 keys with peer suffixes', () => {
    const text = ['lockfileVersion: 5.4', '', 'packages:', '', '  /react-dom/17.0.2_react@17.0.2:', '    resolution: {integrity: x}', '  /@babel/core/7.20.0:', '    resolution: {integrity: y}', '  github.com/user/repo/abc123:', '    name: repo', '    version: 1.0.0'].join('\n');
    expect(read(text).items).toEqual(['npm:react-dom@17.0.2', 'npm:@babel/core@7.20.0', 'npm:github.com/user/repo !not-registry']);
  });

  it('reads pnpm v6 keys', () => {
    const text = ["lockfileVersion: '6.0'", '', 'packages:', '', '  /vite@8.3.1(@types/node@22.0.0):', '    resolution: {integrity: x}', "  '/@pkgr/core@0.2.8':", '    resolution: {integrity: y}'].join('\n');
    expect(read(text).items).toEqual(['npm:vite@8.3.1', 'npm:@pkgr/core@0.2.8']);
  });

  it('reads pnpm v9 packages and snapshots once each', () => {
    const text = [
      "lockfileVersion: '9.0'",
      '',
      'importers:',
      '  .:',
      '    dependencies:',
      '      constructor:',
      '        version: 1.0.0',
      '',
      'packages:',
      '  __proto__@1.0.0:',
      '    resolution: {integrity: x}',
      "  'local@file:../local':",
      '    resolution: {directory: ../local}',
      '',
      'snapshots:',
      '  __proto__@1.0.0: {}',
      '  vite@8.3.1(@types/node@22.0.0):',
      '    dependencies:',
      '      rollup: 4.59.0',
    ].join('\n');
    expect(read(text).items).toEqual(['npm:__proto__@1.0.0', 'npm:local !not-registry', 'npm:vite@8.3.1']);
  });
});

describe('Python', () => {
  it('reads requirements.txt: pins, extras, markers, continuations, options and direct references', () => {
    const text = [
      '# comment',
      'Django==4.2.7 # trailing comment',
      'requests[socks,security] == 2.32.3 ; python_version >= "3.8"',
      'numpy===1.26.4',
      'urllib3==1.* ',
      'flask>=3.0,<4',
      'six',
      'idna==3.7 \\',
      '    --hash=sha256:00 \\',
      '    --hash=sha256:11',
      'mylib @ https://example.com/mylib-1.0.tar.gz',
      '-e git+https://github.com/x/y.git#egg=ylib',
      '-r base.txt',
      '--index-url https://pypi.org/simple',
      './local/path',
    ].join('\r\n');
    const r = read(text, 'requirements-dev.txt');
    expect(r.items).toEqual([
      'PyPI:Django@4.2.7',
      'PyPI:requests@2.32.3',
      'PyPI:numpy@1.26.4',
      'PyPI:urllib3 (not-exact)',
      'PyPI:flask (not-exact)',
      'PyPI:six (not-exact)',
      'PyPI:idna@3.7',
      'PyPI:mylib !not-registry',
      'PyPI:ylib !not-registry',
    ]);
    expect(r.notes).toHaveLength(2);
  });

  it('reads Pipfile.lock non-registry entries and loose specs', () => {
    const lock = { _meta: {}, default: { a: { version: '==1.0' }, b: { git: 'https://x/b.git' }, c: { version: '*' } }, develop: {} };
    expect(read(JSON.stringify(lock)).items).toEqual(['PyPI:a@1.0', 'PyPI:b !not-registry', 'PyPI:c (not-exact)']);
  });
});

describe('Go, Ruby, PHP, .NET', () => {
  it('reads go.mod replace forms', () => {
    const text = [
      'module example.com/app',
      'go 1.22',
      'require (',
      '\t"example.com/a" v1.0.0',
      '\texample.com/b v1.1.0 // indirect',
      '\texample.com/c v1.2.0',
      ')',
      'replace example.com/b => example.com/b-fork v1.1.5',
      'replace example.com/c v1.0.0 => ../c',
      'replace (',
      '\texample.com/a => C:\\src\\a',
      ')',
      'exclude example.com/d v0.1.0',
    ].join('\n');
    expect(read(text).items).toEqual(['Go:example.com/a (go-local)', 'Go:example.com/b-fork@v1.1.5', 'Go:example.com/c@v1.2.0', 'Go:stdlib !go-stdlib']);
  });

  it('strips gem platforms and keeps odd names as names', () => {
    const text = ['GEM', '  remote: https://rubygems.org/', '  specs:', '    __proto__ (1.0.0)', '    jruby-openssl (0.14.2-java)', '    sqlite3 (1.7.0-arm64-darwin)', '    rails (7.1.0.rc1)', '', 'PATH', '  remote: .', '  specs:', '    mygem (0.1.0)'].join('\n');
    expect(read(text).items).toEqual(['RubyGems:__proto__@1.0.0', 'RubyGems:jruby-openssl@0.14.2', 'RubyGems:sqlite3@1.7.0', 'RubyGems:rails@7.1.0.rc1', 'RubyGems:mygem !not-registry']);
  });

  it('reads composer dev branches and path packages', () => {
    const lock = { 'content-hash': 'x', packages: [{ name: 'a/b', version: '1.x-dev' }, { name: 'c/d', version: '2.0.0', dist: { type: 'path' } }], 'packages-dev': [{ name: 'e/f', version: '3.0.0' }] };
    expect(read(JSON.stringify(lock)).items).toEqual(['Packagist:a/b !dev-branch', 'Packagist:c/d !not-registry', 'Packagist:e/f@3.0.0']);
  });
});

describe('input handling', () => {
  it('accepts CRLF line ends and a UTF-8 byte order mark', () => {
    expect(read('\ufeffpkg:npm/a@1.0.0\r\npkg:npm/b@2.0.0\r\n').items).toEqual(['npm:a@1.0.0', 'npm:b@2.0.0']);
    expect(read(`\ufeff${JSON.stringify({ bomFormat: 'CycloneDX', components: [{ purl: 'pkg:npm/a@1' }] })}`).items).toEqual(['npm:a@1']);
  });

  it('reports empty input, unknown files, truncated JSON and files with no packages', () => {
    const kind = (text: string, forced: FormatId | null = null) => {
      try {
        parse(text, '', forced);
        return 'parsed';
      } catch (e) {
        return e instanceof ParseError ? e.kind : 'other';
      }
    };
    expect(kind('   \n')).toBe('empty');
    expect(kind('hello world\nthis is text')).toBe('unknown');
    expect(kind('{"bomFormat": "CycloneDX", "components": [')).toBe('json');
    expect(kind('{"some": "json"}')).toBe('unknown');
    expect(kind('{"bomFormat": "CycloneDX", "components": []}')).toBe('empty');
    expect(kind('module x\n')).toBe('empty');
    expect(kind('not json', 'npm-lock')).toBe('json');
    const e = (() => {
      try {
        parse('{"a": tru');
      } catch (err) {
        return err as ParseError;
      }
    })();
    expect(e?.message).toMatch(/^This looks like JSON, but it could not be read: .+\. Check that the whole file was pasted\.$/);
  });

  it('reads deeply nested CycloneDX components without recursion', () => {
    const depth = 50_000;
    const text = `{"bomFormat":"CycloneDX","components":${'[{"purl":"pkg:npm/a@1","components":'.repeat(depth)}[]${'}]'.repeat(depth)}}`;
    expect(parse(text).components).toHaveLength(depth);
  });

  it('detects SPDX 3 from a shallow @context only, so a deep one cannot overflow the stack', () => {
    const pkg = '{"type":"software_Package","name":"a","software_packageUrl":"pkg:npm/a@1"}';
    const depth = 200_000;
    const deep = `{"@graph":[${pkg}],"@context":${'['.repeat(depth)}"https://spdx.org/rdf/3.0.1/spdx-context.jsonld"${']'.repeat(depth)}}`;
    // Before: JSON.stringify(@context) threw a RangeError, which is not a ParseError and left the page waiting.
    expect(() => parse(deep)).toThrow(ParseError);
    expect(read(`{"@graph":[${pkg}],"@context":["https://spdx.org/rdf/3.0.1/spdx-context.jsonld",{"x":"y"}]}`).items).toEqual(['npm:a@1']);
    expect(read(`{"@graph":[${pkg}],"@context":{"spdx":"https://spdx.org/rdf/3.0.1/terms/"}}`).items).toEqual(['npm:a@1']);
  });

  it('skips lines over 64 KB in line formats, with a note', () => {
    const r = read(`pkg:npm/a@1\npkg:npm/${'b'.repeat(MAX_LINE)}@1\npkg:npm/c@2\n`);
    expect(r.items).toEqual(['npm:a@1', 'npm:c@2']);
    expect(r.notes).toContain('Skipped a line longer than 64 KB.');
  });

  it('reads minified CycloneDX JSON and XML on one line in full', () => {
    const n = 20_000;
    const json = JSON.stringify({ bomFormat: 'CycloneDX', components: Array.from({ length: n }, (_, i) => ({ purl: `pkg:npm/pkg-${i}@1.0.${i}` })) });
    expect(json.length).toBeGreaterThan(MAX_LINE * 8);
    expect(parse(json).components).toHaveLength(n);
    const xml = `<bom xmlns="http://cyclonedx.org/schema/bom/1.6"><components>${Array.from({ length: n }, (_, i) => `<component bom-ref="pkg:npm/pkg-${i}@1.0.${i}"><purl>pkg:npm/pkg-${i}@1.0.${i}</purl></component>`).join('')}</components><dependencies><dependency ref="pkg:npm/pkg-0@1.0.0"/></dependencies></bom>`;
    expect(xml.includes('\n')).toBe(false);
    expect(parse(xml).components).toHaveLength(n);
  });

  it('decodes XML entities in package URLs and expands nothing else', () => {
    const xml = '<bom xmlns="http://cyclonedx.org/schema/bom/1.5"><components><component><purl>pkg:npm/&#x40;a/b@1.0.0?x=1&amp;y=2</purl></component><component><purl>pkg:npm/c@&ext;</purl></component></components></bom>';
    expect(read(xml).items).toEqual(['npm:@a/b@1.0.0', 'npm:c@&ext;']);
  });

  it('drops names over 512 characters with a note', () => {
    const r = read(`pkg:npm/${'n'.repeat(600)}@1\npkg:npm/ok@1\n`);
    expect(r.items).toEqual(['npm:ok@1']);
    expect(r.notes).toContain('Skipped an entry with no name or a name longer than 512 characters.');
  });

  it('never writes to Object.prototype, whatever the names', () => {
    const names = ['__proto__', 'constructor', 'prototype', 'toString', 'hasOwnProperty'];
    const yarn = names.map((n) => `${n}@^1.0.0:\n  version "1.0.0"\n`).join('\n');
    const pnpm = `lockfileVersion: '9.0'\npackages:\n${names.map((n) => `  ${n}@1.0.0:\n    resolution: {integrity: x}\n`).join('')}`;
    const gem = `GEM\n  remote: https://rubygems.org/\n  specs:\n${names.map((n) => `    ${n} (1.0.0)\n`).join('')}`;
    const lock = JSON.stringify({ lockfileVersion: 3, packages: Object.fromEntries(names.map((n) => [`node_modules/${n}`, { version: '1.0.0' }])) });
    for (const [text, file] of [
      [yarn, 'yarn.lock'],
      [pnpm, 'pnpm-lock.yaml'],
      [gem, 'Gemfile.lock'],
      [lock, 'package-lock.json'],
    ]) {
      expect(parse(text, file).components.map((c) => c.name).sort()).toEqual([...names].sort());
    }
    expect(Object.getOwnPropertyNames(Object.prototype).sort()).not.toContain('version');
    expect(({} as Record<string, unknown>).version).toBeUndefined();
  });
});

describe('hostile input', () => {
  // A quadratic regular expression takes seconds on 1 MB; linear work takes a few milliseconds.
  const chars = ['a', '-', '.', '@', '=', '%', '"', ' ', '<', '#', ':', '/', '\\'];
  const formats: (FormatId | null)[] = [null, ...FORMATS.map(([id]) => id)];
  for (const ch of chars) {
    it(`1 MB of ${JSON.stringify(ch)}, on one line and in 1,000-character lines, in every parser within 50 ms`, () => {
      for (const text of [ch.repeat(1 << 20), `${ch.repeat(999)}\n`.repeat(1 << 10)]) {
        for (const f of formats) {
          let best = Infinity;
          // Best of three, so a garbage collection pause is not read as a slow parser.
          for (let i = 0; i < 3 && best >= 50; i++) {
            const t0 = performance.now();
            try {
              parse(text, '', f);
            } catch {
              // Rejecting the input is fine; only the time matters here.
            }
            best = Math.min(best, performance.now() - t0);
          }
          expect(best, `${f ?? 'detect'}`).toBeLessThan(50);
        }
      }
    });
  }
});
