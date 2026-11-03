import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { deflateRawSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { ZIP_LIMITS, ZipError, ZipReader, type ZipLimits } from '../../src/util/zip';
import { buildZip, type ZipFile, type ZipOptions } from '../fixtures/zip';
import { tempDir } from './helpers';

function open(files: ZipFile[], opts: ZipOptions = {}, limits?: ZipLimits): ZipReader {
  const file = path.join(tempDir('zip-test-'), 'a.zip');
  writeFileSync(file, buildZip(files, opts));
  return new ZipReader(file, limits);
}

const readAll = (z: ZipReader) => Object.fromEntries(z.entries.map((e) => [e.name, z.read(e).toString('utf8')]));

describe('ZipReader', () => {
  it('reads stored and deflated entries', () => {
    const z = open([
      { name: 'GHSA-aaaa.json', data: '{"id":"GHSA-aaaa"}', method: 8 },
      { name: 'MAL-1.json', data: 'not read', method: 0 },
      { name: 'b/c.txt', data: 'x'.repeat(10_000) },
    ]);
    expect(z.entries.map((e) => [e.name, e.method])).toEqual([['GHSA-aaaa.json', 8], ['MAL-1.json', 0], ['b/c.txt', 8]]);
    expect(readAll(z)).toEqual({ 'GHSA-aaaa.json': '{"id":"GHSA-aaaa"}', 'MAL-1.json': 'not read', 'b/c.txt': 'x'.repeat(10_000) });
    z.close();
  });

  it('reads the ZIP64 end records and extra fields', () => {
    const z = open([{ name: 'one.json', data: '1' }, { name: 'two.json', data: '22', method: 0 }], { zip64: true });
    expect(z.entries.map((e) => [e.name, e.size])).toEqual([['one.json', 1], ['two.json', 2]]);
    expect(readAll(z)).toEqual({ 'one.json': '1', 'two.json': '22' });
    z.close();
  });

  it('rejects a central directory that runs past the end of the file', () => {
    expect(() => open([{ name: 'a', data: 'a' }], { cdSizeDelta: 1000 })).toThrow(ZipError);
    expect(() => open([{ name: 'a', data: 'a' }], { cdSizeDelta: 1000 })).toThrow(/runs past its end record/);
  });

  it('rejects an offset plus size that overflows the file', () => {
    expect(() => open([{ name: 'a', data: 'a' }], { cdOffset: 0xfffffff0 })).toThrow(/runs past its end record/);
  });

  it('rejects a ZIP64 locator that points outside the file', () => {
    expect(() => open([{ name: 'a', data: 'a' }], { zip64: true, zip64Offset: 2n ** 40n })).toThrow(/ZIP64 end of central directory record outside the file/);
  });

  it('rejects more entries than fit in the central directory', () => {
    expect(() => open([{ name: 'a', data: 'a' }], { count: 500 })).toThrow(/cannot fit/);
  });

  it('rejects a central directory over its limit before reading it', () => {
    expect(() => open([{ name: 'a', data: 'a' }], {}, { ...ZIP_LIMITS, maxCentralDirectoryBytes: 10 })).toThrow(/exceeds the 10-byte limit/);
  });

  it('rejects an entry whose claimed size is over the limit, before allocating it', () => {
    const z = open([{ name: 'big', data: 'small', claimCompressedSize: 9 * 1024 * 1024 }]);
    expect(() => z.read(z.entries[0])).toThrow(/exceeds the 8388608-byte entry limit/);
    z.close();
  });

  it('stops a deflate bomb whose claimed size lies', () => {
    const bomb = Buffer.alloc(10 * 1024 * 1024);
    expect(deflateRawSync(bomb).length).toBeLessThan(20_000);
    const z = open([{ name: 'bomb', data: bomb, claimSize: 1024 }]);
    expect(() => z.read(z.entries[0])).toThrow(/cannot inflate/);
    z.close();
  });

  it('rejects two entries sharing one local header', () => {
    expect(() => open([{ name: 'a', data: 'a' }, { name: 'b', data: 'b', shareHeaderOf: 0 }])).toThrow(/share the local header/);
  });

  it('rejects a corrupt local header and a size mismatch', () => {
    const file = path.join(tempDir('zip-test-'), 'c.zip');
    const buf = buildZip([{ name: 'a', data: 'abc' }, { name: 'b', data: 'xyz', method: 0, claimSize: 2, claimCompressedSize: 3 }]);
    buf.writeUInt32LE(0xdeadbeef, 0);
    writeFileSync(file, buf);
    const z = new ZipReader(file);
    expect(() => z.read(z.entries[0])).toThrow(/bad local header/);
    expect(() => z.read(z.entries[1])).toThrow(/3 bytes, the directory says 2/);
    z.close();
  });

  it('caps the total inflated bytes of one archive', () => {
    const z = open([{ name: 'a', data: 'x'.repeat(600) }, { name: 'b', data: 'y'.repeat(600) }], {}, { ...ZIP_LIMITS, maxTotalBytes: 1000 });
    expect(z.read(z.entries[0]).length).toBe(600);
    expect(() => z.read(z.entries[1])).toThrow(/1000-byte limit for inflated data/);
    z.close();
  });

  it('rejects files that are not zip archives', () => {
    const dir = tempDir('zip-test-');
    writeFileSync(path.join(dir, 'empty'), '');
    writeFileSync(path.join(dir, 'text'), 'x'.repeat(100));
    expect(() => new ZipReader(path.join(dir, 'empty'))).toThrow(/too small/);
    expect(() => new ZipReader(path.join(dir, 'text'))).toThrow(/no end of central directory/);
  });
});
