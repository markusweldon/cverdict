/** Builds small ZIP archives in memory for tests, including ZIP64 and deliberately broken ones. */
import { deflateRawSync } from 'node:zlib';

export interface ZipFile {
  name: string;
  data: Buffer | string;
  /** 0 stored, 8 deflate (default). */
  method?: 0 | 8;
  /** Lie about the uncompressed size in the central directory. */
  claimSize?: number;
  /** Lie about the compressed size in the central directory. */
  claimCompressedSize?: number;
  /** Point the central directory entry at another entry's local header (by index). */
  shareHeaderOf?: number;
}

export interface ZipOptions {
  /** Write the ZIP64 end records, saturate the classic ones, and put offsets in ZIP64 extra fields. */
  zip64?: boolean;
  /** Add to the central directory size written in the end record. */
  cdSizeDelta?: number;
  /** Replace the central directory offset written in the end record. */
  cdOffset?: number;
  /** Replace the entry count written in the end record. */
  count?: number;
  /** Replace the ZIP64 end record offset written in the locator. */
  zip64Offset?: bigint;
}

const u16 = (n: number) => {
  const b = Buffer.alloc(2);
  b.writeUInt16LE(n);
  return b;
};
const u32 = (n: number) => {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n >>> 0);
  return b;
};
const u64 = (n: number | bigint) => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(n));
  return b;
};

export function buildZip(files: ZipFile[], opts: ZipOptions = {}): Buffer {
  const locals: Buffer[] = [];
  const offsets: number[] = [];
  const central: Buffer[] = [];
  let offset = 0;
  const stored = files.map((f) => {
    const raw = Buffer.isBuffer(f.data) ? f.data : Buffer.from(f.data, 'utf8');
    const method = f.method ?? 8;
    return { f, raw, method, body: method === 8 ? deflateRawSync(raw) : raw };
  });
  for (const { f, raw, method, body } of stored) {
    const name = Buffer.from(f.name, 'utf8');
    const header = Buffer.concat([u32(0x04034b50), u16(20), u16(0), u16(method), u16(0), u16(0), u32(0), u32(body.length), u32(raw.length), u16(name.length), u16(0), name]);
    offsets.push(offset);
    locals.push(header, body);
    offset += header.length + body.length;
  }
  stored.forEach(({ f, raw, method, body }, i) => {
    const name = Buffer.from(f.name, 'utf8');
    const size = f.claimSize ?? raw.length;
    const csize = f.claimCompressedSize ?? body.length;
    const at = offsets[f.shareHeaderOf ?? i];
    const extra = opts.zip64 ? Buffer.concat([u16(0x0001), u16(24), u64(size), u64(csize), u64(at)]) : Buffer.alloc(0);
    const sat = (n: number) => (opts.zip64 ? 0xffffffff : n);
    central.push(
      Buffer.concat([
        u32(0x02014b50), u16(45), u16(45), u16(0), u16(method), u16(0), u16(0), u32(0),
        u32(sat(csize)), u32(sat(size)), u16(name.length), u16(extra.length), u16(0), u16(0), u16(0), u32(0), u32(sat(at)), name, extra,
      ]),
    );
  });
  const cd = Buffer.concat(central);
  const cdOffset = opts.cdOffset ?? offset;
  const count = opts.count ?? files.length;
  const cdSize = cd.length + (opts.cdSizeDelta ?? 0);
  const parts = [...locals, cd];
  if (opts.zip64) {
    const z64At = offset + cd.length;
    parts.push(Buffer.concat([u32(0x06064b50), u64(44), u16(45), u16(45), u32(0), u32(0), u64(count), u64(count), u64(cdSize), u64(cdOffset)]));
    parts.push(Buffer.concat([u32(0x07064b50), u32(0), u64(opts.zip64Offset ?? BigInt(z64At)), u32(1)]));
    parts.push(Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(0xffff), u16(0xffff), u32(0xffffffff), u32(0xffffffff), u16(0)]));
  } else {
    parts.push(Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(count), u16(count), u32(cdSize), u32(cdOffset), u16(0)]));
  }
  return Buffer.concat(parts);
}
