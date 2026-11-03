/**
 * A small ZIP and ZIP64 reader on Node built-ins, for the OSV.dev `all.zip` dumps.
 *
 * Reads the end of central directory record (and the ZIP64 locator and record when counts or
 * offsets are saturated), the central directory, then each entry's local header by offset.
 * Methods 0 (stored) and 8 (deflate). Entries are only read into memory, never written to disk,
 * so names cannot escape anywhere. Every size and offset is checked against the file and the
 * limits before any buffer is allocated: the archive is untrusted input.
 */
import { closeSync, fstatSync, openSync, readSync } from 'node:fs';
import { inflateRawSync } from 'node:zlib';

export interface ZipLimits {
  /** Largest compressed or uncompressed entry, as claimed and as inflated. */
  maxEntryBytes: number;
  /** Total inflated bytes read from one archive (entries skipped by name do not count). */
  maxTotalBytes: number;
  /** Largest central directory. npm's is about 18 MB for 231,075 entries. */
  maxCentralDirectoryBytes: number;
}

export const ZIP_LIMITS: ZipLimits = {
  maxEntryBytes: 8 * 1024 * 1024,
  maxTotalBytes: 1024 * 1024 * 1024,
  maxCentralDirectoryBytes: 64 * 1024 * 1024,
};

export interface ZipEntry {
  name: string;
  method: number;
  compressedSize: number;
  size: number;
  /** Offset of the local file header. */
  offset: number;
}

export class ZipError extends Error {
  override name = 'ZipError';
}

const EOCD_SIG = 0x06054b50;
const ZIP64_LOCATOR_SIG = 0x07064b50;
const ZIP64_EOCD_SIG = 0x06064b50;
const CENTRAL_SIG = 0x02014b50;
const LOCAL_SIG = 0x04034b50;
const EOCD_SIZE = 22;
const ZIP64_LOCATOR_SIZE = 20;
const ZIP64_EOCD_SIZE = 56;
const CENTRAL_SIZE = 46;
const LOCAL_SIZE = 30;
const MAX_COMMENT = 0xffff;

/** A read-only ZIP archive on disk. Call close() when done. */
export class ZipReader {
  private readonly fd: number;
  private readonly fileSize: number;
  private readonly limits: ZipLimits;
  private inflated = 0;
  readonly entries: ZipEntry[];

  constructor(file: string, limits: ZipLimits = ZIP_LIMITS) {
    this.limits = limits;
    this.fd = openSync(file, 'r');
    try {
      this.fileSize = fstatSync(this.fd).size;
      this.entries = this.readCentralDirectory();
    } catch (err) {
      closeSync(this.fd);
      throw err;
    }
  }

  close(): void {
    closeSync(this.fd);
  }

  /** Read `length` bytes at `position`, which must lie inside the file. */
  private readAt(position: number, length: number): Buffer {
    if (!Number.isSafeInteger(position) || !Number.isSafeInteger(length) || position < 0 || length < 0 || position + length > this.fileSize) {
      throw new ZipError(`read of ${length} bytes at ${position} is outside the ${this.fileSize}-byte file`);
    }
    const buf = Buffer.alloc(length);
    let done = 0;
    while (done < length) {
      const n = readSync(this.fd, buf, done, length - done, position + done);
      if (n === 0) throw new ZipError('unexpected end of file');
      done += n;
    }
    return buf;
  }

  private readCentralDirectory(): ZipEntry[] {
    if (this.fileSize < EOCD_SIZE) throw new ZipError('file too small to be a zip archive');
    const tailLength = Math.min(this.fileSize, EOCD_SIZE + MAX_COMMENT + ZIP64_LOCATOR_SIZE);
    const tailStart = this.fileSize - tailLength;
    const tail = this.readAt(tailStart, tailLength);
    let eocd = -1;
    for (let i = tailLength - EOCD_SIZE; i >= 0; i--) {
      if (tail.readUInt32LE(i) === EOCD_SIG) {
        eocd = i;
        break;
      }
    }
    if (eocd < 0) throw new ZipError('no end of central directory record');
    const eocdOffset = tailStart + eocd;
    let count = tail.readUInt16LE(eocd + 10);
    let cdSize = tail.readUInt32LE(eocd + 12);
    let cdOffset = tail.readUInt32LE(eocd + 16);
    let cdEnd = eocdOffset;

    if (count === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
      const loc = eocdOffset - ZIP64_LOCATOR_SIZE;
      if (loc < 0) throw new ZipError('ZIP64 locator outside the file');
      const locator = this.readAt(loc, ZIP64_LOCATOR_SIZE);
      if (locator.readUInt32LE(0) !== ZIP64_LOCATOR_SIG) throw new ZipError('no ZIP64 end of central directory locator');
      const z64Offset = Number(locator.readBigUInt64LE(8));
      if (!Number.isSafeInteger(z64Offset) || z64Offset + ZIP64_EOCD_SIZE > loc) throw new ZipError('ZIP64 end of central directory record outside the file');
      const z = this.readAt(z64Offset, ZIP64_EOCD_SIZE);
      if (z.readUInt32LE(0) !== ZIP64_EOCD_SIG) throw new ZipError('bad ZIP64 end of central directory record');
      count = Number(z.readBigUInt64LE(32));
      cdSize = Number(z.readBigUInt64LE(40));
      cdOffset = Number(z.readBigUInt64LE(48));
      cdEnd = z64Offset;
    }
    if (!Number.isSafeInteger(count) || !Number.isSafeInteger(cdSize) || !Number.isSafeInteger(cdOffset)) throw new ZipError('central directory size or offset out of range');
    if (cdOffset + cdSize > cdEnd) throw new ZipError(`central directory (${cdSize} bytes at ${cdOffset}) runs past its end record`);
    if (cdSize > this.limits.maxCentralDirectoryBytes) throw new ZipError(`central directory of ${cdSize} bytes exceeds the ${this.limits.maxCentralDirectoryBytes}-byte limit`);
    if (count > Math.floor(cdSize / CENTRAL_SIZE)) throw new ZipError(`${count} entries cannot fit in a ${cdSize}-byte central directory`);

    const cd = this.readAt(cdOffset, cdSize);
    const entries: ZipEntry[] = [];
    const offsets = new Set<number>();
    let p = 0;
    for (let n = 0; n < count; n++) {
      if (p + CENTRAL_SIZE > cdSize || cd.readUInt32LE(p) !== CENTRAL_SIG) throw new ZipError(`bad central directory header ${n}`);
      const method = cd.readUInt16LE(p + 10);
      let compressedSize = cd.readUInt32LE(p + 20);
      let size = cd.readUInt32LE(p + 24);
      const nameLength = cd.readUInt16LE(p + 28);
      const extraLength = cd.readUInt16LE(p + 30);
      const commentLength = cd.readUInt16LE(p + 32);
      let offset = cd.readUInt32LE(p + 42);
      const nameStart = p + CENTRAL_SIZE;
      const extraEnd = nameStart + nameLength + extraLength;
      const next = extraEnd + commentLength;
      if (next > cdSize) throw new ZipError(`central directory header ${n} runs past the directory`);
      const name = cd.toString('utf8', nameStart, nameStart + nameLength);
      // ZIP64 extended information: only the fields saturated in the header, in this order.
      for (let x = nameStart + nameLength; x + 4 <= extraEnd; ) {
        const id = cd.readUInt16LE(x);
        const len = cd.readUInt16LE(x + 2);
        const end = x + 4 + len;
        if (end > extraEnd) throw new ZipError(`extra field of ${name} runs past its header`);
        if (id === 0x0001) {
          let q = x + 4;
          const take = (): number => {
            if (q + 8 > end) throw new ZipError(`short ZIP64 extra field in ${name}`);
            const v = Number(cd.readBigUInt64LE(q));
            q += 8;
            return v;
          };
          if (size === 0xffffffff) size = take();
          if (compressedSize === 0xffffffff) compressedSize = take();
          if (offset === 0xffffffff) offset = take();
        }
        x = end;
      }
      if (offsets.has(offset)) throw new ZipError(`two entries share the local header at ${offset}`);
      offsets.add(offset);
      entries.push({ name, method, compressedSize, size, offset });
      p = next;
    }
    return entries;
  }

  /** The entry's content. Throws a ZipError on any limit, bad header or size mismatch. */
  read(entry: ZipEntry): Buffer {
    const { maxEntryBytes, maxTotalBytes } = this.limits;
    if (entry.compressedSize > maxEntryBytes || entry.size > maxEntryBytes) {
      throw new ZipError(`${entry.name}: ${Math.max(entry.compressedSize, entry.size)} bytes exceeds the ${maxEntryBytes}-byte entry limit`);
    }
    if (entry.method !== 0 && entry.method !== 8) throw new ZipError(`${entry.name}: unsupported compression method ${entry.method}`);
    if (this.inflated + entry.size > maxTotalBytes) throw new ZipError(`archive exceeds the ${maxTotalBytes}-byte limit for inflated data`);
    const header = this.readAt(entry.offset, LOCAL_SIZE);
    if (header.readUInt32LE(0) !== LOCAL_SIG) throw new ZipError(`${entry.name}: bad local header`);
    const start = entry.offset + LOCAL_SIZE + header.readUInt16LE(26) + header.readUInt16LE(28);
    const data = this.readAt(start, entry.compressedSize);
    let out: Buffer;
    if (entry.method === 0) out = data;
    else {
      try {
        // maxOutputLength stops a deflate bomb whose claimed size lies.
        out = inflateRawSync(data, { maxOutputLength: Math.max(1, entry.size) });
      } catch (err) {
        throw new ZipError(`${entry.name}: cannot inflate (${err instanceof Error ? err.message : String(err)})`);
      }
    }
    if (out.length !== entry.size) throw new ZipError(`${entry.name}: ${out.length} bytes, the directory says ${entry.size}`);
    this.inflated += out.length;
    return out;
  }
}
