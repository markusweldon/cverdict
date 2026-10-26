/** Number of detail shards. Changing this is a breaking change to the data contract. */
export const SHARD_COUNT = 256;

/** FNV-1a 32-bit hash of the upper-cased CVE ID. */
export function fnv1a(input: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

/** Shard name for a CVE ID: two lowercase hex digits, e.g. "3f". */
export function shardOf(cveId: string): string {
  return (fnv1a(cveId.trim().toUpperCase()) % SHARD_COUNT).toString(16).padStart(2, '0');
}

export const CVE_ID_RE = /^CVE-\d{4}-\d{4,}$/;
