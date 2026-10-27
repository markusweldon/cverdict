/**
 * Narrowing helpers for untrusted JSON. Upstream feeds change shape without notice, so parsers
 * read every field through these instead of trusting a declared type.
 */

export type JsonObject = Record<string, unknown>;

export function asObject(value: unknown): JsonObject | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? (value as JsonObject) : null;
}

export function asArray(value: unknown): readonly unknown[] {
  return Array.isArray(value) ? value : [];
}

export function asString(value: unknown): string | null {
  return typeof value === 'string' ? value : null;
}

/** A finite number, also accepting numeric strings ("9.8"). */
export function asNumber(value: unknown): number | null {
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'string' && value.trim() !== '') {
    const n = Number(value);
    return Number.isFinite(n) ? n : null;
  }
  return null;
}

/** Parse JSON from a buffer, naming the source in the error. */
export function parseJson(body: Buffer | string, what: string): unknown {
  try {
    return JSON.parse(typeof body === 'string' ? body : body.toString('utf8'));
  } catch (err) {
    throw new Error(`${what}: invalid JSON (${(err as Error).message})`);
  }
}
