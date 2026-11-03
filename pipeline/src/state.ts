/**
 * Carry-forward state between hourly runs.
 *
 * The data branch is one commit without history, so anything a later run must remember (when an
 * undated artifact was first seen, which CVEs were flagged when) travels in one internal file,
 * `v1/state.json`, read back from `--previous`. The file is split into named sections, each with
 * its own version, so features can evolve their part independently:
 *
 *   { schema_version: 1, generated_at, state_version: 1, note, sections: { woke: { version: 1, data } } }
 *
 * Loading never throws and never invents data: a missing, unreadable or foreign file starts every
 * section fresh, and a section whose version or shape is unknown starts that section fresh. A
 * section this build does not know is carried over unchanged, so a rollback does not lose it.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { SCHEMA_VERSION } from '../../shared/contract';
import type { Logger } from './types';
import { asObject, type JsonObject } from './util/json';

/** Version of the envelope (not of any section). */
export const STATE_VERSION = 1;
/** Same as PATHS.state in emit/json.ts. */
export const STATE_PATH = 'v1/state.json';
const NOTE = 'Internal pipeline state carried between runs. Unstable: the format may change without notice. Do not build on it.';

/** A named, versioned part of the state file, owned by one feature. */
export interface StateSection<T> {
  key: string;
  version: number;
  /** Validate previous data. Return null to start fresh (shape not understood). Never throw. */
  parse(data: unknown): T | null;
}

export type StateStatus = 'missing' | 'corrupt' | 'ok';

export interface LoadedState {
  status: StateStatus;
  /** Why the state could not be used (status ≠ ok). */
  reason: string | null;
  /** generated_at of the run that wrote it. */
  generatedAt: string | null;
  sections: ReadonlyMap<string, { version: number; data: unknown }>;
}

export const EMPTY_STATE: LoadedState = { status: 'missing', reason: 'no previous state', generatedAt: null, sections: new Map() };

/** Parse the content of a state file. Never throws. */
export function parseState(text: string): LoadedState {
  let doc: JsonObject | null;
  try {
    doc = asObject(JSON.parse(text));
  } catch (e) {
    return { ...EMPTY_STATE, status: 'corrupt', reason: `invalid JSON (${(e as Error).message})` };
  }
  if (!doc) return { ...EMPTY_STATE, status: 'corrupt', reason: 'top level is not an object' };
  if (doc.schema_version !== SCHEMA_VERSION || doc.state_version !== STATE_VERSION) {
    return { ...EMPTY_STATE, status: 'corrupt', reason: `unknown version (schema ${String(doc.schema_version)}, state ${String(doc.state_version)})` };
  }
  const generatedAt = typeof doc.generated_at === 'string' && Number.isFinite(Date.parse(doc.generated_at)) ? doc.generated_at : null;
  if (!generatedAt) return { ...EMPTY_STATE, status: 'corrupt', reason: 'missing generated_at' };
  const raw = asObject(doc.sections);
  if (!raw) return { ...EMPTY_STATE, status: 'corrupt', reason: 'missing sections' };
  const sections = new Map<string, { version: number; data: unknown }>();
  for (const [key, value] of Object.entries(raw)) {
    const s = asObject(value);
    if (s && Number.isInteger(s.version) && 'data' in s) sections.set(key, { version: s.version as number, data: s.data });
  }
  return { status: 'ok', reason: null, generatedAt, sections };
}

/** Read `<previous>/v1/state.json`. A missing root or file is `missing`, never an error. */
export function loadState(previousRoot: string | null, log?: Logger): LoadedState {
  if (!previousRoot) return EMPTY_STATE;
  let text: string;
  try {
    text = readFileSync(join(previousRoot, STATE_PATH), 'utf8');
  } catch {
    log?.info(`state: no previous ${STATE_PATH}; starting fresh`);
    return { ...EMPTY_STATE, reason: `no ${STATE_PATH} in the previous output` };
  }
  const state = parseState(text);
  if (state.status === 'corrupt') log?.warn(`state: previous ${STATE_PATH} is unusable (${state.reason}); starting fresh`);
  else log?.info(`state: loaded ${STATE_PATH} from ${state.generatedAt} (${[...state.sections.keys()].join(', ') || 'no sections'})`);
  return state;
}

/** A section's previous data, or null (start fresh) when absent, of another version, or not understood. */
export function readSection<T>(state: LoadedState, section: StateSection<T>, log?: Logger): T | null {
  const s = state.sections.get(section.key);
  if (!s) return null;
  if (s.version !== section.version) {
    log?.warn(`state: section ${section.key} is version ${s.version}, expected ${section.version}; starting it fresh`);
    return null;
  }
  let data: T | null;
  try {
    data = section.parse(s.data);
  } catch {
    data = null;
  }
  if (data === null) log?.warn(`state: section ${section.key} is not understood; starting it fresh`);
  return data;
}

/** One section's new content, as written by its owner this run. */
export interface SectionWrite {
  key: string;
  version: number;
  data: unknown;
}

/**
 * Serialise the state file: this run's sections, plus every previous section nobody wrote this
 * run (carried over verbatim). Keys are sorted so the file is stable.
 */
export function serializeState(now: Date, writes: readonly SectionWrite[], previous: LoadedState = EMPTY_STATE): string {
  const sections: Record<string, { version: number; data: unknown }> = {};
  const written = new Map(writes.map((w) => [w.key, w]));
  for (const key of [...new Set([...previous.sections.keys(), ...written.keys()])].sort()) {
    const w = written.get(key);
    sections[key] = w ? { version: w.version, data: w.data } : previous.sections.get(key)!;
  }
  return JSON.stringify({ schema_version: SCHEMA_VERSION, generated_at: now.toISOString(), state_version: STATE_VERSION, note: NOTE, sections });
}
