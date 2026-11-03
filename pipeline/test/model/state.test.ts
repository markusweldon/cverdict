import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { EMPTY_STATE, loadState, parseState, readSection, serializeState, STATE_PATH, STATE_VERSION, type StateSection } from '../../src/state';
import { NOW } from '../fixtures/model/builders';
import { captureLogger } from '../ingest/helpers';

interface Counter {
  n: number;
}
const COUNTER: StateSection<Counter> = {
  key: 'counter',
  version: 2,
  parse: (d) => (typeof (d as Counter | null)?.n === 'number' ? { n: (d as Counter).n } : null),
};

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'state-'));
  mkdirSync(join(dir, 'v1'));
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));
const writeState = (text: string) => writeFileSync(join(dir, STATE_PATH), text);

describe('state file', () => {
  it('saves and loads sections, keyed and versioned', () => {
    writeState(serializeState(NOW, [{ key: 'counter', version: 2, data: { n: 41 } }]));
    const state = loadState(dir);
    expect(state.status).toBe('ok');
    expect(state.generatedAt).toBe(NOW.toISOString());
    expect(readSection(state, COUNTER)).toEqual({ n: 41 });
    const doc = JSON.parse(serializeState(NOW, [{ key: 'counter', version: 2, data: { n: 1 } }]));
    expect(doc).toMatchObject({ schema_version: 1, generated_at: NOW.toISOString(), state_version: STATE_VERSION, sections: { counter: { version: 2, data: { n: 1 } } } });
    expect(doc.note).toMatch(/Unstable/);
  });

  it('is missing, not an error, without a previous root or file', () => {
    expect(loadState(null)).toBe(EMPTY_STATE);
    const log = captureLogger();
    expect(loadState(dir, log).status).toBe('missing');
    expect(readSection(loadState(dir), COUNTER)).toBeNull();
    expect(log.lines.some((l) => /starting fresh/.test(l))).toBe(true);
  });

  it.each([
    ['truncated JSON', '{"schema_version":1,"gener'],
    ['an array', '[]'],
    ['another schema version', JSON.stringify({ schema_version: 2, state_version: 1, generated_at: NOW.toISOString(), sections: {} })],
    ['another envelope version', JSON.stringify({ schema_version: 1, state_version: 9, generated_at: NOW.toISOString(), sections: {} })],
    ['no generated_at', JSON.stringify({ schema_version: 1, state_version: 1, sections: {} })],
    ['no sections', JSON.stringify({ schema_version: 1, state_version: 1, generated_at: NOW.toISOString() })],
  ])('starts fresh on a corrupt file: %s', (_name, text) => {
    writeState(text);
    const log = captureLogger();
    const state = loadState(dir, log);
    expect(state.status).toBe('corrupt');
    expect(state.sections.size).toBe(0);
    expect(log.lines.some((l) => l.startsWith('WARN state:'))).toBe(true);
  });

  it('starts one section fresh when its version or shape is unknown, never guessing', () => {
    const log = captureLogger();
    expect(readSection(parseState(serializeState(NOW, [{ key: 'counter', version: 1, data: { n: 5 } }])), COUNTER, log)).toBeNull();
    expect(readSection(parseState(serializeState(NOW, [{ key: 'counter', version: 2, data: { n: 'five' } }])), COUNTER, log)).toBeNull();
    const throwing: StateSection<Counter> = { ...COUNTER, parse: () => { throw new Error('bad'); } };
    expect(readSection(parseState(serializeState(NOW, [{ key: 'counter', version: 2, data: {} }])), throwing, log)).toBeNull();
    expect(log.lines.filter((l) => l.startsWith('WARN'))).toHaveLength(3);
  });

  it('carries sections nobody wrote this run, so a rollback keeps another feature’s records', () => {
    const prev = parseState(serializeState(NOW, [{ key: 'receipts', version: 1, data: { flagged: { 'CVE-2026-1': '2026-10-01' } } }, { key: 'counter', version: 2, data: { n: 1 } }]));
    const next = JSON.parse(serializeState(new Date(NOW.getTime() + 3_600_000), [{ key: 'counter', version: 2, data: { n: 2 } }], prev));
    expect(Object.keys(next.sections)).toEqual(['counter', 'receipts']);
    expect(next.sections.receipts).toEqual({ version: 1, data: { flagged: { 'CVE-2026-1': '2026-10-01' } } });
    expect(next.sections.counter.data).toEqual({ n: 2 });
  });
});
