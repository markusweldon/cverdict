/** Test helpers for the ingest layer: temp dirs, tiny git repos, fixtures and a capturing logger. */
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach } from 'vitest';
import type { Logger } from '../../src/types';

export { recordPath } from '../../src/sources/cvelist';

export const FIXTURES = fileURLToPath(new URL('../fixtures/ingest/', import.meta.url));

/** A real CVE record from the fixtures directory, parsed. */
export function fixtureRecord(id: string): Record<string, unknown> {
  return JSON.parse(readFileSync(path.join(FIXTURES, 'records', `${id}.json`), 'utf8'));
}

const tempDirs: string[] = [];
afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

/** A fresh temp directory, removed after the current test. */
export function tempDir(prefix = 'ingest-test-'): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

// Isolate test repos from the user's git configuration (signing, hooks, default branch).
const GIT_ENV = { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1', GIT_TERMINAL_PROMPT: '0' };

export function runGit(cwd: string, ...args: string[]): string {
  return execFileSync('git', args, { cwd, env: GIT_ENV, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}

/** Write files (relative path → content) into `dir`. */
export function writeFiles(dir: string, files: Record<string, string | Buffer>): void {
  for (const [rel, content] of Object.entries(files)) {
    const file = path.join(dir, rel);
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(file, content);
  }
}

/** Commit `files` to the repo at `dir` (created on first use) and return the commit SHA. */
export function commitFiles(dir: string, files: Record<string, string | Buffer>, message = 'update'): string {
  if (!existsSync(path.join(dir, '.git'))) {
    mkdirSync(dir, { recursive: true });
    runGit(dir, 'init', '-q', '-b', 'main');
  }
  writeFiles(dir, files);
  runGit(dir, 'add', '-A');
  runGit(dir, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-q', '--no-gpg-sign', '-m', message);
  return runGit(dir, 'rev-parse', 'HEAD');
}

/** A new repository containing `files`, plus a `--no-checkout` clone of it (no working tree). */
export function repoWithClone(files: Record<string, string | Buffer>): { origin: string; clone: string; commit: string } {
  const root = tempDir();
  const origin = path.join(root, 'origin');
  const commit = commitFiles(origin, files, 'init');
  const clone = path.join(root, 'clone');
  runGit(root, 'clone', '-q', '--no-checkout', `file://${origin}`, clone);
  return { origin, clone, commit };
}

export interface CapturedLogger extends Logger {
  lines: string[];
}

export function captureLogger(): CapturedLogger {
  const lines: string[] = [];
  return {
    lines,
    info: (m) => void lines.push(`INFO ${m}`),
    warn: (m) => void lines.push(`WARN ${m}`),
    error: (m) => void lines.push(`ERROR ${m}`),
  };
}
