/**
 * Which files a dependency check reads, shared by the browser (a public GitHub repo, Check page) and
 * the command line (cli/src/discover.ts): the lockfile names the parser knows, common SBOM names,
 * and the folders never searched. Pure: no Node or DOM APIs.
 */
import { formatOfFilename } from './parse';

/** Directories never walked: installed dependencies, build output, virtualenvs, VCS metadata, test data. */
export const SKIP_DIRS: ReadonlySet<string> = new Set([
  '.git',
  '.hg',
  '.svn',
  'node_modules',
  'bower_components',
  'jspm_packages',
  'vendor',
  'Pods',
  '.venv',
  'venv',
  '__pycache__',
  '.tox',
  '.nox',
  '.gradle',
  '.terraform',
  'dist',
  'build',
  'out',
  'target',
  'coverage',
  '.next',
  '.nuxt',
  '.cache',
  // Test inputs (Go's testdata, test fixtures): sample lockfiles there are not what the project runs.
  'testdata',
  'fixtures',
  '__fixtures__',
]);

/** CycloneDX and SPDX files as tools usually name them. */
const SBOM_NAME = /^(?:bom\.(?:json|xml)|sbom(?:[\w.-]{0,64})?\.json|[\w.-]{1,128}\.(?:cdx\.(?:json|xml)|spdx(?:\.json)?))$/i;

/** True when the walk picks a file of this name. */
export const isCheckable = (name: string): boolean => formatOfFilename(name) !== null || SBOM_NAME.test(name);
