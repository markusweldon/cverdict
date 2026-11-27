/**
 * The "In CI" path of the Check page: the workflow file a repository adds to run the check on every
 * push, pull request and day, and a link that opens GitHub's new-file page with it filled in. The
 * Action reads the checkout in the runner; nothing is sent to CVErdict and no app is installed.
 */
import { BRAND } from '../../../shared/brand';
import { VERSION } from '../../../cli/src/version';
import type { RepoRef } from './repo';

export const WORKFLOW_PATH = '.github/workflows/cverdict.yml';
export const ACTION_REF = `${BRAND.repo}/action@check-v${VERSION}`;
export const CLI_LINE = `npx -y ${BRAND.slug} check`;

/** The workflow file: every pull request, every push to the default branch, and once a day, because verdicts change after a merge. */
export function workflowYaml(): string {
  return `name: ${BRAND.slug}
on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: '17 6 * * *' # verdicts change after you merge: re-check every day
permissions:
  contents: read
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: ${ACTION_REF}
        with:
          fail-on: exploited
`;
}

/** GitHub's new-file page in `branch` of the repository, with the workflow filled in: one click on Commit adds it. */
export function addWorkflowUrl(r: Pick<RepoRef, 'owner' | 'repo'>, branch: string): string {
  const yaml = workflowYaml().replace('branches: [main]', `branches: [${branch}]`);
  const q = new URLSearchParams({ filename: WORKFLOW_PATH, value: yaml });
  return `https://github.com/${encodeURIComponent(r.owner)}/${encodeURIComponent(r.repo)}/new/${branch.split('/').map(encodeURIComponent).join('/')}?${q}`;
}
