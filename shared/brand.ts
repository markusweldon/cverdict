/**
 * Every brand string lives here so a fork (or a rename) touches one file.
 * Also update `vercel.json` rewrites, which cannot import this file.
 */
export const BRAND = {
  name: 'PROJECT_NAME',
  slug: 'project-name',
  tagline: 'The few CVEs that matter today — and exactly why.',
  /** GitHub owner/repo that hosts the code and the `data` branch. */
  repo: 'markusweldon/project-name',
  /** Branch the hourly workflow publishes data to. */
  dataBranch: 'data',
} as const;

export const REPO_URL = `https://github.com/${BRAND.repo}`;
export const RAW_DATA_URL = `https://raw.githubusercontent.com/${BRAND.repo}/${BRAND.dataBranch}`;
