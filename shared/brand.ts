/**
 * Every brand string lives here so a fork (or a rename) touches one file.
 * Also update `vercel.json` rewrites, which cannot import this file.
 */
export const BRAND = {
  name: 'CVErdict',
  slug: 'cverdict',
  tagline: 'Every CVE gets a verdict. Every verdict comes with receipts.',
  /** One-line pitch for meta descriptions and the README. */
  pitch: 'Open-source CVE triage for the 2026 flood: the few CVEs that matter today, and exactly why — built only from free public data.',
  /** GitHub owner/repo that hosts the code and the `data` branch. */
  repo: 'markusweldon/cverdict',
  /** Branch the hourly workflow publishes data to. */
  dataBranch: 'data',
} as const;

export const REPO_URL = `https://github.com/${BRAND.repo}`;
export const RAW_DATA_URL = `https://raw.githubusercontent.com/${BRAND.repo}/${BRAND.dataBranch}`;
