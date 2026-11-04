/**
 * Every brand string lives here so a fork (or a rename) touches one file.
 * Also update `vercel.json` rewrites, which cannot import this file.
 */
export const BRAND = {
  name: 'CVErdict',
  /** The name in two parts for the wordmark: the first is set bold, the rest regular ("CVE" + "rdict"). */
  wordmark: ['CVE', 'rdict'],
  slug: 'cverdict',
  tagline: 'Every CVE gets a verdict. Every verdict comes with receipts.',
  /** One-line pitch for meta descriptions and the README. */
  pitch: 'Open-source CVE triage for the 2026 flood: the few CVEs that matter today, and exactly why. Built only from free public data.',
  /** GitHub owner/repo that hosts the code and the `data` branch. */
  repo: 'markusweldon/cverdict',
  /** Branch the hourly workflow publishes data to. */
  dataBranch: 'data',
  /** Public site; feed links point here unless SITE_URL is set. */
  siteUrl: 'https://cverdict-psi.vercel.app',
} as const;

export const REPO_URL = `https://github.com/${BRAND.repo}`;
/** Title of the home page: the static head (link previews, crawlers) and the tab once the app runs. */
export const HOME_TITLE = `${BRAND.name}: the few CVEs that matter today`;
export const RAW_DATA_URL = `https://raw.githubusercontent.com/${BRAND.repo}/${BRAND.dataBranch}`;
