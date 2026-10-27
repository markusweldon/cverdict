/** Pure formatting helpers. Dates are shown in UTC: batches, KEV due dates and the window are UTC days. */

const NUMBER = new Intl.NumberFormat('en-US');
const COMPACT = new Intl.NumberFormat('en-US', { notation: 'compact', maximumFractionDigits: 1 });
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
export const HOUR_MS = 3_600_000;
export const DAY_MS = 24 * HOUR_MS;

export const fmtInt = (n: number): string => NUMBER.format(Math.round(n));
export const fmtCompact = (n: number): string => COMPACT.format(n);

/** Fraction → percent with sensible precision: 0.0186 → "1.9%", 0.0004 → "0.04%". */
export function fmtPct(fraction: number): string {
  if (!Number.isFinite(fraction)) return '—';
  const p = fraction * 100;
  if (p === 0) return '0%';
  const digits = p >= 10 ? 0 : p >= 1 ? 1 : p >= 0.01 ? 2 : 3;
  return `${p.toFixed(digits).replace(/(\.\d*?)0+$/, '$1').replace(/\.$/, '')}%`;
}

/** "1 in 54" — how many CVEs you skim for each one that matters. */
export function oneIn(part: number, total: number): string {
  if (part <= 0 || total <= 0) return '—';
  return `1 in ${fmtInt(Math.max(1, Math.round(total / part)))}`;
}

export const signed = (n: number): string => (n > 0 ? `+${n}` : n < 0 ? `−${Math.abs(n)}` : '0');

export function plural(n: number, one: string, many = `${one}s`): string {
  return `${fmtInt(n)} ${n === 1 ? one : many}`;
}

/** Accepts full ISO timestamps and bare YYYY-MM-DD dates (treated as UTC midnight). */
export function toMs(isoOrDate: string): number {
  return Date.parse(/^\d{4}-\d{2}-\d{2}$/.test(isoOrDate) ? `${isoOrDate}T00:00:00Z` : isoOrDate);
}

/** "Oct 13" (or "Oct 13, 2025" when the year differs from `refYear`). */
export function fmtDate(isoOrDate: string, refYear: number = new Date().getUTCFullYear()): string {
  const d = new Date(toMs(isoOrDate));
  if (Number.isNaN(d.getTime())) return '—';
  const base = `${MONTHS[d.getUTCMonth()]} ${d.getUTCDate()}`;
  return d.getUTCFullYear() === refYear ? base : `${base}, ${d.getUTCFullYear()}`;
}

/** "Oct 13, 2026 · 17:04 UTC". */
export function fmtDateTime(iso: string): string {
  const d = new Date(toMs(iso));
  if (Number.isNaN(d.getTime())) return '—';
  const hh = String(d.getUTCHours()).padStart(2, '0');
  const mm = String(d.getUTCMinutes()).padStart(2, '0');
  return `${MONTHS[d.getUTCMonth()]} ${d.getUTCDate()}, ${d.getUTCFullYear()} · ${hh}:${mm} UTC`;
}

export function fmtHour(ms: number): string {
  const d = new Date(ms);
  return `${String(d.getUTCHours()).padStart(2, '0')}:00`;
}

export const fmtMonth = (yyyyMm: string): string => {
  const [y, m] = yyyyMm.split('-');
  return `${MONTHS[Number(m) - 1]} ${y}`;
};

/** Compact age: "now", "12m", "5h", "3d", "6w", "4mo", "2y". */
export function fmtAge(iso: string, now: number): string {
  const ms = now - toMs(iso);
  if (!Number.isFinite(ms)) return '—';
  const min = Math.floor(ms / 60_000);
  if (min < 1) return 'now';
  if (min < 60) return `${min}m`;
  const h = Math.floor(min / 60);
  if (h < 48) return `${h}h`;
  const d = Math.floor(h / 24);
  if (d < 14) return `${d}d`;
  if (d < 60) return `${Math.floor(d / 7)}w`;
  if (d < 730) return `${Math.floor(d / 30)}mo`;
  return `${Math.floor(d / 365)}y`;
}

/** "5 hours ago", "in 2 days". */
export function fmtRelative(iso: string, now: number): string {
  const ms = toMs(iso) - now;
  const abs = Math.abs(ms);
  const unit = abs < HOUR_MS ? ['minute', 60_000] : abs < DAY_MS * 2 ? ['hour', HOUR_MS] : ['day', DAY_MS];
  const n = Math.max(1, Math.round(abs / (unit[1] as number)));
  if (abs < 60_000) return 'just now';
  const text = `${n} ${unit[0]}${n === 1 ? '' : 's'}`;
  return ms < 0 ? `${text} ago` : `in ${text}`;
}

/** Countdown text for |ms|: "2d 04h" (or "2d 04:12:09" when `precise`), "04:12:09" under a day. */
export function fmtCountdown(ms: number, precise = false): string {
  const s = Math.max(0, Math.floor(Math.abs(ms) / 1000));
  const d = Math.floor(s / 86_400);
  const h = Math.floor((s % 86_400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  const p = (n: number) => String(n).padStart(2, '0');
  const clock = `${p(h)}:${p(m)}:${p(sec)}`;
  if (d === 0) return clock;
  return precise ? `${d}d ${clock}` : `${d}d ${p(h)}h`;
}

/** A KEV due date is met by the end of that (UTC) day. */
export const kevDeadline = (dueDate: string): number => toMs(dueDate) + DAY_MS;

// CNA short names → display names. Unknown names fall back to themselves.
const CNA_NAMES: Readonly<Record<string, string>> = {
  microsoft: 'Microsoft', oracle: 'Oracle', GitHub_M: 'GitHub', mitre: 'MITRE', redhat: 'Red Hat', ibm: 'IBM', hpe: 'HPE',
  adobe: 'Adobe', mozilla: 'Mozilla', juniper: 'Juniper', nvidia: 'NVIDIA', cisco: 'Cisco', apache: 'Apache', eclipse: 'Eclipse',
  icscert: 'CISA ICS', 'cisa-cg': 'CISA', drupal: 'Drupal', dell: 'Dell', zephyr: 'Zephyr', brocade: 'Brocade', fortinet: 'Fortinet',
  paloalto: 'Palo Alto Networks', ivanti: 'Ivanti', sap: 'SAP', siemens: 'Siemens', citrix: 'Citrix', f5: 'F5', vmware: 'VMware',
  atlassian: 'Atlassian', qualcomm: 'Qualcomm', apple: 'Apple', zdi: 'ZDI', twcert: 'TWCERT/CC', jpcert: 'JPCERT/CC',
  trendmicro: 'Trend Micro', TPLink: 'TP-Link', ProgressSoftware: 'Progress', google: 'Google', huntr_ai: 'huntr',
  canonical: 'Canonical', debian: 'Debian', suse: 'SUSE', jenkins: 'Jenkins', intel: 'Intel', amd: 'AMD', samsung: 'Samsung',
  wordfence: 'Wordfence', hashicorp: 'HashiCorp', snyk: 'Snyk', mattermost: 'Mattermost', elastic: 'Elastic', schneider: 'Schneider Electric',
};
export function cnaName(cna: string): string {
  return CNA_NAMES[cna] ?? (/^[a-z]/.test(cna) ? cna.charAt(0).toUpperCase() + cna.slice(1) : cna);
}

/** "Fortinet · FortiSandbox"; collapses "Microsoft · Microsoft Exchange" and "Linux · Linux". */
export function vendorProduct(v: string, p: string): string {
  const vendor = v.trim();
  const product = p.trim();
  if (!vendor || /^(unknown|n\/a)$/i.test(vendor)) return product;
  if (!product || vendor.toLowerCase() === product.toLowerCase()) return vendor;
  if (product.toLowerCase().startsWith(vendor.toLowerCase())) return product;
  return `${vendor} · ${product}`;
}

/** Only absolute http(s) URLs are ever turned into links. */
export function isHttpUrl(value: string): boolean {
  try {
    const u = new URL(value);
    return u.protocol === 'https:' || u.protocol === 'http:';
  } catch {
    return false;
  }
}

/** Host for compact link labels ("www.cisa.gov"), or the input when it is not a URL. */
export function hostOf(value: string): string {
  try {
    return new URL(value).host;
  } catch {
    return value;
  }
}

export const cveOrgUrl = (id: string): string => `https://www.cve.org/CVERecord?id=${encodeURIComponent(id)}`;

/** The record's file in the CVE List V5 repository: cves/2024/12xxx/CVE-2024-12345.json. */
export function cveListUrl(id: string): string | null {
  const m = /^CVE-(\d{4})-(\d{4,})$/.exec(id);
  if (!m) return null;
  const bucket = `${Math.floor(Number(m[2]) / 1000)}xxx`;
  return `https://github.com/CVEProject/cvelistV5/blob/main/cves/${m[1]}/${bucket}/${id}.json`;
}
