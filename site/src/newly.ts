/**
 * The list behind the waterfall legend's "N newly exploited" (stats.json hourly.new_exploited_cves):
 * when it opens, what each row says, and where its popover goes.
 */
import type { NewExploitedCve } from '../../shared/contract';
import { fmtDate, fmtInt, fmtMonth } from './format';

/** The legend item is a button only with names in the data and at least one new; otherwise it is the plain label. */
export const listOpens = (count: number, list: readonly NewExploitedCve[] | null): list is NewExploitedCve[] => count > 0 && list !== null && list.length > 0;

const VIA_LABEL: Readonly<Record<string, string>> = { Vendor: 'Vendor flag' };

/** "CISA KEV, Nov 18" or "Vendor flag, Nov 19". */
export function signalLine(c: Pick<NewExploitedCve, 'via' | 'at'>, refYear?: number): string {
  return [VIA_LABEL[c.via] ?? c.via, fmtDate(c.at, refYear)].filter(Boolean).join(', ');
}

/** For a CVE published before the chart starts: "Published Mar 2024, before this chart". Null for one on the chart. */
export function olderNote(c: Pick<NewExploitedCve, 'hour' | 'published'>): string | null {
  if (c.hour !== undefined || !c.published || !/^\d{4}-\d{2}/.test(c.published)) return null;
  return `Published ${fmtMonth(c.published.slice(0, 7))}, before this chart`;
}

/** Under the heading when the list is capped: "Newest 50 of 61." */
export const capNote = (count: number, shown: number): string | null => (count > shown ? `Newest ${fmtInt(shown)} of ${fmtInt(count)}.` : null);

/**
 * The popover's left edge relative to its anchor: lined up with the anchor's right edge when it
 * fits, kept `gutter` px inside the viewport otherwise, so a phone never scrolls sideways.
 */
export function popoverLeft(anchor: { left: number; right: number }, width: number, viewport: number, gutter = 16): number {
  const want = anchor.right - width;
  const left = Math.max(gutter, Math.min(want, viewport - gutter - width));
  return Math.round(left - anchor.left);
}
