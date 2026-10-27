/** User actions shared by several pages and the keyboard handler. */
import { data } from './data';
import { cveHref } from './router';
import { knob, toast, toggleWatch } from './state';
import { copyText, ticketMarkdown } from './ticket';
import { detailTier } from './tiers';

export const absoluteUrl = (path: string): string => new URL(path, window.location.origin).href;

/** Copy a CVE as a Markdown ticket. Uses the cached shard when present so the copy stays synchronous. */
export async function copyTicket(id: string): Promise<void> {
  const loader = data.detail(id);
  let detail = loader.peek();
  if (detail === undefined) {
    try {
      detail = await loader.load();
    } catch {
      toast(`Couldn’t load ${id}`, 'error');
      return;
    }
  }
  if (!detail) {
    toast(`${id} is not in our data`, 'error');
    return;
  }
  const level = knob.get();
  const ok = await copyText(ticketMarkdown(detail, detailTier(detail, level), level, absoluteUrl(cveHref(detail.id))));
  toast(ok ? `Copied ${detail.id} as a ticket` : 'Couldn’t reach the clipboard — try again', ok ? 'ok' : 'error');
}

/** Watch or unwatch a row's vendor (its product when no vendor is listed). */
export function watchVendorOf(row: { v: string; p: string; cna: string }): void {
  const name = row.v || row.p;
  if (!name) {
    toast('This CVE lists no vendor or product to watch', 'info');
    return;
  }
  toast(toggleWatch(name) ? `Watching ${name} — it now bypasses the knob` : `Stopped watching ${name}`, 'info');
}

export async function copyLink(url: string, what = 'Link'): Promise<void> {
  const ok = await copyText(url);
  toast(ok ? `${what} copied` : 'Couldn’t reach the clipboard', ok ? 'ok' : 'error');
}
