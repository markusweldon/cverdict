/** Feeds: the open JSON API, Atom and iCalendar feeds, with copyable URLs and examples. */
import type { ComponentChildren } from 'preact';
import { RAW_DATA_URL } from '../../../shared/brand';
import { SIGNAL_MIN_SCORE } from '../../../shared/contract';
import { SHARD_COUNT } from '../../../shared/shard';
import { copyLink } from '../actions';
import { IconCalendar, IconCode, IconCopy, IconExternal, IconRss } from '../components/icons';
import { Snippet } from '../components/Snippet';
import { DATA_BASE, FEEDS_BASE } from '../data';
import { useTitle } from '../hooks';
import { href } from '../router';
import { vendorFeedOrigin } from '../vendorfeed';

const abs = (path: string) => new URL(path, window.location.origin).href;

const JSON_FILES: readonly [string, string][] = [
  ['meta.json', 'Counts, window, definitions and the status of every source.'],
  ['signal.json', `Row table: every window CVE with score ≥ ${SIGNAL_MIN_SCORE}, or exploited/weaponized. Score order.`],
  ['index.json', 'Row table: every CVE published in the window, newest first (~700 KB gzip).'],
  [`cve/<shard>.json`, `Full records with every chip, in ${SHARD_COUNT} shards named by FNV-1a(id) mod ${SHARD_COUNT} (two hex digits).`],
  ['batches.json', 'Patch-day cohorts: tier counts, product families, top CVEs.'],
  ['kev.json', 'CISA KEV entries added in 30 days or due from 14 days ago, with our score.'],
  ['stats.json', 'Monthly volume since 1999, daily window counts, hourly waterfall buckets, top CNAs.'],
  ['surge.json', 'Published CVEs per month by CVSS severity and top 30 CNA, and CISA KEV CVEs by publication month. About 18 KB gzip.'],
  ['changes.json', 'Escalations from the runs of the last 7 days.'],
  ['events.json', 'Verdict events from the last 7 days: KEV and catalog listings, vendor reports, moves into Likely next or Exploited, fast lane, new exploit modules and templates. Newest first, each with a stable id.'],
  ['woke.json', 'Old CVEs (published before the window) that gained exploitation evidence in the last 30 days, with the dated signals.'],
  ['receipts.json', 'Receipts: which CVEs CISA added to KEV that each method had flagged before the listing, from the live log and the hindsight backtest.'],
  ['packages.json', 'Package versions the tracked CVEs affect, from OSV.dev advisories, for the Check page. About 120 KB gzip.'],
  ['packages-older.json', 'The same for every other CVE an OSV.dev advisory names: older, scored, no CVE page. Read with packages.json by the Check page, cverdict-check and the MCP server. About 2 MB gzip.'],
];

const SHARD_JS = `// FNV-1a 32-bit of the upper-cased ID, mod ${SHARD_COUNT}, as two hex digits.
function shardOf(id) {
  let h = 0x811c9dc5;
  for (const ch of id.trim().toUpperCase()) {
    h ^= ch.charCodeAt(0);
    h = Math.imul(h, 0x01000193);
  }
  return ((h >>> 0) % ${SHARD_COUNT}).toString(16).padStart(2, '0');
}`;

/** Posts each new events.json item for one vendor once; works with ntfy, Slack or Teams workflow webhooks. */
const WEBHOOK_SH = `#!/bin/sh
# Remembers what it posted in ./seen. For Slack, post {"text": ...} JSON to your webhook instead.
v=fortinet
curl -fsS ${RAW_DATA_URL}/v1/events.json \\
  | jq -r --arg v "$v" '.items[] | select((.vendor | ascii_downcase) == $v or (.product | ascii_downcase) == $v)
           | "\\(.id)\\t\\(.title) https://cverdict.dev/cve/\\(.cve)"' \\
  | while IFS="$(printf '\\t')" read -r id msg; do
      grep -qxF "$id" seen 2>/dev/null || { curl -fsS -d "$msg" https://ntfy.sh/your-topic && echo "$id" >>seen; }
    done`;

function UrlRow({ url, label, note, icon, open = url }: { url: string; label: string; note: string; icon: ComponentChildren; open?: string }) {
  return (
    <li class="endpoint">
      <span class="endpoint__icon">{icon}</span>
      <div class="endpoint__body">
        <p class="endpoint__label">{label}</p>
        <p class="endpoint__note">{note}</p>
        <code class="endpoint__url">{url}</code>
      </div>
      <div class="endpoint__actions">
        <button type="button" class="iconbtn" onClick={() => void copyLink(url, 'URL')} aria-label={`Copy the URL of ${label}`} data-tip="Copy URL">
          <IconCopy size={14} />
        </button>
        <a class="iconbtn" href={open} target="_blank" rel="noopener noreferrer" aria-label={`Open ${label} (new tab)`} data-tip={open === url ? 'Open' : 'Open an example'}>
          <IconExternal size={14} />
        </a>
      </div>
    </li>
  );
}

export default function Feeds() {
  useTitle('Feeds & API');
  const base = abs(DATA_BASE);
  const feeds = abs(FEEDS_BASE);
  const vendor = vendorFeedOrigin();
  return (
    <div class="page page--feeds">
      <header class="page__head">
        <p class="eyebrow">API · Open data, refreshed hourly</p>
        <h1 class="page__title" tabIndex={-1}>
          Feeds &amp; API
        </h1>
        <p class="page__lede">
          Everything on this site is a static file you can fetch: no key, no account, no rate limit beyond your host’s. The same files live on the git data branch. AI agents can read them through the{' '}
          <a href={href('mcp')}>MCP server</a>.
        </p>
      </header>

      <section class="prose-section" aria-labelledby="sub-h">
        <h2 id="sub-h" class="section__title">
          Subscribe
        </h2>
        <ul class="endpoints">
          <UrlRow url={`${feeds}signal.xml`} label="Signal (Atom)" note="The newest 100 Exploited and Likely-next CVEs." icon={<IconRss size={16} />} />
          <UrlRow url={`${feeds}kev.xml`} label="KEV additions (Atom)" note="CISA KEV entries added in the last 30 days." icon={<IconRss size={16} />} />
          <UrlRow url={`${feeds}woke.xml`} label="Woke Up (Atom)" note="Up to 100 old CVEs that gained exploitation evidence in the last 30 days, newest first. CISA KEV, EU KEV and CIRCL listings and Exploit-DB entries always make it in. A PoC repo alone counts only when the CVE is Likely next or Exploited." icon={<IconRss size={16} />} />
          <UrlRow
            url={`${RAW_DATA_URL}/feeds/events.xml`}
            label="Verdict events (Atom)"
            note="Up to 200 events from the last 7 days: why a verdict moved, newest first. KEV and catalog listings, vendor reports and moves into Exploited always make it in. Served straight from GitHub, so polling it costs this site nothing."
            icon={<IconRss size={16} />}
          />
          <UrlRow url={`${feeds}kev-due.ics`} label="KEV due dates (iCalendar)" note="One all-day event per deadline, from a week ago to 60 days out. Subscribe from any calendar app." icon={<IconCalendar size={16} />} />
        </ul>
      </section>

      <section class="prose-section" id="vendors" aria-labelledby="vendors-h">
        <h2 id="vendors-h" class="section__title">
          Feeds for your vendors
        </h2>
        <p class="muted">
          Every vendor or product name has its own Atom feed of verdict events: <code>{vendor}/feeds/v/&lt;name&gt;.xml</code>. The name is lower case, with every run of other characters turned into one hyphen, so
          “Palo Alto Networks” is <code>palo-alto-networks</code>. An event matches when its vendor or its product has that name, the same rule as the watchlist. The watchlist on Today copies the URL for each name.
        </p>
        <p class="muted">Poll hourly. The data changes once an hour, sooner when CISA or ENISA list something. No account needed, and we send nothing: every feed is a file you fetch.</p>
        <ul class="endpoints">
          <UrlRow url={`${vendor}/feeds/v/fortinet.xml`} label="Example: Fortinet (Atom)" note="Up to 50 events from the last 7 days. A name with no events gets an empty feed, not an error." icon={<IconRss size={16} />} />
        </ul>
        <div class="snippets">
          <Snippet title="Slack (the RSS app)" code={`/feed subscribe ${vendor}/feeds/v/fortinet.xml`} />
          <Snippet title="Microsoft Teams" code={'Power Automate: "When a feed item is published" (RSS connector),\nthen "Post message in a chat or channel".'} />
          <Snippet title="One vendor's events with curl and jq" code={`curl -s ${RAW_DATA_URL}/v1/events.json \\\n  | jq -r '.items[] | select((.vendor | ascii_downcase) == "fortinet" or (.product | ascii_downcase) == "fortinet") | "\\(.at)  \\(.title)"'`} />
          <Snippet title="Post new events to a webhook (cron, every 15 min)" code={WEBHOOK_SH} />
        </div>
      </section>

      <section class="prose-section" aria-labelledby="json-h">
        <h2 id="json-h" class="section__title">
          JSON (schema v1)
        </h2>
        <p class="muted">
          Base URL <code>{base}</code> · also served raw from <code>{`${RAW_DATA_URL}/v1/`}</code>. Every file carries <code>schema_version</code> and <code>generated_at</code>; row tables are columnar (<code>cols</code> + <code>rows</code>).
        </p>
        <ul class="endpoints">
          {JSON_FILES.map(([file, note]) => (
            <UrlRow key={file} url={`${base}${file}`} open={`${base}${file.replace('<shard>', '00')}`} label={file} note={note} icon={<IconCode size={16} />} />
          ))}
        </ul>
      </section>

      <section class="prose-section" aria-labelledby="ex-h">
        <h2 id="ex-h" class="section__title">
          Examples
        </h2>
        <div class="snippets">
          <Snippet title="Exploited CVEs right now (curl + jq)" code={`curl -s ${base}signal.json \\\n  | jq -r '.cols as $c | .rows[] | [$c, .] | transpose | map({(.[0]): .[1]}) | add\n           | select(.tier == "exploited") | "\\(.id)  \\(.s)  \\(.v) \\(.p)"'`} />
          <Snippet
            title="KEV deadlines in the next 7 days"
            code={`# GNU date; on macOS use: date -u -v+7d +%F\ncurl -s ${base}kev.json \\\n  | jq -r --arg t "$(date -u +%F)" --arg d "$(date -u -d '+7 days' +%F)" \\\n      '.entries[] | select(.due_date >= $t and .due_date <= $d) | "\\(.due_date)  \\(.id)  \\(.vendor) \\(.product)"'`}
          />
          <Snippet title="Look up one CVE (JavaScript)" code={`${SHARD_JS}\n\nconst id = 'CVE-2026-12345';\nconst shard = await fetch(\`${base}cve/\${shardOf(id)}.json\`).then((r) => r.json());\nconsole.log(shard.items[id]?.reasons);`} />
        </div>
      </section>

      <section class="prose-section" id="mcp" aria-labelledby="mcp-h">
        <h2 id="mcp-h" class="section__title">
          AI agents (MCP)
        </h2>
        <p class="muted">
          A read-only MCP server gives AI agents the same verdicts, chips and links as this site, from these same files. How to add it to your agent, its tools and its limits:{' '}
          <a href={href('mcp')}>MCP Server</a>.
        </p>
      </section>
    </div>
  );
}
