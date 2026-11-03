/** Feeds: the open JSON API, Atom and iCalendar feeds, with copyable URLs and examples. */
import type { ComponentChildren } from 'preact';
import { RAW_DATA_URL } from '../../../shared/brand';
import { SIGNAL_MIN_SCORE } from '../../../shared/contract';
import { SHARD_COUNT } from '../../../shared/shard';
import { copyLink } from '../actions';
import { IconCalendar, IconCode, IconCopy, IconExternal, IconRss } from '../components/icons';
import { DATA_BASE, FEEDS_BASE } from '../data';
import { useTitle } from '../hooks';

const abs = (path: string) => new URL(path, window.location.origin).href;

const JSON_FILES: readonly [string, string][] = [
  ['meta.json', 'Counts, window, definitions and the status of every source.'],
  ['signal.json', `Row table: every window CVE with score ≥ ${SIGNAL_MIN_SCORE}, or exploited/weaponized. Score order.`],
  ['index.json', 'Row table: every CVE published in the window, newest first (~700 KB gzip).'],
  [`cve/<shard>.json`, `Full records with every chip, in ${SHARD_COUNT} shards named by FNV-1a(id) mod ${SHARD_COUNT} (two hex digits).`],
  ['batches.json', 'Patch-day cohorts: tier counts, product families, top CVEs.'],
  ['kev.json', 'CISA KEV entries added in 30 days or due from 14 days ago, with our score.'],
  ['stats.json', 'Monthly volume since 1999, daily window counts, hourly waterfall buckets, top CNAs.'],
  ['changes.json', 'Escalations from the last 7 days of hourly runs.'],
  ['woke.json', 'Old CVEs (published before the window) that gained exploitation evidence in the last 30 days, with the dated signals.'],
  ['receipts.json', 'Receipts: which CVEs CISA added to KEV that each method had flagged before the listing, from the live log and the hindsight backtest.'],
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

function Snippet({ title, code }: { title: string; code: string }) {
  return (
    <figure class="snippet">
      <figcaption>
        <span>{title}</span>
        <button type="button" class="btn btn--ghost btn--sm" onClick={() => void copyLink(code, 'Snippet')}>
          <IconCopy size={12} /> Copy
        </button>
      </figcaption>
      <pre class="code">
        <code>{code}</code>
      </pre>
    </figure>
  );
}

export default function Feeds() {
  useTitle('Feeds');
  const base = abs(DATA_BASE);
  const feeds = abs(FEEDS_BASE);
  return (
    <div class="page page--feeds">
      <header class="page__head">
        <p class="eyebrow">Open data, refreshed hourly</p>
        <h1 class="page__title" tabIndex={-1}>
          Feeds &amp; API
        </h1>
        <p class="page__lede">Everything on this site is a static file you can fetch: no key, no account, no rate limit beyond your host’s. The same files live on the git data branch.</p>
      </header>

      <section class="prose-section" aria-labelledby="sub-h">
        <h2 id="sub-h" class="section__title">
          Subscribe
        </h2>
        <ul class="endpoints">
          <UrlRow url={`${feeds}signal.xml`} label="Signal (Atom)" note="The newest 100 Exploited and Likely-next CVEs." icon={<IconRss size={16} />} />
          <UrlRow url={`${feeds}kev.xml`} label="KEV additions (Atom)" note="CISA KEV entries added in the last 30 days." icon={<IconRss size={16} />} />
          <UrlRow url={`${feeds}woke.xml`} label="Woke up (Atom)" note="Up to 100 old CVEs that gained exploitation evidence in the last 30 days, newest first. KEV listings and Exploit-DB entries always make it in. A PoC repo alone counts only when the CVE is Likely next or Exploited." icon={<IconRss size={16} />} />
          <UrlRow url={`${feeds}kev-due.ics`} label="KEV due dates (iCalendar)" note="One all-day event per deadline, from a week ago to 60 days out. Subscribe from any calendar app." icon={<IconCalendar size={16} />} />
        </ul>
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
    </div>
  );
}
