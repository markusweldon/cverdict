/** MCP Server: how to add the read-only MCP server to an AI agent, its tools, where it reads from and its limits. */
import { REPO_URL } from '../../../shared/brand';
import { MCP_SERVER, MCP_SNIPPETS, MCP_TOOLS, UNTRUSTED } from '../../../shared/mcp';
import { SHARD_COUNT } from '../../../shared/shard';
import { ExtLink } from '../components/ExtLink';
import { IconCode } from '../components/icons';
import { Snippet } from '../components/Snippet';
import { useTitle } from '../hooks';
import { href } from '../router';

const NPM_URL = `https://www.npmjs.com/package/${MCP_SERVER.npm}`;

export default function Mcp() {
  useTitle('MCP Server');
  return (
    <div class="page page--feeds page--mcp">
      <header class="page__head">
        <p class="eyebrow">For AI agents</p>
        <h1 class="page__title" tabIndex={-1}>
          MCP Server
        </h1>
        <p class="page__lede">
          A read-only Model Context Protocol server that gives AI agents the same verdicts as this site: the tier, the score, every reason chip with its points and evidence link, and what is unknown. Every answer
          says when the data was generated and which files it came from. No key, no account.
        </p>
      </header>

      <section class="prose-section" id="install" aria-labelledby="install-h">
        <h2 id="install-h" class="section__title">
          Install
        </h2>
        <p class="muted">
          Node 22.12 or later. The server is the npm package <ExtLink href={NPM_URL}>{MCP_SERVER.npm}</ExtLink>: one file, no runtime dependencies. Your agent starts it on your machine when it needs it.
        </p>
        <div class="snippets">
          {MCP_SNIPPETS.map(([title, code]) => (
            <Snippet key={title} title={title} code={code} />
          ))}
        </div>
      </section>

      <section class="prose-section" id="tools" aria-labelledby="tools-h">
        <h2 id="tools-h" class="section__title">
          Tools
        </h2>
        <p class="muted">Six read-only tools. An agent picks one from the question you ask, for example "Should I patch CVE-2026-12345?" or "Which KEV deadlines are due this week?".</p>
        <ul class="endpoints" aria-label="MCP tools">
          {MCP_TOOLS.map((t) => (
            <li class="endpoint" key={t.name}>
              <span class="endpoint__icon">
                <IconCode size={16} />
              </span>
              <div class="endpoint__body">
                <p class="endpoint__label">
                  <code>{t.name}</code> · {t.title}
                </p>
                <p class="endpoint__note">{t.description.replace(UNTRUSTED, '')}</p>
              </div>
              <span />
            </li>
          ))}
        </ul>
      </section>

      <section class="prose-section" id="data" aria-labelledby="data-h">
        <h2 id="data-h" class="section__title">
          Where it reads from
        </h2>
        <p class="muted">
          It reads the same public files as this site, from the data branch on GitHub, so it keeps working when this site is down. GitHub sees which of the {SHARD_COUNT} shard files it fetches, never your CVE IDs or
          search words. If GitHub refuses or fails, the same requests go to this site’s /data/ copy. Set <code>CVERDICT_DATA_BASE</code> to point it at a fork or a mirror. The files themselves are on{' '}
          <a href={href('feeds')}>Feeds &amp; API</a>.
        </p>
      </section>

      <section class="prose-section" id="limits" aria-labelledby="limits-h">
        <h2 id="limits-h" class="section__title">
          Keep in mind
        </h2>
        <ul class="prose-list">
          <li>Quiet means no evidence yet, never safe. A CVE outside the data comes back as not found, which says nothing either way.</li>
          <li>It covers CVEs published in the last 30 days, every CVE in CISA KEV and old CVEs that woke up. get_verdict takes 1 to 15 CVE IDs, at most 5 with detail.</li>
          <li>Text from CVE records is quoted as it was published and is untrusted. The server tells the agent so.</li>
        </ul>
        <p class="muted">
          Every input and limit: <ExtLink href={MCP_SERVER.docs}>the server’s README</ExtLink>. What each answer contains: <ExtLink href={`${REPO_URL}/blob/main/docs/DATA.md#mcp-server`}>DATA.md</ExtLink>. Source:{' '}
          <ExtLink href={`${REPO_URL}/tree/main/mcp`}>mcp/ in the repository</ExtLink>.
        </p>
      </section>
    </div>
  );
}
