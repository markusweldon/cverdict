/**
 * The MCP install snippet with a client picker (Claude Code, Codex, Cursor, Copilot in VS Code, Gemini CLI,
 * Claude Desktop), on the homepage's MCP card and the MCP Server page. The last pick is remembered
 * in this browser, so both places open on the same client.
 */
import { useState } from 'preact/hooks';
import { MCP_CLIENTS } from '../../../shared/mcp';
import { storage } from '../state';
import { Snippet } from './Snippet';

const KEY = 'mcp-client';

export function McpInstall() {
  const [id, setId] = useState(() => storage.get(KEY) ?? MCP_CLIENTS[0].id);
  const client = MCP_CLIENTS.find((c) => c.id === id) ?? MCP_CLIENTS[0];
  const pick = (next: string) => {
    setId(next);
    storage.set(KEY, next);
  };
  return (
    <div class="mcpi">
      <div class="seg seg--sm mcpi__tabs" role="group" aria-label="MCP client">
        {MCP_CLIENTS.map((c) => (
          <button key={c.id} type="button" class="seg__btn" aria-pressed={c.id === client.id ? 'true' : 'false'} onClick={() => pick(c.id)}>
            {c.label}
          </button>
        ))}
      </div>
      <Snippet title={client.where} code={client.code} />
    </div>
  );
}
