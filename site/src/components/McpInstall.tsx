/**
 * The MCP install snippet with a client picker (Claude, Codex, Cursor, Copilot, Gemini,
 * Antigravity), on the homepage's MCP card and the MCP Server page. The last pick is remembered
 * in this browser, so both places open on the same client.
 */
import { useState } from 'preact/hooks';
import { MCP_CLIENTS } from '../../../shared/mcp';
import { storage } from '../state';
import { Picker } from './Picker';
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
      <Picker label="MCP client" options={MCP_CLIENTS} value={client.id} onPick={pick} />
      <Snippet title={client.where} code={client.code} />
    </div>
  );
}
