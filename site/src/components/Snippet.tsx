/** A titled code block with a Copy button (Feeds & API and MCP Server pages). */
import { copyLink } from '../actions';
import { IconCopy } from './icons';

export function Snippet({ title, code }: { title: string; code: string }) {
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
