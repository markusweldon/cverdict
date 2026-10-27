import type { ComponentChildren } from 'preact';
import { hostOf, isHttpUrl } from '../format';
import { IconExternal } from './icons';

/**
 * Link to a third-party URL. Only absolute http(s) URLs become links (CVE data is untrusted);
 * anything else is shown as inert text.
 */
export function ExtLink({ href, children, class: cls, icon = true }: { href: string; children?: ComponentChildren; class?: string; icon?: boolean }) {
  if (!isHttpUrl(href)) {
    return <span class={`ext ext--inert${cls ? ` ${cls}` : ''}`} title="Not an http(s) link — shown as text">{children ?? href}</span>;
  }
  return (
    <a class={`ext${cls ? ` ${cls}` : ''}`} href={href} target="_blank" rel="noopener noreferrer nofollow">
      {children ?? hostOf(href)}
      {icon && <IconExternal size={12} class="ext__icon" />}
      <span class="sr-only"> (opens in a new tab)</span>
    </a>
  );
}
