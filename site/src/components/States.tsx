/** Loading, empty and error states. */
import type { ComponentChildren } from 'preact';
import { IconAlert, IconRefresh } from './icons';

export function Skeleton({ lines = 3, height, class: cls }: { lines?: number; height?: string; class?: string }) {
  return (
    <div class={`skeleton${cls ? ` ${cls}` : ''}`} aria-hidden="true">
      {Array.from({ length: lines }, (_, i) => (
        <span key={i} class="skeleton__bar" style={{ height: height ?? undefined, width: `${92 - ((i * 17) % 38)}%` }} />
      ))}
    </div>
  );
}

/** Screen-reader announcement plus a visual skeleton. */
export function Loading({ label, lines, height, class: cls }: { label: string; lines?: number; height?: string; class?: string }) {
  return (
    <div class="loading" role="status">
      <span class="sr-only">{label}</span>
      <Skeleton lines={lines} height={height} class={cls} />
    </div>
  );
}

/** A flat noise floor with no spike: the illustration for "nothing here". */
export function Flatline() {
  return (
    <svg class="flatline" viewBox="0 0 160 40" aria-hidden="true" focusable="false">
      <path d="M2 24h18l3-3 3 4 3-2 3 1h20l2-2 2 3 3-1h22l3-2 2 3 2-1h24l2-3 3 4 2-1h22l2 1 3-2 2 2h11" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />
    </svg>
  );
}

/** `heading` makes the title the page's h1 when the state is all a route has to show. */
export function EmptyState({ title, children, action, heading }: { title: string; children?: ComponentChildren; action?: ComponentChildren; heading?: boolean }) {
  return (
    <div class="state">
      <Flatline />
      {heading ? (
        <h1 class="state__title" tabIndex={-1}>
          {title}
        </h1>
      ) : (
        <p class="state__title">{title}</p>
      )}
      {children && <p class="state__text">{children}</p>}
      {action && <div class="state__action">{action}</div>}
    </div>
  );
}

export function ErrorState({ error, onRetry, title = 'Couldn’t load this data' }: { error: Error; onRetry?: () => void; title?: string }) {
  return (
    <div class="state state--error" role="alert">
      <IconAlert size={20} />
      <p class="state__title">{title}</p>
      <p class="state__text">
        {error.message}. The data refreshes every hour; if this persists the pipeline may be mid-publish.
      </p>
      {onRetry && (
        <div class="state__action">
          <button type="button" class="btn" onClick={onRetry}>
            <IconRefresh size={14} /> Try again
          </button>
        </div>
      )}
    </div>
  );
}
