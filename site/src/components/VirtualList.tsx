/**
 * Window-scrolled virtual list with fixed row height: only the rows in (and just around) the
 * viewport are in the DOM, so 16k rows cost the same as 40.
 */
import type { ComponentChildren, RefObject } from 'preact';
import { useEffect, useState } from 'preact/hooks';

interface Props<T> {
  items: readonly T[];
  rowHeight: number;
  render: (item: T, index: number) => ComponentChildren;
  listRef: RefObject<HTMLDivElement | null>;
  overscan?: number;
  label: string;
}

export function VirtualList<T>({ items, rowHeight, render, listRef, overscan = 6, label }: Props<T>) {
  const [range, setRange] = useState<[number, number]>([0, 24]);
  useEffect(() => {
    const el = listRef.current;
    if (!el) return;
    let raf = 0;
    const update = () => {
      raf = 0;
      const top = el.getBoundingClientRect().top + window.scrollY;
      const y = window.scrollY - top;
      const first = Math.max(0, Math.floor(y / rowHeight) - overscan);
      const last = Math.min(items.length, Math.ceil((y + window.innerHeight) / rowHeight) + overscan);
      setRange((prev) => (prev[0] === first && prev[1] === last ? prev : [first, Math.max(first, last)]));
    };
    const schedule = () => {
      if (!raf) raf = requestAnimationFrame(update);
    };
    update();
    window.addEventListener('scroll', schedule, { passive: true });
    window.addEventListener('resize', schedule);
    return () => {
      window.removeEventListener('scroll', schedule);
      window.removeEventListener('resize', schedule);
      cancelAnimationFrame(raf);
    };
  }, [items.length, rowHeight, overscan, listRef]);

  const [first, last] = range;
  return (
    <div ref={listRef} class="vlist" style={{ height: `${items.length * rowHeight}px` }} role="list" aria-label={label}>
      <div class="vlist__window" style={{ transform: `translateY(${first * rowHeight}px)` }}>
        {items.slice(first, last).map((item, k) => (
          <div key={first + k} role="listitem" aria-setsize={items.length} aria-posinset={first + k + 1} style={{ height: `${rowHeight}px` }}>
            {render(item, first + k)}
          </div>
        ))}
      </div>
    </div>
  );
}

/** Scroll the window so row `index` of a virtual list is comfortably visible. */
export function revealRow(list: HTMLElement | null, index: number, rowHeight: number, headerOffset = 120): void {
  if (!list) return;
  const top = list.getBoundingClientRect().top + window.scrollY + index * rowHeight;
  const viewTop = window.scrollY + headerOffset;
  const viewBottom = window.scrollY + window.innerHeight - 24;
  if (top < viewTop) window.scrollTo({ top: top - headerOffset });
  else if (top + rowHeight > viewBottom) window.scrollTo({ top: top + rowHeight - window.innerHeight + 24 });
}
