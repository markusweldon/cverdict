/**
 * One tooltip for the whole app: any element with `data-tip` gets it on hover (after a short
 * delay) and on keyboard focus. Text is set with textContent; it is positioned to stay on screen.
 */
import { useEffect, useRef } from 'preact/hooks';

export function TooltipLayer() {
  const tip = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = tip.current!;
    let target: HTMLElement | null = null;
    let timer = 0;
    const hide = () => {
      window.clearTimeout(timer);
      target = null;
      el.classList.remove('is-on');
    };
    const show = (t: HTMLElement) => {
      const text = t.dataset.tip;
      if (!text) return;
      target = t;
      el.textContent = text;
      el.classList.add('is-on');
      const r = t.getBoundingClientRect();
      const w = el.offsetWidth;
      const h = el.offsetHeight;
      const left = Math.min(window.innerWidth - w - 8, Math.max(8, r.left + r.width / 2 - w / 2));
      const above = r.top - h - 8;
      el.style.left = `${left}px`;
      el.style.top = `${above > 8 ? above : r.bottom + 8}px`;
    };
    const from = (e: Event) => (e.target instanceof Element ? (e.target.closest('[data-tip]') as HTMLElement | null) : null);
    const over = (e: PointerEvent) => {
      if (e.pointerType === 'touch') return;
      const t = from(e);
      // Clear first: a pending show for an element the pointer already left must not fire.
      window.clearTimeout(timer);
      if (t === target) return;
      if (!t) return hide();
      timer = window.setTimeout(() => show(t), target ? 0 : 280);
    };
    const focus = (e: FocusEvent) => {
      const t = from(e);
      if (t && t.matches(':focus-visible')) show(t);
    };
    // Any key press (typing, shortcuts, opening the palette) dismisses a hover tooltip.
    document.addEventListener('pointerover', over);
    document.addEventListener('focusin', focus);
    document.addEventListener('focusout', hide);
    document.addEventListener('keydown', hide);
    window.addEventListener('scroll', hide, { passive: true, capture: true });
    return () => {
      document.removeEventListener('pointerover', over);
      document.removeEventListener('focusin', focus);
      document.removeEventListener('focusout', hide);
      document.removeEventListener('keydown', hide);
      window.removeEventListener('scroll', hide, { capture: true });
    };
  }, []);
  return <div ref={tip} class="tooltip" role="tooltip" aria-hidden="true" />;
}
