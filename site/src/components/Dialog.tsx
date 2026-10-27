import type { ComponentChildren } from 'preact';
import { useEffect, useRef } from 'preact/hooks';

/**
 * Modal built on the native <dialog>: focus trapping, Escape and an inert background come from
 * the platform. Clicking the backdrop closes it.
 */
export function Dialog({ open, onClose, label, class: cls, children }: { open: boolean; onClose: () => void; label: string; class?: string; children: ComponentChildren }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    if (!open && d.open) d.close();
  }, [open]);
  return (
    <dialog
      ref={ref}
      class={`dialog${cls ? ` ${cls}` : ''}`}
      aria-label={label}
      onClose={onClose}
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
      onClick={(e) => {
        if (e.target === ref.current) onClose();
      }}
    >
      {open && children}
    </dialog>
  );
}
