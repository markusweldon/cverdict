import { toasts, useStore } from '../state';
import { IconAlert, IconCheck, IconInfo } from './icons';

export function Toasts() {
  const list = useStore(toasts);
  return (
    <div class="toasts" role="status" aria-live="polite">
      {list.map((t) => (
        <div key={t.id} class={`toast toast--${t.tone}`}>
          {t.tone === 'error' ? <IconAlert size={14} /> : t.tone === 'info' ? <IconInfo size={14} /> : <IconCheck size={14} />}
          <span>{t.text}</span>
        </div>
      ))}
    </div>
  );
}
