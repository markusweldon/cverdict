import { signed } from '../format';
import { chipDef, chipTone, SOURCE_NAMES } from '../tiers';
import { IconDown, IconInfo, IconSparkle, IconUnknown, IconUp } from './icons';

function PolarityIcon({ tone }: { tone: string }) {
  if (tone === 'down') return <IconDown size={12} />;
  if (tone === 'info') return <IconInfo size={12} />;
  if (tone === 'ai') return <IconSparkle size={12} />;
  if (tone === 'unknown') return <IconUnknown size={12} />;
  return <IconUp size={12} />;
}

interface ChipProps {
  id: string;
  /** Full dated label (detail view); defaults to the catalogue's short label. */
  label?: string;
  points?: number;
  active?: boolean;
  onClick?: (id: string) => void;
  href?: string;
  dim?: boolean;
  /** Rows set this false: the row itself is the tab stop and j/k drive the list. */
  tabbable?: boolean;
}

/** One reason chip. Short label, colour and tooltip all come from the shared chip catalogue. */
export function Chip({ id, label, points, active, onClick, href, dim, tabbable = true }: ChipProps) {
  const def = chipDef(id);
  const tone = def ? chipTone(def) : 'unknown';
  const text = label ?? def?.short ?? id;
  const pts = points ?? def?.points ?? 0;
  const tip = def ? `${def.explain}${def.polarity === 'info' || def.polarity === 'unknown' ? '' : ` (${signed(pts)} pts · ${SOURCE_NAMES[def.source]})`}` : 'Unknown chip';
  const cls = `chip chip--${tone}${active ? ' is-active' : ''}${dim ? ' is-dim' : ''}`;
  const body = (
    <>
      <PolarityIcon tone={tone} />
      <span class="chip__text">{text}</span>
    </>
  );
  if (onClick) {
    return (
      <button type="button" class={cls} data-tip={tip} tabIndex={tabbable ? undefined : -1} aria-pressed={active ? 'true' : 'false'} aria-label={`${text}. ${tip}. Filter by this reason`} onClick={(e) => (e.preventDefault(), e.stopPropagation(), onClick(id))}>
        {body}
      </button>
    );
  }
  if (href) {
    return (
      <a class={cls} href={href} data-tip={tip} aria-label={`${text}. ${tip}`}>
        {body}
      </a>
    );
  }
  return (
    <span class={cls} data-tip={tip}>
      {body}
    </span>
  );
}

export function ChipList({ ids, onChip, activeChip, tabbable }: { ids: readonly string[]; onChip?: (id: string) => void; activeChip?: string | null; tabbable?: boolean }) {
  return (
    <span class="chips">
      {ids.map((id) => (
        <Chip key={id} id={id} onClick={onChip} active={activeChip === id} tabbable={tabbable} />
      ))}
    </span>
  );
}
