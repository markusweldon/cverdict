import type { Row, Tier } from '../../../shared/contract';
import { hasChip, pubMs } from '../filters';
import { batchKind, batchLabel, cnaName, fmtAge, vendorProduct } from '../format';
import { cveHref, href } from '../router';
import { ChipList } from './Chip';
import { IconEye, IconLayers } from './icons';
import { TierPill } from './Tier';

/** Score with a hairline meter and a tick where the knob sits. */
export function ScoreMeter({ score, knob, tier }: { score: number; knob: number; tier: Tier }) {
  return (
    <span class={`score score--${tier}`} aria-label={`Score ${score} of 100`}>
      <span class="score__meter" aria-hidden="true">
        <span class="score__fill" style={{ width: `${score}%` }} />
        <span class="score__knob" style={{ left: `${knob}%` }} />
      </span>
      <span class="score__num">{score}</span>
    </span>
  );
}

interface CveRowProps {
  row: Row;
  tier: Tier;
  knob: number;
  now: number;
  selected?: boolean;
  watched?: boolean;
  isNew?: boolean;
  activeChip?: string | null;
  onChip?: (id: string) => void;
  onSelect?: () => void;
  style?: Record<string, string>;
}

/** One CVE in a list. The whole row is a link; chips and the batch tag sit above it. */
export function CveRow({ row, tier, knob, now, selected, watched, isNew, activeChip, onChip, onSelect, style }: CveRowProps) {
  const who = vendorProduct(row.v, row.p) || cnaName(row.cna);
  const top = row.b ? row.c.filter((c) => c !== 'batch') : row.c;
  // A reason filter also matches chips outside the top four: show the matching one in place of the last.
  const chips = activeChip && activeChip !== 'batch' && !top.includes(activeChip) && hasChip(row, activeChip) ? [...top.slice(0, 3), activeChip] : top;
  return (
    <article class={`row row--${tier}${selected ? ' is-selected' : ''}`} data-id={row.id} style={style} onPointerEnter={onSelect}>
      <TierPill tier={tier} size="sm" />
      <div class="row__body">
        <div class="row__line">
          <a class="row__link" href={cveHref(row.id)} data-row-link={row.id} onFocus={onSelect}>
            <span class="row__id">{row.id}</span>
          </a>
          <span class="row__who">{who}</span>
          {watched && (
            <span class="row__flag row__flag--watch" data-tip="On your watchlist: shown regardless of the knob">
              <IconEye size={12} />
              <span class="sr-only">Watched</span>
            </span>
          )}
          {isNew && <span class="row__flag row__flag--new">new</span>}
        </div>
        <p class="row__title">{row.t}</p>
        <div class="row__meta">
          <ChipList ids={chips} onChip={onChip} activeChip={activeChip} tabbable={false} />
          {row.b && (
            <a class="row__batch" href={href(`batches#${row.b}`)} tabIndex={-1} data-tip={`Part of a ${batchKind(row.cna)} (50+ CVEs from one CNA in one day)`}>
              <IconLayers size={12} />
              {batchLabel(row.b, row.cna)}
            </a>
          )}
        </div>
      </div>
      <div class="row__side">
        <ScoreMeter score={row.s} knob={knob} tier={tier} />
        <time class="row__age" dateTime={row.pub} data-tip={`Published ${new Date(pubMs(row)).toUTCString()}`}>
          {fmtAge(row.pub, now)}
        </time>
      </div>
    </article>
  );
}
