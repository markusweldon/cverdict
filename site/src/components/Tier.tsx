import type { Tier } from '../../../shared/contract';
import { TIER_META } from '../tiers';
import { IconCrosshair, IconEye, IconFlame, IconQuiet } from './icons';

export function TierIcon({ tier, size = 14 }: { tier: Tier; size?: number }) {
  switch (tier) {
    case 'exploited':
      return <IconFlame size={size} />;
    case 'likely':
      return <IconCrosshair size={size} />;
    case 'watch':
      return <IconEye size={size} />;
    default:
      return <IconQuiet size={size} />;
  }
}

/** Tier label with icon and text: tier colour is never the only signal. */
export function TierPill({ tier, size = 'md' }: { tier: Tier; size?: 'sm' | 'md' | 'lg' }) {
  return (
    <span class={`tier tier--${tier} tier--${size}`}>
      <TierIcon tier={tier} size={size === 'lg' ? 16 : size === 'sm' ? 12 : 13} />
      <span>{TIER_META[tier].label}</span>
    </span>
  );
}

/** Proportional stacked bar of tier counts; tiny non-zero passed tiers stay visible. */
export function TierBar({ counts, total, label }: { counts: Record<Tier, number>; total?: number; label?: string }) {
  const sum = total ?? counts.exploited + counts.likely + counts.watch + counts.quiet;
  const order: Tier[] = ['exploited', 'likely', 'watch', 'quiet'];
  return (
    <div class="tierbar" role="img" aria-label={label ?? order.map((t) => `${TIER_META[t].label} ${counts[t]}`).join(', ')}>
      {order.map((t) =>
        counts[t] > 0 ? (
          <span
            key={t}
            class={`tierbar__seg tierbar__seg--${t}`}
            style={{ flexGrow: String(sum > 0 ? counts[t] / sum : 0), minWidth: t === 'exploited' || t === 'likely' ? '4px' : '2px' }}
          />
        ) : null,
      )}
    </div>
  );
}
