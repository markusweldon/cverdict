/**
 * A row of equal-width tabs for a card (the MCP client picker, the Check card's Repo, File and CI).
 * Equal cells in a grid, so the row never breaks into ragged lines: on a phone six tabs make two
 * rows of three (pages.css, .picker).
 */
export function Picker<T extends string>({ label, options, value, onPick }: { label: string; options: readonly { id: T; label: string }[]; value: T; onPick: (id: T) => void }) {
  return (
    <div class={`picker${options.length > 3 ? ' picker--many' : ''}`} style={{ '--n': options.length }} role="group" aria-label={label}>
      {options.map((o) => (
        <button key={o.id} type="button" class="picker__btn" aria-pressed={o.id === value ? 'true' : 'false'} onClick={() => onPick(o.id)}>
          {o.label}
        </button>
      ))}
    </div>
  );
}
