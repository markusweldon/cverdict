import { Fragment } from 'preact';
import { closeOverlay, overlay, useStore } from '../state';
import { isMac } from './Chrome';
import { Dialog } from './Dialog';

const GROUPS: readonly [string, readonly [string[], string][]][] = [
  [
    'Lists',
    [
      [['j'], 'Next CVE'],
      [['k'], 'Previous CVE'],
      [['Enter'], 'Open the selected CVE'],
      [['o'], 'Open the selected CVE'],
      [['w'], 'Watch / unwatch its vendor'],
      [['c'], 'Copy it as a ticket (Markdown)'],
    ],
  ],
  [
    'Anywhere',
    [
      [[isMac ? '⌘' : 'Ctrl', 'K'], 'Command palette'],
      [['/'], 'Focus search'],
      [['[', ']'], 'Turn the knob down / up by 5'],
      [['?'], 'This help'],
      [['Esc'], 'Close / leave a field'],
    ],
  ],
  [
    'Go to',
    [
      [['g', 't'], 'Today'],
      [['g', 'k'], 'KEV Clock'],
      [['g', 'w'], 'Woke Up'],
      [['g', 'e'], 'Explore'],
      [['g', 'c'], 'Check Deps'],
      [['g', 'b'], 'Batches'],
      [['g', 'r'], 'Receipts'],
      [['g', 'm'], 'Method'],
      [['g', 's'], 'The Surge'],
      [['g', 'f'], 'Feeds & API'],
      [['g', 'a'], 'MCP Server'],
    ],
  ],
];

export function ShortcutsHelp() {
  const open = useStore(overlay) === 'help';
  return (
    <Dialog open={open} onClose={() => closeOverlay('help')} label="Keyboard shortcuts" class="dialog--help">
      <div class="help">
        <header class="help__head">
          <h2>Keyboard shortcuts</h2>
          <button type="button" class="iconbtn" onClick={() => closeOverlay('help')} aria-label="Close">
            <kbd class="kbd">esc</kbd>
          </button>
        </header>
        <div class="help__grid">
          {GROUPS.map(([title, rows]) => (
            <section key={title}>
              <h3 class="help__title">{title}</h3>
              <dl class="help__list">
                {rows.map(([keys, what]) => (
                  <div key={what + keys.join()} class="help__row">
                    <dt>
                      {keys.map((k, i) => (
                        <Fragment key={k}>
                          {i > 0 && keys[0] === 'g' && <span class="help__then">then</span>}
                          <kbd class="kbd">{k}</kbd>
                        </Fragment>
                      ))}
                    </dt>
                    <dd>{what}</dd>
                  </div>
                ))}
              </dl>
            </section>
          ))}
        </div>
        <p class="help__note">The knob also answers to arrow keys when focused (Shift for single steps). On the waterfall, ← → step through time and Enter opens that day in Explore.</p>
      </div>
    </Dialog>
  );
}
