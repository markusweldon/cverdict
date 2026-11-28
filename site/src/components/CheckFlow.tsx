/**
 * The Check page's data-flow diagram, one per tab: where your files come from, where they are
 * matched, and what comes from cverdict.dev. The dashed zone is what stays on your side. Every
 * label is real text (read by screen readers in order); the wires and moving dots are decoration.
 * The dots move toward the place the matching happens, and stop under prefers-reduced-motion.
 */
import type { ComponentChildren } from 'preact';
import { IconLayers, IconLock, IconScan, IconSource, IconTerminal, Mark } from './icons';

export type FlowMode = 'repo' | 'file' | 'ci';

interface Node {
  icon: ComponentChildren;
  title: string;
  sub: string;
}
interface Flow {
  summary: string;
  zone: { span: 'mid' | 'left'; label: string };
  src: Node;
  in: { label: string; note: string };
  mid: Node;
  result: string;
}

const FLOWS: Record<FlowMode, Flow> = {
  repo: {
    summary:
      'GitHub sends the lockfiles and SBOMs of your public repository to your browser; only the repository name goes to GitHub. cverdict.dev sends the public index, the same files for everyone. Your browser matches and ranks them. Nothing goes back to cverdict.dev.',
    zone: { span: 'mid', label: 'On your device' },
    src: { icon: <IconSource size={18} />, title: 'GitHub', sub: 'your public repo' },
    in: { label: 'lockfiles and SBOMs', note: 'only its name goes out' },
    mid: { icon: <IconScan size={18} />, title: 'Your browser', sub: 'matches and ranks' },
    result: 'Your dependencies with CVEs, most exploited first',
  },
  file: {
    summary:
      'Your lockfile or SBOM is read in place by your browser and never uploaded. cverdict.dev sends the public index, the same files for everyone. Your browser matches and ranks them. Nothing goes back to cverdict.dev.',
    zone: { span: 'left', label: 'On your device' },
    src: { icon: <IconLayers size={18} />, title: 'Your file', sub: 'lockfile or SBOM' },
    in: { label: 'read in place', note: 'never uploaded' },
    mid: { icon: <IconScan size={18} />, title: 'Your browser', sub: 'matches and ranks' },
    result: 'Your dependencies with CVEs, most exploited first',
  },
  ci: {
    summary:
      'Your repository, private ones too, is checked out in your own GitHub Actions runner, where the CVErdict Action reads the lockfiles, with no token and no app. cverdict.dev sends the public index, the same files for everyone. Nothing goes back to cverdict.dev. The Action writes a job summary, marks lockfile lines in pull requests and fails on an Exploited dependency.',
    zone: { span: 'left', label: 'In your CI' },
    src: { icon: <IconSource size={18} />, title: 'Your repo', sub: 'private ones too' },
    in: { label: 'lockfiles in the runner', note: 'no token, no app' },
    mid: { icon: <IconTerminal size={18} />, title: 'Your runner', sub: 'the CVErdict Action' },
    result: 'Job summary, PR annotations, fails on Exploited',
  },
};

function FlowNode({ n, kind }: { n: Node; kind: 'src' | 'mid' | 'dst' }) {
  return (
    <div class={`flow__node flow__node--${kind}`}>
      <span class="flow__icon">{n.icon}</span>
      <span class="flow__text">
        <span class="flow__title">{n.title}</span>
        <span class="flow__sub">{n.sub}</span>
      </span>
    </div>
  );
}

function Wire({ side, label, note, safe }: { side: 'in' | 'index'; label: string; note: string; safe?: boolean }) {
  return (
    <div class={`flow__wire flow__wire--${side}`}>
      <span class="flow__line" aria-hidden="true">
        <span class="flow__dot" />
        <span class="flow__dot flow__dot--late" />
      </span>
      <span class="flow__wiretext">
        <span class="flow__label">{label}</span>
        <span class={`flow__note${safe ? ' flow__note--safe' : ''}`}>
          {safe && <IconLock size={12} />}
          {note}
        </span>
      </span>
    </div>
  );
}

/** compact: on a phone, one short row of icons and names (the homepage's Check card) instead of the tall column. */
export function CheckFlow({ mode, compact }: { mode: FlowMode; compact?: boolean }) {
  const f = FLOWS[mode];
  return (
    <figure class={`flow flow--${mode}${compact ? ' flow--compact' : ''}`} key={mode} aria-labelledby="check-flow-cap">
      <figcaption id="check-flow-cap" class="sr-only">
        How it works: {f.summary}
      </figcaption>
      <div class="flow__grid" aria-hidden="true">
        <div class={`flow__zone flow__zone--${f.zone.span}`}>
          <span class="flow__zonelabel">{f.zone.label}</span>
        </div>
        <FlowNode n={f.src} kind="src" />
        <Wire side="in" label={f.in.label} note={f.in.note} />
        <FlowNode n={f.mid} kind="mid" />
        <Wire side="index" label="public index" note="nothing goes back" safe />
        <FlowNode n={{ icon: <Mark size={18} />, title: 'cverdict.dev', sub: 'same for everyone' }} kind="dst" />
        <div class="flow__result">
          <span class="flow__tiers">
            <i class="flow__tier flow__tier--exploited" />
            <i class="flow__tier flow__tier--likely" />
            <i class="flow__tier flow__tier--watch" />
          </span>
          {f.result}
        </div>
      </div>
    </figure>
  );
}
