import { Flatline } from '../components/States';
import { useTitle } from '../hooks';
import { href } from '../router';
import { overlay } from '../state';

export default function NotFound({ path }: { path: string }) {
  useTitle('Not found');
  return (
    <div class="page page--404">
      <div class="lost">
        <Flatline />
        <p class="eyebrow">404</p>
        <h1 class="page__title" tabIndex={-1}>
          Nothing on this frequency
        </h1>
        <p class="page__lede">
          <code>{path}</code> isn’t a page here. The signal is still on Today.
        </p>
        <div class="page__actions">
          <a class="btn btn--primary" href={href('')}>
            Back to Today
          </a>
          <a class="btn" href={href('explore')}>
            Explore every CVE
          </a>
          <button type="button" class="btn btn--ghost" onClick={() => overlay.set('palette')}>
            Search
          </button>
        </div>
      </div>
    </div>
  );
}
