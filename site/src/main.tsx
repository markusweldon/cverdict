import '@fontsource-variable/geist';
import '@fontsource-variable/geist-mono';
import './styles/tokens.css';
import './styles/base.css';
import './styles/components.css';
import './styles/pages.css';
import { render } from 'preact';
import { App } from './app';
import { storage, theme } from './state';

// theme-init.js already applied a saved choice before first paint; make the attribute explicit and
// keep following the OS setting until the viewer picks a theme themselves.
document.documentElement.dataset.theme = theme.get();
const light = window.matchMedia('(prefers-color-scheme: light)');
light.addEventListener('change', () => {
  if (storage.get('theme') === null) theme.set(light.matches ? 'light' : 'dark');
});

render(<App />, document.getElementById('app')!);
