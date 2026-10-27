import { afterEach, describe, expect, it, vi } from 'vitest';
import { appPath, historyValue, href, isAppUrl, parsePath, savedScroll, scrollToHash, setHistoryValue } from './router';

describe('parsePath', () => {
  it('maps every route at the root base', () => {
    expect(parsePath('/', '/')).toEqual({ name: 'today' });
    expect(parsePath('/kev', '/')).toEqual({ name: 'kev' });
    expect(parsePath('/batches/', '/')).toEqual({ name: 'batches' });
    expect(parsePath('/explore', '/')).toEqual({ name: 'explore' });
    expect(parsePath('/surge', '/')).toEqual({ name: 'surge' });
    expect(parsePath('/method', '/')).toEqual({ name: 'method' });
    expect(parsePath('/feeds', '/')).toEqual({ name: 'feeds' });
  });

  it('normalises CVE IDs and keeps invalid ones for the page to explain', () => {
    expect(parsePath('/cve/cve-2026-12345', '/')).toEqual({ name: 'cve', id: 'CVE-2026-12345' });
    expect(parsePath('/cve/CVE-2026-12345/', '/')).toEqual({ name: 'cve', id: 'CVE-2026-12345' });
    expect(parsePath('/cve/%3Cscript%3E', '/')).toEqual({ name: 'cve', id: '<script>' });
    expect(parsePath('/cve/%E0%A4%A', '/')).toEqual({ name: 'cve', id: '%E0%A4%A' });
  });

  it('honours a GitHub Pages base path', () => {
    expect(parsePath('/repo/', '/repo/')).toEqual({ name: 'today' });
    expect(parsePath('/repo', '/repo/')).toEqual({ name: 'today' });
    expect(parsePath('/repo/cve/CVE-2026-1000', '/repo/')).toEqual({ name: 'cve', id: 'CVE-2026-1000' });
    expect(parsePath('/other/kev', '/repo/')).toEqual({ name: 'notfound', path: '/other/kev' });
  });

  it('sends unknown paths to the 404 view', () => {
    expect(parsePath('/nope', '/')).toEqual({ name: 'notfound', path: '/nope' });
    expect(parsePath('/cve', '/')).toEqual({ name: 'notfound', path: '/cve' });
  });
});

describe('links', () => {
  it('builds hrefs under the base', () => {
    expect(href('cve/CVE-2026-1', '/repo/')).toBe('/repo/cve/CVE-2026-1');
    expect(href('/kev', '/')).toBe('/kev');
    expect(href('', '/repo/')).toBe('/repo/');
  });

  it('strips the base from paths', () => {
    expect(appPath('/repo/batches/', '/repo/')).toBe('batches');
    expect(appPath('/elsewhere', '/repo/')).toBeNull();
  });

  it('only intercepts in-app pages, never static files', () => {
    const o = 'https://site.example';
    expect(isAppUrl(new URL(`${o}/explore?q=x`), o, '/')).toBe(true);
    expect(isAppUrl(new URL(`${o}/cve/CVE-2026-1`), o, '/')).toBe(true);
    expect(isAppUrl(new URL(`${o}/data/v1/meta.json`), o, '/')).toBe(false);
    expect(isAppUrl(new URL(`${o}/data/feeds/kev-due.ics`), o, '/')).toBe(false);
    expect(isAppUrl(new URL(`${o}/feeds`), o, '/')).toBe(true);
    expect(isAppUrl(new URL(`${o}/repo/feeds/`), o, '/repo/')).toBe(true);
    expect(isAppUrl(new URL(`${o}/feeds/signal.xml`), o, '/')).toBe(false);
    expect(isAppUrl(new URL(`${o}/feeds/x`), o, '/')).toBe(false);
    expect(isAppUrl(new URL(`${o}/robots.txt`), o, '/')).toBe(false);
    expect(isAppUrl(new URL('https://www.cve.org/CVERecord?id=1'), o, '/')).toBe(false);
    expect(isAppUrl(new URL(`${o}/other/kev`), o, '/repo/')).toBe(false);
  });
});

describe('history entry values', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('merge into the entry state without dropping the saved scroll position', () => {
    const history = { state: { scrollY: 900 } as unknown, replaceState: vi.fn((state: unknown) => (history.state = state)) };
    vi.stubGlobal('history', history);
    setHistoryValue('feedLimit', 120);
    expect(historyValue('feedLimit')).toBe(120);
    expect(savedScroll()).toBe(900);
    setHistoryValue('feedLimit', 120);
    expect(history.replaceState).toHaveBeenCalledTimes(1);
  });
});

describe('scrollToHash', () => {
  afterEach(() => vi.unstubAllGlobals());

  function setup() {
    const frames: (() => void)[] = [];
    const target = { scrollIntoView: vi.fn() };
    let rendered = false;
    vi.stubGlobal('document', { getElementById: (id: string) => (rendered && id === 'sources' ? target : null) });
    vi.stubGlobal('requestAnimationFrame', (fn: () => void) => frames.push(fn));
    return { frames, target, render: () => (rendered = true) };
  }

  it('waits for a target that a lazy page renders later', () => {
    const { frames, target, render } = setup();
    scrollToHash('#sources');
    frames.shift()!();
    expect(target.scrollIntoView).not.toHaveBeenCalled();
    render();
    frames.shift()!();
    expect(target.scrollIntoView).toHaveBeenCalledWith({ block: 'start' });
    expect(frames).toHaveLength(0);
  });

  it('gives up after a bounded number of frames', () => {
    const { frames } = setup();
    scrollToHash('#sources', 3);
    let n = 0;
    while (frames.length) (frames.shift()!(), n++);
    expect(n).toBe(3);
  });
});
