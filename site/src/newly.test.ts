import { describe, expect, it } from 'vitest';
import type { NewExploitedCve } from '../../shared/contract';
import { capNote, listOpens, popoverLeft, signalLine } from './newly';

const item = (o: Partial<NewExploitedCve> = {}): NewExploitedCve => ({ id: 'CVE-2026-1', title: 'Acme · Widget', via: 'CISA KEV', at: '2026-11-18', hour: 10, ...o });

describe('listOpens', () => {
  it('is a button only with names in the data and at least one new', () => {
    expect(listOpens(2, [item(), item({ id: 'CVE-2026-2' })])).toBe(true);
    // None new: the plain dim label, as before.
    expect(listOpens(0, [])).toBe(false);
    expect(listOpens(0, [item()])).toBe(false);
    // Older data without the list: a plain label even when the chart counts some.
    expect(listOpens(3, null)).toBe(false);
    expect(listOpens(3, [])).toBe(false);
  });
});

describe('signalLine', () => {
  it('names the signal and the day it came, in the site date style', () => {
    expect(signalLine(item(), 2026)).toBe('CISA KEV, Nov 18');
    expect(signalLine(item({ via: 'Vendor', at: '2026-11-19T01:29:12.970Z' }), 2026)).toBe('Vendor flag, Nov 19');
    expect(signalLine(item({ via: 'CISA SSVC', at: '2026-11-17T23:59:00.000Z' }), 2026)).toBe('CISA SSVC, Nov 17');
    expect(signalLine(item({ via: 'EU KEV', at: '2025-12-31' }), 2026)).toBe('EU KEV, Dec 31, 2025');
    // A signal this build does not know is shown as written; none at all leaves the date.
    expect(signalLine(item({ via: 'Other' as NewExploitedCve['via'] }), 2026)).toBe('Other, Nov 18');
    expect(signalLine(item({ via: '' as NewExploitedCve['via'] }), 2026)).toBe('Nov 18');
  });
});

describe('capNote', () => {
  it('says so only when the list is capped', () => {
    expect(capNote(3, 3)).toBeNull();
    expect(capNote(61, 50)).toBe('Newest 50 of 61.');
    expect(capNote(1200, 50)).toBe('Newest 50 of 1,200.');
  });
});

describe('popoverLeft', () => {
  it('lines up with the anchor right edge when it fits', () => {
    expect(popoverLeft({ left: 900, right: 1000 }, 320, 1440)).toBe(-220);
  });

  it('stays 16px inside a phone screen on both sides', () => {
    // The legend item near the left of a 390px screen: pushed right to the gutter.
    expect(popoverLeft({ left: 120, right: 200 }, 320, 390)).toBe(16 - 120);
    // Near the right edge: pulled back left.
    expect(popoverLeft({ left: 300, right: 400 }, 320, 390)).toBe(390 - 16 - 320 - 300);
    // As wide as the screen allows (max-width 100vw - 32px).
    expect(popoverLeft({ left: 50, right: 150 }, 358, 390)).toBe(16 - 50);
  });
});
