import { describe, expect, it } from 'vitest';
import type { EventItem, EventType, Tier } from '../../shared/contract';
import { HEAT_DAYS, heatingUp } from './heat';

const NOW = '2026-11-26T18:00:00Z';
const hoursAgo = (h: number) => new Date(Date.parse(NOW) - h * 3_600_000).toISOString();
const ev = (cve: string, type: EventType, h: number, tier: Tier = 'exploited', score = 90): EventItem => ({
  id: `${type}:${cve}:${h}`,
  at: hoursAgo(h),
  type,
  cve,
  vendor: `Vendor ${cve}`,
  product: 'Product',
  tier_before: 'likely',
  tier_after: tier,
  score,
  title: '',
  via: 'kev',
  url: '',
  detail: '',
  backfill: false,
});
const file = (items: EventItem[]) => ({ generated_at: NOW, items });

describe('heatingUp', () => {
  it('ranks by evidence, newer evidence weighing more', () => {
    const cards = heatingUp(
      file([
        ev('CVE-A', 'nuclei_template', 2),
        ev('CVE-B', 'kev_added', 1),
        ev('CVE-B', 'metasploit_module', 5),
        ev('CVE-C', 'kev_added', 6 * 24), // same evidence as B's KEV listing, but six days old
        ev('CVE-D', 'catalog_listed', 3),
      ]),
    );
    expect(cards.map((c) => c.cve)).toEqual(['CVE-B', 'CVE-D', 'CVE-A', 'CVE-C']);
    expect(cards[0].what).toEqual(['kev_added', 'metasploit_module']);
    expect(cards[0].latest).toBe(hoursAgo(1));
  });

  it('keeps only Exploited and Likely next, by the newest event', () => {
    const cards = heatingUp(file([ev('CVE-A', 'nuclei_template', 1, 'watch'), ev('CVE-B', 'tier_up', 9, 'watch'), ev('CVE-B', 'nuclei_template', 2, 'likely', 61)]));
    expect(cards.map((c) => [c.cve, c.tier, c.score])).toEqual([['CVE-B', 'likely', 61]]);
  });

  it('gives the fast lane no points, and leaves out a CVE with nothing else', () => {
    const cards = heatingUp(file([ev('CVE-A', 'fast_lane', 1, 'likely'), ev('CVE-B', 'fast_lane', 1, 'likely'), ev('CVE-B', 'tier_up', 1, 'likely')]));
    expect(cards.map((c) => c.cve)).toEqual(['CVE-B']);
    expect(cards[0].what).toEqual(['tier_up']);
  });

  it('looks back HEAT_DAYS days, caps the list, and breaks ties by the newest then the ID', () => {
    const old = ev('CVE-OLD', 'kev_added', HEAT_DAYS * 24 + 1);
    const same = [ev('CVE-2', 'kev_added', 4), ev('CVE-1', 'kev_added', 4), ev('CVE-3', 'kev_added', 4), ev('CVE-4', 'kev_added', 4), ev('CVE-5', 'kev_added', 4)];
    expect(heatingUp(file([old, ...same])).map((c) => c.cve)).toEqual(['CVE-1', 'CVE-2', 'CVE-3', 'CVE-4']);
    expect(heatingUp(file([old]))).toEqual([]);
  });

  it('puts CVEs of one vendor on the hottest one\'s card', () => {
    const a = { ...ev('CVE-A1', 'kev_added', 1), vendor: 'Danfoss', product: 'AK-SM800A' };
    const b = { ...ev('CVE-A2', 'kev_added', 2), vendor: 'danfoss ', product: 'AK-SM 8xxA Series' };
    const c = { ...ev('CVE-B', 'nuclei_template', 1), vendor: 'OpenBSD', product: 'OpenSSH' };
    const cards = heatingUp(file([b, a, c]));
    expect(cards.map((x) => [x.cve, x.more])).toEqual([
      ['CVE-A1', ['CVE-A2']],
      ['CVE-B', []],
    ]);
  });

  it('lays the evidence out by day for the strip, merged vendor CVEs included, the fast lane left out', () => {
    const items = [ev('CVE-A', 'kev_added', 2), ev('CVE-A', 'nuclei_template', 3 * 24 + 1), ev('CVE-A', 'fast_lane', 4), ev('CVE-B', 'metasploit_module', 6 * 24 + 2)];
    items[3].vendor = items[0].vendor;
    const [card] = heatingUp(file(items));
    expect(card.more).toEqual(['CVE-B']);
    expect(card.timeline).toEqual([
      { day: 0, type: 'metasploit_module' },
      { day: HEAT_DAYS - 1 - 3, type: 'nuclei_template' },
      { day: HEAT_DAYS - 1, type: 'kev_added' },
    ]);
  });

  it('copes with no file and a bad generated_at', () => {
    expect(heatingUp(null)).toEqual([]);
    expect(heatingUp({ generated_at: 'nope', items: [ev('CVE-A', 'kev_added', 1)] })).toEqual([]);
  });
});
