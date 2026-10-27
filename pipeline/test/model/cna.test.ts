import { describe, expect, it } from 'vitest';
import { cnaName, isBulkCna } from '../../../shared/cna';

describe('cnaName', () => {
  it.each([
    ['microsoft', 'Microsoft'],
    ['oracle', 'Oracle'],
    ['Chrome', 'Google Chrome'],
    ['Linux', 'Linux kernel'],
    ['GitHub_M', 'GitHub'],
    ['redhat', 'Red Hat'],
    ['ibm', 'IBM'],
    ['hpe', 'HPE'],
    ['qnap', 'QNAP'],
    ['mitre', 'MITRE'],
    ['jetbrains', 'JetBrains'],
    ['JetBrains', 'JetBrains'],
    ['nvidia', 'NVIDIA'],
    ['VulnCheck', 'VulnCheck'],
    ['WPScan', 'WPScan'],
    ['curl', 'curl'],
  ])('%s → %s', (cna, name) => {
    expect(cnaName(cna)).toBe(name);
  });

  it('falls back to title-casing lower-case words and keeps other spellings', () => {
    expect(cnaName('someone')).toBe('Someone');
    expect(cnaName('acme_corp')).toBe('Acme Corp');
    expect(cnaName('TR-CERT')).toBe('TR-CERT');
    expect(cnaName('Hitachi Energy')).toBe('Hitachi Energy');
    expect(cnaName('')).toBe('');
  });
});

describe('isBulkCna', () => {
  it('flags aggregator CNAs, case-insensitively', () => {
    for (const cna of ['VulnCheck', 'VulDB', 'Patchstack', 'Wordfence', 'WPScan', 'GitHub_M', 'mitre', 'vulncheck']) expect(isBulkCna(cna)).toBe(true);
    for (const cna of ['microsoft', 'Linux', 'Chrome', 'GitHub_P', 'oracle']) expect(isBulkCna(cna)).toBe(false);
  });
});
