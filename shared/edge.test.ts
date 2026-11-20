import { describe, expect, it } from 'vitest';
import { EDGE_ENTRIES, cpeVendorProduct, edgeDevice, edgeEntryFor, normName } from './edge';

const nameOf = (vendor: string, product: string) => edgeEntryFor(vendor, product)?.name ?? null;

// Real vendor and product spellings from CVE List affected[] entries (CNA records).
const EDGE: readonly [string, string, string][] = [
  // VPN and remote access
  ['Ivanti', 'Connect Secure', 'Ivanti Connect Secure'],
  ['Ivanti', 'ICS', 'Ivanti Connect Secure'],
  ['', 'Pulse Connect Secure', 'Ivanti Connect Secure'],
  ['Ivanti', 'Policy Secure', 'Ivanti Policy Secure'],
  ['Ivanti', 'Neurons for ZTA gateways', 'Ivanti ZTA Gateway'],
  ['Ivanti', 'CSA (Cloud Services Appliance)', 'Ivanti Cloud Services Appliance'],
  ['Ivanti', 'MobileIron Sentry', 'Ivanti Sentry'],
  ['Ivanti', 'Endpoint Manager Mobile', 'Ivanti EPMM'],
  ['Palo Alto Networks', 'PAN-OS', 'Palo Alto PAN-OS'],
  ['', 'Palo Alto Networks GlobalProtect Portal/Gateway Interface', 'Palo Alto PAN-OS'],
  ['SonicWall', 'SMA100', 'SonicWall SMA'],
  ['SonicWall', 'SMA1000', 'SonicWall SMA'],
  ['SonicWall', 'SonicWall SRA/SMA100', 'SonicWall SMA'],
  ['Array Networks', 'ArrayOS AG', 'Array Networks AG'],
  ['Cisco', 'Cisco Expressway Series', 'Cisco Expressway'],
  // Firewalls and UTM
  ['Fortinet', 'FortiOS', 'Fortinet FortiOS'],
  ['Fortinet', 'FortiOS-6K7K', 'Fortinet FortiOS'],
  ['Fortinet', 'Fortinet FortiOS, FortiProxy', 'Fortinet FortiOS'],
  ['Fortinet', 'FortiGate', 'Fortinet FortiOS'],
  ['Fortinet', 'FortiProxy', 'Fortinet FortiProxy'],
  ['Fortinet', 'FortiWeb', 'Fortinet FortiWeb'],
  ['Fortinet', 'FortiManager', 'Fortinet FortiManager'],
  ['Cisco', 'Cisco Adaptive Security Appliance (ASA) Software', 'Cisco ASA and FTD'],
  ['Cisco', 'Cisco Secure Firewall Threat Defense (FTD) Software', 'Cisco ASA and FTD'],
  ['Cisco', 'Cisco Firepower Threat Defense Software', 'Cisco ASA and FTD'],
  ['SonicWall', 'SonicOS', 'SonicWall SonicOS'],
  ['checkpoint', 'Quantum Security Gateway', 'Check Point Security Gateway'],
  ['Check Point Software Technologies Ltd.', 'Check Point Quantum Gateway, Spark Gateway and CloudGuard Network', 'Check Point Security Gateway'],
  ['Juniper Networks', 'Junos OS', 'Juniper Junos OS'],
  ['Zyxel', 'USG FLEX 100(W) firmware', 'Zyxel firewalls'],
  ['Zyxel', 'ATP series firmware', 'Zyxel firewalls'],
  ['Zyxel', 'USG20(W)-VPN firmware', 'Zyxel firewalls'],
  ['Zyxel', 'ZyWALL/USG series firmware', 'Zyxel firewalls'],
  ['Zyxel', 'VPN series firmware', 'Zyxel firewalls'],
  ['Sophos', 'Sophos Firewall', 'Sophos Firewall'],
  ['Sophos', 'SG UTM', 'Sophos Firewall'],
  ['WatchGuard', 'Fireware OS', 'WatchGuard Firebox'],
  // Load balancers and ADCs
  ['Citrix', 'NetScaler ADC', 'Citrix NetScaler ADC and Gateway'],
  ['Citrix', 'NetScaler Gateway', 'Citrix NetScaler ADC and Gateway'],
  ['NetScaler', 'ADC', 'Citrix NetScaler ADC and Gateway'],
  ['Citrix NetScaler', 'Gateway', 'Citrix NetScaler ADC and Gateway'],
  ['Cloud Software Group', 'NetScaler ADC', 'Citrix NetScaler ADC and Gateway'],
  ['', 'Citrix ADC, Citrix Gateway, Citrix SDWAN WAN-OP', 'Citrix NetScaler ADC and Gateway'],
  ['F5', 'BIG-IP', 'F5 BIG-IP'],
  ['Fortinet', 'FortiADC', 'Fortinet FortiADC'],
  ['Progress Software', 'LoadMaster', 'Progress Kemp LoadMaster'],
  ['Ivanti', 'vTM', 'Ivanti Virtual Traffic Manager'],
  // Email and web gateways
  ['Barracuda Networks', 'Barracuda Email Security Gateway (ESG)', 'Barracuda Email Security Gateway'],
  ['Cisco', 'Cisco Secure Email', 'Cisco Secure Email'],
  ['Fortinet', 'FortiMail', 'Fortinet FortiMail'],
  ['Sophos', 'Sophos Web Appliance', 'Sophos Web Appliance'],
  // File transfer
  ['Progress Software Corporation', 'MOVEit Transfer', 'Progress MOVEit Transfer'],
  ['Progress Software', 'WS_FTP Server', 'Progress WS_FTP Server'],
  ['Fortra', 'GoAnywhere MFT', 'Fortra GoAnywhere MFT'],
  ['Cleo', 'Harmony', 'Cleo Harmony, VLTrader and LexiCom'],
  ['CrushFTP', 'CrushFTP', 'CrushFTP'],
  ['Wing FTP Software', 'Wing FTP Server', 'Wing FTP Server'],
  ['SolarWinds', 'Serv-U', 'SolarWinds Serv-U'],
  ['IBM', 'Aspera Faspex', 'IBM Aspera Faspex'],
  ['Gladinet', 'CentreStack and TrioFox', 'Gladinet CentreStack and Triofox'],
  ['Citrix', 'Citrix ShareFile Storage Zones Controller', 'Citrix ShareFile Storage Zones Controller'],
  // Webmail
  ['Zimbra', 'Zimbra Collaboration Suite', 'Zimbra Collaboration'],
  ['Synacor', 'Zimbra Collaboration', 'Zimbra Collaboration'],
  ['Microsoft', 'Microsoft Exchange Server 2019 Cumulative Update 14', 'Microsoft Exchange Server'],
  ['Microsoft', 'Microsoft Exchange Server Subscription Edition RTM', 'Microsoft Exchange Server'],
  ['Roundcube', 'Webmail', 'Roundcube Webmail'],
  ['SmarterTools', 'SmarterMail', 'SmarterTools SmarterMail'],
  // Remote support
  ['BeyondTrust', 'Remote Support(RS) & Privileged Remote Access(PRA)', 'BeyondTrust Remote Support and PRA'],
  ['ConnectWise', 'ScreenConnect', 'ConnectWise ScreenConnect'],
  ['SimpleHelp', 'SimpleHelp', 'SimpleHelp'],
  // SD-WAN
  ['Cisco', 'Cisco Catalyst SD-WAN Manager', 'Cisco Catalyst SD-WAN'],
  ['Arista Networks', 'VeloCloud Orchestrator', 'Arista VeloCloud'],
  ['VMware', 'NSX SD-WAN by VeloCloud', 'Arista VeloCloud'],
  ['Versa', 'Director', 'Versa Director and Concerto'],
  // Edge routers
  ['Cisco', 'Cisco IOS XE Software', 'Cisco IOS XE and IOS XR'],
  ['', 'Cisco IOS, IOS XE, and IOS XR', 'Cisco IOS XE and IOS XR'],
  ['Cisco', 'Cisco Small Business RV Series Router Firmware', 'Cisco RV series routers'],
  ['', 'Cisco RV132W and RV134W', 'Cisco RV series routers'],
  ['MikroTik', 'RouterOS', 'MikroTik RouterOS'],
  // CISA KEV spellings
  ['Zyxel', 'Multiple Firewalls', 'Zyxel firewalls'],
  ['Citrix', 'NetScaler', 'Citrix NetScaler ADC and Gateway'],
  ['Cisco', 'IOS, XR, and XE Software', 'Cisco IOS XE and IOS XR'],
  ['Cisco', 'VPN Routers', 'Cisco RV series routers'],
  ['DrayTek', 'Vigor2960', 'DrayTek Vigor'],
];

// Same vendor or a similar name, but endpoint software, management consoles or something else.
const NOT_EDGE: readonly [string, string][] = [
  ['Fortinet', 'FortiClientWindows'],
  ['Fortinet', 'FortiClientEMS'],
  ['Fortinet', 'FortiAnalyzer'],
  ['Fortinet', 'FortiSandbox'],
  ['Fortinet', 'FortiAuthenticator'],
  ['Cisco', 'Cisco Webex Meetings'],
  ['Cisco', 'Cisco AnyConnect Secure Mobility Client'],
  ['Cisco', 'Cisco Secure Client'],
  ['Cisco', 'Cisco Identity Services Engine Software'],
  ['Cisco', 'Cisco Secure Firewall Management Center (FMC)'],
  ['Cisco', 'IOS'],
  ['Cisco', 'Cisco NX-OS Software'],
  ['Palo Alto Networks', 'GlobalProtect App'],
  ['Palo Alto Networks', 'Expedition'],
  ['Palo Alto Networks', 'Cortex XDR Agent'],
  ['Ivanti', 'Endpoint Manager'],
  ['Ivanti', 'EPM'],
  ['Ivanti', 'Secure Access Client'],
  ['F5', 'BIG-IP Edge Client'],
  ['F5', 'BIG-IQ'],
  ['F5', 'NGINX Plus'],
  ['SonicWall', 'NetExtender'],
  ['SonicWall', 'Global Management System (GMS)'],
  ['WatchGuard', 'Mobile VPN with SSL Client'],
  ['WatchGuard', 'Dimension'],
  ['Citrix', 'Citrix Workspace app'],
  ['Citrix', 'Citrix Session Recording'],
  ['NetScaler', 'Console'],
  ['Citrix', 'NetScaler Console'],
  ['checkpoint', 'Quantum Security Management'],
  ['Check Point Software Technologies Ltd.', 'WinRAR'],
  ['Check Point', 'Harmony Endpoint'],
  ['Microsoft', 'Microsoft Exchange Online'],
  ['Microsoft', 'Internet Key Exchange (IKE) Service Extensions'],
  ['Microsoft', 'Windows Server 2025'],
  ['Progress Software', 'Telerik Report Server'],
  ['Progress Software', 'WhatsUp Gold'],
  ['progressplanner', 'AAA Autoload Optimizer'],
  ['Zyxel', 'NAS326 firmware'],
  ['Zyxel', 'GS1900-24 firmware'],
  ['Zyxel', 'VMG4325-B10A firmware'],
  ['Juniper Networks', 'Session Smart Router'],
  ['Arraytics', 'WPCafe'],
  ['IBM', 'Aspera Connect'],
  ['ConnectWise', 'Automate'],
  ['Sophos', 'Intercept X for Windows'],
  ['Barracuda Networks', 'Barracuda WAF Control Center (WCC)'],
  ['Barracuda Networks', 'Barracuda Web Application Firewall (WAF)'],
  ['SonicWall', 'Email Security'],
  ['D-Link', 'DIR-859'],
  ['TP-Link', 'Archer AX21'],
  ['Acme', 'Widget'],
];

describe('edgeEntryFor', () => {
  it.each(EDGE)('%s | %s is %s', (vendor, product, name) => {
    expect(nameOf(vendor, product)).toBe(name);
  });

  it.each(NOT_EDGE)('%s | %s is not an edge device', (vendor, product) => {
    expect(nameOf(vendor, product)).toBeNull();
  });

  it('is case-insensitive', () => {
    expect(nameOf('FORTINET', 'fortios')).toBe('Fortinet FortiOS');
    expect(nameOf('palo alto networks', 'pan-os')).toBe('Palo Alto PAN-OS');
  });

  it('needs the vendor: a product name alone from another vendor does not match', () => {
    expect(nameOf('Acme', 'Connect Secure')).toBeNull();
    expect(nameOf('Acme', 'FortiOS')).toBeNull();
    expect(nameOf('Example Corp', 'Exchange Server')).toBeNull();
  });

  it('has at least one tested spelling for every entry', () => {
    const tested = new Set(EDGE.map(([, , name]) => name));
    expect(EDGE_ENTRIES.map((e) => e.name).filter((n) => !tested.has(n))).toEqual([]);
  });
});

describe('edgeDevice', () => {
  const affected = [{ vendor: 'Fortinet', product: 'FortiOS' }];

  it('needs attack vector Network when CVSS is present', () => {
    expect(edgeDevice({ affected, attackVector: 'N' })).toEqual({ name: 'Fortinet FortiOS', kind: 'firewall, SSL VPN' });
    expect(edgeDevice({ affected, attackVector: 'A' })).toBeNull();
    expect(edgeDevice({ affected, attackVector: 'L' })).toBeNull();
    expect(edgeDevice({ affected, attackVector: null })).not.toBeNull();
  });

  it('checks every affected entry and CPE name', () => {
    const mixed = [
      { vendor: 'Fortinet', product: 'FortiClientWindows' },
      { vendor: 'Fortinet', product: 'FortiProxy' },
    ];
    expect(edgeDevice({ affected: mixed, attackVector: 'N' })?.name).toBe('Fortinet FortiProxy');
    expect(edgeDevice({ affected: [], cpes: ['cpe:2.3:a:f5:big-ip_access_policy_manager:17.1.0:*:*:*:*:*:*:*'], attackVector: 'N' })?.name).toBe('F5 BIG-IP');
    expect(edgeDevice({ affected: [], cpes: ['cpe:2.3:a:fortinet:forticlient:7.0:*:*:*:*:*:*:*'], attackVector: 'N' })).toBeNull();
  });
});

describe('helpers', () => {
  it('normName folds case, accents and punctuation', () => {
    expect(normName('PAN-OS®')).toBe('pan os');
    expect(normName('  Zimbra Collaboration Suite (ZCS) ')).toBe('zimbra collaboration suite zcs');
    expect(normName('Dassault Systèmes')).toBe('dassault systemes');
  });

  it('cpeVendorProduct reads CPE 2.3 names only', () => {
    expect(cpeVendorProduct('cpe:2.3:o:paloaltonetworks:pan-os:11.1.0:*:*:*:*:*:*:*')).toEqual({ vendor: 'paloaltonetworks', product: 'pan-os' });
    expect(cpeVendorProduct('cpe:2.3:a:progress:moveit\\_transfer:*:*')).toEqual({ vendor: 'progress', product: 'moveit transfer' });
    expect(cpeVendorProduct('cpe:/a:fortinet:fortios:7.0')).toBeNull();
    expect(cpeVendorProduct('cpe:2.3:a:*:*:*')).toBeNull();
  });
});
