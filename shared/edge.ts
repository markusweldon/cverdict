/**
 * Internet-facing edge devices: a small, curated list of product families whose job is to accept
 * connections from the internet (VPN and remote access gateways, firewalls, load balancers, email
 * and web gateways, file transfer servers, webmail, SD-WAN controllers, edge routers).
 *
 * Attackers often exploit these within days, before any public exploit exists, so a CVE in one of
 * them does not get the early "no exploit yet" penalty (x.early). It keeps x.too_new (unknown, 0)
 * and shows the edge.device chip (0 points). Nothing else in the score changes.
 *
 * The list comes from the CISA KEV catalog: product families listed again and again from 2021 to
 * 2026 that face the internet by design. docs/SCORING.md#internet-facing-edge-devices explains
 * each choice, what is left out and why, and how to propose an addition.
 *
 * Matching is on the CVE record's affected vendor and product (and CPE names when present),
 * case-insensitive on normalized words. A CVSS vector that is not attack vector Network rules it
 * out. Endpoint software (clients, apps, agents) never matches.
 */

export interface EdgeEntry {
  /** Display name, e.g. "Fortinet FortiOS". */
  name: string;
  /** What kind of edge device, e.g. "firewall, SSL VPN". */
  kind: string;
  /** Normalized vendor names; the vendor matches when it is one of these or starts with one plus a word. */
  vendors: readonly string[];
  /** Normalized product phrases (whole words, a trailing "s" allowed) or patterns, tested on "vendor product". */
  products: readonly (string | RegExp)[];
}

export interface EdgeMatch {
  name: string;
  kind: string;
}

const VPN = 'VPN, remote access';
const FW = 'firewall';
const FW_VPN = 'firewall, SSL VPN';
const ADC = 'load balancer, gateway';
const MAIL = 'email gateway';
const WEB = 'web gateway';
const MFT = 'file transfer';
const WEBMAIL = 'webmail';
const REMOTE = 'remote support';
const SDWAN = 'SD-WAN';
const ROUTER = 'edge router';
const MDM = 'mobile device gateway';

export const EDGE_ENTRIES: readonly EdgeEntry[] = [
  // VPN and remote access gateways
  { name: 'Ivanti Connect Secure', kind: VPN, vendors: ['ivanti', 'pulse', 'pulsesecure'], products: ['connect secure', 'connect secre', 'ics'] },
  { name: 'Ivanti Policy Secure', kind: VPN, vendors: ['ivanti', 'pulse', 'pulsesecure'], products: ['policy secure', 'ips'] },
  { name: 'Ivanti ZTA Gateway', kind: VPN, vendors: ['ivanti'], products: ['zta gateway'] },
  { name: 'Ivanti Cloud Services Appliance', kind: VPN, vendors: ['ivanti'], products: ['cloud services appliance', 'cloud service appliance', 'cloud services application', 'csa'] },
  { name: 'Ivanti Sentry', kind: MDM, vendors: ['ivanti', 'mobileiron'], products: ['sentry'] },
  { name: 'Ivanti EPMM', kind: MDM, vendors: ['ivanti', 'mobileiron'], products: ['endpoint manager mobile', 'epmm', 'mobileiron core'] },
  { name: 'Palo Alto PAN-OS', kind: FW_VPN, vendors: ['palo alto', 'paloaltonetworks'], products: ['pan os', 'globalprotect portal', 'globalprotect gateway'] },
  { name: 'SonicWall SMA', kind: VPN, vendors: ['sonicwall'], products: [/\bsma ?\d/, 'sra', 'secure mobile access', 'secure remote access'] },
  { name: 'Array Networks AG', kind: VPN, vendors: ['array networks', 'arraynetworks'], products: ['arrayos', 'ag series', 'vxag'] },
  { name: 'Cisco Expressway', kind: VPN, vendors: ['cisco'], products: ['expressway'] },

  // Firewalls and UTM
  { name: 'Fortinet FortiOS', kind: FW_VPN, vendors: ['fortinet'], products: ['fortios', 'fortigate'] },
  { name: 'Fortinet FortiProxy', kind: WEB, vendors: ['fortinet'], products: ['fortiproxy'] },
  { name: 'Fortinet FortiWeb', kind: 'web application firewall', vendors: ['fortinet'], products: ['fortiweb'] },
  { name: 'Fortinet FortiManager', kind: 'firewall manager', vendors: ['fortinet'], products: ['fortimanager'] },
  { name: 'Cisco ASA and FTD', kind: FW_VPN, vendors: ['cisco'], products: ['adaptive security appliance', 'firepower threat defense', 'secure firewall threat defense', 'secure firewall asa', 'ftd software'] },
  { name: 'SonicWall SonicOS', kind: FW_VPN, vendors: ['sonicwall'], products: ['sonicos'] },
  { name: 'Check Point Security Gateway', kind: FW_VPN, vendors: ['check point', 'checkpoint'], products: ['security gateway', 'quantum gateway', 'spark gateway', 'spark firewall', 'cloudguard network', 'scalable platforms'] },
  { name: 'Juniper Junos OS', kind: FW, vendors: ['juniper'], products: ['junos os', 'j web', 'screenos', 'srx'] },
  { name: 'Zyxel firewalls', kind: FW_VPN, vendors: ['zyxel'], products: [/\busg/, 'zywall', 'atp', 'vpn series', 'firewall'] },
  { name: 'Sophos Firewall', kind: FW, vendors: ['sophos'], products: ['firewall', 'xg', 'sg utm', 'utm', 'cyberoamos', 'cyberoam'] },
  { name: 'WatchGuard Firebox', kind: FW_VPN, vendors: ['watchguard'], products: ['fireware', 'firebox', 'xtm'] },

  // Load balancers and application delivery controllers
  { name: 'Citrix NetScaler ADC and Gateway', kind: ADC, vendors: ['citrix', 'netscaler', 'cloud software group'], products: ['netscaler adc', 'netscaler gateway', 'citrix adc', 'citrix gateway', 'application delivery controller', /^(citrix )?netscaler$/] },
  { name: 'F5 BIG-IP', kind: ADC, vendors: ['f5'], products: ['big ip'] },
  { name: 'Fortinet FortiADC', kind: ADC, vendors: ['fortinet'], products: ['fortiadc'] },
  { name: 'Progress Kemp LoadMaster', kind: ADC, vendors: ['progress', 'kemp'], products: ['loadmaster'] },
  { name: 'Ivanti Virtual Traffic Manager', kind: ADC, vendors: ['ivanti'], products: ['virtual traffic manager', 'vtm'] },

  // Email and secure web gateways
  { name: 'Barracuda Email Security Gateway', kind: MAIL, vendors: ['barracuda'], products: ['email security gateway', 'esg'] },
  { name: 'Cisco Secure Email', kind: MAIL, vendors: ['cisco'], products: ['secure email', 'email security appliance', 'secure web appliance', 'web security appliance'] },
  { name: 'Fortinet FortiMail', kind: MAIL, vendors: ['fortinet'], products: ['fortimail'] },
  { name: 'Sophos Web Appliance', kind: WEB, vendors: ['sophos'], products: ['web appliance'] },

  // File transfer servers that face the internet
  { name: 'Progress MOVEit Transfer', kind: MFT, vendors: ['progress'], products: ['moveit transfer', 'moveit gateway'] },
  { name: 'Progress WS_FTP Server', kind: MFT, vendors: ['progress'], products: ['ws ftp server'] },
  { name: 'Fortra GoAnywhere MFT', kind: MFT, vendors: ['fortra', 'helpsystems'], products: ['goanywhere'] },
  { name: 'Cleo Harmony, VLTrader and LexiCom', kind: MFT, vendors: ['cleo'], products: ['harmony', 'vltrader', 'lexicom'] },
  { name: 'CrushFTP', kind: MFT, vendors: ['crushftp'], products: ['crushftp'] },
  { name: 'Wing FTP Server', kind: MFT, vendors: ['wing ftp', 'wing soft', 'wftpserver'], products: ['wing ftp server'] },
  { name: 'SolarWinds Serv-U', kind: MFT, vendors: ['solarwinds'], products: ['serv u'] },
  { name: 'IBM Aspera Faspex', kind: MFT, vendors: ['ibm'], products: ['aspera faspex'] },
  { name: 'Gladinet CentreStack and Triofox', kind: MFT, vendors: ['gladinet'], products: ['centrestack', 'triofox'] },
  { name: 'Citrix ShareFile Storage Zones Controller', kind: MFT, vendors: ['citrix'], products: ['sharefile storage zones'] },

  // Webmail: the mail server's web interface faces the internet by design
  { name: 'Zimbra Collaboration', kind: WEBMAIL, vendors: ['zimbra', 'synacor'], products: ['zimbra', 'collaboration'] },
  { name: 'Microsoft Exchange Server', kind: WEBMAIL, vendors: ['microsoft'], products: ['exchange server'] },
  { name: 'Roundcube Webmail', kind: WEBMAIL, vendors: ['roundcube'], products: ['webmail', 'roundcubemail', 'roundcube'] },
  { name: 'SmarterTools SmarterMail', kind: WEBMAIL, vendors: ['smartertools'], products: ['smartermail'] },

  // Remote support servers
  { name: 'BeyondTrust Remote Support and PRA', kind: REMOTE, vendors: ['beyondtrust', 'bomgar'], products: ['remote support', 'privileged remote access'] },
  { name: 'ConnectWise ScreenConnect', kind: REMOTE, vendors: ['connectwise'], products: ['screenconnect'] },
  { name: 'SimpleHelp', kind: REMOTE, vendors: ['simplehelp'], products: ['simplehelp'] },

  // SD-WAN controllers and edges
  { name: 'Cisco Catalyst SD-WAN', kind: SDWAN, vendors: ['cisco'], products: ['sd wan', 'vmanage', 'vedge', 'vsmart'] },
  { name: 'Arista VeloCloud', kind: SDWAN, vendors: ['arista', 'vmware', 'broadcom'], products: ['velocloud', 'sd wan edge', 'sd wan orchestrator'] },
  { name: 'Versa Director and Concerto', kind: SDWAN, vendors: ['versa'], products: ['director', 'concerto'] },

  // Edge routers: the management plane of routers that sit on the network edge
  { name: 'Cisco IOS XE and IOS XR', kind: ROUTER, vendors: ['cisco'], products: ['ios xe', 'ios xr', /^cisco (xe|xr)\b/] },
  { name: 'Cisco RV series routers', kind: ROUTER, vendors: ['cisco'], products: [/\brv ?\d{3}/, 'rv series', 'vpn router'] },
  { name: 'MikroTik RouterOS', kind: ROUTER, vendors: ['mikrotik'], products: ['routeros'] },
  { name: 'DrayTek Vigor', kind: ROUTER, vendors: ['draytek'], products: [/\bvigor/] },
];

/** Endpoint software that shares a name with an edge product ("BIG-IP Edge Client", "GlobalProtect App"). */
const ENDPOINT_RE = /\b(client|clients|app|apps|agent|agents)\b/;

/** Lower-case, accent-free words joined by single spaces: "PAN-OS®" → "pan os". */
export function normName(s: string): string {
  return s
    .normalize('NFKD')
    .replace(/\p{M}+/gu, '')
    .toLowerCase()
    .replace(/[^\p{L}\p{N}]+/gu, ' ')
    .trim();
}

const vendorIs = (vendor: string, names: readonly string[]) => names.some((n) => vendor === n || vendor.startsWith(`${n} `));

function phraseIn(hay: string, p: string | RegExp): boolean {
  if (typeof p !== 'string') return p.test(hay);
  return new RegExp(`(^| )${p}s?( |$)`).test(hay);
}

/**
 * The edge entry one affected vendor and product name, else null. A combined product name
 * ("FortiOS, FortiProxy", "IOS and IOS XE") is split and each part is tested on its own.
 */
export function edgeEntryFor(vendor: string, product: string): EdgeEntry | null {
  const v = normName(vendor);
  // A record without a vendor sometimes names it in the product ("Pulse Connect Secure").
  const gate = v || normName(product);
  if (!gate) return null;
  const parts = product.split(/,|;|&|\/|\band\b/i).map(normName).filter(Boolean);
  for (const e of EDGE_ENTRIES) {
    if (!vendorIs(gate, e.vendors)) continue;
    for (const part of parts) {
      const hay = v ? `${v} ${part}` : part;
      if (ENDPOINT_RE.test(part)) continue;
      if (e.products.some((p) => phraseIn(hay, p))) return e;
    }
  }
  return null;
}

/** "cpe:2.3:o:fortinet:fortios:7.4.1:…" → { vendor: "fortinet", product: "fortios" }; null if not a CPE 2.3 name. */
export function cpeVendorProduct(cpe: string): { vendor: string; product: string } | null {
  const m = /^cpe:2\.3:[aho]:([^:]+):([^:]+)/i.exec(cpe.trim());
  if (!m || m[1] === '*' || m[2] === '*' || m[1] === '-' || m[2] === '-') return null;
  const unescape = (s: string) => s.replace(/\\(.)/g, '$1').replace(/_/g, ' ');
  return { vendor: unescape(m[1]), product: unescape(m[2]) };
}

export interface EdgeInput {
  affected: readonly { vendor: string; product: string }[];
  /** CPE 2.3 names from the record's affected entries, when it has any. */
  cpes?: readonly string[];
  /** CVSS attack vector of the scored vector ("N", "A", "L", "P"), or null without CVSS. */
  attackVector: string | null;
}

/** The internet-facing edge device a CVE affects, or null. With CVSS, only attack vector Network counts. */
export function edgeDevice(input: EdgeInput): EdgeMatch | null {
  if (input.attackVector !== null && input.attackVector !== 'N') return null;
  const pairs = [...input.affected];
  for (const cpe of input.cpes ?? []) {
    const p = cpeVendorProduct(cpe);
    if (p) pairs.push(p);
  }
  for (const { vendor, product } of pairs) {
    const e = edgeEntryFor(vendor, product);
    if (e) return { name: e.name, kind: e.kind };
  }
  return null;
}
