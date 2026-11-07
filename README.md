# Data branch

Machine-generated data for [markusweldon/cverdict](https://github.com/markusweldon/cverdict). The `refresh-data` workflow
rebuilds it every hour and force-pushes it as a single commit without history: do not commit
here, and do not pin old commits — they are garbage-collected.

## JSON API (schema v1)

Base URL: `https://raw.githubusercontent.com/markusweldon/cverdict/data/`

| Path | Contents |
|---|---|
| `v1/meta.json` | Run metadata: 30-day window, headline counts with definitions, score model, source health |
| `v1/signal.json` | Rows worth a look (score >= 35 or exploited/weaponized; published in the last 30 days); columnar |
| `v1/index.json` | Every CVE published in the last 30 days; columnar |
| `v1/cve/<xx>.json` | Full per-CVE detail with every reason chip; `<xx>` is the FNV-1a shard of the CVE ID |
| `v1/batches.json` | Patch-day batches: 50+ CVEs from one CNA on one day |
| `v1/kev.json` | Recent CISA KEV additions and upcoming due dates |
| `v1/stats.json` | Monthly history since 1999, daily and hourly counts, top CNAs, AI credits |
| `v1/changes.json` | Escalations (tier went up, or new exploit evidence) in the last 7 days |
| `v1/woke.json` | Old CVEs (published before the window) that gained exploitation evidence in the last 30 days |
| `v1/receipts.json` | Receipts: how often CVErdict flagged a CVE before CISA listed it in KEV (forward log and hindsight backtest) |
| `v1/packages.json` | Package versions the CVEs with a detail shard affect, from OSV.dev advisories, with each CVE's row (for the site's Check Deps page) |
| `v1/state.json` | Internal state carried between runs; unstable, do not build on it |
| `feeds/signal.xml` | Atom: newest Exploited and Likely-next CVEs |
| `feeds/kev.xml` | Atom: KEV additions |
| `feeds/kev-due.ics` | iCalendar: KEV remediation due dates |
| `feeds/woke.xml` | Atom: old CVEs that woke up |

Every JSON file carries `schema_version` and `generated_at`. Fields, sharding and the
versioning policy are documented in
[docs/DATA.md](https://github.com/markusweldon/cverdict/blob/HEAD/docs/DATA.md).
AI agents can read the same files through the read-only MCP server, `npx -y cverdict-mcp`:
[docs/DATA.md#mcp-server](https://github.com/markusweldon/cverdict/blob/HEAD/docs/DATA.md#mcp-server).

```sh
curl -s https://raw.githubusercontent.com/markusweldon/cverdict/data/v1/meta.json | jq .counts
```

## License and attribution

Scores, tiers and reason chips are dedicated to the public domain (CC0-1.0). Upstream data in
these files stays under its own terms:

- **CVE List** (IDs, dates, titles, descriptions, affected products, CVSS, CWE, references): the
  [CVE Program Terms of Use](https://www.cve.org/Legal/TermsOfUse), whose notice follows.
- **CISA KEV and Vulnrichment** (KEV entries, SSVC): CC0-1.0. Use of the information does not
  authorize you to use the CISA Logo or DHS Seal, nor should such use be interpreted as an
  endorsement by CISA or DHS.
- **EPSS**: by the [FIRST EPSS SIG](https://www.first.org/epss), free to use with attribution.
- **Exploit feeds**: identifiers and links only, no exploit code. Metasploit Framework
  (BSD-3-Clause, © Rapid7, Inc.), Nuclei templates (MIT, © ProjectDiscovery, Inc.), Exploit-DB
  (GPL-2.0), PoC-in-GitHub (CC0-1.0).
- **Package advisories** in `v1/packages.json`, through [OSV.dev](https://osv.dev): GitHub Advisory
  Database (CC-BY-4.0), PyPI Advisory Database (CC-BY-4.0), Go Vulnerability Database (CC-BY-4.0),
  RustSec Advisory Database (CC0-1.0) and Drupal security advisories (MIT, Copyright (c) 2025
  Ackama; the full notice is in the file's `attribution` and in ATTRIBUTIONS.md). Only advisory
  IDs, package names and version ranges are kept, for the CVEs this data covers.

Full notices and license texts:
[ATTRIBUTIONS.md](https://github.com/markusweldon/cverdict/blob/HEAD/ATTRIBUTIONS.md).

> Copyright © 1999-2026, The MITRE Corporation. CVE is a trademark and the CVE logo is a
> registered trademark of The MITRE Corporation.
>
> **CVE Usage:** MITRE hereby grants you a perpetual, worldwide, non-exclusive, no-charge,
> royalty-free, irrevocable copyright license to reproduce, prepare derivative works of, publicly
> display, publicly perform, sublicense, and distribute Common Vulnerabilities and Exposures
> (CVE™). Any copy you make for such purposes is authorized provided that you reproduce MITRE's
> copyright designation and this license in any such copy.

### Drupal security advisories (OSV) (MIT, Copyright (c) 2025 Ackama)

```text
The MIT License (MIT)

Copyright (c) 2025 Ackama

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```
