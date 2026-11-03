# Attributions

CVErdict is built entirely from free, public data. This file lists every source, what we take
from it, what we republish, and the notices its terms require. None of these organisations
sponsor, endorse or are affiliated with CVErdict.

CVErdict does not use data from the NIST National Vulnerability Database (NVD).

Our own output (scores, tiers, reason chips, batches and statistics) is dedicated to the public
domain under [CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/). Upstream content inside
the data files, such as CVE descriptions and KEV entries, remains under the terms below.

## CVE List (CVE Program)

- **Source:** [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5), the official CVE
  Record downloads.
- **We use and republish:** CVE IDs, dates, CNA names, titles, English descriptions (cut to 1,000
  characters), affected vendors and products, CVSS vectors, CWE ids, tags, excerpts (up to 80
  characters) of credits that name AI tools, and up to 10 reference URLs per record. CVE records
  are written by the CNAs that publish them and are reproduced as published.
- **Terms:** [CVE Program Terms of Use](https://www.cve.org/Legal/TermsOfUse). As those terms
  require, MITRE's copyright designation and license are reproduced here:

> Copyright © 1999-2026, The MITRE Corporation. CVE is a trademark and the CVE logo is a
> registered trademark of The MITRE Corporation.
>
> **CVE Usage:** MITRE hereby grants you a perpetual, worldwide, non-exclusive, no-charge,
> royalty-free, irrevocable copyright license to reproduce, prepare derivative works of, publicly
> display, publicly perform, sublicense, and distribute Common Vulnerabilities and Exposures
> (CVE™). Any copy you make for such purposes is authorized provided that you reproduce MITRE's
> copyright designation and this license in any such copy.
>
> **Disclaimers:** ALL DOCUMENTS AND THE INFORMATION CONTAINED THEREIN PROVIDED BY MITRE ARE
> PROVIDED ON AN "AS IS" BASIS AND THE CONTRIBUTOR, THE ORGANIZATION HE/SHE REPRESENTS OR IS
> SPONSORED BY (IF ANY), THE MITRE CORPORATION, ITS BOARD OF TRUSTEES, OFFICERS, AGENTS, AND
> EMPLOYEES, DISCLAIM ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTY
> THAT THE USE OF THE INFORMATION THEREIN WILL NOT INFRINGE ANY RIGHTS OR ANY IMPLIED WARRANTIES OF
> MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.

## CISA Known Exploited Vulnerabilities (KEV)

- **Source:** the [KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  JSON feed, with the [cisagov/kev-data](https://github.com/cisagov/kev-data) mirror as fallback.
- **We use and republish:** KEV entries (vendor, product, name, dates added and due, description,
  required action, notes, known ransomware use, forensic-triage flag) and counts derived from them.
- **License:** [CC0 1.0](https://github.com/cisagov/kev-data/blob/main/LICENSE). In CISA's words:
  "Use of the information does not authorize you to use the CISA Logo or DHS Seal, nor should such
  use be interpreted as an endorsement by CISA or DHS." Information at third-party links inside
  KEV entries is bound by those sites' own policies.

## CISA Vulnrichment (CISA-ADP)

- **Source:** the CISA Authorized Data Publisher container inside each CVE record
  ([cisagov/vulnrichment](https://github.com/cisagov/vulnrichment)).
- **We use and republish:** SSVC decision points (exploitation, automatable, technical impact),
  CVSS scores where the CNA gave none, and the KEV block CISA adds to listed records.
- **License:** [CC0 1.0](https://github.com/cisagov/vulnrichment/blob/develop/LICENSE). The same
  CISA logo and endorsement notice applies.

## SSVC (CERT/CC)

The Stakeholder-Specific Vulnerability Categorization methodology was developed by the CERT
Coordination Center at Carnegie Mellon University's Software Engineering Institute
([CERTCC/SSVC](https://github.com/CERTCC/SSVC)). We use the decision-point values that CISA
publishes (above) and refer to the decision points by name; we do not copy or redistribute SSVC
documentation or software. For reference, the SSVC repository licenses its documentation under
CC BY-NC 4.0 and its software files under an MIT (SEI)-style license, © Carnegie Mellon
University. CERT Coordination Center® is registered in the U.S. Patent and Trademark Office by
Carnegie Mellon University.

## EPSS (FIRST)

- **Source:** daily EPSS scores from [epss.empiricalsecurity.com](https://epss.empiricalsecurity.com/)
  and the [empiricalsec/epss_scores](https://github.com/empiricalsec/epss_scores) archive.
- **We use and republish:** the EPSS probability, percentile, score date and model version per CVE.
- **Terms:** EPSS is developed by the [FIRST EPSS Special Interest Group](https://www.first.org/epss/)
  and is free to use with attribution. Citation: Jay Jacobs, Sasha Romanosky, et al., *Exploit
  Prediction Scoring System (EPSS)*, FIRST, <https://www.first.org/epss>.

## Metasploit Framework

- **Source:** [`db/modules_metadata_base.json`](https://github.com/rapid7/metasploit-framework/blob/master/db/modules_metadata_base.json)
  from [rapid7/metasploit-framework](https://github.com/rapid7/metasploit-framework).
- **We use and republish:** for modules that reference a CVE, the module name, full name, rank,
  type, disclosure date and a link to its source. No module code.
- **License:** BSD-3-Clause.

<details>
<summary>Metasploit Framework license notice</summary>

```text
Copyright: 2006-2026, Rapid7, Inc.
License: BSD-3-clause

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

    * Neither the name of Rapid7, Inc. nor the names of its contributors
    may be used to endorse or promote products derived from this software
    without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

</details>

Metasploit is a registered trademark of Rapid7, Inc.

## Nuclei templates

- **Source:** [`cves.json`](https://github.com/projectdiscovery/nuclei-templates/blob/main/cves.json)
  from [projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates).
- **We use and republish:** for templates that reference a CVE, the template path, severity and a
  link. No template content.
- **License:** MIT, Copyright (c) 2025 ProjectDiscovery, Inc.

<details>
<summary>MIT license text</summary>

```text
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

</details>

## Exploit-DB

- **Source:** [`files_exploits.csv`](https://gitlab.com/exploit-database/exploitdb/-/blob/main/files_exploits.csv)
  from [exploit-database/exploitdb](https://gitlab.com/exploit-database/exploitdb), maintained by OffSec.
- **We use and republish:** only the Exploit-DB ID, its verified flag, its publication date and a
  link to [exploit-db.com](https://www.exploit-db.com/) for entries that reference a CVE. We do not
  copy or redistribute exploit code or descriptions.
- **License:** the repository is licensed under
  [GPL-2.0](https://gitlab.com/exploit-database/exploitdb/-/blob/main/LICENSE.md).

## PoC-in-GitHub

- **Source:** [nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub).
- **We use and republish:** for each CVE, the number of listed proof-of-concept repositories and,
  for up to five, the repository URL, star count and creation date.
- **License:** [CC0 1.0](https://github.com/nomi-sec/PoC-in-GitHub/blob/master/LICENSE). The listed
  repositories are third-party code under their own licenses. They are unverified and may be
  malware; we link to them and never copy or run them.

## Fonts

[Geist and Geist Mono](https://github.com/vercel/geist-font), Copyright 2024 The Geist Project
Authors, are licensed under the [SIL Open Font License, Version 1.1](https://openfontlicense.org/).
They are bundled from the `@fontsource-variable/geist` and `@fontsource-variable/geist-mono`
packages, which include the full license text.

## MCP server libraries

The single-file MCP server (`mcp/dist/cverdict-mcp.mjs`, the `cverdict-mcp` package) bundles the
[MCP TypeScript SDK](https://github.com/modelcontextprotocol/typescript-sdk)
(`@modelcontextprotocol/server` and `@modelcontextprotocol/core`, Apache-2.0, with contributions
under MIT), [zod](https://github.com/colinhacks/zod) (MIT), and the libraries the SDK vendors in its
own build: ajv, ajv-formats, fast-deep-equal, json-schema-traverse and content-type (MIT) and
fast-uri (BSD-3-Clause). Their full license texts ship with the bundle in
[mcp/LICENSE-THIRD-PARTY](mcp/LICENSE-THIRD-PARTY). None of them is part of the site.

## Share images

The link-preview images in `site/public/og/` are rendered by hand with `tools/og/render.mjs`, using
[satori](https://github.com/vercel/satori) and [resvg-wasm](https://github.com/yisibl/resvg-js)
(both MPL-2.0) as build tools; neither ships with the site. The text in them is drawn as glyph
outlines from the static Geist files of `@fontsource/geist` (SIL Open Font License 1.1, as above).
