# Security policy

CVErdict handles attacker-controlled text from thousands of sources every hour, so we take
reports about the project itself seriously.

## Reporting a vulnerability

Please report privately through GitHub's
[private vulnerability reporting](https://github.com/markusweldon/cverdict/security/advisories/new)
(Security tab → **Report a vulnerability**). Do not open a public issue, pull request or discussion.

Include what you found, where (URL, file or workflow), how to reproduce it, and the impact you
expect. A proof of concept is welcome; please keep it minimal and harmless.

This is a volunteer project, but we aim to acknowledge reports within **3 working days** and to
agree on a fix and disclosure date within **14 days**. We credit reporters in the advisory unless
you ask us not to.

## Supported versions

Only the latest commit on `main`, the published `data` branch and the official deployments built
from them. Forks and self-hosted copies are maintained by their owners.

## Scope

In scope:

- **The site**: cross-site scripting or HTML injection (for example a CVE record whose text
  renders as markup), Content Security Policy bypasses, unsafe links, open redirects, anything that
  runs script or exfiltrates data from a visitor's browser, `localStorage` or clipboard.
- **The pipeline and data**: input that crashes a run, corrupts or truncates published files,
  escapes the output directory, injects markup into the Atom or iCalendar feeds, or makes the
  pipeline execute code; ways for one upstream source to forge evidence attributed to another.
- **Automation and supply chain**: GitHub Actions workflows (token permissions, script or
  workflow-command injection from upstream data, cache poisoning), the data-branch publisher, and
  dependencies we ship.
- **Hosting configuration**: headers and rewrites in `vercel.json` and the Pages deployment.

Out of scope:

- **Vulnerabilities in the CVEs we list.** Report those to the vendor or the CNA, or the CVE Program
  for problems with a record.
- **Disagreement with a score or tier.** That is a methodology question: use the
  ["Disagree with a score"](https://github.com/markusweldon/cverdict/issues/new?template=disagree-with-a-score.yml)
  issue template.
- **Malicious proof-of-concept repositories** that we link to. They are third-party and labelled
  unverified; report them to GitHub. If our vetting can be trivially gamed to promote one, that is
  in scope.
- Findings in GitHub, Vercel or raw.githubusercontent.com themselves, volumetric denial of service,
  missing headers without a demonstrated impact, and reports from automated scanners alone.

## Untrusted input

Treat everything the pipeline ingests as hostile. CVE titles, descriptions, credits and references
are written by many different CNAs, and real records contain `<script>` and `onerror` payloads.
The project's rules:

- CVE text is rendered as plain text only: no `innerHTML`, no `dangerouslySetInnerHTML`, never
  `supportingMedia`. A strict Content Security Policy is the second line of defence.
- Only `http(s)` URLs are linked, always with `rel="noopener noreferrer nofollow"`.
- Text is sanitised (control characters stripped, length capped) before it is stored, and escaped
  for XML and iCalendar output.
- Upstream data never reaches a shell, `eval` or a workflow command unescaped.

If you find a record that breaks any of these, it is a valid report.

## Safe harbour

We will not pursue or support legal action against good-faith research that follows this policy,
avoids privacy violations and service disruption, and gives us reasonable time to fix the issue
before disclosure. The site is static: please do not load-test it.
