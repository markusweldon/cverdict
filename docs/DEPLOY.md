# Deploying CVErdict

CVErdict is a static site plus a JSON data branch. Two pieces run independently:

- **Data**: the `refresh-data` workflow (`.github/workflows/refresh.yml`) runs every hour at minute
  17, builds the data from public sources and force-pushes it to the `data` branch. In a fork or
  copy, the hourly schedule is off until you opt in (see [Configuration](#configuration)).
- **Site**: a Vite build of `site/`, hosted on Vercel or GitHub Pages, that reads the data.

No servers, databases, accounts or API keys are involved, and nothing needs secrets.

## Vercel (recommended)

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/markusweldon/cverdict)

1. Import the repository in Vercel (or use the button). There is nothing to configure:
   `vercel.json` sets the install command (`npm ci`), the build (`npm run build`), the output
   directory (`site/dist`) and the security headers.
2. Deploy.

The site itself contains no data. `vercel.json` rewrites `/data/*` and the feed files
`/feeds/*.xml` and `/feeds/*.ics` to the `data` branch on raw.githubusercontent.com, so every hourly
publish is live within minutes **without a redeploy**. `/feeds` itself is the site's Feeds page:
any path that is not a built file or one of those rewrites gets `index.html`. The rewrite target is
hard-coded:

```json
"destination": "https://raw.githubusercontent.com/markusweldon/cverdict/data/:path+"
```

A fresh deployment therefore serves this repository's data until you point both rewrites at your
own repository (see [Forking](#forking-and-renaming)). Until then, the copy of the repository that
the Deploy button creates needs no workflow runs of its own, which is why its hourly schedule stays
off unless you opt in.

Deploy from Git rather than uploading a local working copy with the Vercel CLI: Vite copies
`site/public/`, so a local `site/public/data/` from `npm run pipeline` would be baked into the build,
and Vercel serves files from the build before applying rewrites, so it would shadow the live data.

The data branch carries its own tiny `vercel.json` with `"git": { "deploymentEnabled": false }`, so
Vercel does not build a preview deployment of it every hour.

## GitHub Pages

1. Settings → Pages → Build and deployment → Source: **GitHub Actions**.
2. In a fork or copy, set the repository variable `REFRESH_SCHEDULE` to `on` so the workflow runs
   hourly (see [Configuration](#configuration)).
3. Actions → **refresh-data** → **Run workflow** (or wait for the next hour).

The workflow detects that Pages deploys from Actions (`build_type: workflow`) and adds a `pages` job
to every run: it builds the site with `BASE=/<repo>/` (or `/` for a user site or a custom domain),
copies the fresh data into `site/dist/data/` and the feeds into `site/dist/feeds/`, and deploys with
`actions/deploy-pages`. When Pages is off or builds from a branch, the job is skipped and only the
data branch is updated.

The site is then at `https://<owner>.github.io/<repo>/`.

Pages has no rewrites, so the job copies `index.html` into a folder per page (`kev/`, `batches/`,
`explore/`, `surge/`, `method/`, `feeds/`), which are served with status 200. CVE pages
(`/cve/<id>`) are served from a copy at `404.html`: they work in a browser, but with HTTP status 404,
so crawlers, link previews and uptime checks treat them as missing. For CVE links you want to share,
prefer Vercel.

## First run

A new repository has no `data` branch, and both hosting options need one.

1. Actions → enable workflows if GitHub asks (forks start with Actions disabled).
2. Settings → Code security → **Private vulnerability reporting** → Enable (or
   `gh api -X PUT repos/<owner>/<repo>/private-vulnerability-reporting`). It is off by default, and
   `SECURITY.md` and the issue templates send security reports there.
3. Anywhere but `markusweldon/cverdict`: set the `REFRESH_SCHEDULE` variable to `on` if you want
   hourly runs (see [Configuration](#configuration)).
4. Recommended: Settings → Rules → Rulesets → New branch ruleset for the default branch, with
   *Restrict deletions*, *Block force pushes* and *Require a pull request before merging* (add
   *Repository admin* to the bypass list if you push directly). The publish job's token can write
   to every branch; the ruleset keeps it off `main`.
5. Actions → **refresh-data** → **Run workflow**.

The first run clones the CVE List (a few minutes), creates the `data` branch and starts with an
empty "what changed" list. From then on it runs hourly (in a copy, once step 3 is done). The run
summary shows the published data's age and the health of every source.

## Forking and renaming

1. Edit [`shared/brand.ts`](../shared/brand.ts): name, slug, tagline and `repo` (`owner/name`).
   The site, the pipeline's User-Agent, feed metadata and links all read from it.
2. Edit the two rewrite destinations in [`vercel.json`](../vercel.json), which cannot import
   `brand.ts`, to `https://raw.githubusercontent.com/<owner>/<repo>/data/...`.
3. Documentation and templates use the placeholders `CVErdict` and `cverdict`; replace them
   (for example with `git grep -l CVErdict | xargs sed -i 's/CVErdict/YourName/g'`, and the
   same for `cverdict` and `markusweldon`). This also rewrites the repository check at the top of
   `refresh.yml`, so the hourly schedule runs once it names your repository, with or without
   `REFRESH_SCHEDULE`.
4. Run the workflow once (see [First run](#first-run)).

### Configuration

| Setting | Where | Default | Purpose |
|---|---|---|---|
| `SITE_URL` | Settings → Secrets and variables → Actions → **Variables** | the Pages URL when Pages is on, else `BRAND.siteUrl` from `shared/brand.ts` | Public site URL used for links inside the Atom and iCalendar feeds. Set it when you use Vercel with a custom domain |
| `REFRESH_SCHEDULE` | same | off | `on` makes the hourly schedule run in a fork or copy. Scheduled runs only do work in `markusweldon/cverdict` (the check at the top of `refresh.yml`) or when this is `on`, so copies that only host the site, like the one the Vercel button creates, spend no Actions minutes. **Run workflow** works regardless |

There are no secrets to set. The workflow only uses the built-in `GITHUB_TOKEN`:

- `build` installs npm dependencies and runs the pipeline, so it gets a read-only token. It reads
  the `data` branch anonymously, so the repository must be public, as raw.githubusercontent.com
  requires anyway.
- `publish` is the only job with `contents: write`, to push the data branch. It runs no npm code,
  only `scripts/publish-data-branch.sh` from a fresh checkout, and gets the build output as an
  artifact.
- `pages` gets `pages: write` + `id-token: write`.

## Troubleshooting

**The site says the data is hours old.** The site shows the age of `meta.generated_at` in the
ticker, and the method page shows each source's status. Open Actions → refresh-data:

- A red run means the pipeline failed (the CVE List could not be read, or the output failed
  validation) and the previous data stayed up. The failing step has the log.
- The **Freshness watchdog** job checks what is actually published after every run. It fails the
  run when the data is more than 3 hours old, when a source is down, or when a source has served
  its cached copy for more than 48 hours, and it warns on shorter outages. GitHub emails the
  failure to whoever last changed the workflow's schedule.
- Individual sources falling back to their cache (CISA or FIRST briefly unreachable, GitLab
  rate-limiting Exploit-DB) is normal and does not stop a run; the source shows as *stale*.

**No runs at all for days.** GitHub disables scheduled workflows in a **public repository with no
activity for 60 days**, and sends a warning email beforehand. The hourly bot push to the data branch
may not count as activity. Re-enable the workflow under Actions → refresh-data → *Enable workflow*;
any commit to the default branch also resets the timer. Forks never run scheduled workflows until
you enable Actions on them. In a fork or copy, a scheduled run whose jobs all show as *skipped*
means `REFRESH_SCHEDULE` is not set to `on`.

**Vercel shows a 404 or old data under `/data/`.** Check that the rewrite destinations in
`vercel.json` name a repository whose `data` branch exists and is public (raw.githubusercontent.com
cannot read private repositories), and remember that raw.githubusercontent.com caches files for up
to 5 minutes.

**Pages shows a blank page or 404s for assets.** The site must be built with the base path Pages
serves it from. The workflow reads it from the Pages settings; if you build by hand, use
`BASE=/<repo>/ npm run build`.

**The Pages job is skipped.** It only runs when Settings → Pages → Source is *GitHub Actions*. The
"Detect GitHub Pages" step in the build job logs what it found.

**Repository size.** The data branch is one commit without history; each hourly push makes the
previous one unreachable, and GitHub garbage-collects it. A plain `git clone` still downloads that
one commit (tens of MB); `git clone --single-branch` skips it.

## Costs

Free. The hourly run takes about 5 minutes of GitHub Actions time, which is free and unlimited for
public repositories; old source-cache entries are evicted automatically to stay within the free
10 GB. Private repositories have a monthly minutes quota that an hourly run would use up, one
reason why copies have to opt in to the schedule. GitHub Pages is free for public repositories.
Vercel's Hobby plan covers a static site of this size for personal, non-commercial use; for
anything else, check Vercel's plans or use GitHub Pages.
