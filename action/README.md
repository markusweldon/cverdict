# CVErdict check (GitHub Action)

```yaml
- uses: actions/checkout@v4
- uses: markusweldon/cverdict/action@check-v0.1.0
  with:
    fail-on: exploited
```

Checks the lockfiles and SBOMs in the checkout against the CVEs CVErdict tracks, and fails the step when a
dependency is affected by an Exploited one. Inputs, outputs, code scanning and scheduled runs:
[cli/README.md](../cli/README.md#in-github-actions).

`dist/index.mjs` is built from `cli/src` by `npm run build:cli`. Do not edit it by hand; CI checks it matches.
