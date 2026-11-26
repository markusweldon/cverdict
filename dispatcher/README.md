# cverdict

One command for the [CVErdict](https://cverdict.dev) tools:

```sh
npx -y cverdict check                  # your lockfiles and SBOMs: which dependencies have CVEs, most exploited first
npx -y cverdict check --help           # its options
claude mcp add cverdict -- npx -y cverdict mcp   # the read-only MCP server, for AI agents
npx -y cverdict --version
```

`cverdict` adds nothing of its own: `check` runs [`cverdict-check`](https://www.npmjs.com/package/cverdict-check)
and `mcp` runs [`cverdict-mcp`](https://www.npmjs.com/package/cverdict-mcp), in the same process, with the same
arguments, output and exit codes. You can install either tool on its own instead; the MCP Registry lists
`cverdict-mcp`.

- [Dependency check docs](https://github.com/markusweldon/cverdict/blob/main/cli/README.md), including the GitHub Action
- [MCP server docs](https://github.com/markusweldon/cverdict/blob/main/mcp/README.md)
- [Open data](https://github.com/markusweldon/cverdict/blob/main/docs/DATA.md)

## Versions

The tools are on 0.x, where a minor release can change behaviour, so this package pins each to its current
minor version (`^0.1.0` is 0.1.x only). A minor release of either tool comes with a release of `cverdict` that
moves the range; a test checks the ranges match the tools in the repository.

MIT licensed.
