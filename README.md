# OrphaNode

Find dead code in JavaScript and TypeScript projects, without the false positives.

OrphaNode builds a real reachability graph of your project. It follows imports,
exports, declarations, class members, dependencies, and workspace packages from
actual entry points. If it can't prove code is unused, it doesn't report it.
It tells you what it couldn't see instead.

[![crates.io](https://img.shields.io/crates/v/orphanode?logo=rust&label=crates.io)](https://crates.io/crates/orphanode)
[![npm](https://img.shields.io/npm/v/orphanode?logo=npm)](https://www.npmjs.com/package/orphanode)
[![CI](https://github.com/wthrajat/orphanode/actions/workflows/ci.yml/badge.svg)](https://github.com/wthrajat/orphanode/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/crates/l/orphanode)](LICENSE-MIT)

## Install

```sh
npm install --global orphanode   # prebuilt binaries for macOS, Linux, Windows
```

```sh
cargo install orphanode          # Rust 1.95+
```

## Quick start

```sh
cd my-project
orphanode scan
```

That's it. Workspaces, entry points, package exports, scripts, tsconfig, and
common framework conventions get picked up on their own.

Real output from a small monorepo fixture:

```text
ORPHANODE  reachability scan

› Entries  2 configured
    ├─ packages/closed/src/index.js
    └─ packages/open/src/index.js
  Mode  balanced · 4 workspaces (mixed world) · 5 target profiles
  3 reachable · 1 unreachable · 0 incomplete · 0 diagnostics

FINDINGS
● ORP1002  HIGH confidence
  Scope  packages/closed  ·  browser, cli, node, test, types  ·  fix preview only
  export closedApi from packages/closed/src/index.js has no live consumer
  Symbol  closedApi
  Paths
    └─ packages/closed/src/index.js
  Evidence
    ├─ No resolved import or re-export reaches this export binding
    └─ The package is analyzed as closed world for this entry
  Next
    └─ Review the public contract and request a fix preview before editing

● ORP1003  HIGH confidence
  Scope  packages/closed  ·  browser, cli, node, test, types  ·  fix preview only
  declaration closedApi has no live reference
  Symbol  closedApi
  Paths
    └─ packages/closed/src/index.js
  Evidence
    └─ No reachable execution region, import, export contract, or live declaration reaches this binding
  Next
    └─ Inspect the exact declaration span in a fix preview

● ORP3001  HIGH confidence
  Scope  packages/unused  ·  node, browser, types, cli, test  ·  fix not available
  workspace @fixture/unused has no live root or consumer
  Paths
    └─ packages/unused/package.json
  Evidence
    └─ No reachable file, package-name import, package script, or public contract retains this private workspace
  Next
    └─ Review workspace consumers and configuration before removing the package

● ORP1001  HIGH confidence
  Scope  packages/unused  ·  browser, cli, node, test, types  ·  fix eligible
  packages/unused/src/index.js is unreachable
  Paths
    └─ packages/unused/src/index.js
  Evidence
    └─ No resolved path from any of the 2 configured entries
  Next
    └─ Review the files or configure an additional entry before removal

DIAGNOSTICS
  — None reported

✓ COMPLETE  Reachability analysis finished.
```

Disagree with a verdict? Ask for the reasoning:

```sh
$ orphanode why packages/unused/src/index.js

packages/unused/src/index.js is unreachable
└─ No resolved path from any of the 2 configured entries
```

## Why bother

Dead code tools are easy to write and hard to trust. Most of them pattern match,
hand you 400 suspects, and wish you good luck. So you end up deleting nothing
and keeping that one util file from 2021 around forever lol.

OrphaNode takes the slower route: resolve every import properly (package
exports, tsconfig path aliases, ESM conditions, workspace boundaries), build the
graph, then report only what nothing can reach. Every finding ships with the
evidence chain behind it. And when something is genuinely ambiguous, like a
dynamic import or a loader it can't see through, it prints a diagnostic instead
of a guess.

Also in the box:

- `orphanode why src/foo.ts` explains any verdict, kept or reported
- Safe fixes: preview first, verify file and manifest hashes right before
  writing, then re-scan the whole project and abort if anything new appears
- Deterministic JSON against a versioned schema, SARIF 2.1.0 for CI, exit codes
  that make sense (`2` means incomplete analysis, never silently clean)
- ts-prune style compact output when you just want greppable lines:

  ```sh
  $ orphanode scan --issues exports --format compact
  packages/closed/src/index.js:1:17 - ORP1002 'closedApi' is unused
  ```

- A local cache, so repeat scans skip most of the work

## What it finds

| Code | Finding |
| --- | --- |
| `ORP1001` | Unreachable source file |
| `ORP1002` | Unused export |
| `ORP1003` | Unused declaration |
| `ORP1004` | Unused class member |
| `ORP2001` | Unused direct dependency |
| `ORP2002` | Unlisted or misplaced dependency |
| `ORP3001` | Unused private workspace package |

Understands JavaScript, JSX, TypeScript, TSX, ESM, CommonJS, npm/pnpm/Yarn/Bun
workspaces, and common framework entry conventions, across `node`, `browser`,
`types`, `cli`, and `test` target profiles.

## Speed

Performance here is enforced in CI, not vibes. A pinned million-line corpus has
to stay inside these budgets or the release gets blocked
([methodology](docs/benchmark-baseline.md)):

| Scenario | Budget |
| --- | --- |
| Cold scan, 1,000,000 lines | ≤ 5 s |
| Unchanged rescan | ≤ 500 ms |
| One-file incremental edit | ≤ 750 ms |
| Peak memory | < 750 MiB |

## How it's tested

- Around 210 tests across library, CLI, and integration suites, plus fixture
  scans covering every supported module system
- Fuzzing in CI on five targets: parser, config, resolver, plugin protocol, and
  cache corruption
- Differential tests against Node's own resolver and the TypeScript compiler
- cargo-deny for the supply chain, pinned toolchains, hash-pinned GitHub Actions
- Releases publish through trusted publishing (OIDC) with checksums, an SBOM,
  and Sigstore attestations

## Limits

Static analysis can't see everything, and pretending otherwise is how you get
tools that delete production code lol. Reflection, computed requires, custom
loaders, Vue/Svelte single-file components, executable config files: OrphaNode
either handles them or says so. Anything it can't fully model becomes a
diagnostic, and findings those gaps could invalidate get suppressed.

Scans never run your project source. Deep mode may load your project's
TypeScript compiler, but in a separate worker process, and if that's missing it
just keeps the affected code and explains why.

## Commands

```text
orphanode scan       Analyze a project
orphanode why        Explain why a file or package is kept or reported
orphanode explain    Explain an issue code
orphanode config     Validate and show project configuration
orphanode cache      Manage the local analysis cache
```

<details>
<summary><strong>Full <code>scan</code> options</strong></summary>

| Option | What it does |
| --- | --- |
| `--root DIR` | Project directory. Defaults to the current directory. |
| `--entry PATH` | Replace inferred entry points. Repeat for multiple entries. |
| `--workspace PATH` | Analyze one workspace relative to the controlling package. |
| `--issues LIST` | Run selected issue families. Values: `files`, `exports`, `declarations`, `members`, `dependencies`, `workspaces`. |
| `--mode MODE` | Analysis depth: `fast`, `balanced`, or `deep`. |
| `--target PROFILE` | Select built-in or configured target profiles. Repeat it or use commas. |
| `--closed-world` | Treat public packages as closed world for this scan. |
| `--open-world` | Treat private packages as open world for this scan. |
| `--format FORMAT` | Output `human`, `compact`, `json`, or `sarif`. |
| `--color WHEN` | Use `auto`, `always`, or `never` color in human output. |
| `--ascii` | Use ASCII instead of Unicode drawing characters. |
| `--pretty` | Pretty-print JSON or SARIF. |
| `--timings` | Show named stage timings. Machine-output timings go to stderr. |
| `--debug` | Show timings, counts, cache activity, effective configuration, and diagnostics on stderr. |
| `--fix` | Preview a fix plan. Never changes files by itself. |
| `--apply` | Apply the previewed plan and re-scan. Requires `--fix`. |
| `--fix-file PATH` | Select one reported file for a fix preview. Repeat as needed; requires `--fix`. |
| `--fix-dependency NAME` | Select a dependency. Use `WORKSPACE:NAME` when ambiguous; requires `--fix`. |
| `--file PATH` | Add a file to an exact, caller-owned source universe. Repeat as needed. |
| `--files-from PATH` | Read an exact source universe from a JSON manifest. |
| `--report-tests` | Also report findings in test files. Tests always stay in the reachability graph as roots; by default they are analyzed but not reported. |

Without `--file` or `--files-from`, `scan` uses full project discovery. Adding
`--entry` changes only the roots. The exact-universe flags are for tools that
already know the complete file set, and they can't be combined with project-only
options like `--workspace`, `--mode`, `--target`, world overrides, or fixes.

An exact-universe manifest (`--files-from`) looks like this:

```json
{
  "entries": ["src/index.ts", "tests/index.test.ts"],
  "files": [
    "src/index.ts",
    "src/server.ts",
    "tests/index.test.ts"
  ]
}
```

</details>

<details>
<summary><strong>Configuration</strong></summary>

Put an `orphanode` object in `package.json`, or an `orphanode.jsonc` file next
to it (which wins):

```jsonc
{
  "mode": "balanced",
  "targets": {
    "server": {
      "extends": "node",
      "conditions": ["development"]
    }
  },
  "confidence": {
    "report": "medium",
    "fail": "high"
  },
  "workspaces": {
    "packages/internal": {
      "world": "closed",
      "entry": ["src/index.ts"]
    }
  }
}
```

Validate any setup with:

```sh
orphanode config --check --pretty
```

Full machine-readable contract:
[`schemas/config-v1.schema.json`](schemas/config-v1.schema.json).

Analysis modes:

- `balanced` (default)
- `fast`: keeps more code when member evidence is expensive to establish
- `deep`: asks an isolated TypeScript worker for extra member and override
  facts. No worker available? Affected code stays, with an explanation.

The npm install wires up the worker automatically. Source builds can point
`ORPHANODE_TYPESCRIPT_WORKER` at the worker path.

Cache lives at `.orphanode/cache` in the project root:

```sh
orphanode cache clean
```

</details>

## Project

- [Contributing guide](CONTRIBUTING.md) and [architecture notes](DEVELOPMENT.md)
- [Security policy](SECURITY.md) · [Changelog](CHANGELOG.md)

MIT or [Apache-2.0](LICENSE-APACHE), your pick.
