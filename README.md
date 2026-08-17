# OrphaNode

Find unused JavaScript and TypeScript without running your application.

OrphaNode follows files, exports, declarations, class members, dependencies,
and workspace packages from the places your project can actually start. When it
cannot prove something is unused, it reports the missing coverage instead of
guessing.

It supports JavaScript, JSX, TypeScript, TSX, ESM, CommonJS, npm, pnpm, Yarn,
Bun workspaces, TypeScript configuration, package exports, and common framework
entry conventions.

## Install

With npm:

```sh
npm install --global orphanode
```

With Cargo:

```sh
cargo install orphanode-cli
```

Or build the current checkout:

```sh
cargo install --path crates/orphanode-cli
```

The npm package requires Node.js 18.18 or newer. Building from source requires
Rust 1.95 or newer.

## Quick start

Run OrphaNode from a package or monorepo:

```sh
cd my-project
orphanode scan
```

That is enough for most projects. OrphaNode discovers workspaces, source files,
package entry points, exports, scripts, TypeScript configuration, and supported
framework conventions. Project scans run every issue family by default across
the built-in `node`, `browser`, `types`, `cli`, and `test` target profiles.

Common examples:

```sh
# Scan one workspace in a monorepo
orphanode scan --workspace packages/api

# Check only files, exports, and dependencies
orphanode scan --issues files,exports,dependencies

# Scan the Node and CLI target profiles
orphanode scan --target node,cli

# Write deterministic JSON or SARIF
orphanode scan --format json --pretty > orphanode-report.json
orphanode scan --format sarif --pretty > orphanode.sarif

# Explain a result
orphanode why src/legacy.ts
orphanode why eslint
```

## Commands

```text
orphanode scan       Analyze a project
orphanode why        Explain why a file or package is kept or reported
orphanode explain    Explain an issue code
orphanode config     Validate and show project configuration
orphanode cache      Manage the local analysis cache
```

Use `orphanode --help` or `orphanode <command> --help` for built-in help.
Use `orphanode --version` to print the installed version.

### `orphanode scan`

```sh
orphanode scan [OPTIONS]
```

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
| `--format FORMAT` | Output `human`, `json`, or `sarif`. |
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

Without `--file` or `--files-from`, `scan` uses full project discovery. Adding
`--entry` changes only the roots; discovery still handles the rest of the
project.

`--file` and `--files-from` are for tools that already know the complete source
universe. They cannot be combined with project-only options such as
`--workspace`, `--mode`, `--target`, world overrides, dependency/workspace
issues, or fixes. A repeated `--file` universe also needs at least one `--entry`.
`--files-from` cannot be combined with `--entry` or `--file`.

An exact-universe manifest looks like this:

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

It may use a single `entry` instead of `entries`, but not both. Every entry must
also appear in `files`.

### `orphanode why`

Explain a file or npm package:

```sh
orphanode why src/server.ts
orphanode why react --root ./apps/web
orphanode why src/server.ts --format json --pretty
```

Syntax:

```text
orphanode why QUERY [--root DIR] [--entry PATH ...]
                     [--file PATH ... | --files-from PATH]
                     [--format human|json] [--pretty]
```

The result shows a supported reachability chain, finding evidence, an incomplete
coverage explanation, or a not-found result.

### `orphanode explain`

Show the safety rule behind an issue:

```sh
orphanode explain ORP1001
orphanode explain ORP2001 --json
```

Supported issue codes:

| Code | Meaning |
| --- | --- |
| `ORP1001` | Unreachable source file |
| `ORP1002` | Unused export |
| `ORP1003` | Unused declaration |
| `ORP1004` | Unused class member |
| `ORP2001` | Unused direct dependency |
| `ORP2002` | Unlisted or misplaced dependency |
| `ORP3001` | Unused private workspace package |

### `orphanode config`

Validate configuration and print the normalized project state:

```sh
orphanode config --check --pretty
orphanode config --root ./my-project --check
```

Options are `--root DIR`, `--check`, and `--pretty`.

OrphaNode reads an `orphanode` object from `package.json` and a higher-priority
`orphanode.jsonc`. A small example:

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

The complete machine-readable contract is
[`schemas/config-v1.schema.json`](schemas/config-v1.schema.json).

### `orphanode cache clean`

Remove only OrphaNode's cache for a project:

```sh
orphanode cache clean
orphanode cache clean --root ./my-project
```

The cache lives at `.orphanode/cache` inside the resolved project root.

## Analysis modes

- `balanced` is the default.
- `fast` keeps more code when member evidence is expensive to establish.
- `deep` asks the isolated TypeScript worker for additional member and override
  facts. If the worker or a compatible project TypeScript installation is not
  available, OrphaNode keeps affected code and explains the limitation.

The npm installation configures the worker automatically. Source and Cargo
installs can set `ORPHANODE_TYPESCRIPT_WORKER` to
`packages/typescript-worker/src/worker.mjs`.

## Safe fixes

Fixes always require an exact selection and a preview:

```sh
# Preview
orphanode scan --issues dependencies --fix --fix-dependency lodash
orphanode scan --issues files --fix --fix-file src/unused.ts

# Apply the same selected plan
orphanode scan --issues dependencies --fix --fix-dependency lodash --apply
```

Only eligible high-confidence dependency removals and closed-world whole-file
deletions can be applied. OrphaNode rechecks file and manifest hashes immediately
before changing anything, then performs a complete scan. It fails the operation
if new findings, diagnostics, or unresolved imports appear. Export, declaration,
and member edits remain review-only.

Fixes currently require human output.

## Output and exit codes

Human output is designed for terminals and honors `NO_COLOR`. JSON uses the
versioned [`scan-report-v0.2` schema](schemas/scan-report-v0.2.schema.json).
SARIF 2.1.0 is available for code-scanning tools.

| Exit code | Meaning |
| ---: | --- |
| `0` | Analysis completed and no finding reached the configured failure threshold. |
| `1` | Analysis completed and at least one finding reached the failure threshold. |
| `2` | Analysis or input was incomplete or invalid. |
| `3` | Output, cache, fix planning, or fix application failed. |

For `why`, `0` means explained, `1` means not found, and `2` means incomplete.

## What OrphaNode does not guess

Static analysis cannot fully model arbitrary reflection, computed runtime loads,
custom loaders, executable configuration, or embedded scripts inside component
formats such as Vue and Svelte. OrphaNode surfaces relevant gaps as diagnostics
and suppresses findings they could invalidate.

Ordinary scans do not execute project source, package scripts, dynamic
configuration, or network requests. Deep mode may load the project's TypeScript
compiler. A configured `exec:` plugin is trusted code and is not an operating-
system sandbox.

## Development and support

- Technical architecture, testing, fixtures, and release notes:
  [DEVELOPMENT.md](DEVELOPMENT.md)
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md)
- Security reports: [SECURITY.md](SECURITY.md)
- Release history: [CHANGELOG.md](CHANGELOG.md)

OrphaNode is licensed under either the [MIT License](LICENSE-MIT) or the
[Apache License 2.0](LICENSE-APACHE), at your option.
