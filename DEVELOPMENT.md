# Developing Orphanode

This document is for contributors and maintainers. The user-facing command guide
is in [README.md](README.md).

## Requirements

- Rust 1.95 or newer with `rustfmt` and Clippy
- Node.js 24.11.1 for the deep-analysis worker tests
- A local TypeScript 5.9.3 installation for the reference resolver checks

Build and run the CLI:

```sh
cargo build --workspace
cargo run -- scan --root fixtures/esm --files-from files.json
```

The fixture intentionally contains an unreachable file, so the scan exits `1`.
That is a finding, not a crash.

The repository intentionally generates one `Cargo.lock` in the release workflow
and passes that exact artifact to every release job. Ordinary local development
can resolve dependencies without `--locked`.

## Architecture

```text
workspace, manifest, config, script, and plugin discovery
  -> bounded source universe and entry roots
  -> Oxc parse and semantic facts
  -> module, symbol, member, dependency, and workspace graphs
  -> optional TypeScript deep facts
  -> conservative policy and explanations
  -> human, JSON, SARIF, or reviewed fix plan
```

- `crates/orphanode` is the single Rust crate. Its library owns discovery,
  parsing, resolution, graph policy, caching, plugins, fixes, and the report
  model; its binary target owns arguments, terminal rendering, process
  execution, output, and exit codes.
- `worker/` is the optional deep-analysis worker, a plain Node.js script.
- `schemas` contains public configuration, plugin, and report contracts.
- `fixtures`, `benchmarks`, and `fuzz` contain validation assets.

The core has two entry points:

```rust
use std::path::PathBuf;

use orphanode::{ProjectScanRequest, ScanRequest, scan, scan_project};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Normal project discovery.
    let project_report = scan_project(&ProjectScanRequest::new("./my-project"))?;

    // Caller-owned exact universe.
    let exact_report = scan(&ScanRequest {
        root: PathBuf::from("./my-project"),
        entries: vec![PathBuf::from("src/index.ts")],
        files: vec![
            PathBuf::from("src/index.ts"),
            PathBuf::from("src/unused.ts"),
        ],
    })?;

    println!("{} {}", project_report.findings.len(), exact_report.findings.len());
    Ok(())
}
```

The Rust API is pre-1.0. Persisted integrations should prefer the versioned JSON
report contract.

## Correctness rules

These rules are architectural constraints:

- Missing parser, resolver, plugin, or dynamic-load coverage becomes a visible
  diagnostic. It is never evidence that code is dead.
- Public packages default to open world; private packages default to closed
  world.
- Cycles do not make themselves reachable.
- Runtime and type-only namespaces remain separate.
- Paths are canonicalized and contained by the physical workspace.
- Reports are deterministic and use normalized project-relative paths.
- Project source, scripts, and dynamic configuration are not executed during an
  ordinary scan.
- Deep TypeScript and configured `exec:` plugins are explicit trusted-code
  boundaries. Process limits are not an OS sandbox.
- A fix requires explicit item selection, eligibility, current content hashes,
  and strict post-apply revalidation.

## Validation

Run the narrowest relevant test while developing, then the complete local suite:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo test --workspace --doc
node --test "worker/test/*.test.mjs"
```

Check the separate fuzz workspace formatting and metadata:

```sh
cargo fmt --manifest-path fuzz/Cargo.toml --all --check
cargo metadata --manifest-path fuzz/Cargo.toml --no-deps
```

Run the reviewed resolver references with a TypeScript 5.9.3 installation:

```sh
TYPESCRIPT_PATH=/path/to/typescript/lib/typescript.js \
  node fixtures/reference/check-references.mjs
```

Run microbenchmarks:

```sh
cargo bench --package orphanode --bench hot_paths
```

Run the generated million-line release gate after building the release binary:

```sh
cargo build --release --package orphanode
node benchmarks/benchmark.mjs \
  --binary target/release/orphanode \
  --output target/benchmark-result.json
```

The end-to-end gate checks cold, warm, and one-file incremental behavior,
correctness, cache hits, wall time, and peak RSS.

## Tests and fixtures

A behavior fix should include the smallest fixture that proves it. Keep fixture
paths sorted and use a `files.json` manifest with either `entry` or `entries` and
the complete explicit source universe.

Prefer semantic assertions over broad snapshots. Cover the relevant positive,
negative, incomplete, and path-boundary cases. Changes to a public JSON contract
must update its versioned schema, producer tests, consumer tests, user docs, and
changelog together.

The CI workflow runs formatting, Clippy, documentation, unit/integration tests on
Linux, macOS, and Windows, the Rust 1.95 check, dependency policy, crate packaging,
worker protocol tests, report-schema validation, determinism, resolver differential
checks, and the performance gate. A separate
scheduled workflow runs bounded fuzz campaigns.

## Caches and generated files

- Project analysis cache: `.orphanode/cache`
- Rust output: `target`
- Fuzz output: `fuzz/artifacts`, `fuzz/coverage`, `fuzz/target`
- Benchmark output: caller-selected paths under `target`

Do not commit generated packages, binaries, cache generations, benchmark output,
fuzz crashes, credentials, or private corpus data.

## Distribution

The release workflow coordinates:

1. validation and one generated Cargo lock artifact;
2. bounded release fuzzing and the performance gate;
3. native builds for GNU/Linux x64, macOS arm64/x64, and Windows x64;
4. checksum and executable smoke tests;
5. checksummed archives, SBOM, build attestations, and the GitHub release.

Publishing to crates.io is a manual maintainer step:

```sh
cargo publish --locked --package orphanode
```

Run it from the exact release tag commit after the release workflow passes.

## Pull requests

A useful pull request:

- explains the user-visible problem and conservative behavior;
- keeps unrelated refactors out;
- adds focused evidence for correctness changes;
- updates public schemas and docs when contracts change; and
- lists the exact validation commands that passed or the exact external blocker.

Security issues must follow [SECURITY.md](SECURITY.md). All contributions are
licensed under the repository's dual MIT OR Apache-2.0 terms.
