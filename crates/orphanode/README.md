# Orphanode

[Orphanode](https://github.com/wthrajat/orphanode) is accuracy-first
reachability analysis for JavaScript and TypeScript projects: find the code
that nothing can reach anymore, with evidence.

The `orphanode` crate ships both the native CLI and the Rust analysis library
it is built on.

## Install the CLI

```sh
cargo install orphanode
cd my-project
orphanode scan
```

It supports automatic project discovery, exact caller-supplied file universes,
human/JSON/SARIF output, explanations, configuration checks, cache management,
and explicitly selected safe-fix previews.

See the [complete command guide](https://github.com/wthrajat/orphanode#readme)
for every option and example. Prebuilt binaries for common platforms are
available on the [releases page](https://github.com/wthrajat/orphanode/releases).

## Use it as a library

```rust
use orphanode::{ProjectScanRequest, scan_project};

let request = ProjectScanRequest::new("/path/to/project");
let report = scan_project(&request)?;
```

It provides automatic project discovery and exact-universe APIs for
reachability analysis. Results include evidence and explicit coverage
diagnostics; incomplete analysis never becomes unsafe cleanup advice. API
documentation is available on [docs.rs](https://docs.rs/orphanode).
Architecture and contributor guidance are in the repository's
[DEVELOPMENT.md](https://github.com/wthrajat/orphanode/blob/main/DEVELOPMENT.md).

Licensed under either the [Apache License 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT), at your option.
