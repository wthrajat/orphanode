# OrphaNode CLI

`orphanode-cli` provides the native `orphanode` command for finding unused
JavaScript and TypeScript.

```sh
cargo install orphanode-cli
cd my-project
orphanode scan
```

It supports automatic project discovery, exact caller-supplied file universes,
human/JSON/SARIF output, explanations, configuration checks, cache management,
and explicitly selected safe-fix previews.

See the [complete command guide](https://github.com/wthrajat/orphanode#readme)
for every option and example.

Licensed under either the [Apache License 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT), at your option.
