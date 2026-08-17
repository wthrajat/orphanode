# OrphaNode

Find unused JavaScript and TypeScript without running your application.

OrphaNode reports unreachable files, unused exports, declarations, class
members, dependencies, and private workspace packages. When static analysis is
incomplete, it reports the gap instead of guessing.

## Install

```sh
npm install --global orphanode
```

Node.js 18.18 or newer is required. Keep optional dependencies enabled: npm uses
them to install the native binary for your operating system. The launcher checks
the package version and SHA-256 checksum before running it.

## Use

Run from a package or monorepo:

```sh
orphanode scan
```

Useful commands:

```sh
# Select checks, a workspace, or target profiles
orphanode scan --issues files,exports,dependencies
orphanode scan --workspace packages/api
orphanode scan --target node,cli

# Machine-readable output
orphanode scan --format json --pretty
orphanode scan --format sarif --pretty

# Explain results and issue policies
orphanode why src/legacy.ts
orphanode why eslint
orphanode explain ORP1001

# Validate configuration and clear the local cache
orphanode config --check --pretty
orphanode cache clean

# Preview an explicitly selected fix
orphanode scan --issues dependencies --fix --fix-dependency lodash
orphanode scan --issues files --fix --fix-file src/unused.ts
```

`--fix` is preview-only. Add `--apply` to authorize the selected eligible plan;
OrphaNode checks current hashes and performs a complete post-change scan.

`balanced` is the default analysis mode. Use `--mode fast` for a more
conservative quick scan or `--mode deep` for additional TypeScript member facts.
This npm package configures the deep-analysis worker automatically.

For every command, option, exit code, configuration example, and safety boundary,
see the [complete CLI guide](https://github.com/wthrajat/orphanode#readme).

## License

Licensed under either the [Apache License 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT), at your option.
