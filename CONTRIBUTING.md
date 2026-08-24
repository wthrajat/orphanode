# Contributing to Orphanode

Thanks for helping make Orphanode more accurate and useful.

## Before you start

- Read [DEVELOPMENT.md](DEVELOPMENT.md) for architecture, safety rules, tests,
  fixtures, and release details.
- Open an issue before a large feature or behavior change.
- Report vulnerabilities privately using [SECURITY.md](SECURITY.md).
- Follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Make a change

Keep changes focused and add the smallest test or fixture that proves the new
behavior. A missing parser, resolver, or discovery edge must become a diagnostic;
it must not become evidence that code is unused.

Run the relevant focused tests, then:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo test --workspace --doc
npm test --prefix packages/orphanode
npm test --prefix packages/typescript-worker
```

If a command cannot run, include the command and exact blocker in the pull
request. Do not claim checks that were not executed.

## Open a pull request

Explain:

- the user-visible problem;
- the conservative behavior chosen;
- the tests and fixtures added;
- any schema, CLI, MSRV, or platform impact; and
- the exact validation commands that passed.

By contributing, you agree that your contribution is licensed under the
repository's dual MIT OR Apache-2.0 terms.
