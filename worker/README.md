# orphanode worker

Optional deep-analysis worker for [Orphanode](https://github.com/wthrajat/orphanode).
A plain Node.js script (no dependencies, nothing published to any registry) that
loads the project's TypeScript compiler in an isolated process and answers
member and override fact queries for `orphanode scan --mode deep`.

Point Orphanode at it with:

```sh
export ORPHANODE_TYPESCRIPT_WORKER=/path/to/worker/src/worker.mjs
```

Requires Node.js 18.18 or newer and a TypeScript installation compatible with
the analyzed project. If the worker is unavailable, deep mode keeps the affected
code and explains the limitation instead of guessing.

Run the protocol tests with:

```sh
node --test "worker/test/*.test.mjs"
```

Licensed under either the [Apache License 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT), at your option.
