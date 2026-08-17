# OrphaNode TypeScript worker

This package contains OrphaNode's isolated TypeScript compiler worker. It is
installed by the `orphanode` npm launcher and is not intended to be invoked
directly. The worker loads the nearest workspace-contained compatible
`typescript` package for each owning TypeScript configuration only when the user
explicitly selects deep analysis. Separate configuration workers preserve nested
monorepo compiler-version boundaries.

The JSON-lines protocol is versioned, size-bounded, deadline-bounded, and emits
facts only; unused-code policy remains in the native OrphaNode core.
