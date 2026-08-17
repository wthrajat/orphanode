# Changelog

Notable changes to OrphaNode are recorded here. The project follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Reworked public documentation around a concise user guide and a separate
  contributor guide.

## [0.1.0] - Unreleased

### Added

- Automatic discovery for JavaScript and TypeScript packages, npm/pnpm/Yarn/Bun
  workspaces, entries, exports, scripts, TypeScript configuration, and common
  framework conventions.
- Findings for unreachable files, unused exports, declarations, class members,
  direct dependencies, and private workspace packages.
- JavaScript, JSX, TypeScript, TSX, ESM, CommonJS, package maps, target profiles,
  TypeScript aliases, and bounded static dynamic-load support.
- `fast`, `balanced`, and optional TypeScript-backed `deep` analysis modes.
- Built-in framework/tool detection plus declarative and explicitly trusted
  executable plugin contracts.
- Layered `package.json` and `orphanode.jsonc` configuration.
- Human, deterministic JSON, and SARIF output with stable issue codes and exit
  behavior.
- `why`, `explain`, `config --check`, and `cache clean` commands.
- Preview-first, explicitly selected fixes for eligible dependency removals and
  hash-guarded whole-file deletions, followed by a complete re-scan.
- Persistent fact and deep-analysis caches.
- crates.io packages, a six-package npm distribution, and checksummed native
  release archives.
- Cross-platform CI, resolver differential checks, schema/determinism checks,
  package smoke tests, fuzzing, and performance gates.

### Safety

- Ordinary scans do not execute project source, package scripts, dynamic
  configuration, or network requests.
- Unsupported or unresolved behavior becomes a visible coverage diagnostic and
  suppresses findings it could invalidate.
- Paths are contained by the physical project root, terminal text is sanitized,
  and machine output is deterministic.
- Deep TypeScript analysis and configured `exec:` plugins are explicit trusted-
  code boundaries.
- Applying a fix requires eligibility, explicit selection, current hashes, and
  strict post-change validation.

### Known limitations

- Arbitrary reflection, computed runtime loading, custom loaders, executable
  configuration, and embedded scripts in component formats cannot always be
  modeled statically.
- Automatic apply is limited to eligible direct dependencies and whole files;
  export, declaration, and member edits remain review-only.
