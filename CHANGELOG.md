# Changelog

Notable changes to OrphaNode are recorded here. The project follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Reworked public documentation around a concise user guide and a separate
  contributor guide.

### Fixed

- TypeScript constructor parameter properties are retained conservatively
  instead of being reported as unused declarations; their `this.<name>` reads
  are not resolved identifier references.
- Exported TypeScript type aliases, interfaces, and enums now become module
  exports, so cross-file imports reach them instead of reporting the defining
  declaration as unused.
- Type-position references retain symbols in the type lane, and import links
  propagate across lanes, so types used through value-syntax imports are no
  longer reported as unused declarations.
- Dependency analysis no longer reports imports that resolve to project files,
  including tsconfig path aliases and paths excluded by discovery policy, as
  unlisted dependencies.
- Package scripts invoking package-manager CLI actions such as `pnpm up` no
  longer produce missing-script diagnostics or false nested script calls.
- Script-entry and tooling-configuration gaps (`entry_source_not_found`,
  `missing_package_script`, and built-in plugin unsupported cases) stay visible
  as warnings without suppressing every finding. The plugin contract now allows
  non-blocking unsupported cases, and hard analysis failures such as parse
  errors and unenumerable dynamic imports keep blocking coverage.
- Discovery excludes nested repository boundaries, such as git submodules,
  from the source universe and from workspace package discovery.

### Added

- NestJS joins the built-in framework plugins with `src/main.*` and
  `apps/*/src/main.*` entry conventions.

- Project scans now treat imports that resolve into paths excluded by the
  discovery policy, such as ignored generated code or nested workspace
  packages, as external boundaries with a visible warning instead of failing
  the scan with `outside_file_universe` errors. Caller-owned explicit universes
  keep the error behavior.
- Merging per-target-profile reports no longer duplicates identical diagnostics;
  repeated diagnostics collapse into one entry whose `[target ...]` prefix names
  every reporting profile.

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
