pub mod configuration;
pub mod manifest;
pub mod scripts;
pub mod workspace;

use std::{
    collections::BTreeSet,
    ffi::OsStr,
    path::{Path, PathBuf},
};

use ignore::{DirEntry, WalkBuilder};
use thiserror::Error;

use crate::limits::AnalysisLimits;

const SOURCE_EXTENSIONS: [&str; 8] = ["js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts"];
const SKIPPED_DIRECTORIES: [&str; 14] = [
    "node_modules",
    ".git",
    ".hg",
    ".svn",
    "target",
    "dist",
    "build",
    "coverage",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".turbo",
    ".cache",
    ".orphanode",
];

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("cannot walk project root `{root}` while discovering source files: {source}")]
    Walk {
        root: PathBuf,
        #[source]
        source: ignore::Error,
    },

    #[error(
        "nested package boundary `{path}` prevents automatic source discovery; automatic discovery supports one package at a time, so use --file or --files-from to provide the source universe explicitly"
    )]
    NestedPackage { path: PathBuf },

    #[error(
        "discovered path `{path}` is outside project root `{root}`; use a physical project root without path aliases"
    )]
    PathOutsideRoot { root: PathBuf, path: PathBuf },

    #[error(
        "source discovery under `{root}` exceeded the configured limit of {limit} files; narrow the root or raise the discovery limit explicitly"
    )]
    FileLimitExceeded { root: PathBuf, limit: usize },
}

/// Discovers the analyzable source files in one package rooted at `root`.
///
/// Returned paths are relative to `root`, sorted, and deduplicated. Project
/// `.gitignore` and `.ignore` files are respected, while user-global and parent
/// ignore configuration is deliberately excluded so discovery is reproducible.
///
/// # Errors
///
/// Returns an error when the project cannot be walked completely, a discovered
/// path cannot be expressed relative to `root`, or a nested `package.json`
/// marks a package boundary that automatic single-package discovery cannot cross.
pub fn discover_source_files(root: &Path) -> Result<Vec<PathBuf>, DiscoveryError> {
    discover_source_files_with_limits(root, AnalysisLimits::default())
}

/// Discovers source files with explicit request safety limits.
///
/// # Errors
///
/// Returns the same failures as [`discover_source_files`], plus a visible
/// error if the discovered source universe exceeds the configured file limit.
pub fn discover_source_files_with_limits(
    root: &Path,
    limits: AnalysisLimits,
) -> Result<Vec<PathBuf>, DiscoveryError> {
    discover_source_files_internal(root, limits, BTreeSet::new())
}

/// Discovers one package while pruning already-discovered nested workspace packages.
///
/// `nested_package_roots` must be package-relative directory paths below `root`.
/// An unexpected nested package still fails closed.
///
/// # Errors
///
/// Returns the same errors as [`discover_source_files_with_limits`] and rejects an
/// unsafe nested-package root.
pub fn discover_package_source_files(
    root: &Path,
    nested_package_roots: &[PathBuf],
    limits: AnalysisLimits,
) -> Result<Vec<PathBuf>, DiscoveryError> {
    let mut excluded = BTreeSet::new();
    for nested in nested_package_roots {
        if nested.as_os_str().is_empty()
            || nested.is_absolute()
            || nested
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(DiscoveryError::PathOutsideRoot {
                root: root.to_path_buf(),
                path: nested.clone(),
            });
        }
        excluded.insert(nested.clone());
    }
    discover_source_files_internal(root, limits, excluded)
}

fn discover_source_files_internal(
    root: &Path,
    limits: AnalysisLimits,
    excluded_package_roots: BTreeSet<PathBuf>,
) -> Result<Vec<PathBuf>, DiscoveryError> {
    let filter_root = root.to_path_buf();
    let mut builder = WalkBuilder::new(root);
    builder
        .standard_filters(false)
        .hidden(false)
        .ignore(true)
        .git_ignore(true)
        .require_git(false)
        .follow_links(false)
        .sort_by_file_path(Path::cmp)
        .filter_entry(move |entry| {
            should_visit_entry(entry)
                && !entry
                    .path()
                    .strip_prefix(&filter_root)
                    .is_ok_and(|relative| excluded_package_roots.contains(relative))
        });

    let mut source_files = BTreeSet::new();
    let mut nested_packages = BTreeSet::new();

    for result in builder.build() {
        let entry = result.map_err(|source| DiscoveryError::Walk {
            root: root.to_path_buf(),
            source,
        })?;
        if let Some(source) = entry.error() {
            return Err(DiscoveryError::Walk {
                root: root.to_path_buf(),
                source: source.clone(),
            });
        }
        if entry.path_is_symlink() || !entry.file_type().is_some_and(|kind| kind.is_file()) {
            continue;
        }

        let relative_path =
            entry
                .path()
                .strip_prefix(root)
                .map_err(|_| DiscoveryError::PathOutsideRoot {
                    root: root.to_path_buf(),
                    path: entry.path().to_path_buf(),
                })?;
        if is_nested_package(relative_path) {
            nested_packages.insert(relative_path.to_path_buf());
        } else if is_source_file(relative_path) {
            source_files.insert(relative_path.to_path_buf());
            if source_files.len() > limits.max_discovered_files {
                return Err(DiscoveryError::FileLimitExceeded {
                    root: root.to_path_buf(),
                    limit: limits.max_discovered_files,
                });
            }
        }
    }

    if let Some(path) = nested_packages.into_iter().next() {
        return Err(DiscoveryError::NestedPackage { path });
    }

    Ok(source_files.into_iter().collect())
}

fn should_visit_entry(entry: &DirEntry) -> bool {
    if entry.depth() == 0 || !entry.file_type().is_some_and(|kind| kind.is_dir()) {
        return true;
    }
    !SKIPPED_DIRECTORIES
        .iter()
        .any(|directory| entry.file_name() == OsStr::new(directory))
}

fn is_nested_package(path: &Path) -> bool {
    path.file_name() == Some(OsStr::new("package.json"))
        && path
            .parent()
            .is_some_and(|parent| !parent.as_os_str().is_empty())
}

fn is_source_file(path: &Path) -> bool {
    path.extension()
        .and_then(OsStr::to_str)
        .is_some_and(|extension| SOURCE_EXTENSIONS.contains(&extension))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        process,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::{
        DiscoveryError, SKIPPED_DIRECTORIES, discover_source_files,
        discover_source_files_with_limits,
    };
    use crate::limits::AnalysisLimits;

    static NEXT_PROJECT_ID: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn discovery_is_sorted_and_respects_project_ignores_and_skipped_directories() {
        let project = TestProject::new();
        project.write("package.json", "{}");
        project.write(".gitignore", "ignored.ts\n");
        project.write(".ignore", "also-ignored.js\n");
        project.write("ignored.ts", "");
        project.write("also-ignored.js", "");
        project.write(".hidden/visible.mts", "");
        project.write("src/eight.cts", "");
        project.write("src/five.ts", "");
        project.write("src/four.cjs", "");
        project.write("src/one.js", "");
        project.write("src/seven.mts", "");
        project.write("src/six.tsx", "");
        project.write("src/three.mjs", "");
        project.write("src/two.jsx", "");
        project.write("src/not-source.css", "");
        for directory in SKIPPED_DIRECTORIES {
            project.write(&format!("{directory}/package.json"), "{}");
            project.write(&format!("{directory}/skipped.js"), "");
        }

        let files = discover_source_files(project.path()).expect("discover sources");

        assert_eq!(
            files,
            [
                ".hidden/visible.mts",
                "src/eight.cts",
                "src/five.ts",
                "src/four.cjs",
                "src/one.js",
                "src/seven.mts",
                "src/six.tsx",
                "src/three.mjs",
                "src/two.jsx",
            ]
            .map(PathBuf::from)
        );
    }

    #[test]
    fn nested_package_boundaries_fail_with_the_first_sorted_relative_path() {
        let project = TestProject::new();
        project.write("package.json", "{}");
        project.write("packages/z/package.json", "{}");
        project.write("packages/a/package.json", "{}");
        project.write("packages/a/index.ts", "");

        let error = discover_source_files(project.path()).expect_err("reject nested packages");

        assert!(matches!(
            error,
            DiscoveryError::NestedPackage { path }
                if path == Path::new("packages/a/package.json")
        ));
    }

    #[test]
    fn known_workspace_packages_are_pruned_from_parent_package_discovery() {
        let project = TestProject::new();
        project.write("package.json", "{}");
        project.write("src/index.ts", "");
        project.write("packages/child/package.json", "{}");
        project.write("packages/child/src/index.ts", "");

        let files = super::discover_package_source_files(
            project.path(),
            &[PathBuf::from("packages/child")],
            crate::limits::AnalysisLimits::default(),
        )
        .expect("discover parent package");

        assert_eq!(files, [PathBuf::from("src/index.ts")]);
    }

    #[test]
    fn a_missing_project_root_is_a_visible_walk_error() {
        let project = TestProject::new();
        let missing_root = project.path().join("missing");

        let error = discover_source_files(&missing_root).expect_err("reject missing root");

        assert!(matches!(error, DiscoveryError::Walk { root, .. } if root == missing_root));
    }

    #[test]
    fn invalid_ignore_rules_are_visible_walk_errors() {
        let project = TestProject::new();
        project.write(".ignore", "[z-a]\n");
        project.write("index.js", "");

        let error = discover_source_files(project.path()).expect_err("reject invalid ignore rule");

        assert!(matches!(error, DiscoveryError::Walk { root, .. } if root == project.path()));
    }

    #[test]
    fn exceeding_the_configured_file_limit_fails_instead_of_truncating() {
        let project = TestProject::new();
        project.write("a.js", "");
        project.write("b.js", "");
        let limits = AnalysisLimits {
            max_discovered_files: 1,
            ..AnalysisLimits::default()
        };

        let error = discover_source_files_with_limits(project.path(), limits)
            .expect_err("reject oversized source universe");

        assert!(matches!(
            error,
            DiscoveryError::FileLimitExceeded { root, limit: 1 } if root == project.path()
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symbolic_links_are_not_discovered_or_followed() {
        use std::os::unix::fs::symlink;

        let project = TestProject::new();
        let external = TestProject::new();
        external.write("external.js", "");
        symlink(external.path(), project.path().join("linked-directory"))
            .expect("create directory symlink");
        symlink(
            external.path().join("external.js"),
            project.path().join("linked-file.js"),
        )
        .expect("create file symlink");
        project.write("local.js", "");

        let files = discover_source_files(project.path()).expect("discover sources");

        assert_eq!(files, [PathBuf::from("local.js")]);
    }

    struct TestProject {
        root: PathBuf,
    }

    impl TestProject {
        fn new() -> Self {
            loop {
                let id = NEXT_PROJECT_ID.fetch_add(1, Ordering::Relaxed);
                let root = std::env::temp_dir()
                    .join(format!("orphanode-discovery-test-{}-{id}", process::id()));
                match fs::create_dir(&root) {
                    Ok(()) => return Self { root },
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("create test project `{}`: {error}", root.display()),
                }
            }
        }

        fn path(&self) -> &Path {
            &self.root
        }

        fn write(&self, relative_path: &str, contents: &str) {
            let path = self.root.join(relative_path);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("create test parent directories");
            }
            fs::write(path, contents).expect("write test file");
        }
    }

    impl Drop for TestProject {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
