use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs, io,
    path::{Path, PathBuf},
};

use ignore::gitignore::{Gitignore, GitignoreBuilder};
use serde::Serialize;
use thiserror::Error;

use super::manifest::{ManifestError, PackageManifest, read_package_manifest};

const PACKAGE_MANIFEST: &str = "package.json";
const PNPM_WORKSPACE: &str = "pnpm-workspace.yaml";
const SKIPPED_PACKAGE_DIRECTORIES: [&str; 12] = [
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
    ".cache",
    ".orphanode",
];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageManager {
    Npm,
    Pnpm,
    Yarn,
    Bun,
    Other(String),
}

impl PackageManager {
    #[must_use]
    pub fn from_package_manager_field(value: &str) -> Self {
        let name = value.split_once('@').map_or(value, |(name, _)| name);
        match name {
            "npm" => Self::Npm,
            "pnpm" => Self::Pnpm,
            "yarn" => Self::Yarn,
            "bun" => Self::Bun,
            other => Self::Other(other.to_owned()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LockfileKind {
    Npm,
    Pnpm,
    Yarn,
    BunText,
    BunBinary,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LockfileEvidence {
    pub path: PathBuf,
    pub kind: LockfileKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageManagerDetection {
    /// `packageManager` wins when present. Otherwise a manager is selected only
    /// when all local metadata agrees.
    pub selected: Option<PackageManager>,
    pub declared: Option<String>,
    pub lockfiles: Vec<LockfileEvidence>,
    pub conflicting_candidates: Vec<PackageManager>,
    pub yarn_plug_and_play: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspacePatternSource {
    PackageManifest,
    PnpmWorkspace,
    None,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspacePackage {
    /// Package root relative to the controlling workspace. The controlling
    /// package itself is represented by an empty path.
    pub root: PathBuf,
    pub manifest_path: PathBuf,
    pub manifest: PackageManifest,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceDiscovery {
    pub display_root: PathBuf,
    pub requested_physical_root: PathBuf,
    pub workspace_root: PathBuf,
    pub controlling_manifest: PathBuf,
    pub package_manager: PackageManagerDetection,
    pub pattern_source: WorkspacePatternSource,
    pub workspace_patterns: Vec<String>,
    pub packages: Vec<WorkspacePackage>,
}

impl WorkspaceDiscovery {
    /// Returns the nearest containing package. A path may be absolute beneath
    /// the workspace root or workspace-relative.
    #[must_use]
    pub fn package_for_path(&self, path: &Path) -> Option<&WorkspacePackage> {
        let relative = if path.is_absolute() {
            path.strip_prefix(&self.workspace_root).ok()?
        } else {
            path
        };
        self.packages
            .iter()
            .filter(|package| relative.starts_with(&package.root))
            .max_by_key(|package| package.root.components().count())
    }
}

#[derive(Debug, Error)]
pub enum WorkspaceError {
    #[error("cannot resolve requested workspace root `{path}`: {source}")]
    ResolveRoot {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("requested workspace root `{0}` is not a directory")]
    RootIsNotDirectory(PathBuf),

    #[error("no controlling package.json exists at or above `{0}`")]
    MissingControllingManifest(PathBuf),

    #[error("cannot inspect workspace directory `{path}`: {source}")]
    Inspect {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("package manifest `{path}` is outside controlling workspace `{root}`")]
    PackageOutsideWorkspace { root: PathBuf, path: PathBuf },

    #[error("invalid workspace pattern `{pattern}`: {source}")]
    WorkspacePattern {
        pattern: String,
        #[source]
        source: ignore::Error,
    },

    #[error("invalid pnpm workspace `{path}`: {message}")]
    PnpmWorkspace { path: PathBuf, message: String },

    #[error("workspace package name `{name}` is declared by both `{first}` and `{second}`")]
    DuplicatePackageName {
        name: String,
        first: PathBuf,
        second: PathBuf,
    },

    #[error(transparent)]
    Manifest(#[from] ManifestError),
}

/// Discovers a controlling package and its npm, pnpm, Yarn, or Bun workspaces
/// without executing package scripts or configuration.
///
/// # Errors
///
/// Returns an error for unreadable roots or manifests, malformed static
/// workspace metadata, containment violations, or duplicate package names.
pub fn discover_workspace(requested_root: &Path) -> Result<WorkspaceDiscovery, WorkspaceError> {
    let requested_physical_root =
        requested_root
            .canonicalize()
            .map_err(|source| WorkspaceError::ResolveRoot {
                path: requested_root.to_path_buf(),
                source,
            })?;
    if !requested_physical_root.is_dir() {
        return Err(WorkspaceError::RootIsNotDirectory(requested_physical_root));
    }

    let controlling_manifest = find_nearest_package_manifest(&requested_physical_root)
        .ok_or_else(|| WorkspaceError::MissingControllingManifest(requested_root.to_path_buf()))?;
    let Some(workspace_root) = controlling_manifest.parent().map(Path::to_path_buf) else {
        return Err(WorkspaceError::MissingControllingManifest(
            requested_root.to_path_buf(),
        ));
    };
    let controlling_package = read_package_manifest(&controlling_manifest)?;
    let package_manager = detect_package_manager(&workspace_root, &controlling_package);
    let pnpm_workspace_path = workspace_root.join(PNPM_WORKSPACE);
    let (pattern_source, workspace_patterns) = if pnpm_workspace_path.is_file() {
        (
            WorkspacePatternSource::PnpmWorkspace,
            read_pnpm_workspace_patterns(&pnpm_workspace_path)?,
        )
    } else if controlling_package.workspaces.patterns.is_empty() {
        (WorkspacePatternSource::None, Vec::new())
    } else {
        (
            WorkspacePatternSource::PackageManifest,
            controlling_package.workspaces.patterns.clone(),
        )
    };

    let matcher = workspace_matcher(&workspace_root, &workspace_patterns)?;
    let mut manifest_paths = collect_package_manifests(&workspace_root)?;
    manifest_paths.sort();
    manifest_paths.dedup();

    let mut packages = vec![WorkspacePackage {
        root: PathBuf::new(),
        manifest_path: controlling_manifest.clone(),
        manifest: controlling_package,
    }];
    for manifest_path in manifest_paths {
        if manifest_path == controlling_manifest {
            continue;
        }
        let Some(package_root) = manifest_path.parent() else {
            return Err(WorkspaceError::PackageOutsideWorkspace {
                root: workspace_root,
                path: manifest_path,
            });
        };
        let relative_root = package_root
            .strip_prefix(&workspace_root)
            .map_err(|_| WorkspaceError::PackageOutsideWorkspace {
                root: workspace_root.clone(),
                path: manifest_path.clone(),
            })?
            .to_path_buf();
        if !workspace_patterns.is_empty()
            && matcher
                .matched_path_or_any_parents(package_root, true)
                .is_ignore()
        {
            let manifest = read_package_manifest(&manifest_path)?;
            packages.push(WorkspacePackage {
                root: relative_root,
                manifest_path,
                manifest,
            });
        }
    }
    packages.sort_by(|left, right| left.root.cmp(&right.root));
    reject_duplicate_package_names(&packages)?;

    Ok(WorkspaceDiscovery {
        display_root: requested_root.to_path_buf(),
        requested_physical_root,
        workspace_root,
        controlling_manifest,
        package_manager,
        pattern_source,
        workspace_patterns,
        packages,
    })
}

#[must_use]
pub fn find_nearest_package_manifest(start: &Path) -> Option<PathBuf> {
    let mut directory = if start.is_dir() {
        start
    } else {
        start.parent()?
    };
    loop {
        let candidate = directory.join(PACKAGE_MANIFEST);
        if candidate.is_file() {
            return Some(candidate);
        }
        directory = directory.parent()?;
    }
}

fn workspace_matcher(root: &Path, patterns: &[String]) -> Result<Gitignore, WorkspaceError> {
    let mut builder = GitignoreBuilder::new(root);
    for pattern in patterns {
        let normalized = pattern
            .strip_prefix("./")
            .unwrap_or(pattern)
            .trim_end_matches('/');
        builder
            .add_line(None, normalized)
            .map_err(|source| WorkspaceError::WorkspacePattern {
                pattern: pattern.clone(),
                source,
            })?;
    }
    builder
        .build()
        .map_err(|source| WorkspaceError::WorkspacePattern {
            pattern: patterns.join(", "),
            source,
        })
}

fn collect_package_manifests(root: &Path) -> Result<Vec<PathBuf>, WorkspaceError> {
    let mut manifests = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(&directory).map_err(|source| WorkspaceError::Inspect {
            path: directory.clone(),
            source,
        })?;
        let mut entries =
            entries
                .collect::<Result<Vec<_>, _>>()
                .map_err(|source| WorkspaceError::Inspect {
                    path: directory.clone(),
                    source,
                })?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries.into_iter().rev() {
            let path = entry.path();
            let metadata =
                fs::symlink_metadata(&path).map_err(|source| WorkspaceError::Inspect {
                    path: path.clone(),
                    source,
                })?;
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                if !SKIPPED_PACKAGE_DIRECTORIES
                    .iter()
                    .any(|name| entry.file_name() == OsStr::new(name))
                {
                    pending.push(path);
                }
            } else if metadata.is_file() && entry.file_name() == OsStr::new(PACKAGE_MANIFEST) {
                manifests.push(path);
            }
        }
    }
    Ok(manifests)
}

fn reject_duplicate_package_names(packages: &[WorkspacePackage]) -> Result<(), WorkspaceError> {
    let mut names = BTreeMap::new();
    for package in packages {
        let Some(name) = &package.manifest.name else {
            continue;
        };
        if let Some(first) = names.insert(name, &package.manifest_path) {
            return Err(WorkspaceError::DuplicatePackageName {
                name: name.clone(),
                first: first.clone(),
                second: package.manifest_path.clone(),
            });
        }
    }
    Ok(())
}

fn detect_package_manager(root: &Path, manifest: &PackageManifest) -> PackageManagerDetection {
    let lockfile_names = [
        ("package-lock.json", LockfileKind::Npm, PackageManager::Npm),
        (
            "npm-shrinkwrap.json",
            LockfileKind::Npm,
            PackageManager::Npm,
        ),
        ("pnpm-lock.yaml", LockfileKind::Pnpm, PackageManager::Pnpm),
        ("yarn.lock", LockfileKind::Yarn, PackageManager::Yarn),
        ("bun.lock", LockfileKind::BunText, PackageManager::Bun),
        ("bun.lockb", LockfileKind::BunBinary, PackageManager::Bun),
    ];
    let mut lockfiles = Vec::new();
    let mut candidates = BTreeSet::new();
    for (name, kind, manager) in lockfile_names {
        let path = root.join(name);
        if path.is_file() {
            lockfiles.push(LockfileEvidence {
                path: PathBuf::from(name),
                kind,
            });
            candidates.insert(manager);
        }
    }
    if root.join(PNPM_WORKSPACE).is_file() {
        candidates.insert(PackageManager::Pnpm);
    }

    let yarn_plug_and_play = [".pnp.cjs", ".pnp.loader.mjs"]
        .into_iter()
        .filter(|name| root.join(name).is_file())
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    if !yarn_plug_and_play.is_empty() {
        candidates.insert(PackageManager::Yarn);
    }

    let declared = manifest.package_manager.clone();
    let selected = declared
        .as_deref()
        .map(PackageManager::from_package_manager_field)
        .or_else(|| {
            if candidates.len() == 1 {
                candidates.iter().next().cloned()
            } else {
                None
            }
        });
    let conflicting_candidates = candidates
        .into_iter()
        .filter(|candidate| selected.as_ref() != Some(candidate))
        .collect();

    PackageManagerDetection {
        selected,
        declared,
        lockfiles,
        conflicting_candidates,
        yarn_plug_and_play,
    }
}

fn read_pnpm_workspace_patterns(path: &Path) -> Result<Vec<String>, WorkspaceError> {
    let source = fs::read_to_string(path).map_err(|source| WorkspaceError::Inspect {
        path: path.to_path_buf(),
        source,
    })?;
    parse_pnpm_workspace_patterns(&source).map_err(|message| WorkspaceError::PnpmWorkspace {
        path: path.to_path_buf(),
        message,
    })
}

fn parse_pnpm_workspace_patterns(source: &str) -> Result<Vec<String>, String> {
    let mut packages_indent = None;
    let mut patterns = Vec::new();
    for (index, raw_line) in source.lines().enumerate() {
        let without_comment = strip_yaml_comment(raw_line);
        let line = without_comment.trim_end();
        if line.trim().is_empty() {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let trimmed = line.trim_start();
        if packages_indent.is_none() {
            let Some(rest) = trimmed.strip_prefix("packages:") else {
                continue;
            };
            packages_indent = Some(indent);
            let inline = rest.trim();
            if !inline.is_empty() {
                patterns.extend(
                    parse_inline_yaml_array(inline)
                        .map_err(|message| format!("line {}: {message}", index + 1))?,
                );
            }
            continue;
        }

        let root_indent = packages_indent.expect("packages indentation exists");
        if indent <= root_indent {
            break;
        }
        let item = trimmed.strip_prefix('-').ok_or_else(|| {
            format!(
                "line {}: `packages` must contain only a sequence of string patterns",
                index + 1
            )
        })?;
        patterns.push(
            parse_yaml_scalar(item.trim())
                .map_err(|message| format!("line {}: {message}", index + 1))?,
        );
    }
    Ok(patterns)
}

fn parse_inline_yaml_array(value: &str) -> Result<Vec<String>, String> {
    let inner = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .ok_or_else(|| "inline `packages` must be a bracketed array".to_owned())?;
    if inner.trim().is_empty() {
        return Ok(Vec::new());
    }
    split_yaml_list(inner)
        .into_iter()
        .map(|item| parse_yaml_scalar(item.trim()))
        .collect()
}

fn split_yaml_list(value: &str) -> Vec<&str> {
    let mut items = Vec::new();
    let mut quote = None;
    let mut start = 0;
    for (index, character) in value.char_indices() {
        match character {
            '\'' | '"' if quote == Some(character) => quote = None,
            '\'' | '"' if quote.is_none() => quote = Some(character),
            ',' if quote.is_none() => {
                items.push(&value[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    items.push(&value[start..]);
    items
}

fn parse_yaml_scalar(value: &str) -> Result<String, String> {
    if value.is_empty() {
        return Err("workspace pattern cannot be empty".to_owned());
    }
    if value.starts_with('"') {
        return serde_json::from_str(value)
            .map_err(|error| format!("invalid quoted workspace pattern: {error}"));
    }
    if let Some(inner) = value
        .strip_prefix('\'')
        .and_then(|value| value.strip_suffix('\''))
    {
        return Ok(inner.replace("''", "'"));
    }
    if value.contains(['&', '{', '}', '[', ']']) {
        return Err(
            "dynamic or structured YAML is not supported for workspace patterns".to_owned(),
        );
    }
    Ok(value.to_owned())
}

fn strip_yaml_comment(line: &str) -> &str {
    let mut quote = None;
    for (index, character) in line.char_indices() {
        match character {
            '\'' | '"' if quote == Some(character) => quote = None,
            '\'' | '"' if quote.is_none() => quote = Some(character),
            '#' if quote.is_none() => return &line[..index],
            _ => {}
        }
    }
    line
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
        PackageManager, WorkspacePatternSource, discover_workspace, parse_pnpm_workspace_patterns,
    };

    static NEXT_PROJECT_ID: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn package_workspaces_are_expanded_and_owned_by_the_nearest_package() {
        let project = TestProject::new();
        project.write(
            "package.json",
            r#"{"name":"root","packageManager":"npm@11.0.0","workspaces":["packages/*"]}"#,
        );
        project.write("packages/a/package.json", r#"{"name":"a"}"#);
        project.write("packages/a/src/index.ts", "");
        project.write("unmatched/package.json", r#"{"name":"unmatched"}"#);

        let discovery = discover_workspace(project.path()).expect("discover workspace");

        assert_eq!(
            discovery.pattern_source,
            WorkspacePatternSource::PackageManifest
        );
        assert_eq!(
            discovery.package_manager.selected,
            Some(PackageManager::Npm)
        );
        assert_eq!(discovery.packages.len(), 2);
        assert_eq!(
            discovery
                .package_for_path(Path::new("packages/a/src/index.ts"))
                .and_then(|package| package.manifest.name.as_deref()),
            Some("a")
        );
        assert_eq!(
            discovery
                .package_for_path(Path::new("unmatched/index.ts"))
                .and_then(|package| package.manifest.name.as_deref()),
            Some("root")
        );
    }

    #[test]
    fn pnpm_patterns_override_manifest_patterns_and_apply_exclusions() {
        let project = TestProject::new();
        project.write(
            "package.json",
            r#"{"name":"root","workspaces":["wrong/*"]}"#,
        );
        project.write(
            "pnpm-workspace.yaml",
            "packages:\n  - 'packages/**'\n  - '!**/test/**'\n",
        );
        project.write("pnpm-lock.yaml", "");
        project.write("packages/a/package.json", r#"{"name":"a"}"#);
        project.write(
            "packages/test/fixture/package.json",
            r#"{"name":"fixture"}"#,
        );

        let discovery = discover_workspace(project.path()).expect("discover pnpm workspace");

        assert_eq!(
            discovery.pattern_source,
            WorkspacePatternSource::PnpmWorkspace
        );
        assert_eq!(
            discovery.package_manager.selected,
            Some(PackageManager::Pnpm)
        );
        assert_eq!(
            discovery
                .packages
                .iter()
                .filter_map(|package| package.manifest.name.as_deref())
                .collect::<Vec<_>>(),
            ["root", "a"]
        );
    }

    #[test]
    fn yarn_pnp_and_bun_lockfiles_are_visible_without_guessing_a_winner() {
        let project = TestProject::new();
        project.write("package.json", r#"{"name":"root"}"#);
        project.write(".pnp.cjs", "");
        project.write("yarn.lock", "");
        project.write("bun.lock", "");

        let discovery = discover_workspace(project.path()).expect("discover workspace");

        assert_eq!(discovery.package_manager.selected, None);
        assert_eq!(
            discovery.package_manager.conflicting_candidates,
            [PackageManager::Yarn, PackageManager::Bun]
        );
        assert_eq!(
            discovery.package_manager.yarn_plug_and_play,
            [PathBuf::from(".pnp.cjs")]
        );
    }

    #[test]
    fn pnpm_static_yaml_parser_supports_block_and_inline_arrays() {
        assert_eq!(
            parse_pnpm_workspace_patterns("packages:\n  - 'packages/*' # apps\n  - \"apps/**\"\n")
                .expect("block packages"),
            ["packages/*", "apps/**"]
        );
        assert_eq!(
            parse_pnpm_workspace_patterns("packages: ['packages/*', \"apps/*\"]\n")
                .expect("inline packages"),
            ["packages/*", "apps/*"]
        );
    }

    struct TestProject {
        root: PathBuf,
    }

    impl TestProject {
        fn new() -> Self {
            loop {
                let id = NEXT_PROJECT_ID.fetch_add(1, Ordering::Relaxed);
                let root = std::env::temp_dir()
                    .join(format!("orphanode-workspace-test-{}-{id}", process::id()));
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
