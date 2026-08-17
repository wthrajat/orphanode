use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    ffi::OsStr,
    fs, io,
    path::{Component, Path, PathBuf},
};

use ignore::gitignore::GitignoreBuilder;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use super::manifest::{ManifestError, read_package_manifest};

const PROJECT_CONFIG_NAMES: [&str; 2] = ["tsconfig.json", "jsconfig.json"];
const SKIPPED_CONFIG_DIRECTORIES: [&str; 12] = [
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisMode {
    Fast,
    Balanced,
    Deep,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorldMode {
    Open,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceLevel {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetConfiguration {
    #[serde(default)]
    pub extends: Option<String>,
    #[serde(default)]
    pub conditions: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfidenceConfiguration {
    #[serde(default)]
    pub report: Option<ConfidenceLevel>,
    #[serde(default)]
    pub fail: Option<ConfidenceLevel>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetainRule {
    pub pattern: String,
    #[serde(default)]
    pub issues: BTreeSet<String>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IgnoreRule {
    pub pattern: String,
    pub reason: String,
}

/// A mergeable configuration fragment. `Option<Vec<_>>` deliberately
/// distinguishes an omitted list from an explicitly empty list at a higher
/// precedence layer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfigurationOverride {
    #[serde(default)]
    pub mode: Option<AnalysisMode>,
    #[serde(default)]
    pub world: Option<WorldMode>,
    #[serde(default)]
    pub targets: BTreeMap<String, TargetConfiguration>,
    #[serde(default)]
    pub plugins: Option<Vec<String>>,
    #[serde(default)]
    pub entry: Option<Vec<PathBuf>>,
    #[serde(default)]
    pub retain: Option<Vec<RetainRule>>,
    #[serde(default)]
    pub ignore: Option<Vec<IgnoreRule>>,
    #[serde(default)]
    pub confidence: Option<ConfidenceConfiguration>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OrphanodeConfiguration {
    pub schema: Option<String>,
    pub root: ConfigurationOverride,
    pub workspaces: BTreeMap<String, ConfigurationOverride>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SerializableOrphanodeConfiguration<'a> {
    #[serde(rename = "$schema", skip_serializing_if = "Option::is_none")]
    schema: &'a Option<String>,
    #[serde(flatten)]
    root: &'a ConfigurationOverride,
    workspaces: &'a BTreeMap<String, ConfigurationOverride>,
}

impl Serialize for OrphanodeConfiguration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        SerializableOrphanodeConfiguration {
            schema: &self.schema,
            root: &self.root,
            workspaces: &self.workspaces,
        }
        .serialize(serializer)
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawOrphanodeConfiguration {
    #[serde(default, rename = "$schema")]
    schema: Option<String>,
    #[serde(default)]
    mode: Option<AnalysisMode>,
    #[serde(default)]
    world: Option<WorldMode>,
    #[serde(default)]
    targets: BTreeMap<String, TargetConfiguration>,
    #[serde(default)]
    plugins: Option<Vec<String>>,
    #[serde(default)]
    entry: Option<Vec<PathBuf>>,
    #[serde(default)]
    retain: Option<Vec<RetainRule>>,
    #[serde(default)]
    ignore: Option<Vec<IgnoreRule>>,
    #[serde(default)]
    confidence: Option<ConfidenceConfiguration>,
    #[serde(default)]
    workspaces: BTreeMap<String, ConfigurationOverride>,
}

impl<'de> Deserialize<'de> for OrphanodeConfiguration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawOrphanodeConfiguration::deserialize(deserializer)?;
        Ok(Self {
            schema: raw.schema,
            root: ConfigurationOverride {
                mode: raw.mode,
                world: raw.world,
                targets: raw.targets,
                plugins: raw.plugins,
                entry: raw.entry,
                retain: raw.retain,
                ignore: raw.ignore,
                confidence: raw.confidence,
            },
            workspaces: raw.workspaces,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ConfigurationLayers<'a> {
    pub inferred: &'a ConfigurationOverride,
    pub root: &'a ConfigurationOverride,
    pub workspace: &'a ConfigurationOverride,
    pub cli: &'a ConfigurationOverride,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StaticConfigurationSourceKind {
    PackageManifest,
    OrphanodeJsonc,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StaticConfigurationSource {
    pub kind: StaticConfigurationSourceKind,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoadedOrphanodeConfiguration {
    /// Ordered from lower to higher precedence. A dedicated JSONC file refines
    /// an `orphanode` package-manifest object when both are present.
    pub sources: Vec<StaticConfigurationSource>,
    pub configuration: OrphanodeConfiguration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StaleRetainRule {
    pub index: usize,
    pub pattern: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StaleIgnoreRule {
    pub index: usize,
    pub pattern: String,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectConfigurationKind {
    JavaScript,
    TypeScript,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigurationReferenceTarget {
    Local(PathBuf),
    Package(String),
    Missing(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigurationReference {
    pub specifier: String,
    pub target: ConfigurationReferenceTarget,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectConfiguration {
    pub path: PathBuf,
    pub root: PathBuf,
    pub kind: ProjectConfigurationKind,
    pub extends: Option<ConfigurationReference>,
    pub references: Vec<ConfigurationReference>,
    pub files: Vec<String>,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub root_dir: Option<PathBuf>,
    pub out_dir: Option<PathBuf>,
    pub dependency_evidence: Vec<ConfigurationDependencyEvidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigurationDependencyKind {
    Extends,
    Types,
    JsxImportSource,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigurationDependencyEvidence {
    pub kind: ConfigurationDependencyKind,
    pub specifier: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawProjectConfiguration {
    #[serde(default)]
    extends: Option<String>,
    #[serde(default)]
    references: Vec<RawProjectReference>,
    #[serde(default)]
    files: Vec<String>,
    #[serde(default)]
    include: Vec<String>,
    #[serde(default)]
    exclude: Vec<String>,
    #[serde(default)]
    compiler_options: RawCompilerOptions,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawCompilerOptions {
    #[serde(default)]
    root_dir: Option<String>,
    #[serde(default)]
    out_dir: Option<String>,
    #[serde(default)]
    types: Vec<String>,
    #[serde(default)]
    jsx_import_source: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawProjectReference {
    path: String,
}

#[derive(Debug, Error)]
pub enum ConfigurationError {
    #[error("cannot read configuration `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("invalid JSONC in `{path}`: {message}")]
    Jsonc { path: PathBuf, message: String },

    #[error("invalid static configuration `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("configuration rule `{pattern}` must provide a non-empty reason")]
    MissingRuleReason { pattern: String },

    #[error("configuration rule pattern must not be empty")]
    EmptyRulePattern,

    #[error("configuration path `{path}` escapes workspace root `{root}`")]
    PathOutsideWorkspace { root: PathBuf, path: PathBuf },

    #[error("invalid retain pattern `{pattern}`: {source}")]
    RetainPattern {
        pattern: String,
        #[source]
        source: ignore::Error,
    },

    #[error("invalid ignore pattern `{pattern}`: {source}")]
    IgnorePattern {
        pattern: String,
        #[source]
        source: ignore::Error,
    },

    #[error("unknown retain issue family `{0}`")]
    UnknownRetainIssue(String),

    #[error("project configuration inheritance contains a cycle at `{0}`")]
    ProjectConfigurationCycle(PathBuf),

    #[error("target profile `{target}` extends unknown profile `{parent}`")]
    UnknownTargetProfile { target: String, parent: String },

    #[error("target profile inheritance contains a cycle at `{0}`")]
    TargetProfileCycle(String),

    #[error("target profile or condition `{0}` is empty or contains control characters")]
    InvalidTargetName(String),

    #[error(transparent)]
    Manifest(#[from] ManifestError),
}

/// Loads only static configuration. Package data is the lower-precedence source
/// and `orphanode.jsonc` is the higher-precedence source when both exist.
///
/// # Errors
///
/// Returns an error for unreadable, malformed, unknown, or unsafe static data.
pub fn load_orphanode_configuration(
    package_root: &Path,
) -> Result<LoadedOrphanodeConfiguration, ConfigurationError> {
    let package_path = package_root.join("package.json");
    let jsonc_path = package_root.join("orphanode.jsonc");
    let mut loaded = LoadedOrphanodeConfiguration::default();

    if package_path.is_file() {
        let manifest = read_package_manifest(&package_path)?;
        if let Some(value) = manifest.orphanode {
            let package_configuration = serde_json::from_value::<OrphanodeConfiguration>(value)
                .map_err(|source| ConfigurationError::Parse {
                    path: package_path.clone(),
                    source,
                })?;
            validate_orphanode_configuration(&package_configuration)?;
            loaded.sources.push(StaticConfigurationSource {
                kind: StaticConfigurationSourceKind::PackageManifest,
                path: package_path,
            });
            loaded.configuration = package_configuration;
        }
    }

    if jsonc_path.is_file() {
        let file_configuration = read_jsonc::<OrphanodeConfiguration>(&jsonc_path)?;
        validate_orphanode_configuration(&file_configuration)?;
        loaded.sources.push(StaticConfigurationSource {
            kind: StaticConfigurationSourceKind::OrphanodeJsonc,
            path: jsonc_path,
        });
        loaded.configuration.root = merge_configuration_layers(ConfigurationLayers {
            inferred: &loaded.configuration.root,
            root: &ConfigurationOverride::default(),
            workspace: &ConfigurationOverride::default(),
            cli: &file_configuration.root,
        });
        for (workspace, configuration) in file_configuration.workspaces {
            if let Some(existing) = loaded.configuration.workspaces.get_mut(&workspace) {
                merge_override(existing, &configuration);
            } else {
                loaded
                    .configuration
                    .workspaces
                    .insert(workspace, configuration);
            }
        }
        if file_configuration.schema.is_some() {
            loaded.configuration.schema = file_configuration.schema;
        }
    }

    Ok(loaded)
}

/// Applies the documented precedence: CLI > workspace > root > inferred.
#[must_use]
pub fn merge_configuration_layers(layers: ConfigurationLayers<'_>) -> ConfigurationOverride {
    let mut effective = layers.inferred.clone();
    merge_override(&mut effective, layers.root);
    merge_override(&mut effective, layers.workspace);
    merge_override(&mut effective, layers.cli);
    effective
}

fn merge_override(effective: &mut ConfigurationOverride, higher: &ConfigurationOverride) {
    if higher.mode.is_some() {
        effective.mode = higher.mode;
    }
    if higher.world.is_some() {
        effective.world = higher.world;
    }
    for (name, target) in &higher.targets {
        effective.targets.insert(name.clone(), target.clone());
    }
    if higher.plugins.is_some() {
        effective.plugins.clone_from(&higher.plugins);
    }
    if higher.entry.is_some() {
        effective.entry.clone_from(&higher.entry);
    }
    if higher.retain.is_some() {
        effective.retain.clone_from(&higher.retain);
    }
    if higher.ignore.is_some() {
        effective.ignore.clone_from(&higher.ignore);
    }
    if let Some(higher_confidence) = &higher.confidence {
        let confidence = effective
            .confidence
            .get_or_insert_with(ConfidenceConfiguration::default);
        if higher_confidence.report.is_some() {
            confidence.report = higher_confidence.report;
        }
        if higher_confidence.fail.is_some() {
            confidence.fail = higher_confidence.fail;
        }
    }
}

/// Reports retain rules that match none of the supplied workspace-relative
/// paths. The caller controls whether generated or excluded files participate.
///
/// # Errors
///
/// Returns an error for an invalid pattern or a path outside the workspace.
pub fn stale_retain_rules(
    workspace_root: &Path,
    rules: &[RetainRule],
    candidate_paths: &[PathBuf],
) -> Result<Vec<StaleRetainRule>, ConfigurationError> {
    let mut stale = Vec::new();
    for (index, rule) in rules.iter().enumerate() {
        let mut builder = GitignoreBuilder::new(workspace_root);
        builder.add_line(None, &rule.pattern).map_err(|source| {
            ConfigurationError::RetainPattern {
                pattern: rule.pattern.clone(),
                source,
            }
        })?;
        let matcher = builder
            .build()
            .map_err(|source| ConfigurationError::RetainPattern {
                pattern: rule.pattern.clone(),
                source,
            })?;
        for candidate in candidate_paths {
            if (candidate.is_absolute() && !candidate.starts_with(workspace_root))
                || (!candidate.is_absolute() && !is_safe_relative_path(candidate))
            {
                return Err(ConfigurationError::PathOutsideWorkspace {
                    root: workspace_root.to_path_buf(),
                    path: candidate.clone(),
                });
            }
        }
        let has_match = candidate_paths.iter().any(|candidate| {
            let path = if candidate.is_absolute() {
                candidate.clone()
            } else {
                workspace_root.join(candidate)
            };
            matcher.matched_path_or_any_parents(path, false).is_ignore()
        });
        if !has_match {
            stale.push(StaleRetainRule {
                index,
                pattern: rule.pattern.clone(),
                reason: rule.reason.clone(),
            });
        }
    }
    Ok(stale)
}

/// Reports ignore rules that match none of the supplied pre-ignore paths.
///
/// # Errors
///
/// Returns an error for an invalid pattern or a path outside the workspace.
pub fn stale_ignore_rules(
    workspace_root: &Path,
    rules: &[IgnoreRule],
    candidate_paths: &[PathBuf],
) -> Result<Vec<StaleIgnoreRule>, ConfigurationError> {
    let mut stale = Vec::new();
    for (index, rule) in rules.iter().enumerate() {
        let mut builder = GitignoreBuilder::new(workspace_root);
        builder.add_line(None, &rule.pattern).map_err(|source| {
            ConfigurationError::IgnorePattern {
                pattern: rule.pattern.clone(),
                source,
            }
        })?;
        let matcher = builder
            .build()
            .map_err(|source| ConfigurationError::IgnorePattern {
                pattern: rule.pattern.clone(),
                source,
            })?;
        validate_rule_candidate_paths(workspace_root, candidate_paths)?;
        let has_match = candidate_paths.iter().any(|candidate| {
            let path = if candidate.is_absolute() {
                candidate.clone()
            } else {
                workspace_root.join(candidate)
            };
            matcher.matched_path_or_any_parents(path, false).is_ignore()
        });
        if !has_match {
            stale.push(StaleIgnoreRule {
                index,
                pattern: rule.pattern.clone(),
                reason: rule.reason.clone(),
            });
        }
    }
    Ok(stale)
}

fn validate_rule_candidate_paths(
    workspace_root: &Path,
    candidate_paths: &[PathBuf],
) -> Result<(), ConfigurationError> {
    for candidate in candidate_paths {
        if (candidate.is_absolute() && !candidate.starts_with(workspace_root))
            || (!candidate.is_absolute() && !is_safe_relative_path(candidate))
        {
            return Err(ConfigurationError::PathOutsideWorkspace {
                root: workspace_root.to_path_buf(),
                path: candidate.clone(),
            });
        }
    }
    Ok(())
}

/// Discovers base `tsconfig.json` and `jsconfig.json` files and follows local
/// `extends` and project-reference edges. Package-based `extends` values are
/// recorded as evidence but are not executed or resolved through installed code.
///
/// # Errors
///
/// Returns an error for unreadable or malformed JSONC and unsafe project paths.
#[allow(clippy::too_many_lines)]
pub fn discover_project_configurations(
    workspace_root: &Path,
) -> Result<Vec<ProjectConfiguration>, ConfigurationError> {
    let physical_root =
        workspace_root
            .canonicalize()
            .map_err(|source| ConfigurationError::Read {
                path: workspace_root.to_path_buf(),
                source,
            })?;
    let mut initial = collect_base_project_configs(&physical_root)?;
    initial.sort();
    let mut pending = VecDeque::from(initial);
    let mut visited = BTreeSet::new();
    let mut configurations = Vec::new();

    while let Some(config_path) = pending.pop_front() {
        let physical_path =
            config_path
                .canonicalize()
                .map_err(|source| ConfigurationError::Read {
                    path: config_path.clone(),
                    source,
                })?;
        if !physical_path.starts_with(&physical_root) {
            return Err(ConfigurationError::PathOutsideWorkspace {
                root: physical_root,
                path: physical_path,
            });
        }
        if !visited.insert(physical_path.clone()) {
            continue;
        }
        let relative_path = physical_path
            .strip_prefix(&physical_root)
            .map_err(|_| ConfigurationError::PathOutsideWorkspace {
                root: physical_root.clone(),
                path: physical_path.clone(),
            })?
            .to_path_buf();
        let raw = read_jsonc::<RawProjectConfiguration>(&physical_path)?;
        let Some(containing_directory) = physical_path.parent() else {
            return Err(ConfigurationError::PathOutsideWorkspace {
                root: physical_root.clone(),
                path: physical_path,
            });
        };
        let extends = raw
            .extends
            .as_deref()
            .map(|specifier| {
                resolve_configuration_reference(
                    &physical_root,
                    containing_directory,
                    specifier,
                    ReferenceKind::Extends,
                )
            })
            .transpose()?;
        let mut references = raw
            .references
            .iter()
            .map(|reference| {
                resolve_configuration_reference(
                    &physical_root,
                    containing_directory,
                    &reference.path,
                    ReferenceKind::Project,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        references.sort_by(|left, right| left.specifier.cmp(&right.specifier));
        let root_dir = raw
            .compiler_options
            .root_dir
            .as_deref()
            .map(|path| normalize_compiler_directory(&physical_root, containing_directory, path))
            .transpose()?;
        let out_dir = raw
            .compiler_options
            .out_dir
            .as_deref()
            .map(|path| normalize_compiler_directory(&physical_root, containing_directory, path))
            .transpose()?;
        let mut dependency_evidence = Vec::new();
        if let Some(ConfigurationReference {
            target: ConfigurationReferenceTarget::Package(specifier),
            ..
        }) = &extends
        {
            dependency_evidence.push(ConfigurationDependencyEvidence {
                kind: ConfigurationDependencyKind::Extends,
                specifier: specifier.clone(),
            });
        }
        dependency_evidence.extend(raw.compiler_options.types.iter().map(|specifier| {
            ConfigurationDependencyEvidence {
                kind: ConfigurationDependencyKind::Types,
                specifier: specifier.clone(),
            }
        }));
        if let Some(specifier) = raw.compiler_options.jsx_import_source {
            dependency_evidence.push(ConfigurationDependencyEvidence {
                kind: ConfigurationDependencyKind::JsxImportSource,
                specifier,
            });
        }
        dependency_evidence.sort();
        dependency_evidence.dedup();

        if let Some(ConfigurationReference {
            target: ConfigurationReferenceTarget::Local(path),
            ..
        }) = &extends
        {
            pending.push_back(physical_root.join(path));
        }
        for reference in &references {
            if let ConfigurationReferenceTarget::Local(path) = &reference.target {
                pending.push_back(physical_root.join(path));
            }
        }

        let kind = if relative_path.file_name() == Some(OsStr::new("jsconfig.json")) {
            ProjectConfigurationKind::JavaScript
        } else {
            ProjectConfigurationKind::TypeScript
        };
        configurations.push(ProjectConfiguration {
            root: relative_path
                .parent()
                .unwrap_or_else(|| Path::new(""))
                .to_path_buf(),
            path: relative_path,
            kind,
            extends,
            references,
            files: raw.files,
            include: raw.include,
            exclude: raw.exclude,
            root_dir,
            out_dir,
            dependency_evidence,
        });
    }

    configurations.sort_by(|left, right| left.path.cmp(&right.path));
    apply_local_configuration_inheritance(&mut configurations)?;
    Ok(configurations)
}

fn apply_local_configuration_inheritance(
    configurations: &mut [ProjectConfiguration],
) -> Result<(), ConfigurationError> {
    let snapshot = configurations.to_vec();
    let indices = snapshot
        .iter()
        .enumerate()
        .map(|(index, configuration)| (configuration.path.clone(), index))
        .collect::<BTreeMap<_, _>>();
    for (index, configuration) in configurations.iter_mut().enumerate() {
        let mut visiting = BTreeSet::new();
        let inherited = inherited_configuration_values(index, &snapshot, &indices, &mut visiting)?;
        if configuration.root_dir.is_none() {
            configuration.root_dir = inherited.root_dir;
        }
        if configuration.out_dir.is_none() {
            configuration.out_dir = inherited.out_dir;
        }
        configuration
            .dependency_evidence
            .extend(inherited.dependency_evidence);
        configuration.dependency_evidence.sort();
        configuration.dependency_evidence.dedup();
    }
    Ok(())
}

#[derive(Default)]
struct InheritedConfigurationValues {
    root_dir: Option<PathBuf>,
    out_dir: Option<PathBuf>,
    dependency_evidence: Vec<ConfigurationDependencyEvidence>,
}

fn inherited_configuration_values(
    index: usize,
    configurations: &[ProjectConfiguration],
    indices: &BTreeMap<PathBuf, usize>,
    visiting: &mut BTreeSet<usize>,
) -> Result<InheritedConfigurationValues, ConfigurationError> {
    if !visiting.insert(index) {
        return Err(ConfigurationError::ProjectConfigurationCycle(
            configurations[index].path.clone(),
        ));
    }
    let configuration = &configurations[index];
    let mut values = InheritedConfigurationValues {
        root_dir: configuration.root_dir.clone(),
        out_dir: configuration.out_dir.clone(),
        dependency_evidence: configuration.dependency_evidence.clone(),
    };
    if let Some(ConfigurationReference {
        target: ConfigurationReferenceTarget::Local(parent),
        ..
    }) = &configuration.extends
        && let Some(parent_index) = indices.get(parent).copied()
    {
        let parent =
            inherited_configuration_values(parent_index, configurations, indices, visiting)?;
        if values.root_dir.is_none() {
            values.root_dir = parent.root_dir;
        }
        if values.out_dir.is_none() {
            values.out_dir = parent.out_dir;
        }
        values
            .dependency_evidence
            .extend(parent.dependency_evidence);
    }
    visiting.remove(&index);
    Ok(values)
}

/// Chooses the deepest config root. A `tsconfig` wins over a `jsconfig` in the
/// same directory, matching TypeScript project-root precedence.
#[must_use]
pub fn project_configuration_for_path<'a>(
    path: &Path,
    configurations: &'a [ProjectConfiguration],
) -> Option<&'a ProjectConfiguration> {
    configurations
        .iter()
        .filter(|configuration| path.starts_with(&configuration.root))
        .max_by_key(|configuration| (configuration.root.components().count(), configuration.kind))
}

fn validate_orphanode_configuration(
    configuration: &OrphanodeConfiguration,
) -> Result<(), ConfigurationError> {
    validate_override(&configuration.root)?;
    validate_target_map(&configuration.root.targets)?;
    for (workspace, workspace_configuration) in &configuration.workspaces {
        if !is_safe_relative_path(Path::new(workspace)) {
            return Err(ConfigurationError::PathOutsideWorkspace {
                root: PathBuf::from("."),
                path: PathBuf::from(workspace),
            });
        }
        validate_override(workspace_configuration)?;
        let mut targets = configuration.root.targets.clone();
        targets.extend(workspace_configuration.targets.clone());
        validate_target_map(&targets)?;
    }
    Ok(())
}

fn validate_target_map(
    targets: &BTreeMap<String, TargetConfiguration>,
) -> Result<(), ConfigurationError> {
    let mut resolved = BTreeSet::new();
    let mut visiting = BTreeSet::new();
    for target in targets.keys() {
        validate_target_name(target)?;
        validate_target_chain(target, targets, &mut visiting, &mut resolved)?;
    }
    for target in targets.values() {
        for condition in &target.conditions {
            validate_target_name(condition)?;
        }
    }
    Ok(())
}

fn validate_target_chain(
    target: &str,
    targets: &BTreeMap<String, TargetConfiguration>,
    visiting: &mut BTreeSet<String>,
    resolved: &mut BTreeSet<String>,
) -> Result<(), ConfigurationError> {
    if resolved.contains(target) {
        return Ok(());
    }
    if !visiting.insert(target.to_owned()) {
        return Err(ConfigurationError::TargetProfileCycle(target.to_owned()));
    }
    if let Some(parent) = targets
        .get(target)
        .and_then(|configuration| configuration.extends.as_deref())
    {
        validate_target_name(parent)?;
        if targets.contains_key(parent) {
            validate_target_chain(parent, targets, visiting, resolved)?;
        } else if !is_builtin_target(parent) {
            return Err(ConfigurationError::UnknownTargetProfile {
                target: target.to_owned(),
                parent: parent.to_owned(),
            });
        }
    }
    visiting.remove(target);
    resolved.insert(target.to_owned());
    Ok(())
}

fn validate_target_name(name: &str) -> Result<(), ConfigurationError> {
    if name.trim().is_empty() || name.chars().any(char::is_control) {
        Err(ConfigurationError::InvalidTargetName(name.to_owned()))
    } else {
        Ok(())
    }
}

fn is_builtin_target(name: &str) -> bool {
    matches!(
        name,
        "node"
            | "production"
            | "worker"
            | "browser"
            | "bundler"
            | "types"
            | "cli"
            | "test"
            | "development"
    )
}

fn validate_override(configuration: &ConfigurationOverride) -> Result<(), ConfigurationError> {
    for entry in configuration.entry.iter().flatten() {
        if !is_safe_relative_path(entry) {
            return Err(ConfigurationError::PathOutsideWorkspace {
                root: PathBuf::from("."),
                path: entry.clone(),
            });
        }
    }
    for rule in configuration.retain.iter().flatten() {
        if rule.pattern.trim().is_empty() {
            return Err(ConfigurationError::EmptyRulePattern);
        }
        if rule.reason.trim().is_empty() {
            return Err(ConfigurationError::MissingRuleReason {
                pattern: rule.pattern.clone(),
            });
        }
        validate_gitignore_pattern(&rule.pattern).map_err(|source| {
            ConfigurationError::RetainPattern {
                pattern: rule.pattern.clone(),
                source,
            }
        })?;
        for issue in &rule.issues {
            if !matches!(
                issue.as_str(),
                "files" | "exports" | "declarations" | "members" | "dependencies" | "workspaces"
            ) {
                return Err(ConfigurationError::UnknownRetainIssue(issue.clone()));
            }
        }
    }
    for rule in configuration.ignore.iter().flatten() {
        if rule.pattern.trim().is_empty() {
            return Err(ConfigurationError::EmptyRulePattern);
        }
        if rule.reason.trim().is_empty() {
            return Err(ConfigurationError::MissingRuleReason {
                pattern: rule.pattern.clone(),
            });
        }
        validate_gitignore_pattern(&rule.pattern).map_err(|source| {
            ConfigurationError::IgnorePattern {
                pattern: rule.pattern.clone(),
                source,
            }
        })?;
    }
    Ok(())
}

fn validate_gitignore_pattern(pattern: &str) -> Result<(), ignore::Error> {
    let mut builder = GitignoreBuilder::new(".");
    builder.add_line(None, pattern)?;
    builder.build().map(|_| ())
}

fn is_safe_relative_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && !path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
}

fn collect_base_project_configs(root: &Path) -> Result<Vec<PathBuf>, ConfigurationError> {
    let mut configurations = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(&directory).map_err(|source| ConfigurationError::Read {
            path: directory.clone(),
            source,
        })?;
        let mut entries =
            entries
                .collect::<Result<Vec<_>, _>>()
                .map_err(|source| ConfigurationError::Read {
                    path: directory.clone(),
                    source,
                })?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries.into_iter().rev() {
            let path = entry.path();
            let metadata =
                fs::symlink_metadata(&path).map_err(|source| ConfigurationError::Read {
                    path: path.clone(),
                    source,
                })?;
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                if !SKIPPED_CONFIG_DIRECTORIES
                    .iter()
                    .any(|name| entry.file_name() == OsStr::new(name))
                {
                    pending.push(path);
                }
            } else if metadata.is_file()
                && PROJECT_CONFIG_NAMES
                    .iter()
                    .any(|name| entry.file_name() == OsStr::new(name))
            {
                configurations.push(path);
            }
        }
    }
    Ok(configurations)
}

#[derive(Debug, Clone, Copy)]
enum ReferenceKind {
    Extends,
    Project,
}

fn resolve_configuration_reference(
    workspace_root: &Path,
    containing_directory: &Path,
    specifier: &str,
    kind: ReferenceKind,
) -> Result<ConfigurationReference, ConfigurationError> {
    if !specifier.starts_with('.') && !Path::new(specifier).is_absolute() {
        return Ok(ConfigurationReference {
            specifier: specifier.to_owned(),
            target: ConfigurationReferenceTarget::Package(specifier.to_owned()),
        });
    }
    let requested = containing_directory.join(specifier);
    let candidates = reference_candidates(&requested, kind);
    let existing = candidates.iter().find(|candidate| candidate.is_file());
    let selected = existing.unwrap_or(&candidates[0]);
    let normalized = normalize_lexical_path(selected);
    if !normalized.starts_with(workspace_root) {
        return Err(ConfigurationError::PathOutsideWorkspace {
            root: workspace_root.to_path_buf(),
            path: normalized,
        });
    }
    let relative = normalized
        .strip_prefix(workspace_root)
        .expect("reference is within workspace")
        .to_path_buf();
    let target = if existing.is_some() {
        ConfigurationReferenceTarget::Local(relative)
    } else {
        ConfigurationReferenceTarget::Missing(relative)
    };
    Ok(ConfigurationReference {
        specifier: specifier.to_owned(),
        target,
    })
}

fn reference_candidates(path: &Path, kind: ReferenceKind) -> Vec<PathBuf> {
    if path.is_dir() {
        return vec![path.join("tsconfig.json")];
    }
    if path.extension().is_some() {
        return vec![path.to_path_buf()];
    }
    match kind {
        ReferenceKind::Extends => vec![path.with_extension("json"), path.join("tsconfig.json")],
        ReferenceKind::Project => vec![
            path.join("tsconfig.json"),
            path.to_path_buf(),
            path.with_extension("json"),
        ],
    }
}

fn normalize_compiler_directory(
    workspace_root: &Path,
    containing_directory: &Path,
    declared_path: &str,
) -> Result<PathBuf, ConfigurationError> {
    let path = Path::new(declared_path);
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        containing_directory.join(path)
    };
    let normalized = normalize_lexical_path(&candidate);
    if !normalized.starts_with(workspace_root) {
        return Err(ConfigurationError::PathOutsideWorkspace {
            root: workspace_root.to_path_buf(),
            path: normalized,
        });
    }
    Ok(normalized
        .strip_prefix(workspace_root)
        .expect("compiler directory is within workspace")
        .to_path_buf())
}

fn normalize_lexical_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

fn read_jsonc<T>(path: &Path) -> Result<T, ConfigurationError>
where
    T: for<'de> Deserialize<'de>,
{
    let source = fs::read_to_string(path).map_err(|source| ConfigurationError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let normalized = normalize_jsonc(&source).map_err(|message| ConfigurationError::Jsonc {
        path: path.to_path_buf(),
        message,
    })?;
    serde_json::from_str(&normalized).map_err(|source| ConfigurationError::Parse {
        path: path.to_path_buf(),
        source,
    })
}

pub(crate) fn parse_jsonc_value(source: &str) -> Result<serde_json::Value, String> {
    let normalized = normalize_jsonc(source)?;
    serde_json::from_str(&normalized).map_err(|error| error.to_string())
}

fn normalize_jsonc(source: &str) -> Result<String, String> {
    let mut without_comments = String::with_capacity(source.len());
    let mut characters = source.trim_start_matches('\u{feff}').chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    while let Some(character) = characters.next() {
        if in_string {
            without_comments.push(character);
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
            continue;
        }
        match character {
            '"' => {
                in_string = true;
                without_comments.push(character);
            }
            '/' if characters.peek() == Some(&'/') => {
                characters.next();
                for comment_character in characters.by_ref() {
                    if comment_character == '\n' {
                        without_comments.push('\n');
                        break;
                    }
                }
            }
            '/' if characters.peek() == Some(&'*') => {
                characters.next();
                let mut closed = false;
                let mut previous = '\0';
                for comment_character in characters.by_ref() {
                    if comment_character == '\n' {
                        without_comments.push('\n');
                    }
                    if previous == '*' && comment_character == '/' {
                        closed = true;
                        break;
                    }
                    previous = comment_character;
                }
                if !closed {
                    return Err("unterminated block comment".to_owned());
                }
            }
            _ => without_comments.push(character),
        }
    }
    if in_string {
        return Err("unterminated string literal".to_owned());
    }

    let characters = without_comments.chars().collect::<Vec<_>>();
    let mut normalized = String::with_capacity(without_comments.len());
    let mut in_string = false;
    let mut escaped = false;
    for (index, character) in characters.iter().copied().enumerate() {
        if in_string {
            normalized.push(character);
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
            continue;
        }
        if character == '"' {
            in_string = true;
            normalized.push(character);
            continue;
        }
        if character == ',' {
            let next = characters[index + 1..]
                .iter()
                .copied()
                .find(|candidate| !candidate.is_whitespace());
            if matches!(next, Some('}' | ']')) {
                continue;
            }
        }
        normalized.push(character);
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        fs,
        path::{Path, PathBuf},
        process,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::{
        AnalysisMode, ConfigurationError, ConfigurationLayers, ConfigurationOverride,
        ConfigurationReferenceTarget, IgnoreRule, ProjectConfigurationKind, RetainRule, WorldMode,
        discover_project_configurations, load_orphanode_configuration, merge_configuration_layers,
        project_configuration_for_path, stale_ignore_rules, stale_retain_rules,
    };

    static NEXT_PROJECT_ID: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn static_jsonc_refines_package_configuration_without_executing_code() {
        let project = TestProject::new();
        project.write(
            "package.json",
            r#"{"orphanode":{"mode":"fast","entry":["src/package.ts"],"workspaces":{"apps/web":{"plugins":["next"]}}}}"#,
        );
        project.write(
            "orphanode.jsonc",
            r#"{
                // dedicated files have higher precedence
                "mode": "balanced",
                "entry": ["src/file.ts",],
                "workspaces": {"apps/web": {"world": "closed"}},
            }"#,
        );

        let loaded = load_orphanode_configuration(project.path()).expect("load configuration");

        assert_eq!(loaded.sources.len(), 2);
        assert_eq!(loaded.configuration.root.mode, Some(AnalysisMode::Balanced));
        assert_eq!(
            loaded.configuration.root.entry,
            Some(vec![PathBuf::from("src/file.ts")])
        );
        let workspace = &loaded.configuration.workspaces["apps/web"];
        assert_eq!(workspace.world, Some(WorldMode::Closed));
        assert_eq!(workspace.plugins, Some(vec!["next".to_owned()]));
    }

    #[test]
    fn cli_overrides_workspace_root_and_inferred_configuration() {
        let inferred = ConfigurationOverride {
            mode: Some(AnalysisMode::Fast),
            world: Some(WorldMode::Open),
            ..ConfigurationOverride::default()
        };
        let root = ConfigurationOverride {
            mode: Some(AnalysisMode::Balanced),
            ..ConfigurationOverride::default()
        };
        let workspace = ConfigurationOverride {
            world: Some(WorldMode::Closed),
            entry: Some(vec![PathBuf::from("workspace.ts")]),
            ..ConfigurationOverride::default()
        };
        let cli = ConfigurationOverride {
            mode: Some(AnalysisMode::Deep),
            entry: Some(Vec::new()),
            ..ConfigurationOverride::default()
        };

        let effective = merge_configuration_layers(ConfigurationLayers {
            inferred: &inferred,
            root: &root,
            workspace: &workspace,
            cli: &cli,
        });

        assert_eq!(effective.mode, Some(AnalysisMode::Deep));
        assert_eq!(effective.world, Some(WorldMode::Closed));
        assert_eq!(effective.entry, Some(Vec::new()));
    }

    #[test]
    fn retain_rules_without_a_current_target_are_stale() {
        let rules = [
            RetainRule {
                pattern: "src/generated/**".to_owned(),
                issues: ["files".to_owned()].into_iter().collect(),
                reason: "generated API".to_owned(),
            },
            RetainRule {
                pattern: "src/removed/**".to_owned(),
                issues: BTreeSet::new(),
                reason: "old integration".to_owned(),
            },
        ];

        let stale = stale_retain_rules(
            Path::new("/workspace"),
            &rules,
            &[PathBuf::from("src/generated/client.ts")],
        )
        .expect("check retain rules");

        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].pattern, "src/removed/**");
    }

    #[test]
    fn ignore_rules_without_a_pre_ignore_target_are_stale() {
        let rules = [
            IgnoreRule {
                pattern: "src/generated/**".to_owned(),
                reason: "generated output".to_owned(),
            },
            IgnoreRule {
                pattern: "src/removed/**".to_owned(),
                reason: "old integration".to_owned(),
            },
        ];

        let stale = stale_ignore_rules(
            Path::new("/workspace"),
            &rules,
            &[PathBuf::from("src/generated/client.ts")],
        )
        .expect("check ignore rules");

        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].pattern, "src/removed/**");
    }

    #[test]
    fn configuration_rejects_unknown_retain_issue_families() {
        let project = TestProject::new();
        project.write("package.json", r#"{"name":"invalid-retain"}"#);
        project.write(
            "orphanode.jsonc",
            r#"{"retain":[{"pattern":"src/**","issues":["spelling"],"reason":"test"}]}"#,
        );

        assert!(matches!(
            load_orphanode_configuration(project.path()),
            Err(ConfigurationError::UnknownRetainIssue(issue)) if issue == "spelling"
        ));
    }

    #[test]
    fn configuration_rejects_invalid_ignore_globs() {
        let project = TestProject::new();
        project.write("package.json", r#"{"name":"invalid-ignore"}"#);
        project.write(
            "orphanode.jsonc",
            r#"{"ignore":[{"pattern":"[","reason":"test"}]}"#,
        );

        assert!(matches!(
            load_orphanode_configuration(project.path()),
            Err(ConfigurationError::IgnorePattern { .. })
        ));
    }

    #[test]
    fn project_configs_follow_extends_and_references_and_choose_nearest_owner() {
        let project = TestProject::new();
        project.write(
            "tsconfig.json",
            r#"{
                // solution configuration
                "files": [],
                "references": [{"path":"./packages/a"}],
            }"#,
        );
        project.write(
            "packages/a/tsconfig.json",
            r#"{
                "extends":"../../configs/base",
                "include":["src/**/*.ts"],
                "compilerOptions": {
                    "rootDir":"src",
                    "outDir":"../../dist/a",
                    "types":["node"],
                    "jsxImportSource":"react"
                }
            }"#,
        );
        project.write(
            "configs/base.json",
            r#"{"compilerOptions":{"strict":true}}"#,
        );
        project.write("packages/b/jsconfig.json", r#"{"include":["src/**/*.js"]}"#);

        let configurations =
            discover_project_configurations(project.path()).expect("discover project configs");
        let owner =
            project_configuration_for_path(Path::new("packages/a/src/index.ts"), &configurations)
                .expect("config owner");

        assert_eq!(owner.path, Path::new("packages/a/tsconfig.json"));
        assert_eq!(owner.kind, ProjectConfigurationKind::TypeScript);
        assert!(matches!(
            owner.extends.as_ref().map(|reference| &reference.target),
            Some(ConfigurationReferenceTarget::Local(path)) if path == Path::new("configs/base.json")
        ));
        assert_eq!(owner.root_dir, Some(PathBuf::from("packages/a/src")));
        assert_eq!(owner.out_dir, Some(PathBuf::from("dist/a")));
        assert_eq!(
            owner
                .dependency_evidence
                .iter()
                .map(|evidence| evidence.specifier.as_str())
                .collect::<Vec<_>>(),
            ["node", "react"]
        );
        assert!(configurations.iter().any(|configuration| {
            configuration.path == Path::new("packages/b/jsconfig.json")
                && configuration.kind == ProjectConfigurationKind::JavaScript
        }));
    }

    struct TestProject {
        root: PathBuf,
    }

    impl TestProject {
        fn new() -> Self {
            loop {
                let id = NEXT_PROJECT_ID.fetch_add(1, Ordering::Relaxed);
                let root = std::env::temp_dir()
                    .join(format!("orphanode-config-test-{}-{id}", process::id()));
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
