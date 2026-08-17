use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const DECLARATIVE_PLUGIN_API_VERSION: &str = "orphanode.plugin/v1";
pub const DECLARATIVE_PLUGIN_SCHEMA_URL: &str = "https://orphanode.dev/schema/plugin-v1.json";

const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_PATTERN_BYTES: usize = 1_024;
const MAX_REASON_BYTES: usize = 1_024;
const MAX_MESSAGE_BYTES: usize = 4_096;
const MAX_ITEMS_PER_FIELD: usize = 4_096;
const MAX_DIAGNOSTICS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeclarativePlugin {
    #[serde(rename = "$schema", default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    pub api_version: String,
    pub id: String,
    pub version: String,
    pub display_name: String,
    pub capabilities: Vec<PluginCapability>,
    pub detection: DetectionRules,
    pub contributions: PluginContributions,
    pub unsupported_cases: Vec<UnsupportedCase>,
}

impl DeclarativePlugin {
    pub fn canonicalize(&mut self) {
        sort_and_deduplicate(&mut self.capabilities);
        self.detection.canonicalize();
        self.contributions.canonicalize();
        sort_and_deduplicate(&mut self.unsupported_cases);
    }

    /// Validates the API version, canonical ordering, fact bounds, and paths.
    ///
    /// # Errors
    ///
    /// Returns the first contract violation. Callers must not merge any facts
    /// from a plugin that fails this validation.
    pub fn validate(&self) -> Result<(), PluginValidationError> {
        if let Some(schema) = &self.schema
            && schema != DECLARATIVE_PLUGIN_SCHEMA_URL
        {
            return Err(PluginValidationError::SchemaUrl {
                expected: DECLARATIVE_PLUGIN_SCHEMA_URL,
                actual: schema.clone(),
            });
        }
        if self.api_version != DECLARATIVE_PLUGIN_API_VERSION {
            return Err(PluginValidationError::ApiVersion {
                expected: DECLARATIVE_PLUGIN_API_VERSION,
                actual: self.api_version.clone(),
            });
        }
        validate_identifier("id", &self.id)?;
        validate_version(&self.version)?;
        validate_text("displayName", &self.display_name, MAX_REASON_BYTES)?;
        validate_sorted_unique("capabilities", &self.capabilities)?;
        if self.capabilities.is_empty() {
            return Err(PluginValidationError::EmptyField("capabilities"));
        }
        self.detection.validate()?;
        self.contributions.validate()?;
        self.validate_declared_capabilities()?;
        validate_sorted_unique("unsupportedCases", &self.unsupported_cases)?;
        if self.unsupported_cases.len() > MAX_DIAGNOSTICS {
            return Err(PluginValidationError::TooManyItems {
                field: "unsupportedCases",
                maximum: MAX_DIAGNOSTICS,
            });
        }
        for unsupported in &self.unsupported_cases {
            unsupported.validate()?;
        }
        Ok(())
    }

    fn validate_declared_capabilities(&self) -> Result<(), PluginValidationError> {
        for capability in self.contributions.used_capabilities() {
            if self.capabilities.binary_search(&capability).is_err() {
                return Err(PluginValidationError::UndeclaredCapability { capability });
            }
        }
        if self
            .capabilities
            .binary_search(&PluginCapability::Diagnostics)
            .is_err()
        {
            return Err(PluginValidationError::UndeclaredCapability {
                capability: PluginCapability::Diagnostics,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DetectionRules {
    #[serde(default)]
    pub package_names: Vec<String>,
    #[serde(default)]
    pub package_prefixes: Vec<String>,
    #[serde(default)]
    pub config_files: Vec<String>,
}

impl DetectionRules {
    fn canonicalize(&mut self) {
        sort_and_deduplicate(&mut self.package_names);
        sort_and_deduplicate(&mut self.package_prefixes);
        sort_and_deduplicate(&mut self.config_files);
    }

    fn validate(&self) -> Result<(), PluginValidationError> {
        validate_sorted_unique("detection.packageNames", &self.package_names)?;
        validate_sorted_unique("detection.packagePrefixes", &self.package_prefixes)?;
        validate_sorted_unique("detection.configFiles", &self.config_files)?;
        validate_count("detection.packageNames", self.package_names.len())?;
        validate_count("detection.packagePrefixes", self.package_prefixes.len())?;
        validate_count("detection.configFiles", self.config_files.len())?;
        for package in &self.package_names {
            validate_reference_name("detection.packageNames", package)?;
        }
        for prefix in &self.package_prefixes {
            validate_package_prefix(prefix)?;
        }
        for path in &self.config_files {
            validate_workspace_pattern(path)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginCapability {
    Entries,
    ProjectFiles,
    ConfigFiles,
    Exclusions,
    FileEdges,
    References,
    ExportRoots,
    MemberRoots,
    GeneratedFiles,
    DynamicImports,
    TargetConditions,
    FileTransforms,
    Diagnostics,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginContributions {
    #[serde(default)]
    pub entry_patterns: Vec<PatternContribution>,
    #[serde(default)]
    pub project_file_patterns: Vec<PatternContribution>,
    #[serde(default)]
    pub config_file_patterns: Vec<PatternContribution>,
    #[serde(default)]
    pub exclusion_patterns: Vec<PatternContribution>,
    #[serde(default)]
    pub generated_file_patterns: Vec<PatternContribution>,
    #[serde(default)]
    pub file_edges: Vec<FileEdgeContribution>,
    #[serde(default)]
    pub references: Vec<ReferenceContribution>,
    #[serde(default)]
    pub export_roots: Vec<ExportRootContribution>,
    #[serde(default)]
    pub member_roots: Vec<MemberRootContribution>,
    #[serde(default)]
    pub dynamic_imports: Vec<DynamicImportContribution>,
    #[serde(default)]
    pub target_conditions: Vec<String>,
    #[serde(default)]
    pub file_transforms: Vec<FileTransformContribution>,
    #[serde(default)]
    pub diagnostics: Vec<PluginDiagnostic>,
}

impl PluginContributions {
    pub fn canonicalize(&mut self) {
        sort_and_deduplicate(&mut self.entry_patterns);
        sort_and_deduplicate(&mut self.project_file_patterns);
        sort_and_deduplicate(&mut self.config_file_patterns);
        sort_and_deduplicate(&mut self.exclusion_patterns);
        sort_and_deduplicate(&mut self.generated_file_patterns);
        sort_and_deduplicate(&mut self.file_edges);
        sort_and_deduplicate(&mut self.references);
        sort_and_deduplicate(&mut self.export_roots);
        sort_and_deduplicate(&mut self.member_roots);
        sort_and_deduplicate(&mut self.dynamic_imports);
        sort_and_deduplicate(&mut self.target_conditions);
        for transform in &mut self.file_transforms {
            transform.canonicalize();
        }
        sort_and_deduplicate(&mut self.file_transforms);
        sort_and_deduplicate(&mut self.diagnostics);
    }

    /// Validates deterministic ordering and every contributed fact.
    ///
    /// # Errors
    ///
    /// Returns the first ordering, size, path, evidence, or diagnostic error.
    pub fn validate(&self) -> Result<(), PluginValidationError> {
        self.validate_pattern_fields()?;
        self.validate_evidence_fields()?;
        self.validate_protocol_fields()
    }

    #[must_use]
    pub fn is_empty_except_diagnostics(&self) -> bool {
        self.entry_patterns.is_empty()
            && self.project_file_patterns.is_empty()
            && self.config_file_patterns.is_empty()
            && self.exclusion_patterns.is_empty()
            && self.generated_file_patterns.is_empty()
            && self.file_edges.is_empty()
            && self.references.is_empty()
            && self.export_roots.is_empty()
            && self.member_roots.is_empty()
            && self.dynamic_imports.is_empty()
            && self.target_conditions.is_empty()
            && self.file_transforms.is_empty()
    }

    /// Returns the sorted capabilities exercised by the contained facts.
    #[must_use]
    pub fn used_capabilities(&self) -> Vec<PluginCapability> {
        let mut capabilities = Vec::new();
        push_if_present(
            &mut capabilities,
            PluginCapability::Entries,
            &self.entry_patterns,
        );
        push_if_present(
            &mut capabilities,
            PluginCapability::ProjectFiles,
            &self.project_file_patterns,
        );
        push_if_present(
            &mut capabilities,
            PluginCapability::ConfigFiles,
            &self.config_file_patterns,
        );
        push_if_present(
            &mut capabilities,
            PluginCapability::Exclusions,
            &self.exclusion_patterns,
        );
        push_if_present(
            &mut capabilities,
            PluginCapability::FileEdges,
            &self.file_edges,
        );
        push_if_present(
            &mut capabilities,
            PluginCapability::References,
            &self.references,
        );
        push_if_present(
            &mut capabilities,
            PluginCapability::ExportRoots,
            &self.export_roots,
        );
        push_if_present(
            &mut capabilities,
            PluginCapability::MemberRoots,
            &self.member_roots,
        );
        push_if_present(
            &mut capabilities,
            PluginCapability::GeneratedFiles,
            &self.generated_file_patterns,
        );
        push_if_present(
            &mut capabilities,
            PluginCapability::DynamicImports,
            &self.dynamic_imports,
        );
        push_if_present(
            &mut capabilities,
            PluginCapability::TargetConditions,
            &self.target_conditions,
        );
        push_if_present(
            &mut capabilities,
            PluginCapability::FileTransforms,
            &self.file_transforms,
        );
        push_if_present(
            &mut capabilities,
            PluginCapability::Diagnostics,
            &self.diagnostics,
        );
        capabilities.sort();
        capabilities
    }

    fn validate_pattern_fields(&self) -> Result<(), PluginValidationError> {
        validate_pattern_contributions("entryPatterns", &self.entry_patterns)?;
        validate_pattern_contributions("projectFilePatterns", &self.project_file_patterns)?;
        validate_pattern_contributions("configFilePatterns", &self.config_file_patterns)?;
        validate_pattern_contributions("exclusionPatterns", &self.exclusion_patterns)?;
        validate_pattern_contributions("generatedFilePatterns", &self.generated_file_patterns)?;
        Ok(())
    }

    fn validate_evidence_fields(&self) -> Result<(), PluginValidationError> {
        validate_ordered_items(
            "fileEdges",
            &self.file_edges,
            FileEdgeContribution::validate,
        )?;
        validate_ordered_items(
            "references",
            &self.references,
            ReferenceContribution::validate,
        )?;
        validate_ordered_items(
            "exportRoots",
            &self.export_roots,
            ExportRootContribution::validate,
        )?;
        validate_ordered_items(
            "memberRoots",
            &self.member_roots,
            MemberRootContribution::validate,
        )?;
        validate_ordered_items(
            "dynamicImports",
            &self.dynamic_imports,
            DynamicImportContribution::validate,
        )?;
        Ok(())
    }

    fn validate_protocol_fields(&self) -> Result<(), PluginValidationError> {
        validate_sorted_unique("targetConditions", &self.target_conditions)?;
        validate_count("targetConditions", self.target_conditions.len())?;
        for condition in &self.target_conditions {
            validate_identifier("targetConditions", condition)?;
        }
        validate_ordered_items(
            "fileTransforms",
            &self.file_transforms,
            FileTransformContribution::validate,
        )?;
        validate_sorted_unique("diagnostics", &self.diagnostics)?;
        if self.diagnostics.len() > MAX_DIAGNOSTICS {
            return Err(PluginValidationError::TooManyItems {
                field: "diagnostics",
                maximum: MAX_DIAGNOSTICS,
            });
        }
        for diagnostic in &self.diagnostics {
            diagnostic.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PatternContribution {
    pub pattern: String,
    pub reason: String,
}

impl PatternContribution {
    fn validate(&self) -> Result<(), PluginValidationError> {
        validate_workspace_pattern(&self.pattern)?;
        validate_reason(&self.reason)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileEdgeContribution {
    pub from_pattern: String,
    pub to_pattern: String,
    pub reason: String,
}

impl FileEdgeContribution {
    fn validate(&self) -> Result<(), PluginValidationError> {
        validate_workspace_pattern(&self.from_pattern)?;
        validate_workspace_pattern(&self.to_pattern)?;
        validate_reason(&self.reason)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceKind {
    Package,
    Binary,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReferenceContribution {
    pub name: String,
    pub kind: ReferenceKind,
    pub reason: String,
}

impl ReferenceContribution {
    fn validate(&self) -> Result<(), PluginValidationError> {
        validate_reference_name("references.name", &self.name)?;
        validate_reason(&self.reason)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExportRootContribution {
    pub module_pattern: String,
    pub export_name: String,
    pub reason: String,
}

impl ExportRootContribution {
    fn validate(&self) -> Result<(), PluginValidationError> {
        validate_workspace_pattern(&self.module_pattern)?;
        validate_symbol_name("exportRoots.exportName", &self.export_name)?;
        validate_reason(&self.reason)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemberRootContribution {
    pub module_pattern: String,
    pub export_name: String,
    pub member_name: String,
    pub reason: String,
}

impl MemberRootContribution {
    fn validate(&self) -> Result<(), PluginValidationError> {
        validate_workspace_pattern(&self.module_pattern)?;
        validate_symbol_name("memberRoots.exportName", &self.export_name)?;
        validate_symbol_name("memberRoots.memberName", &self.member_name)?;
        validate_reason(&self.reason)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DynamicImportContribution {
    pub importer_pattern: String,
    pub specifier_pattern: String,
    pub reason: String,
}

impl DynamicImportContribution {
    fn validate(&self) -> Result<(), PluginValidationError> {
        validate_workspace_pattern(&self.importer_pattern)?;
        validate_workspace_pattern(&self.specifier_pattern)?;
        validate_reason(&self.reason)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileTransformContribution {
    pub source_pattern: String,
    pub output_extensions: Vec<String>,
    pub reason: String,
}

impl FileTransformContribution {
    fn canonicalize(&mut self) {
        sort_and_deduplicate(&mut self.output_extensions);
    }

    fn validate(&self) -> Result<(), PluginValidationError> {
        validate_workspace_pattern(&self.source_pattern)?;
        validate_sorted_unique("fileTransforms.outputExtensions", &self.output_extensions)?;
        validate_count(
            "fileTransforms.outputExtensions",
            self.output_extensions.len(),
        )?;
        if self.output_extensions.is_empty() {
            return Err(PluginValidationError::EmptyField(
                "fileTransforms.outputExtensions",
            ));
        }
        for extension in &self.output_extensions {
            validate_extension(extension)?;
        }
        validate_reason(&self.reason)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginDiagnosticSeverity {
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginDiagnostic {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub code: String,
    pub severity: PluginDiagnosticSeverity,
    pub message: String,
    pub blocks_reachability: bool,
}

impl PluginDiagnostic {
    /// Validates a diagnostic's namespace, path, message, and fail-closed state.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed diagnostics or for a non-blocking error.
    pub fn validate(&self) -> Result<(), PluginValidationError> {
        validate_diagnostic_code(&self.code)?;
        validate_text("diagnostics.message", &self.message, MAX_MESSAGE_BYTES)?;
        if let Some(path) = &self.path {
            validate_workspace_pattern(path)?;
        }
        if self.severity == PluginDiagnosticSeverity::Error && !self.blocks_reachability {
            return Err(PluginValidationError::NonBlockingErrorDiagnostic {
                code: self.code.clone(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UnsupportedCase {
    pub code: String,
    pub summary: String,
    pub blocks_reachability: bool,
}

impl UnsupportedCase {
    fn validate(&self) -> Result<(), PluginValidationError> {
        validate_diagnostic_code(&self.code)?;
        validate_text("unsupportedCases.summary", &self.summary, MAX_MESSAGE_BYTES)?;
        if !self.blocks_reachability {
            return Err(PluginValidationError::NonBlockingUnsupportedCase {
                code: self.code.clone(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PluginValidationError {
    #[error("unsupported plugin schema URL `{actual}`; expected `{expected}`")]
    SchemaUrl {
        expected: &'static str,
        actual: String,
    },
    #[error("unsupported plugin API version `{actual}`; expected `{expected}`")]
    ApiVersion {
        expected: &'static str,
        actual: String,
    },
    #[error("`{0}` must not be empty")]
    EmptyField(&'static str),
    #[error("plugin detection must contain a package name, package prefix, or config file")]
    EmptyDetection,
    #[error("`{field}` contains invalid value `{value}`")]
    InvalidIdentifier { field: &'static str, value: String },
    #[error("plugin version `{0}` is not a supported semantic version")]
    InvalidVersion(String),
    #[error("workspace pattern `{pattern}` is invalid: {reason}")]
    InvalidPattern {
        pattern: String,
        reason: &'static str,
    },
    #[error("`{field}` must be sorted and contain no duplicates")]
    NonCanonicalOrder { field: &'static str },
    #[error("`{field}` contains more than {maximum} items")]
    TooManyItems { field: &'static str, maximum: usize },
    #[error("`{field}` contains invalid text")]
    InvalidText { field: &'static str },
    #[error("plugin facts use undeclared capability `{capability:?}`")]
    UndeclaredCapability { capability: PluginCapability },
    #[error("error diagnostic `{code}` must block reachability")]
    NonBlockingErrorDiagnostic { code: String },
    #[error("unsupported case `{code}` must block reachability")]
    NonBlockingUnsupportedCase { code: String },
    #[error("cannot canonicalize workspace root `{path}`: {message}")]
    WorkspaceRoot { path: PathBuf, message: String },
    #[error("cannot canonicalize plugin path `{path}`: {message}")]
    PluginPath { path: PathBuf, message: String },
    #[error("plugin path `{path}` escapes workspace root `{root}`")]
    PathOutsideWorkspace { root: PathBuf, path: PathBuf },
}

/// Validates the portable lexical workspace boundary for a path or glob.
///
/// # Errors
///
/// Returns an error for absolute, parent-relative, non-normalized, oversized,
/// or control-character-containing patterns.
pub fn validate_workspace_pattern(pattern: &str) -> Result<(), PluginValidationError> {
    if pattern.is_empty() {
        return Err(invalid_pattern(pattern, "pattern is empty"));
    }
    if pattern.len() > MAX_PATTERN_BYTES {
        return Err(invalid_pattern(pattern, "pattern is too long"));
    }
    if pattern.starts_with('/')
        || pattern.starts_with('\\')
        || pattern.as_bytes().get(1) == Some(&b':')
    {
        return Err(invalid_pattern(pattern, "absolute paths are not allowed"));
    }
    if pattern.contains(':') {
        return Err(invalid_pattern(
            pattern,
            "colons are not portable workspace-path characters",
        ));
    }
    if pattern.contains('\\') {
        return Err(invalid_pattern(
            pattern,
            "backslashes are not normalized path separators",
        ));
    }
    if pattern.chars().any(char::is_control) {
        return Err(invalid_pattern(
            pattern,
            "control characters are not allowed",
        ));
    }
    if pattern
        .split('/')
        .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(invalid_pattern(
            pattern,
            "empty, current-directory, and parent-directory components are not allowed",
        ));
    }
    Ok(())
}

/// Canonicalizes an existing literal path and proves physical root containment.
///
/// # Errors
///
/// Returns an error when the input is not a literal normalized relative path,
/// either path cannot be canonicalized, or a symlink escapes the workspace.
pub fn validate_workspace_path(
    workspace_root: &Path,
    relative_path: &str,
) -> Result<PathBuf, PluginValidationError> {
    validate_workspace_pattern(relative_path)?;
    if contains_glob_meta(relative_path) {
        return Err(invalid_pattern(
            relative_path,
            "a concrete path cannot contain glob metacharacters",
        ));
    }
    let canonical_root =
        workspace_root
            .canonicalize()
            .map_err(|error| PluginValidationError::WorkspaceRoot {
                path: workspace_root.to_path_buf(),
                message: error.to_string(),
            })?;
    let candidate = canonical_root.join(relative_path);
    let canonical_path =
        candidate
            .canonicalize()
            .map_err(|error| PluginValidationError::PluginPath {
                path: candidate.clone(),
                message: error.to_string(),
            })?;
    if !canonical_path.starts_with(&canonical_root) {
        return Err(PluginValidationError::PathOutsideWorkspace {
            root: canonical_root,
            path: canonical_path,
        });
    }
    Ok(canonical_path)
}

#[must_use]
pub(crate) fn contains_glob_meta(pattern: &str) -> bool {
    pattern
        .bytes()
        .any(|byte| matches!(byte, b'*' | b'?' | b'[' | b'{'))
}

pub(crate) fn validate_identifier(
    field: &'static str,
    value: &str,
) -> Result<(), PluginValidationError> {
    let valid = !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase);
    if valid {
        Ok(())
    } else {
        Err(PluginValidationError::InvalidIdentifier {
            field,
            value: value.to_owned(),
        })
    }
}

pub(crate) fn validate_reference_name(
    field: &'static str,
    value: &str,
) -> Result<(), PluginValidationError> {
    let valid = !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && !value.starts_with('.')
        && !value.contains('\\')
        && !value.chars().any(char::is_control)
        && !value.chars().any(char::is_whitespace);
    if valid {
        Ok(())
    } else {
        Err(PluginValidationError::InvalidIdentifier {
            field,
            value: value.to_owned(),
        })
    }
}

fn validate_pattern_contributions(
    field: &'static str,
    values: &[PatternContribution],
) -> Result<(), PluginValidationError> {
    validate_ordered_items(field, values, PatternContribution::validate)
}

fn validate_ordered_items<T>(
    field: &'static str,
    values: &[T],
    validate: impl Fn(&T) -> Result<(), PluginValidationError>,
) -> Result<(), PluginValidationError>
where
    T: Ord,
{
    validate_sorted_unique(field, values)?;
    validate_count(field, values.len())?;
    for value in values {
        validate(value)?;
    }
    Ok(())
}

fn validate_sorted_unique<T: Ord>(
    field: &'static str,
    values: &[T],
) -> Result<(), PluginValidationError> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        Err(PluginValidationError::NonCanonicalOrder { field })
    } else {
        Ok(())
    }
}

fn validate_count(field: &'static str, count: usize) -> Result<(), PluginValidationError> {
    if count > MAX_ITEMS_PER_FIELD {
        Err(PluginValidationError::TooManyItems {
            field,
            maximum: MAX_ITEMS_PER_FIELD,
        })
    } else {
        Ok(())
    }
}

pub(crate) fn validate_version(version: &str) -> Result<(), PluginValidationError> {
    let parts = version.split('.').collect::<Vec<_>>();
    let valid = parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (part.len() == 1 || !part.starts_with('0'))
        });
    if valid {
        Ok(())
    } else {
        Err(PluginValidationError::InvalidVersion(version.to_owned()))
    }
}

fn validate_package_prefix(prefix: &str) -> Result<(), PluginValidationError> {
    if !prefix.ends_with('/') || prefix.ends_with("//") {
        return Err(PluginValidationError::InvalidIdentifier {
            field: "detection.packagePrefixes",
            value: prefix.to_owned(),
        });
    }
    validate_reference_name("detection.packagePrefixes", prefix.trim_end_matches('/'))
}

fn validate_symbol_name(field: &'static str, name: &str) -> Result<(), PluginValidationError> {
    validate_text(field, name, MAX_IDENTIFIER_BYTES)
}

fn validate_extension(extension: &str) -> Result<(), PluginValidationError> {
    let valid = extension.starts_with('.')
        && extension.len() > 1
        && extension.len() <= 32
        && extension[1..]
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
    if valid {
        Ok(())
    } else {
        Err(PluginValidationError::InvalidIdentifier {
            field: "fileTransforms.outputExtensions",
            value: extension.to_owned(),
        })
    }
}

fn validate_diagnostic_code(code: &str) -> Result<(), PluginValidationError> {
    validate_identifier("diagnostic.code", code)?;
    if code.starts_with("plugin_") {
        Ok(())
    } else {
        Err(PluginValidationError::InvalidIdentifier {
            field: "diagnostic.code",
            value: code.to_owned(),
        })
    }
}

fn validate_reason(reason: &str) -> Result<(), PluginValidationError> {
    validate_text("reason", reason, MAX_REASON_BYTES)
}

fn validate_text(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), PluginValidationError> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        Err(PluginValidationError::InvalidText { field })
    } else {
        Ok(())
    }
}

fn invalid_pattern(pattern: &str, reason: &'static str) -> PluginValidationError {
    PluginValidationError::InvalidPattern {
        pattern: pattern.to_owned(),
        reason,
    }
}

fn sort_and_deduplicate<T: Ord>(items: &mut Vec<T>) {
    items.sort();
    items.dedup();
}

fn push_if_present<T>(
    capabilities: &mut Vec<PluginCapability>,
    capability: PluginCapability,
    items: &[T],
) {
    if !items.is_empty() {
        capabilities.push(capability);
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{
        DECLARATIVE_PLUGIN_API_VERSION, DeclarativePlugin, DetectionRules, PatternContribution,
        PluginCapability, PluginContributions, PluginDiagnostic, PluginDiagnosticSeverity,
        PluginValidationError, UnsupportedCase, validate_workspace_path,
        validate_workspace_pattern,
    };

    #[test]
    fn plugin_validation_requires_canonical_ordering() {
        let mut plugin = minimal_plugin();
        plugin.contributions.entry_patterns = vec![
            pattern("src/z.ts"),
            pattern("src/a.ts"),
            pattern("src/a.ts"),
        ];

        assert!(matches!(
            plugin.validate(),
            Err(PluginValidationError::NonCanonicalOrder {
                field: "entryPatterns"
            })
        ));

        plugin.canonicalize();
        plugin.validate().expect("canonical plugin");
        assert_eq!(plugin.contributions.entry_patterns.len(), 2);
    }

    #[test]
    fn patterns_reject_absolute_parent_and_platform_specific_paths() {
        for invalid in [
            "/root.ts",
            "../root.ts",
            "src/../root.ts",
            "C:/root.ts",
            "src\\root.ts",
        ] {
            assert!(validate_workspace_pattern(invalid).is_err(), "{invalid}");
        }
        validate_workspace_pattern("src/**/route.*").expect("safe normalized pattern");
    }

    #[cfg(unix)]
    #[test]
    fn physical_containment_rejects_a_symlink_escape() {
        use std::os::unix::fs::symlink;

        let temporary = std::env::temp_dir().join(format!(
            "orphanode-plugin-contract-test-{}",
            std::process::id()
        ));
        let workspace = temporary.join("workspace");
        let outside = temporary.join("outside");
        let _ = fs::remove_dir_all(&temporary);
        fs::create_dir_all(&workspace).expect("workspace");
        fs::create_dir_all(&outside).expect("outside");
        fs::write(outside.join("plugin.js"), "").expect("outside plugin");
        symlink(&outside, workspace.join("linked")).expect("symlink");

        let result = validate_workspace_path(&workspace, "linked/plugin.js");

        assert!(matches!(
            result,
            Err(PluginValidationError::PathOutsideWorkspace { .. })
        ));
        fs::remove_dir_all(&temporary).expect("cleanup");
    }

    #[test]
    fn error_diagnostics_must_fail_closed() {
        let diagnostic = PluginDiagnostic {
            path: Some("src/index.ts".to_owned()),
            code: "plugin_host_failure".to_owned(),
            severity: PluginDiagnosticSeverity::Error,
            message: "Plugin host failed".to_owned(),
            blocks_reachability: false,
        };

        assert!(matches!(
            diagnostic.validate(),
            Err(PluginValidationError::NonBlockingErrorDiagnostic { .. })
        ));
    }

    #[test]
    fn contributed_facts_require_a_declared_capability() {
        let mut plugin = minimal_plugin();
        plugin.capabilities = vec![PluginCapability::Diagnostics];
        plugin.contributions.entry_patterns = vec![pattern("src/index.ts")];

        assert!(matches!(
            plugin.validate(),
            Err(PluginValidationError::UndeclaredCapability {
                capability: PluginCapability::Entries
            })
        ));
    }

    fn minimal_plugin() -> DeclarativePlugin {
        DeclarativePlugin {
            schema: None,
            api_version: DECLARATIVE_PLUGIN_API_VERSION.to_owned(),
            id: "example".to_owned(),
            version: "1.0.0".to_owned(),
            display_name: "Example".to_owned(),
            capabilities: vec![PluginCapability::Entries, PluginCapability::Diagnostics],
            detection: DetectionRules {
                package_names: vec!["example".to_owned()],
                ..DetectionRules::default()
            },
            contributions: PluginContributions::default(),
            unsupported_cases: vec![UnsupportedCase {
                code: "plugin_example_dynamic_config".to_owned(),
                summary: "Executable configuration is not evaluated".to_owned(),
                blocks_reachability: true,
            }],
        }
    }

    fn pattern(value: &str) -> PatternContribution {
        PatternContribution {
            pattern: value.to_owned(),
            reason: "Test entry".to_owned(),
        }
    }
}
