use std::{fs, path::Path};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::contract::{
    PluginCapability, PluginContributions, PluginDiagnostic, PluginDiagnosticSeverity,
    PluginValidationError, contains_glob_meta, validate_identifier, validate_reference_name,
    validate_version, validate_workspace_path, validate_workspace_pattern,
};

pub const EXECUTABLE_PLUGIN_PROTOCOL_VERSION: u32 = 1;

const MAX_ARGUMENTS: usize = 64;
const MAX_ARGUMENT_BYTES: usize = 4_096;
const MAX_TIMEOUT_MILLISECONDS: u64 = 300_000;
const MIN_RESPONSE_BYTES: u64 = 1_024;
const MAX_RESPONSE_BYTES: u64 = 16 * 1_024 * 1_024;
const MAX_HOST_FACTS: usize = 4_096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutablePluginConfig {
    pub id: String,
    pub version: String,
    pub executable: String,
    #[serde(default)]
    pub arguments: Vec<String>,
    pub trusted: bool,
    pub timeout_milliseconds: u64,
    pub max_response_bytes: u64,
}

impl ExecutablePluginConfig {
    /// Validates explicit trust, executable containment, and resource bounds.
    ///
    /// # Errors
    ///
    /// Returns an error when trust is absent, the executable escapes the
    /// workspace, or an argument/timeout/response bound is invalid.
    pub fn validate(&self, workspace_root: &Path) -> Result<(), HostValidationError> {
        validate_identifier("executablePlugin.id", &self.id)?;
        validate_version(&self.version)?;
        if !self.trusted {
            return Err(HostValidationError::UntrustedPlugin {
                plugin_id: self.id.clone(),
            });
        }
        let executable = validate_workspace_path(workspace_root, &self.executable)?;
        if !fs::metadata(&executable).is_ok_and(|metadata| metadata.is_file()) {
            return Err(HostValidationError::ExecutableIsNotFile {
                path: self.executable.clone(),
            });
        }
        validate_arguments(&self.arguments)?;
        if !(1..=MAX_TIMEOUT_MILLISECONDS).contains(&self.timeout_milliseconds) {
            return Err(HostValidationError::InvalidTimeout {
                value: self.timeout_milliseconds,
                maximum: MAX_TIMEOUT_MILLISECONDS,
            });
        }
        if !(MIN_RESPONSE_BYTES..=MAX_RESPONSE_BYTES).contains(&self.max_response_bytes) {
            return Err(HostValidationError::InvalidResponseLimit {
                value: self.max_response_bytes,
                minimum: MIN_RESPONSE_BYTES,
                maximum: MAX_RESPONSE_BYTES,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostRequest {
    pub protocol_version: u32,
    pub request_id: String,
    pub plugin_id: String,
    pub plugin_version: String,
    pub workspace_root: String,
    pub target_profile: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest: Option<HostManifestFacts>,
    #[serde(default)]
    pub config_files: Vec<HostConfigFact>,
    pub capabilities: Vec<PluginCapability>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostManifestFacts {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_type: Option<HostPackageType>,
    #[serde(default)]
    pub packages: Vec<HostPackageFact>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostPackageType {
    Module,
    CommonJs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostPackageKind {
    Dependency,
    Development,
    Peer,
    Optional,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostPackageFact {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub kind: HostPackageKind,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostConfigFact {
    pub path: String,
    pub format: HostConfigFormat,
    #[serde(default)]
    pub referenced_packages: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostConfigFormat {
    Json,
    JavaScript,
    TypeScript,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostResponse {
    pub protocol_version: u32,
    pub request_id: String,
    pub plugin_id: String,
    pub plugin_version: String,
    pub status: HostResponseStatus,
    #[serde(default)]
    pub contributions: PluginContributions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostResponseStatus {
    Complete,
    Incomplete,
    Failed,
}

/// Validates a deterministic request before it crosses the process boundary.
///
/// # Errors
///
/// Returns an error for a protocol mismatch, malformed identity/path facts, or
/// non-canonical collections.
pub fn validate_host_request(request: &HostRequest) -> Result<(), HostValidationError> {
    validate_protocol_version(request.protocol_version)?;
    validate_identifier("hostRequest.requestId", &request.request_id)?;
    validate_identifier("hostRequest.pluginId", &request.plugin_id)?;
    validate_version(&request.plugin_version)?;
    if request.workspace_root != "." {
        return Err(HostValidationError::InvalidWorkspaceRoot {
            value: request.workspace_root.clone(),
        });
    }
    validate_identifier("hostRequest.targetProfile", &request.target_profile)?;
    validate_sorted_unique("hostRequest.capabilities", &request.capabilities)?;
    if request.capabilities.is_empty() {
        return Err(HostValidationError::MissingCapabilities);
    }
    if let Some(manifest) = &request.manifest {
        validate_manifest_facts(manifest)?;
    }
    validate_host_count("hostRequest.configFiles", request.config_files.len())?;
    validate_sorted_unique("hostRequest.configFiles", &request.config_files)?;
    for config in &request.config_files {
        validate_config_fact(config)?;
    }
    Ok(())
}

/// Validates an executable response before any fact enters analysis.
///
/// # Errors
///
/// Returns an error for identity/protocol mismatches, invalid or escaping facts,
/// non-canonical ordering, or a failed/incomplete response that does not fail
/// closed. Callers should replace any error with [`host_failure_diagnostic`].
pub fn validate_host_response(
    workspace_root: &Path,
    request: &HostRequest,
    response: &HostResponse,
) -> Result<(), HostValidationError> {
    validate_host_request(request)?;
    validate_protocol_version(response.protocol_version)?;
    if response.request_id != request.request_id {
        return Err(HostValidationError::ResponseIdentity {
            field: "requestId",
            expected: request.request_id.clone(),
            actual: response.request_id.clone(),
        });
    }
    if response.plugin_id != request.plugin_id {
        return Err(HostValidationError::ResponseIdentity {
            field: "pluginId",
            expected: request.plugin_id.clone(),
            actual: response.plugin_id.clone(),
        });
    }
    validate_version(&response.plugin_version)?;
    if response.plugin_version != request.plugin_version {
        return Err(HostValidationError::ResponseIdentity {
            field: "pluginVersion",
            expected: request.plugin_version.clone(),
            actual: response.plugin_version.clone(),
        });
    }
    response.contributions.validate()?;
    validate_response_capabilities(request, response)?;
    validate_response_status(response)?;
    validate_response_paths(workspace_root, &response.contributions)?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostFailureKind {
    Spawn,
    Timeout,
    Crash,
    InvalidResponse,
    OversizedResponse,
}

#[must_use]
pub fn host_failure_diagnostic(kind: HostFailureKind) -> PluginDiagnostic {
    let (code, message) = match kind {
        HostFailureKind::Spawn => (
            "plugin_host_spawn_failure",
            "Executable plugin host could not be started",
        ),
        HostFailureKind::Timeout => (
            "plugin_host_timeout",
            "Executable plugin host exceeded its configured time limit",
        ),
        HostFailureKind::Crash => (
            "plugin_host_crash",
            "Executable plugin host exited without a complete response",
        ),
        HostFailureKind::InvalidResponse => (
            "plugin_host_invalid_response",
            "Executable plugin host returned an invalid or incompatible response",
        ),
        HostFailureKind::OversizedResponse => (
            "plugin_host_oversized_response",
            "Executable plugin host exceeded its configured response limit",
        ),
    };
    PluginDiagnostic {
        path: None,
        code: code.to_owned(),
        severity: PluginDiagnosticSeverity::Error,
        message: message.to_owned(),
        blocks_reachability: true,
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HostValidationError {
    #[error(transparent)]
    Plugin(#[from] PluginValidationError),
    #[error("executable plugin `{plugin_id}` requires explicit trust")]
    UntrustedPlugin { plugin_id: String },
    #[error("executable plugin path `{path}` is not a regular file")]
    ExecutableIsNotFile { path: String },
    #[error("executable plugin has more than {maximum} arguments")]
    TooManyArguments { maximum: usize },
    #[error("executable plugin argument {index} is invalid")]
    InvalidArgument { index: usize },
    #[error("plugin timeout {value}ms is outside 1..={maximum}ms")]
    InvalidTimeout { value: u64, maximum: u64 },
    #[error("plugin response limit {value} is outside {minimum}..={maximum} bytes")]
    InvalidResponseLimit {
        value: u64,
        minimum: u64,
        maximum: u64,
    },
    #[error("unsupported executable-plugin protocol {actual}; expected {expected}")]
    ProtocolVersion { expected: u32, actual: u32 },
    #[error("host request workspace root must be `.`, not `{value}`")]
    InvalidWorkspaceRoot { value: String },
    #[error("host request must negotiate at least one capability")]
    MissingCapabilities,
    #[error("`{field}` must be a concrete path, not glob `{path}`")]
    ConcretePathContainsGlob { field: &'static str, path: String },
    #[error("`{field}` must be sorted and contain no duplicates")]
    NonCanonicalOrder { field: &'static str },
    #[error("`{field}` contains more than {maximum} facts")]
    TooManyFacts { field: &'static str, maximum: usize },
    #[error("response {field} `{actual}` does not match request value `{expected}`")]
    ResponseIdentity {
        field: &'static str,
        expected: String,
        actual: String,
    },
    #[error("plugin response used capability `{capability:?}` that the host did not negotiate")]
    UnnegotiatedCapability { capability: PluginCapability },
    #[error("{status:?} plugin response must contain no contributions except diagnostics")]
    FailedResponseContributedFacts { status: HostResponseStatus },
    #[error("{status:?} plugin response requires a blocking diagnostic")]
    FailedResponseWithoutBlocker { status: HostResponseStatus },
}

fn validate_arguments(arguments: &[String]) -> Result<(), HostValidationError> {
    if arguments.len() > MAX_ARGUMENTS {
        return Err(HostValidationError::TooManyArguments {
            maximum: MAX_ARGUMENTS,
        });
    }
    for (index, argument) in arguments.iter().enumerate() {
        if argument.len() > MAX_ARGUMENT_BYTES
            || argument.chars().any(|character| character == '\0')
        {
            return Err(HostValidationError::InvalidArgument { index });
        }
    }
    Ok(())
}

fn validate_protocol_version(actual: u32) -> Result<(), HostValidationError> {
    if actual == EXECUTABLE_PLUGIN_PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(HostValidationError::ProtocolVersion {
            expected: EXECUTABLE_PLUGIN_PROTOCOL_VERSION,
            actual,
        })
    }
}

fn validate_manifest_facts(manifest: &HostManifestFacts) -> Result<(), HostValidationError> {
    validate_request_path("hostRequest.manifest.path", &manifest.path)?;
    if let Some(name) = &manifest.name {
        validate_reference_name("hostRequest.manifest.name", name)?;
    }
    validate_sorted_unique("hostRequest.manifest.packages", &manifest.packages)?;
    validate_host_count("hostRequest.manifest.packages", manifest.packages.len())?;
    for package in &manifest.packages {
        validate_reference_name("hostRequest.manifest.packages.name", &package.name)?;
        if let Some(version) = &package.version {
            validate_host_text("hostRequest.manifest.packages.version", version)?;
        }
    }
    Ok(())
}

fn validate_config_fact(config: &HostConfigFact) -> Result<(), HostValidationError> {
    validate_request_path("hostRequest.configFiles.path", &config.path)?;
    validate_sorted_unique(
        "hostRequest.configFiles.referencedPackages",
        &config.referenced_packages,
    )?;
    validate_host_count(
        "hostRequest.configFiles.referencedPackages",
        config.referenced_packages.len(),
    )?;
    for package in &config.referenced_packages {
        validate_reference_name("hostRequest.configFiles.referencedPackages", package)?;
    }
    Ok(())
}

fn validate_request_path(field: &'static str, path: &str) -> Result<(), HostValidationError> {
    validate_workspace_pattern(path)?;
    if contains_glob_meta(path) {
        Err(HostValidationError::ConcretePathContainsGlob {
            field,
            path: path.to_owned(),
        })
    } else {
        Ok(())
    }
}

fn validate_response_status(response: &HostResponse) -> Result<(), HostValidationError> {
    if response.status == HostResponseStatus::Complete {
        return Ok(());
    }
    if !response.contributions.is_empty_except_diagnostics() {
        return Err(HostValidationError::FailedResponseContributedFacts {
            status: response.status,
        });
    }
    if !response
        .contributions
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.blocks_reachability)
    {
        return Err(HostValidationError::FailedResponseWithoutBlocker {
            status: response.status,
        });
    }
    Ok(())
}

fn validate_response_capabilities(
    request: &HostRequest,
    response: &HostResponse,
) -> Result<(), HostValidationError> {
    for capability in response.contributions.used_capabilities() {
        if request.capabilities.binary_search(&capability).is_err() {
            return Err(HostValidationError::UnnegotiatedCapability { capability });
        }
    }
    Ok(())
}

fn validate_response_paths(
    workspace_root: &Path,
    contributions: &PluginContributions,
) -> Result<(), HostValidationError> {
    for contribution in contributions
        .entry_patterns
        .iter()
        .chain(&contributions.project_file_patterns)
        .chain(&contributions.config_file_patterns)
    {
        validate_literal_path_if_present(workspace_root, &contribution.pattern)?;
    }
    for edge in &contributions.file_edges {
        validate_literal_path_if_present(workspace_root, &edge.from_pattern)?;
        validate_literal_path_if_present(workspace_root, &edge.to_pattern)?;
    }
    for root in &contributions.export_roots {
        validate_literal_path_if_present(workspace_root, &root.module_pattern)?;
    }
    for root in &contributions.member_roots {
        validate_literal_path_if_present(workspace_root, &root.module_pattern)?;
    }
    for dynamic_import in &contributions.dynamic_imports {
        validate_literal_path_if_present(workspace_root, &dynamic_import.importer_pattern)?;
    }
    for transform in &contributions.file_transforms {
        validate_literal_path_if_present(workspace_root, &transform.source_pattern)?;
    }
    Ok(())
}

fn validate_literal_path_if_present(
    workspace_root: &Path,
    pattern: &str,
) -> Result<(), HostValidationError> {
    if !contains_glob_meta(pattern) {
        validate_workspace_path(workspace_root, pattern)?;
    }
    Ok(())
}

fn validate_sorted_unique<T: Ord>(
    field: &'static str,
    values: &[T],
) -> Result<(), HostValidationError> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        Err(HostValidationError::NonCanonicalOrder { field })
    } else {
        Ok(())
    }
}

fn validate_host_count(field: &'static str, count: usize) -> Result<(), HostValidationError> {
    if count > MAX_HOST_FACTS {
        Err(HostValidationError::TooManyFacts {
            field,
            maximum: MAX_HOST_FACTS,
        })
    } else {
        Ok(())
    }
}

fn validate_host_text(field: &'static str, value: &str) -> Result<(), HostValidationError> {
    if value.is_empty() || value.len() > 1_024 || value.chars().any(char::is_control) {
        Err(PluginValidationError::InvalidText { field }.into())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use super::{
        EXECUTABLE_PLUGIN_PROTOCOL_VERSION, ExecutablePluginConfig, HostFailureKind, HostRequest,
        HostResponse, HostResponseStatus, HostValidationError, host_failure_diagnostic,
        validate_host_response,
    };
    use crate::plugins::contract::{
        PatternContribution, PluginCapability, PluginContributions, PluginDiagnostic,
        PluginDiagnosticSeverity,
    };

    #[test]
    fn executable_plugins_require_explicit_trust() {
        let workspace = TestWorkspace::new();
        workspace.write("tools/plugin.js");
        let config = ExecutablePluginConfig {
            id: "custom".to_owned(),
            version: "1.0.0".to_owned(),
            executable: "tools/plugin.js".to_owned(),
            arguments: Vec::new(),
            trusted: false,
            timeout_milliseconds: 10_000,
            max_response_bytes: 1_048_576,
        };

        assert!(matches!(
            config.validate(&workspace.root),
            Err(HostValidationError::UntrustedPlugin { .. })
        ));
    }

    #[test]
    fn incomplete_responses_cannot_contribute_roots() {
        let workspace = TestWorkspace::new();
        workspace.write("src/index.ts");
        let request = request();
        let response = HostResponse {
            protocol_version: EXECUTABLE_PLUGIN_PROTOCOL_VERSION,
            request_id: request.request_id.clone(),
            plugin_id: request.plugin_id.clone(),
            plugin_version: "1.0.0".to_owned(),
            status: HostResponseStatus::Incomplete,
            contributions: PluginContributions {
                entry_patterns: vec![PatternContribution {
                    pattern: "src/index.ts".to_owned(),
                    reason: "Plugin root".to_owned(),
                }],
                diagnostics: vec![blocking_diagnostic()],
                ..PluginContributions::default()
            },
        };

        assert!(matches!(
            validate_host_response(&workspace.root, &request, &response),
            Err(HostValidationError::FailedResponseContributedFacts { .. })
        ));
    }

    #[test]
    fn incomplete_responses_require_and_accept_only_a_blocker() {
        let workspace = TestWorkspace::new();
        let request = request();
        let mut response = HostResponse {
            protocol_version: EXECUTABLE_PLUGIN_PROTOCOL_VERSION,
            request_id: request.request_id.clone(),
            plugin_id: request.plugin_id.clone(),
            plugin_version: "1.0.0".to_owned(),
            status: HostResponseStatus::Incomplete,
            contributions: PluginContributions::default(),
        };

        assert!(matches!(
            validate_host_response(&workspace.root, &request, &response),
            Err(HostValidationError::FailedResponseWithoutBlocker { .. })
        ));

        response.contributions.diagnostics = vec![blocking_diagnostic()];
        validate_host_response(&workspace.root, &request, &response)
            .expect("blocking incomplete response");
    }

    #[test]
    fn host_failures_always_block_reachability() {
        for kind in [
            HostFailureKind::Spawn,
            HostFailureKind::Timeout,
            HostFailureKind::Crash,
            HostFailureKind::InvalidResponse,
            HostFailureKind::OversizedResponse,
        ] {
            let diagnostic = host_failure_diagnostic(kind);
            assert_eq!(diagnostic.severity, PluginDiagnosticSeverity::Error);
            assert!(diagnostic.blocks_reachability);
            diagnostic.validate().expect("valid host diagnostic");
        }
    }

    #[test]
    fn responses_cannot_use_an_unnegotiated_capability() {
        let workspace = TestWorkspace::new();
        workspace.write("src/index.ts");
        let mut request = request();
        request.capabilities = vec![PluginCapability::Diagnostics];
        let response = HostResponse {
            protocol_version: EXECUTABLE_PLUGIN_PROTOCOL_VERSION,
            request_id: request.request_id.clone(),
            plugin_id: request.plugin_id.clone(),
            plugin_version: "1.0.0".to_owned(),
            status: HostResponseStatus::Complete,
            contributions: PluginContributions {
                entry_patterns: vec![PatternContribution {
                    pattern: "src/index.ts".to_owned(),
                    reason: "Plugin root".to_owned(),
                }],
                ..PluginContributions::default()
            },
        };

        assert!(matches!(
            validate_host_response(&workspace.root, &request, &response),
            Err(HostValidationError::UnnegotiatedCapability {
                capability: PluginCapability::Entries
            })
        ));
    }

    fn request() -> HostRequest {
        HostRequest {
            protocol_version: EXECUTABLE_PLUGIN_PROTOCOL_VERSION,
            request_id: "request-1".to_owned(),
            plugin_id: "custom".to_owned(),
            plugin_version: "1.0.0".to_owned(),
            workspace_root: ".".to_owned(),
            target_profile: "default".to_owned(),
            manifest: None,
            config_files: Vec::new(),
            capabilities: vec![PluginCapability::Entries, PluginCapability::Diagnostics],
        }
    }

    fn blocking_diagnostic() -> PluginDiagnostic {
        PluginDiagnostic {
            path: None,
            code: "plugin_custom_incomplete".to_owned(),
            severity: PluginDiagnosticSeverity::Warning,
            message: "Custom plugin could not model its configuration".to_owned(),
            blocks_reachability: true,
        }
    }

    struct TestWorkspace {
        root: PathBuf,
    }

    impl TestWorkspace {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "orphanode-executable-plugin-test-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&root).expect("test workspace");
            Self { root }
        }

        fn write(&self, relative: &str) {
            let path = self.root.join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("test parent");
            }
            fs::write(path, "").expect("test file");
        }
    }

    impl Drop for TestWorkspace {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
