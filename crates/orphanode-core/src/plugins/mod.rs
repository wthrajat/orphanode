//! Versioned plugin contracts and built-in static framework knowledge.
//!
//! Plugin contributions are facts, not liveness decisions. Callers must validate
//! every plugin and host response before merging it into discovery or analysis.

mod builtins;
mod contract;
mod executable;

pub use builtins::{
    BuiltinDetectionInput, DetectedBuiltinPlugin, DetectionEvidence, DetectionEvidenceKind,
    builtin_plugins, detect_builtin_plugins,
};
pub use contract::{
    DECLARATIVE_PLUGIN_API_VERSION, DECLARATIVE_PLUGIN_SCHEMA_URL, DeclarativePlugin,
    DetectionRules, DynamicImportContribution, ExportRootContribution, FileEdgeContribution,
    FileTransformContribution, MemberRootContribution, PatternContribution, PluginCapability,
    PluginContributions, PluginDiagnostic, PluginDiagnosticSeverity, PluginValidationError,
    ReferenceContribution, ReferenceKind, UnsupportedCase, validate_workspace_path,
    validate_workspace_pattern,
};
pub use executable::{
    EXECUTABLE_PLUGIN_PROTOCOL_VERSION, ExecutablePluginConfig, HostConfigFact, HostConfigFormat,
    HostFailureKind, HostManifestFacts, HostPackageFact, HostPackageKind, HostPackageType,
    HostRequest, HostResponse, HostResponseStatus, HostValidationError, host_failure_diagnostic,
    validate_host_request, validate_host_response,
};
