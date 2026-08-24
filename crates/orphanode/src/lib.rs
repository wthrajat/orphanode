//! Accuracy-first JavaScript and TypeScript reachability analysis.

pub mod analysis;
pub mod application;
pub mod cache;
pub mod discovery;
pub mod domain;
pub mod fixes;
pub mod javascript;
pub mod limits;
pub mod plugins;
pub mod report;
pub mod resolution;

pub use application::{
    AnalysisIssue, Explanation, ExplanationStatus, ExplanationStep, ProjectCacheMetrics,
    ProjectScanError, ProjectScanMetrics, ProjectScanOutput, ProjectScanRequest,
    ProjectStageMetrics, ScanError, ScanRequest, TypeScriptWorkerError, TypeScriptWorkerHost,
    TypeScriptWorkerOptions, WorkerReply, explain, scan, scan_project, scan_project_measured,
    scan_with_limits,
};
pub use discovery::{
    DiscoveryError, discover_package_source_files, discover_source_files,
    discover_source_files_with_limits,
};
pub use domain::report::ScanReport;
pub use limits::AnalysisLimits;
pub use report::render_sarif;
