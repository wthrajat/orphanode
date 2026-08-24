//! Conservative, preview-first source and dependency fixes.

mod apply;
mod eligibility;
mod package_manager;
mod plan;

pub use apply::{
    ApplyAuthorization, ApplyReport, CommandExecution, CommandExecutor, FixEngine, FixError,
    FixPreview, PreviewChangeKind, PreviewedFileChange, RevalidationOutcome, RevalidationRequest,
    Revalidator,
};
pub use eligibility::{
    AnalysisConfidence, CoverageBlocker, EligibilityDecision, EligibilityRejection, EligibleFix,
    FixCandidate, PublicApiExposure, WorldAssumption,
};
pub use package_manager::{
    DependencyKind, DependencyRemoval, DirectDependency, PackageManager, PackageManagerCommand,
};
pub use plan::{
    ByteSpan, ExplicitFileFixScope, FIX_PLAN_SCHEMA_VERSION, FileChange, FixPlan, FixPlanError,
    ProjectPath, SourceEdit,
};
