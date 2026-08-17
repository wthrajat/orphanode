use std::collections::BTreeMap;

use serde::{Serialize, ser::SerializeStruct as _};

use super::facts::{
    Activation, AnalysisDiagnostic, ExportFact, ImportKind, ModuleKind, ResolutionMode, SourceKind,
    SourceSpan,
};

pub const REPORT_SCHEMA_VERSION: &str = "0.2";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisStatus {
    Complete,
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FileStatus {
    Reachable,
    Unreachable,
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionStatus {
    Resolved,
    External,
    Unresolved,
    Unsupported,
    Deferred,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    High,
    Medium,
    Low,
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixEligibility {
    NotAvailable,
    PreviewOnly,
    Eligible,
    Blocked,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanReport {
    pub schema_version: &'static str,
    pub status: AnalysisStatus,
    pub entries: Vec<String>,
    pub summary: ReportSummary,
    pub files: Vec<FileReport>,
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub retentions: Vec<RetentionReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<ProjectReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache: Option<CacheReport>,
    pub diagnostics: Vec<AnalysisDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheReport {
    pub status: String,
    pub hits: usize,
    pub misses: usize,
    pub generation_written: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetentionReport {
    pub item: String,
    pub item_type: &'static str,
    pub workspace: String,
    pub target_profiles: Vec<String>,
    pub summary: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectReport {
    pub mode: String,
    pub workspaces: Vec<String>,
    pub worlds: BTreeMap<String, String>,
    pub target_profiles: Vec<String>,
    pub failure_thresholds: BTreeMap<String, Confidence>,
    pub detected_plugins: Vec<String>,
    pub configuration_sources: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportSummary {
    pub files: usize,
    pub reachable_files: usize,
    pub unreachable_files: usize,
    pub incomplete_files: usize,
    pub diagnostics: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileReport {
    pub path: String,
    pub status: FileStatus,
    pub target_statuses: BTreeMap<String, FileStatus>,
    pub source_kind: SourceKind,
    pub module_kind: ModuleKind,
    pub byte_len: u64,
    pub line_count: u32,
    pub content_digest: String,
    pub imports: Vec<ImportReport>,
    pub exports: Vec<ExportFact>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportReport {
    pub specifier: String,
    pub kind: ImportKind,
    pub resolution_mode: ResolutionMode,
    pub activation: Activation,
    pub type_only: bool,
    pub status: ResolutionStatus,
    pub target_profiles: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub span: SourceSpan,
}

#[derive(Debug)]
pub struct Finding {
    pub issue_id: &'static str,
    pub issue_type: &'static str,
    pub workspace: String,
    pub target_profiles: Vec<String>,
    pub paths: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span: Option<SourceSpan>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dependency: Option<String>,
    pub confidence: Confidence,
    pub summary: String,
    pub evidence: Vec<String>,
    pub blockers: Vec<String>,
    pub suggested_actions: Vec<String>,
    pub fix_eligibility: FixEligibility,
}

impl Serialize for Finding {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut finding = serializer.serialize_struct("Finding", 15)?;
        finding.serialize_field("schemaVersion", REPORT_SCHEMA_VERSION)?;
        finding.serialize_field("issueId", self.issue_id)?;
        finding.serialize_field("issueType", self.issue_type)?;
        finding.serialize_field("workspace", &self.workspace)?;
        finding.serialize_field("targetProfiles", &self.target_profiles)?;
        finding.serialize_field("paths", &self.paths)?;
        if let Some(span) = self.span {
            finding.serialize_field("span", &span)?;
        }
        if let Some(symbol) = &self.symbol {
            finding.serialize_field("symbol", symbol)?;
        }
        if let Some(dependency) = &self.dependency {
            finding.serialize_field("dependency", dependency)?;
        }
        finding.serialize_field("confidence", &self.confidence)?;
        finding.serialize_field("summary", &self.summary)?;
        finding.serialize_field("evidence", &self.evidence)?;
        finding.serialize_field("blockers", &self.blockers)?;
        finding.serialize_field("suggestedActions", &self.suggested_actions)?;
        finding.serialize_field("fixEligibility", &self.fix_eligibility)?;
        finding.end()
    }
}

/// Compatibility name retained for library users of the first file-only slice.
pub type UnusedFilesFinding = Finding;

#[cfg(test)]
mod tests {
    use super::{Confidence, Finding, FixEligibility, REPORT_SCHEMA_VERSION};

    #[test]
    fn every_finding_serializes_its_contract_version() {
        let finding = Finding {
            issue_id: "ORP1001",
            issue_type: "unusedFiles",
            workspace: ".".to_owned(),
            target_profiles: vec!["node".to_owned()],
            paths: vec!["src/unused.js".to_owned()],
            span: None,
            symbol: None,
            dependency: None,
            confidence: Confidence::High,
            summary: "unused".to_owned(),
            evidence: vec!["not reachable".to_owned()],
            blockers: Vec::new(),
            suggested_actions: vec!["review".to_owned()],
            fix_eligibility: FixEligibility::PreviewOnly,
        };

        let serialized = serde_json::to_value(finding).expect("serialize finding");
        assert_eq!(serialized["schemaVersion"], REPORT_SCHEMA_VERSION);
        assert!(serialized.get("span").is_none());
        assert!(serialized.get("symbol").is_none());
        assert!(serialized.get("dependency").is_none());
    }
}
