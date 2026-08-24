use std::{
    collections::BTreeSet,
    path::{Component, Path},
};

use serde::Serialize;
use thiserror::Error;

use crate::cache::ContentDigest;

use super::{EligibleFix, PackageManagerCommand};

pub const FIX_PLAN_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ProjectPath(String);

impl ProjectPath {
    /// Creates a normalized project-relative path.
    ///
    /// # Errors
    ///
    /// Returns an error for absolute, traversing, empty, or otherwise unsafe paths.
    pub fn new(value: impl Into<String>) -> Result<Self, FixPlanError> {
        let value = value.into().replace('\\', "/");
        if value == "." {
            return Ok(Self(value));
        }
        if value.is_empty() || value.len() > 16 * 1024 || value.contains('\0') {
            return Err(FixPlanError::UnsafePath(value));
        }
        if value.starts_with('/')
            || value
                .as_bytes()
                .get(1)
                .is_some_and(|separator| *separator == b':')
        {
            return Err(FixPlanError::UnsafePath(value));
        }
        if Path::new(&value).components().any(|component| {
            matches!(
                component,
                Component::Prefix(_)
                    | Component::RootDir
                    | Component::ParentDir
                    | Component::CurDir
            )
        }) {
            return Err(FixPlanError::UnsafePath(value));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn as_path(&self) -> &Path {
        Path::new(&self.0)
    }

    #[must_use]
    pub fn root() -> Self {
        Self(".".to_owned())
    }

    #[must_use]
    pub fn is_lockfile(&self) -> bool {
        self.as_path()
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                matches!(
                    name,
                    "package-lock.json"
                        | "npm-shrinkwrap.json"
                        | "pnpm-lock.yaml"
                        | "yarn.lock"
                        | "bun.lock"
                        | "bun.lockb"
                )
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ByteSpan {
    pub start: usize,
    pub end: usize,
}

impl ByteSpan {
    /// Creates a half-open byte span.
    ///
    /// # Errors
    ///
    /// Returns an error when `start` is after `end`.
    pub fn new(start: usize, end: usize) -> Result<Self, FixPlanError> {
        if start > end {
            return Err(FixPlanError::InvalidSpan { start, end });
        }
        Ok(Self { start, end })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceEdit {
    pub span: ByteSpan,
    pub replacement: String,
}

impl SourceEdit {
    #[must_use]
    pub fn new(span: ByteSpan, replacement: impl Into<String>) -> Self {
        Self {
            span,
            replacement: replacement.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExplicitFileFixScope(());

impl ExplicitFileFixScope {
    /// Creates the marker only after the caller has selected explicit file-fix scope.
    #[must_use]
    pub const fn selected() -> Self {
        Self(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FileChange {
    Modify {
        path: ProjectPath,
        expected_content: ContentDigest,
        edits: Vec<SourceEdit>,
        reason: String,
    },
    Delete {
        path: ProjectPath,
        expected_content: ContentDigest,
        reason: String,
    },
}

impl FileChange {
    #[must_use]
    pub fn path(&self) -> &ProjectPath {
        match self {
            Self::Modify { path, .. } | Self::Delete { path, .. } => path,
        }
    }

    #[must_use]
    pub fn expected_content(&self) -> ContentDigest {
        match self {
            Self::Modify {
                expected_content, ..
            }
            | Self::Delete {
                expected_content, ..
            } => *expected_content,
        }
    }

    #[must_use]
    pub fn reason(&self) -> &str {
        match self {
            Self::Modify { reason, .. } | Self::Delete { reason, .. } => reason,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FixPlan {
    pub schema_version: u32,
    pub plan_id: String,
    pub summary: String,
    pub file_changes: Vec<FileChange>,
    pub package_commands: Vec<PackageManagerCommand>,
}

impl FixPlan {
    /// Creates an empty preview plan with a stable identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the id or summary is empty or exceeds its bound.
    pub fn new(
        plan_id: impl Into<String>,
        summary: impl Into<String>,
    ) -> Result<Self, FixPlanError> {
        let plan = Self {
            schema_version: FIX_PLAN_SCHEMA_VERSION,
            plan_id: plan_id.into(),
            summary: summary.into(),
            file_changes: Vec::new(),
            package_commands: Vec::new(),
        };
        plan.validate_identity()?;
        Ok(plan)
    }

    /// Adds non-overlapping byte-span edits guarded by the analyzed file hash.
    ///
    /// # Errors
    ///
    /// Returns an error for lockfiles, empty/overlapping edits, or duplicate targets.
    pub fn add_source_edits(
        &mut self,
        eligibility: EligibleFix,
        path: ProjectPath,
        mut edits: Vec<SourceEdit>,
        reason: impl Into<String>,
    ) -> Result<(), FixPlanError> {
        reject_lockfile(&path)?;
        if edits.is_empty() {
            return Err(FixPlanError::EmptyEdits(path.as_str().to_owned()));
        }
        edits.sort_by_key(|edit| (edit.span.start, edit.span.end));
        validate_non_overlapping(&path, &edits)?;
        self.reject_duplicate_path(&path)?;
        let reason = reason.into();
        validate_reason(&reason)?;
        self.file_changes.push(FileChange::Modify {
            path,
            expected_content: eligibility.expected_content(),
            edits,
            reason,
        });
        Ok(())
    }

    /// Adds a hash-guarded deletion with an explicit file-scope marker.
    ///
    /// # Errors
    ///
    /// Returns an error for lockfiles or duplicate targets.
    pub fn add_file_deletion(
        &mut self,
        eligibility: EligibleFix,
        path: ProjectPath,
        _scope: ExplicitFileFixScope,
        reason: impl Into<String>,
    ) -> Result<(), FixPlanError> {
        reject_lockfile(&path)?;
        self.reject_duplicate_path(&path)?;
        let reason = reason.into();
        validate_reason(&reason)?;
        self.file_changes.push(FileChange::Delete {
            path,
            expected_content: eligibility.expected_content(),
            reason,
        });
        Ok(())
    }

    pub fn add_package_command(&mut self, command: PackageManagerCommand) {
        self.package_commands.push(command);
    }

    pub(crate) fn validate(&self) -> Result<(), FixPlanError> {
        self.validate_identity()?;
        let mut prior_path: Option<&ProjectPath> = None;
        let mut paths: Vec<_> = self.file_changes.iter().map(FileChange::path).collect();
        paths.sort();
        for path in paths {
            reject_lockfile(path)?;
            if prior_path == Some(path) {
                return Err(FixPlanError::DuplicateFileChange(path.as_str().to_owned()));
            }
            prior_path = Some(path);
        }
        for change in &self.file_changes {
            validate_reason(change.reason())?;
            if let FileChange::Modify { path, edits, .. } = change {
                if edits.is_empty() {
                    return Err(FixPlanError::EmptyEdits(path.as_str().to_owned()));
                }
                validate_non_overlapping(path, edits)?;
            }
        }
        let file_paths = self
            .file_changes
            .iter()
            .map(FileChange::path)
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut package_manifests = BTreeSet::new();
        for command in &self.package_commands {
            command
                .validate()
                .map_err(FixPlanError::InvalidPackageCommand)?;
            if !package_manifests.insert(&command.manifest_path) {
                return Err(FixPlanError::DuplicatePackageCommand(
                    command.manifest_path.as_str().to_owned(),
                ));
            }
            if file_paths.contains(&command.manifest_path) {
                return Err(FixPlanError::ConflictingManifestChange(
                    command.manifest_path.as_str().to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn validate_identity(&self) -> Result<(), FixPlanError> {
        if self.plan_id.is_empty()
            || self.plan_id.len() > 256
            || self.plan_id.contains(char::is_whitespace)
            || self.summary.is_empty()
            || self.summary.len() > 4096
        {
            return Err(FixPlanError::InvalidIdentity);
        }
        Ok(())
    }

    fn reject_duplicate_path(&self, path: &ProjectPath) -> Result<(), FixPlanError> {
        if self.file_changes.iter().any(|change| change.path() == path) {
            return Err(FixPlanError::DuplicateFileChange(path.as_str().to_owned()));
        }
        Ok(())
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FixPlanError {
    #[error("fix plan id and summary must be nonempty and bounded")]
    InvalidIdentity,
    #[error("unsafe project-relative path: {0}")]
    UnsafePath(String),
    #[error("lockfiles may only be changed by the selected package manager: {0}")]
    LockfileEdit(String),
    #[error("invalid byte span {start}..{end}")]
    InvalidSpan { start: usize, end: usize },
    #[error("source edit list is empty for {0}")]
    EmptyEdits(String),
    #[error("source edits overlap or have ambiguous ordering in {0}")]
    OverlappingEdits(String),
    #[error("fix plan contains more than one change for {0}")]
    DuplicateFileChange(String),
    #[error("fix reason must be nonempty, bounded, and safe to display")]
    InvalidReason,
    #[error("invalid package-manager command: {0}")]
    InvalidPackageCommand(&'static str),
    #[error("fix plan contains more than one package-manager command for {0}")]
    DuplicatePackageCommand(String),
    #[error("workspace manifest must be changed only by its package-manager command: {0}")]
    ConflictingManifestChange(String),
}

fn reject_lockfile(path: &ProjectPath) -> Result<(), FixPlanError> {
    if path.is_lockfile() {
        return Err(FixPlanError::LockfileEdit(path.as_str().to_owned()));
    }
    Ok(())
}

fn validate_reason(reason: &str) -> Result<(), FixPlanError> {
    if reason.trim().is_empty() || reason.len() > 4096 || reason.chars().any(char::is_control) {
        Err(FixPlanError::InvalidReason)
    } else {
        Ok(())
    }
}

fn validate_non_overlapping(path: &ProjectPath, edits: &[SourceEdit]) -> Result<(), FixPlanError> {
    if edits.iter().any(|edit| edit.span.start > edit.span.end) {
        return Err(FixPlanError::OverlappingEdits(path.as_str().to_owned()));
    }
    let ordered = edits.windows(2).all(|pair| {
        pair[0].span.end <= pair[1].span.start && pair[0].span.start < pair[1].span.start
    });
    if ordered {
        Ok(())
    } else {
        Err(FixPlanError::OverlappingEdits(path.as_str().to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        cache::ContentDigest,
        fixes::{
            AnalysisConfidence, EligibilityDecision, FixCandidate, PublicApiExposure,
            WorldAssumption,
        },
    };

    use super::{ByteSpan, FixPlan, FixPlanError, ProjectPath, SourceEdit};

    #[test]
    fn rejects_path_escape_and_lockfile_edits() {
        assert!(ProjectPath::new("../outside.js").is_err());
        let mut plan = FixPlan::new("fix-1", "remove stale lock entry").unwrap();
        let error = plan
            .add_source_edits(
                eligible(),
                ProjectPath::new("package-lock.json").unwrap(),
                vec![SourceEdit::new(ByteSpan::new(0, 1).unwrap(), "")],
                "Remove an unused declaration",
            )
            .unwrap_err();
        assert!(matches!(error, FixPlanError::LockfileEdit(_)));
    }

    #[test]
    fn rejects_overlapping_source_spans() {
        let mut plan = FixPlan::new("fix-1", "remove unused declaration").unwrap();
        let error = plan
            .add_source_edits(
                eligible(),
                ProjectPath::new("src/index.ts").unwrap(),
                vec![
                    SourceEdit::new(ByteSpan::new(1, 4).unwrap(), ""),
                    SourceEdit::new(ByteSpan::new(3, 5).unwrap(), ""),
                ],
                "Remove an unused declaration",
            )
            .unwrap_err();

        assert!(matches!(error, FixPlanError::OverlappingEdits(_)));
    }

    fn eligible() -> crate::fixes::EligibleFix {
        let decision = FixCandidate {
            confidence: AnalysisConfidence::High,
            world: WorldAssumption::Closed,
            public_api: PublicApiExposure::OutsidePublicApi,
            blockers: Vec::new(),
            expected_content: Some(ContentDigest::of_bytes(b"source")),
            preserves_trivia_and_semantics: true,
        }
        .evaluate();
        let EligibilityDecision::Eligible(eligible) = decision else {
            panic!("test fixture should be eligible");
        };
        eligible
    }
}
