use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use thiserror::Error;

use crate::cache::{ContentDigest, Digest};

use super::{FileChange, FixPlan, FixPlanError, PackageManagerCommand, ProjectPath};

static TEMPORARY_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreviewChangeKind {
    Modify,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviewedFileChange {
    pub path: ProjectPath,
    pub kind: PreviewChangeKind,
    pub before_digest: ContentDigest,
    pub after_digest: Option<ContentDigest>,
    original_content: Vec<u8>,
    updated_content: Option<Vec<u8>>,
}

impl PreviewedFileChange {
    #[must_use]
    pub fn original_content(&self) -> &[u8] {
        &self.original_content
    }

    #[must_use]
    pub fn updated_content(&self) -> Option<&[u8]> {
        self.updated_content.as_deref()
    }
}

#[derive(Debug, Clone)]
pub struct FixPreview {
    plan: FixPlan,
    fingerprint: Digest,
    pub file_changes: Vec<PreviewedFileChange>,
}

impl FixPreview {
    #[must_use]
    pub fn plan(&self) -> &FixPlan {
        &self.plan
    }

    #[must_use]
    pub fn fingerprint(&self) -> Digest {
        self.fingerprint
    }

    /// Produces the capability required by `FixEngine::apply` after the caller has
    /// displayed this preview and received explicit apply authorization.
    #[must_use]
    pub fn explicit_apply_authorization(&self) -> ApplyAuthorization {
        ApplyAuthorization {
            fingerprint: self.fingerprint,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplyAuthorization {
    fingerprint: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandExecution {
    pub command: PackageManagerCommand,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub message: String,
}

pub trait CommandExecutor {
    /// Executes an already-previewed package-manager command in its exact workspace.
    fn execute(&mut self, project_root: &Path, command: &PackageManagerCommand)
    -> CommandExecution;
}

#[derive(Debug)]
pub struct RevalidationRequest<'a> {
    pub project_root: &'a Path,
    pub plan_id: &'a str,
    pub changed_paths: &'a [ProjectPath],
    pub package_commands: &'a [CommandExecution],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevalidationOutcome {
    Passed { notes: Vec<String> },
    Failed { diagnostics: Vec<String> },
}

pub trait Revalidator {
    /// Re-scans affected analysis scopes and may run configured validation commands.
    fn revalidate(&mut self, request: RevalidationRequest<'_>) -> RevalidationOutcome;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyReport {
    pub plan_id: String,
    pub changed_paths: Vec<ProjectPath>,
    pub package_commands: Vec<CommandExecution>,
    pub revalidation: RevalidationOutcome,
}

#[derive(Debug, Error)]
pub enum FixError {
    #[error(transparent)]
    InvalidPlan(#[from] FixPlanError),
    #[error("project root is not a directory: {0}")]
    InvalidRoot(PathBuf),
    #[error("apply authorization does not match the preview")]
    AuthorizationMismatch,
    #[error("refusing to follow a symlink or edit a non-file: {0}")]
    UnsafeFileType(String),
    #[error("file changed since analysis: {path}")]
    HashMismatch {
        path: String,
        expected: ContentDigest,
        actual: ContentDigest,
    },
    #[error("edit span {start}..{end} is outside {path} ({length} bytes)")]
    SpanOutOfBounds {
        path: String,
        start: usize,
        end: usize,
        length: usize,
    },
    #[error("failed to serialize fix preview: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("fix I/O failed for {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, Clone)]
pub struct FixEngine {
    project_root: PathBuf,
}

impl FixEngine {
    /// Creates a fix engine rooted at an existing project directory.
    ///
    /// # Errors
    ///
    /// Returns an error when the root cannot be canonicalized or is not a directory.
    pub fn new(project_root: impl AsRef<Path>) -> Result<Self, FixError> {
        let supplied_root = project_root.as_ref();
        let project_root = fs::canonicalize(supplied_root).map_err(|source| FixError::Io {
            path: supplied_root.to_path_buf(),
            source,
        })?;
        if !project_root.is_dir() {
            return Err(FixError::InvalidRoot(project_root));
        }
        Ok(Self { project_root })
    }

    #[must_use]
    pub fn project_root(&self) -> &Path {
        &self.project_root
    }

    /// Reads and hash-checks every planned input without changing project files.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid plan, unsafe path, changed file, or I/O failure.
    pub fn preview(&self, plan: &FixPlan) -> Result<FixPreview, FixError> {
        plan.validate()?;
        for command in &plan.package_commands {
            self.verify_package_command(command)?;
        }
        let mut file_changes = Vec::with_capacity(plan.file_changes.len());
        for change in &plan.file_changes {
            file_changes.push(self.preview_file_change(change)?);
        }

        let mut fingerprint_input = serde_json::to_vec(plan)?;
        for change in &file_changes {
            fingerprint_input.extend_from_slice(change.before_digest.0.to_string().as_bytes());
            if let Some(after_digest) = change.after_digest {
                fingerprint_input.extend_from_slice(after_digest.0.to_string().as_bytes());
            }
        }

        Ok(FixPreview {
            plan: plan.clone(),
            fingerprint: Digest::of_bytes(&fingerprint_input),
            file_changes,
        })
    }

    /// Applies a previously previewed plan, then invokes the revalidation port.
    ///
    /// # Errors
    ///
    /// Returns an error when authorization does not match, a hash changed, or an edit fails.
    pub fn apply<E, R>(
        &self,
        preview: &FixPreview,
        authorization: ApplyAuthorization,
        command_executor: &mut E,
        revalidator: &mut R,
    ) -> Result<ApplyReport, FixError>
    where
        E: CommandExecutor,
        R: Revalidator,
    {
        if authorization.fingerprint != preview.fingerprint {
            return Err(FixError::AuthorizationMismatch);
        }

        self.verify_preview_inputs(preview)?;
        let mut changed_paths = Vec::with_capacity(preview.file_changes.len());
        for change in &preview.file_changes {
            self.apply_file_change(change)?;
            changed_paths.push(change.path.clone());
        }

        let mut command_results = Vec::new();
        for command in &preview.plan.package_commands {
            // Keep the manifest precondition adjacent to process execution. The
            // package manager, not OrphaNode, remains the only lockfile writer.
            self.verify_package_command(command)?;
            let result = command_executor.execute(&self.project_root, command);
            let success = result.success;
            command_results.push(result);
            if !success {
                break;
            }
        }

        let revalidation = revalidator.revalidate(RevalidationRequest {
            project_root: &self.project_root,
            plan_id: &preview.plan.plan_id,
            changed_paths: &changed_paths,
            package_commands: &command_results,
        });

        Ok(ApplyReport {
            plan_id: preview.plan.plan_id.clone(),
            changed_paths,
            package_commands: command_results,
            revalidation,
        })
    }

    fn preview_file_change(&self, change: &FileChange) -> Result<PreviewedFileChange, FixError> {
        let path = change.path().clone();
        let original_content = self.read_regular_file(&path)?;
        let before_digest = ContentDigest::of_bytes(&original_content);
        if before_digest != change.expected_content() {
            return Err(FixError::HashMismatch {
                path: path.as_str().to_owned(),
                expected: change.expected_content(),
                actual: before_digest,
            });
        }

        match change {
            FileChange::Modify { edits, .. } => {
                let updated_content = apply_edits(&path, &original_content, edits)?;
                let after_digest = ContentDigest::of_bytes(&updated_content);
                Ok(PreviewedFileChange {
                    path,
                    kind: PreviewChangeKind::Modify,
                    before_digest,
                    after_digest: Some(after_digest),
                    original_content,
                    updated_content: Some(updated_content),
                })
            }
            FileChange::Delete { .. } => Ok(PreviewedFileChange {
                path,
                kind: PreviewChangeKind::Delete,
                before_digest,
                after_digest: None,
                original_content,
                updated_content: None,
            }),
        }
    }

    fn verify_preview_inputs(&self, preview: &FixPreview) -> Result<(), FixError> {
        for change in &preview.file_changes {
            let current = self.read_regular_file(&change.path)?;
            let actual = ContentDigest::of_bytes(&current);
            if actual != change.before_digest {
                return Err(FixError::HashMismatch {
                    path: change.path.as_str().to_owned(),
                    expected: change.before_digest,
                    actual,
                });
            }
        }
        for command in &preview.plan.package_commands {
            self.verify_package_command(command)?;
        }
        Ok(())
    }

    fn verify_package_command(&self, command: &PackageManagerCommand) -> Result<(), FixError> {
        self.verify_workspace_directory(&command.working_directory)?;
        let current = self.read_regular_file(&command.manifest_path)?;
        let actual = ContentDigest::of_bytes(&current);
        if actual != command.analyzed_manifest_content {
            return Err(FixError::HashMismatch {
                path: command.manifest_path.as_str().to_owned(),
                expected: command.analyzed_manifest_content,
                actual,
            });
        }
        Ok(())
    }

    fn apply_file_change(&self, change: &PreviewedFileChange) -> Result<(), FixError> {
        let path = self.project_root.join(change.path.as_path());
        let current = self.read_regular_file(&change.path)?;
        let actual = ContentDigest::of_bytes(&current);
        if actual != change.before_digest {
            return Err(FixError::HashMismatch {
                path: change.path.as_str().to_owned(),
                expected: change.before_digest,
                actual,
            });
        }
        match change.kind {
            PreviewChangeKind::Modify => {
                let contents = change
                    .updated_content
                    .as_deref()
                    .expect("modify previews always contain updated bytes");
                atomic_replace(&path, contents)
            }
            PreviewChangeKind::Delete => {
                fs::remove_file(&path).map_err(|source| FixError::Io {
                    path: path.clone(),
                    source,
                })?;
                if let Some(parent) = path.parent() {
                    sync_directory(parent);
                }
                Ok(())
            }
        }
    }

    fn read_regular_file(&self, path: &ProjectPath) -> Result<Vec<u8>, FixError> {
        let physical_path = self.project_root.join(path.as_path());
        self.reject_symlink_components(path)?;
        let metadata = fs::symlink_metadata(&physical_path).map_err(|source| FixError::Io {
            path: physical_path.clone(),
            source,
        })?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(FixError::UnsafeFileType(path.as_str().to_owned()));
        }
        fs::read(&physical_path).map_err(|source| FixError::Io {
            path: physical_path,
            source,
        })
    }

    fn verify_workspace_directory(&self, path: &ProjectPath) -> Result<(), FixError> {
        if path.as_str() == "." {
            return Ok(());
        }
        self.reject_symlink_components(path)?;
        let physical_path = self.project_root.join(path.as_path());
        let metadata = fs::symlink_metadata(&physical_path).map_err(|source| FixError::Io {
            path: physical_path.clone(),
            source,
        })?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(FixError::UnsafeFileType(path.as_str().to_owned()));
        }
        Ok(())
    }

    fn reject_symlink_components(&self, path: &ProjectPath) -> Result<(), FixError> {
        let mut current = self.project_root.clone();
        for component in path.as_path().components() {
            if matches!(component, std::path::Component::CurDir) {
                continue;
            }
            current.push(component.as_os_str());
            let metadata = fs::symlink_metadata(&current).map_err(|source| FixError::Io {
                path: current.clone(),
                source,
            })?;
            if metadata.file_type().is_symlink() {
                return Err(FixError::UnsafeFileType(path.as_str().to_owned()));
            }
        }
        Ok(())
    }
}

fn apply_edits(
    path: &ProjectPath,
    original: &[u8],
    edits: &[super::SourceEdit],
) -> Result<Vec<u8>, FixError> {
    let mut updated = original.to_vec();
    for edit in edits.iter().rev() {
        if edit.span.end > updated.len() {
            return Err(FixError::SpanOutOfBounds {
                path: path.as_str().to_owned(),
                start: edit.span.start,
                end: edit.span.end,
                length: updated.len(),
            });
        }
        updated.splice(
            edit.span.start..edit.span.end,
            edit.replacement.as_bytes().iter().copied(),
        );
    }
    Ok(updated)
}

fn atomic_replace(path: &Path, contents: &[u8]) -> Result<(), FixError> {
    let parent = path.parent().ok_or_else(|| FixError::Io {
        path: path.to_path_buf(),
        source: std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "fix target has no parent directory",
        ),
    })?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("source");
    let temporary = parent.join(format!(
        ".{name}.orphanode-{}-{}.tmp",
        std::process::id(),
        TEMPORARY_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let permissions = fs::metadata(path)
            .map_err(|source| FixError::Io {
                path: path.to_path_buf(),
                source,
            })?
            .permissions();
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|source| FixError::Io {
                path: temporary.clone(),
                source,
            })?;
        file.write_all(contents).map_err(|source| FixError::Io {
            path: temporary.clone(),
            source,
        })?;
        file.set_permissions(permissions)
            .map_err(|source| FixError::Io {
                path: temporary.clone(),
                source,
            })?;
        file.sync_all().map_err(|source| FixError::Io {
            path: temporary.clone(),
            source,
        })?;
        replace_file(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(unix)]
fn replace_file(temporary: &Path, destination: &Path) -> Result<(), FixError> {
    fs::rename(temporary, destination).map_err(|source| FixError::Io {
        path: destination.to_path_buf(),
        source,
    })?;
    if let Some(parent) = destination.parent() {
        sync_directory(parent);
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directory(directory: &Path) {
    if let Ok(file) = File::open(directory) {
        let _ = file.sync_all();
    }
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) {}

#[cfg(not(unix))]
fn replace_file(temporary: &Path, destination: &Path) -> Result<(), FixError> {
    let backup = destination.with_extension(format!(
        "orphanode-backup-{}",
        TEMPORARY_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    fs::rename(destination, &backup).map_err(|source| FixError::Io {
        path: destination.to_path_buf(),
        source,
    })?;
    if let Err(source) = fs::rename(temporary, destination) {
        let _ = fs::rename(&backup, destination);
        return Err(FixError::Io {
            path: destination.to_path_buf(),
            source,
        });
    }
    let _ = fs::remove_file(backup);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use crate::{
        cache::ContentDigest,
        fixes::{
            AnalysisConfidence, ByteSpan, DependencyKind, DirectDependency, EligibilityDecision,
            FixCandidate, FixPlan, PackageManager, PackageManagerCommand, ProjectPath,
            PublicApiExposure, SourceEdit, WorldAssumption,
        },
    };

    use super::{
        CommandExecution, CommandExecutor, FixEngine, FixError, RevalidationOutcome,
        RevalidationRequest, Revalidator,
    };

    #[test]
    fn preview_is_read_only_and_apply_is_hash_guarded() {
        let directory = TestDirectory::new("preview");
        let source_path = directory.path().join("index.js");
        fs::write(&source_path, b"const unused = 1;\n").unwrap();
        let mut plan = plan();
        plan.add_source_edits(
            eligible(b"const unused = 1;\n"),
            ProjectPath::new("index.js").unwrap(),
            vec![SourceEdit::new(
                ByteSpan::new(0, b"const unused = 1;\n".len()).unwrap(),
                "",
            )],
            "The declaration has no live references",
        )
        .unwrap();
        let engine = FixEngine::new(directory.path()).unwrap();

        let preview = engine.preview(&plan).unwrap();
        assert_eq!(fs::read(&source_path).unwrap(), b"const unused = 1;\n");
        fs::write(&source_path, b"const changed = 2;\n").unwrap();

        let error = engine
            .apply(
                &preview,
                preview.explicit_apply_authorization(),
                &mut RecordingExecutor,
                &mut RecordingRevalidator::default(),
            )
            .unwrap_err();
        assert!(matches!(error, FixError::HashMismatch { .. }));
        assert_eq!(fs::read(&source_path).unwrap(), b"const changed = 2;\n");
    }

    #[test]
    fn explicit_apply_changes_the_file_then_revalidates() {
        let directory = TestDirectory::new("apply");
        let source = b"let keep = 1;\nlet unused = 2;\n";
        let source_path = directory.path().join("index.js");
        fs::write(&source_path, source).unwrap();
        let mut plan = plan();
        plan.add_source_edits(
            eligible(source),
            ProjectPath::new("index.js").unwrap(),
            vec![SourceEdit::new(
                ByteSpan::new(b"let keep = 1;\n".len(), source.len()).unwrap(),
                "",
            )],
            "The declaration has no live references",
        )
        .unwrap();
        let engine = FixEngine::new(directory.path()).unwrap();
        let preview = engine.preview(&plan).unwrap();
        let mut revalidator = RecordingRevalidator::default();

        let report = engine
            .apply(
                &preview,
                preview.explicit_apply_authorization(),
                &mut PanicExecutor,
                &mut revalidator,
            )
            .unwrap();

        assert_eq!(fs::read(&source_path).unwrap(), b"let keep = 1;\n");
        assert_eq!(report.changed_paths.len(), 1);
        assert!(revalidator.called);
        assert!(matches!(
            report.revalidation,
            RevalidationOutcome::Passed { .. }
        ));
    }

    #[test]
    fn changed_workspace_manifest_refuses_package_command_apply() {
        let directory = TestDirectory::new("manifest-precondition");
        let workspace_path = directory.path().join("packages/app");
        fs::create_dir_all(&workspace_path).unwrap();
        let manifest_path = workspace_path.join("package.json");
        let analyzed_manifest = b"{\"dependencies\":{\"unused\":\"1.0.0\"}}\n";
        fs::write(&manifest_path, analyzed_manifest).unwrap();
        let mut plan = plan();
        let command = PackageManagerCommand::remove_direct_dependency(
            PackageManager::Npm,
            ProjectPath::new("packages/app").unwrap(),
            ContentDigest::of_bytes(analyzed_manifest),
            DirectDependency::new("unused", DependencyKind::Production).unwrap(),
            "No reachable runtime or tool reference retains this dependency",
        )
        .unwrap();
        plan.add_package_command(command);
        let engine = FixEngine::new(directory.path()).unwrap();
        let preview = engine.preview(&plan).unwrap();

        fs::write(
            &manifest_path,
            b"{\"dependencies\":{\"unused\":\"2.0.0\"}}\n",
        )
        .unwrap();
        let mut revalidator = RecordingRevalidator::default();
        let error = engine
            .apply(
                &preview,
                preview.explicit_apply_authorization(),
                &mut PanicExecutor,
                &mut revalidator,
            )
            .unwrap_err();

        assert!(matches!(
            error,
            FixError::HashMismatch { ref path, .. } if path == "packages/app/package.json"
        ));
        assert!(!revalidator.called);
    }

    fn plan() -> FixPlan {
        FixPlan::new("fix-unused", "remove an unused declaration").unwrap()
    }

    fn eligible(source: &[u8]) -> crate::fixes::EligibleFix {
        let decision = FixCandidate {
            confidence: AnalysisConfidence::High,
            world: WorldAssumption::Closed,
            public_api: PublicApiExposure::OutsidePublicApi,
            blockers: Vec::new(),
            expected_content: Some(ContentDigest::of_bytes(source)),
            preserves_trivia_and_semantics: true,
        }
        .evaluate();
        let EligibilityDecision::Eligible(eligible) = decision else {
            panic!("test fixture should be eligible");
        };
        eligible
    }

    struct RecordingExecutor;

    impl CommandExecutor for RecordingExecutor {
        fn execute(
            &mut self,
            _project_root: &std::path::Path,
            command: &crate::fixes::PackageManagerCommand,
        ) -> CommandExecution {
            CommandExecution {
                command: command.clone(),
                success: true,
                exit_code: Some(0),
                message: String::new(),
            }
        }
    }

    struct PanicExecutor;

    impl CommandExecutor for PanicExecutor {
        fn execute(
            &mut self,
            _project_root: &std::path::Path,
            _command: &crate::fixes::PackageManagerCommand,
        ) -> CommandExecution {
            panic!("a changed workspace manifest must block process execution")
        }
    }

    #[derive(Default)]
    struct RecordingRevalidator {
        called: bool,
    }

    impl Revalidator for RecordingRevalidator {
        fn revalidate(&mut self, _request: RevalidationRequest<'_>) -> RevalidationOutcome {
            self.called = true;
            RevalidationOutcome::Passed { notes: Vec::new() }
        }
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "orphanode-fixes-{label}-{}-{}",
                std::process::id(),
                super::TEMPORARY_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
