use std::path::{Path, PathBuf};

use orphanode::AnalysisIssue;
use rmcp::schemars::{self, JsonSchema};
use serde::Deserialize;

const DEFAULT_MAX_FINDINGS: usize = 50;

#[derive(Deserialize, JsonSchema)]
pub(super) struct ScanArguments {
    /// Absolute path to the project root, the folder with package.json
    pub root: String,
    /// Issue families to report: files, exports, declarations, members,
    /// dependencies, workspaces. Omit for all of them.
    pub issues: Option<Vec<String>>,
    /// Workspace to analyze, relative to the root, for monorepos
    pub workspace: Option<String>,
    /// Most findings to list. Defaults to 50.
    pub max_findings: Option<usize>,
}

#[derive(Deserialize, JsonSchema)]
pub(super) struct WhyArguments {
    /// Absolute path to the project root, the folder with package.json
    pub root: String,
    /// A file path relative to the root, or a package name
    pub query: String,
}

#[derive(Deserialize, JsonSchema)]
pub(super) struct IssueArguments {
    /// An orphanode issue code, such as ORP1002
    pub issue_id: String,
}

impl ScanArguments {
    pub(super) fn max_findings(&self) -> usize {
        self.max_findings.unwrap_or(DEFAULT_MAX_FINDINGS)
    }
}

pub(super) fn project_root(root: &str) -> Result<PathBuf, String> {
    let path = Path::new(root);
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| error.to_string())?
            .join(path)
    };
    if absolute.is_dir() {
        Ok(absolute)
    } else {
        Err(format!("No project folder at {}", absolute.display()))
    }
}

pub(super) fn issue_families(
    names: Option<&[String]>,
) -> Result<std::collections::BTreeSet<AnalysisIssue>, String> {
    let Some(names) = names.filter(|names| !names.is_empty()) else {
        return Ok(AnalysisIssue::all());
    };
    names.iter().map(|name| issue_family(name)).collect()
}

fn issue_family(name: &str) -> Result<AnalysisIssue, String> {
    match name.trim().to_ascii_lowercase().as_str() {
        "files" => Ok(AnalysisIssue::Files),
        "exports" => Ok(AnalysisIssue::Exports),
        "declarations" => Ok(AnalysisIssue::Declarations),
        "members" => Ok(AnalysisIssue::Members),
        "dependencies" => Ok(AnalysisIssue::Dependencies),
        "workspaces" => Ok(AnalysisIssue::Workspaces),
        other => Err(format!(
            "Unknown issue family \"{other}\"; use files, exports, declarations, members, dependencies or workspaces"
        )),
    }
}
