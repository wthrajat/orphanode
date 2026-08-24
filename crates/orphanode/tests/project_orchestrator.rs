use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use orphanode::domain::report::{AnalysisStatus, Confidence, FileStatus};
use orphanode::{ProjectScanRequest, ScanReport, scan_project};

static NEXT_PROJECT_ID: AtomicU64 = AtomicU64::new(0);

#[test]
fn bare_project_scan_discovers_workspace_files_and_roots() {
    let project = TestProject::from_fixture("project-workspaces");
    let report = scan_project(&ProjectScanRequest::new(project.root())).expect("scan project");

    assert_eq!(
        report.entries,
        vec![
            "packages/closed/src/index.js".to_owned(),
            "packages/open/src/index.js".to_owned(),
        ]
    );
    assert_eq!(
        report
            .files
            .iter()
            .map(|file| file.path.as_str())
            .collect::<Vec<_>>(),
        vec![
            "packages/closed/src/feature.js",
            "packages/closed/src/index.js",
            "packages/open/src/index.js",
            "packages/unused/src/index.js",
        ]
    );
    assert_eq!(
        report
            .project
            .as_ref()
            .expect("project metadata")
            .workspaces,
        vec![
            ".".to_owned(),
            "packages/closed".to_owned(),
            "packages/open".to_owned(),
            "packages/unused".to_owned(),
        ]
    );
}

#[test]
fn explicit_entry_keeps_the_complete_discovered_project_universe() {
    let project = TestProject::from_fixture("project-workspaces");
    let mut request = node_request(project.root());
    request.entries = vec![PathBuf::from("packages/closed/src/index.js")];

    let report = scan_project(&request).expect("scan project with explicit entry");

    assert_eq!(
        report.entries,
        vec!["packages/closed/src/index.js".to_owned()]
    );
    assert_eq!(report.files.len(), 4);
    assert!(
        report
            .files
            .iter()
            .any(|file| file.path == "packages/open/src/index.js")
    );
    assert!(
        report
            .files
            .iter()
            .any(|file| file.path == "packages/unused/src/index.js")
    );
}

#[test]
fn workspace_export_subpaths_link_to_source_without_node_modules() {
    let project = TestProject::from_fixture("project-workspaces");
    let report = scan_node_project(project.root());
    let importing_file = report
        .files
        .iter()
        .find(|file| file.path == "packages/open/src/index.js")
        .expect("workspace consumer");
    let import = importing_file
        .imports
        .iter()
        .find(|import| import.specifier == "@fixture/closed/feature")
        .expect("workspace subpath import");

    assert_eq!(
        import.target.as_deref(),
        Some("packages/closed/src/feature.js")
    );
    assert_eq!(
        file_status(&report, "packages/closed/src/feature.js"),
        FileStatus::Reachable
    );
}

#[test]
fn workspace_manifest_privacy_controls_open_and_closed_world_exports() {
    let project = TestProject::from_fixture("project-workspaces");

    let mut open_request = node_request(project.root());
    open_request.workspace = Some(PathBuf::from("packages/open"));
    let open_report = scan_project(&open_request).expect("scan open workspace");

    let mut closed_request = node_request(project.root());
    closed_request.workspace = Some(PathBuf::from("packages/closed"));
    let closed_report = scan_project(&closed_request).expect("scan closed workspace");

    assert!(!has_symbol_finding(&open_report, "publicApi"));
    assert!(has_symbol_finding(&closed_report, "closedApi"));
}

#[test]
fn unused_private_workspace_emits_orp3001() {
    let project = TestProject::from_fixture("project-workspaces");
    let report = scan_node_project(project.root());

    let workspace_findings = report
        .findings
        .iter()
        .filter(|finding| finding.issue_id == "ORP3001")
        .collect::<Vec<_>>();

    assert_eq!(workspace_findings.len(), 1);
    assert_eq!(workspace_findings[0].workspace, "packages/unused");
    assert_eq!(
        workspace_findings[0].paths,
        vec!["packages/unused/package.json".to_owned()]
    );
}

#[test]
fn custom_target_profiles_preserve_labels_and_select_conditions() {
    let project = TestProject::from_fixture("project-target-profiles");
    let mut request = ProjectScanRequest::new(project.root());
    request.target_profiles = vec!["server".to_owned(), "client".to_owned()];

    let report = scan_project(&request).expect("scan custom target profiles");
    let project_report = report.project.as_ref().expect("project metadata");
    let entry = report
        .files
        .iter()
        .find(|file| file.path == "src/index.js")
        .expect("entry file report");
    let targets = entry
        .imports
        .iter()
        .filter_map(|import| import.target.as_deref())
        .collect::<Vec<_>>();

    assert_eq!(
        project_report.target_profiles,
        vec!["client".to_owned(), "server".to_owned()]
    );
    assert_eq!(targets, vec!["src/client.js", "src/server.js"]);

    let default_finding = report
        .findings
        .iter()
        .find(|finding| finding.paths == ["src/default.js"])
        .expect("inactive default-condition finding");
    assert_eq!(
        default_finding.target_profiles,
        vec!["client".to_owned(), "server".to_owned()]
    );
}

#[test]
fn static_config_applies_ignore_retain_and_confidence_contracts() {
    let project = TestProject::from_fixture("project-config");
    let report = scan_node_project(project.root());
    let project_report = report.project.as_ref().expect("project metadata");

    assert!(
        report
            .files
            .iter()
            .all(|file| file.path != "src/ignored.js")
    );
    assert!(has_path_finding(&report, "src/reported.js"));
    assert!(!has_path_finding(&report, "src/retained.js"));
    assert!(report.retentions.iter().any(|retention| {
        retention.item == "src/retained.js"
            && retention
                .evidence
                .iter()
                .any(|evidence| evidence.contains("loaded by an external fixture host"))
    }));
    assert_eq!(
        project_report.failure_thresholds.get("."),
        Some(&Confidence::Medium)
    );
    assert_eq!(
        project_report.configuration_sources,
        vec!["orphanode.jsonc".to_owned()]
    );
}

#[test]
fn builtin_plugin_config_gaps_warn_while_dynamic_imports_still_block() {
    let project = TestProject::from_fixture("plugin-next-gap");
    let report = scan_node_project(project.root());
    let project_report = report.project.as_ref().expect("project metadata");

    assert!(
        project_report
            .detected_plugins
            .iter()
            .any(|plugin| plugin == "next")
    );
    assert!(
        report
            .entries
            .iter()
            .any(|entry| entry == "app/[slug]/page.tsx")
    );
    assert_eq!(
        file_status(&report, "app/[slug]/page.tsx"),
        FileStatus::Reachable
    );
    // Tooling-configuration gaps are visible without suppressing findings.
    assert!(report.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "plugin_next_dynamic_config" && !diagnostic.blocks_reachability
    }));
    // Unenumerable dynamic imports remain coverage blockers.
    assert!(report.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "unsupported_dynamic_import" && diagnostic.blocks_reachability
    }));
    let blocked_file = report
        .files
        .iter()
        .find(|file| file.path == "lib/unused.ts")
        .expect("blocked file report");
    assert_eq!(blocked_file.status, FileStatus::Incomplete);
    assert_eq!(
        blocked_file.target_statuses.get("node"),
        Some(&FileStatus::Incomplete)
    );
    assert_eq!(report.status, AnalysisStatus::Incomplete);
}

#[test]
fn repeated_project_scan_reuses_fact_cache_without_changing_analysis() {
    let project = TestProject::from_fixture("project-config");
    let request = node_request(project.root());

    let first = scan_project(&request).expect("first project scan");
    let second = scan_project(&request).expect("cached project scan");
    let first_cache = first.cache.as_ref().expect("first cache report");
    let second_cache = second.cache.as_ref().expect("second cache report");

    assert!(first_cache.misses > 0);
    assert!(first_cache.generation_written);
    assert_eq!(second_cache.misses, 0);
    assert_eq!(second_cache.hits, second.files.len());
    assert!(!second_cache.generation_written);

    let mut first_value = serde_json::to_value(&first).expect("serialize first report");
    let mut second_value = serde_json::to_value(&second).expect("serialize second report");
    first_value
        .as_object_mut()
        .expect("report object")
        .remove("cache");
    second_value
        .as_object_mut()
        .expect("report object")
        .remove("cache");
    assert_eq!(first_value, second_value);
}

fn node_request(root: &Path) -> ProjectScanRequest {
    let mut request = ProjectScanRequest::new(root);
    request.target_profiles = vec!["node".to_owned()];
    request
}

fn scan_node_project(root: &Path) -> ScanReport {
    scan_project(&node_request(root)).expect("scan project")
}

fn file_status(report: &ScanReport, path: &str) -> FileStatus {
    report
        .files
        .iter()
        .find(|file| file.path == path)
        .map(|file| file.status)
        .expect("file report")
}

fn has_symbol_finding(report: &ScanReport, symbol: &str) -> bool {
    report
        .findings
        .iter()
        .any(|finding| finding.symbol.as_deref() == Some(symbol))
}

fn has_path_finding(report: &ScanReport, path: &str) -> bool {
    report
        .findings
        .iter()
        .any(|finding| finding.paths.iter().any(|candidate| candidate == path))
}

struct TestProject {
    root: PathBuf,
}

impl TestProject {
    fn from_fixture(name: &str) -> Self {
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures")
            .join(name);
        let id = NEXT_PROJECT_ID.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("orphanode-project-e2e-{}-{id}", std::process::id()));

        fs::create_dir(&root).expect("create temporary project");
        copy_directory(&source, &root);
        Self { root }
    }

    fn root(&self) -> &Path {
        &self.root
    }
}

impl Drop for TestProject {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn copy_directory(source: &Path, destination: &Path) {
    let mut entries = fs::read_dir(source)
        .expect("read fixture directory")
        .collect::<Result<Vec<_>, _>>()
        .expect("read fixture entry");
    entries.sort_by_key(fs::DirEntry::file_name);

    for entry in entries {
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let file_type = entry.file_type().expect("fixture entry type");
        if file_type.is_dir() {
            fs::create_dir(&destination_path).expect("create fixture directory");
            copy_directory(&source_path, &destination_path);
        } else if file_type.is_file() {
            fs::copy(&source_path, &destination_path).expect("copy fixture file");
        } else {
            panic!("project fixture must contain only regular files and directories");
        }
    }
}
