use std::{fs, path::PathBuf};

use orphanode::domain::{
    facts::ImportKind,
    report::{AnalysisStatus, FileStatus, ResolutionStatus},
};
use orphanode::{ScanReport, ScanRequest, scan};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct FixtureManifest {
    #[serde(default)]
    entry: Option<PathBuf>,
    #[serde(default)]
    entries: Vec<PathBuf>,
    files: Vec<PathBuf>,
}

#[test]
fn esm_import_retains_its_target() {
    let report = scan_fixture("esm");

    assert_eq!(report.status, AnalysisStatus::Complete);
    assert_eq!(
        file_status(&report, "src/message.js"),
        FileStatus::Reachable
    );
    assert_eq!(
        file_status(&report, "src/unused.js"),
        FileStatus::Unreachable
    );
    assert!(finding_paths(&report).contains(&"src/unused.js"));
}

#[test]
fn common_js_require_retains_its_target() {
    let report = scan_fixture("commonjs");
    let entry = report
        .files
        .iter()
        .find(|file| file.path == "src/index.cjs")
        .expect("entry report");

    assert_eq!(
        file_status(&report, "src/message.cjs"),
        FileStatus::Reachable
    );
    assert_eq!(entry.imports[0].kind, ImportKind::CommonJsRequire);
    assert_eq!(entry.imports[0].status, ResolutionStatus::Resolved);
}

#[test]
fn side_effect_import_retains_its_target() {
    let report = scan_fixture("side-effect-import");
    let entry = report
        .files
        .iter()
        .find(|file| file.path == "src/index.js")
        .expect("entry report");

    assert_eq!(entry.imports[0].kind, ImportKind::SideEffect);
    assert_eq!(file_status(&report, "src/setup.js"), FileStatus::Reachable);
}

#[test]
fn top_level_literal_dynamic_import_retains_its_target() {
    let report = scan_fixture("literal-dynamic-import");
    let entry = report
        .files
        .iter()
        .find(|file| file.path == "src/index.js")
        .expect("entry report");

    assert_eq!(entry.imports[0].kind, ImportKind::Dynamic);
    assert_eq!(
        file_status(&report, "src/feature.js"),
        FileStatus::Reachable
    );
}

#[test]
fn an_unreachable_cycle_is_grouped() {
    let report = scan_fixture("dead-cycle");

    assert_eq!(report.findings.len(), 1);
    assert_eq!(
        report.findings[0].paths,
        vec!["src/dead-a.js", "src/dead-b.js"]
    );
}

#[test]
fn a_parse_failure_is_incomplete_and_never_unused() {
    let report = scan_fixture("parse-failure");

    assert_eq!(report.status, AnalysisStatus::Incomplete);
    assert_eq!(
        file_status(&report, "src/broken.js"),
        FileStatus::Incomplete
    );
    assert!(
        report
            .diagnostics
            .iter()
            .any(|item| { item.code == "parse_failure" && item.path == "src/broken.js" })
    );
    assert!(!finding_paths(&report).contains(&"src/broken.js"));
}

#[test]
fn a_typescript_path_alias_resolves_to_a_local_source() {
    let report = scan_fixture("ts-path-alias");

    assert_eq!(report.status, AnalysisStatus::Complete);
    assert!(report.findings.is_empty());
    assert_eq!(
        file_status(&report, "src/message.ts"),
        FileStatus::Reachable
    );
}

#[test]
fn a_declared_external_package_does_not_block_file_findings() {
    let report = scan_fixture("external-package-import");
    let entry = report
        .files
        .iter()
        .find(|file| file.path == "src/index.js")
        .expect("entry report");

    assert_eq!(report.status, AnalysisStatus::Complete);
    assert_eq!(entry.imports[0].status, ResolutionStatus::External);
    assert!(finding_paths(&report).contains(&"src/unused.js"));
}

#[test]
fn a_local_stylesheet_is_an_external_asset_edge() {
    let report = scan_fixture("css-asset-import");
    let entry = report
        .files
        .iter()
        .find(|file| file.path == "src/index.ts")
        .expect("entry report");

    assert_eq!(report.status, AnalysisStatus::Complete);
    assert_eq!(entry.imports[0].status, ResolutionStatus::External);
    assert!(finding_paths(&report).contains(&"src/unused.ts"));
}

#[test]
fn an_embedded_code_source_is_a_visible_coverage_gap() {
    let report = scan_fixture("unsupported-source-import");

    assert_eq!(report.status, AnalysisStatus::Incomplete);
    assert!(report.findings.is_empty());
    assert!(report.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "unsupported_imported_source" && diagnostic.path == "src/index.js"
    }));
}

#[test]
fn resource_queries_and_fragments_resolve_using_filesystem_paths() {
    let report = scan_fixture("resource-query-import");
    let entry = report
        .files
        .iter()
        .find(|file| file.path == "src/index.js")
        .expect("entry report");

    assert_eq!(report.status, AnalysisStatus::Complete);
    assert_eq!(entry.imports.len(), 2);
    assert!(
        entry
            .imports
            .iter()
            .all(|import| import.status == ResolutionStatus::Resolved)
    );
    assert_eq!(
        entry
            .imports
            .iter()
            .filter_map(|import| import.target.as_deref())
            .collect::<Vec<_>>(),
        vec!["src/message.js", "src/detail.js"]
    );
    assert_eq!(
        file_status(&report, "src/message.js"),
        FileStatus::Reachable
    );
    assert_eq!(file_status(&report, "src/detail.js"), FileStatus::Reachable);
}

#[test]
fn a_native_addon_is_a_visible_coverage_gap() {
    let report = scan_fixture("native-addon-import");

    assert_eq!(report.status, AnalysisStatus::Incomplete);
    assert!(report.findings.is_empty());
    assert!(report.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "unsupported_imported_source" && diagnostic.path == "src/index.js"
    }));
}

#[test]
fn multiple_entries_are_all_live_roots() {
    let report = scan_fixture("multi-entry");

    assert_eq!(
        report.entries,
        vec!["src/cli.js".to_owned(), "src/server.js".to_owned()]
    );
    assert_eq!(file_status(&report, "src/cli.js"), FileStatus::Reachable);
    assert_eq!(file_status(&report, "src/server.js"), FileStatus::Reachable);
    assert!(finding_paths(&report).contains(&"src/unused.js"));
}

#[test]
fn repeated_scans_produce_byte_identical_json() {
    let first = serde_json::to_vec(&scan_fixture("dead-cycle")).expect("serialize report");
    let second = serde_json::to_vec(&scan_fixture("dead-cycle")).expect("serialize report");

    assert_eq!(first, second);
}

fn scan_fixture(name: &str) -> ScanReport {
    let root = fixture_root(name);
    let manifest_source = fs::read_to_string(root.join("files.json")).expect("fixture manifest");
    let manifest =
        serde_json::from_str::<FixtureManifest>(&manifest_source).expect("valid fixture manifest");
    let entries = match manifest.entry {
        Some(entry) => vec![entry],
        None => manifest.entries,
    };

    scan(&ScanRequest {
        root,
        entries,
        files: manifest.files,
    })
    .expect("scan fixture")
}

fn fixture_root(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

fn file_status(report: &ScanReport, path: &str) -> FileStatus {
    report
        .files
        .iter()
        .find(|file| file.path == path)
        .map(|file| file.status)
        .expect("file report")
}

fn finding_paths(report: &ScanReport) -> Vec<&str> {
    report
        .findings
        .iter()
        .flat_map(|finding| finding.paths.iter().map(String::as_str))
        .collect()
}
