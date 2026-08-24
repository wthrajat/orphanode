use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

use serde_json::Value;

#[test]
fn json_output_is_stable_and_uses_finding_exit_code() {
    let first = run_fixture("esm", ["--format", "json"]);
    let second = run_fixture("esm", ["--format", "json"]);

    assert_eq!(first.status.code(), Some(1));
    assert_eq!(first.stdout, second.stdout);
    let report: Value = serde_json::from_slice(&first.stdout).expect("valid JSON report");
    assert_eq!(report["schemaVersion"], "0.2");
    assert_eq!(report["status"], "complete");
    assert_eq!(report["entries"][0], "src/index.js");
    assert!(report.get("timestamp").is_none());
}

#[test]
fn incomplete_analysis_uses_dedicated_exit_code() {
    let output = run_fixture("parse-failure", ["--format", "json"]);

    assert_eq!(output.status.code(), Some(2));
    let report: Value = serde_json::from_slice(&output.stdout).expect("valid JSON report");
    assert_eq!(report["status"], "incomplete");
    assert_eq!(report["findings"].as_array().map(Vec::len), Some(0));
}

#[test]
fn a_manifest_can_supply_multiple_entries() {
    let output = run_fixture("multi-entry", ["--format", "json"]);

    assert_eq!(output.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&output.stdout).expect("valid JSON report");
    assert_eq!(report["entries"].as_array().map(Vec::len), Some(2));
    assert_eq!(report["summary"]["reachableFiles"], 2);
}

#[test]
fn human_output_has_a_clear_summary_without_color_when_disabled() {
    let output = run_fixture(
        "dead-cycle",
        ["--format", "human", "--color", "never", "--ascii"],
    );
    let status = output.status.code();
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 terminal output");

    assert_eq!(status, Some(1));
    assert!(stdout.contains("ORPHANODE"));
    assert!(stdout.contains("src/dead-a.js"));
    assert!(stdout.contains("ORP1001"));
    assert!(!stdout.contains("\u{1b}["));
}

#[test]
fn entry_only_scans_use_project_discovery() {
    let discovered_output =
        run_discovered_fixture("package-private-app", "src/index.ts", ["--format", "json"]);
    let report: Value =
        serde_json::from_slice(&discovered_output.stdout).expect("valid JSON report");

    assert_eq!(discovered_output.status.code(), Some(1));
    assert_eq!(report["entries"][0], "src/index.ts");
    assert_eq!(report["project"]["mode"], "balanced");
}

#[test]
fn explicit_files_are_not_supplemented_by_discovery() {
    let fixture = fixture_root("esm");
    let output = Command::new(env!("CARGO_BIN_EXE_orphanode"))
        .arg("scan")
        .arg("--root")
        .arg(&fixture)
        .arg("--entry")
        .arg("src/index.js")
        .arg("--file")
        .arg("src/index.js")
        .arg("--format")
        .arg("json")
        .output()
        .expect("run orphanode");
    let report: Value = serde_json::from_slice(&output.stdout).expect("valid JSON report");

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(report["status"], "incomplete");
    assert_eq!(report["summary"]["files"], 1);
    assert!(report["project"].is_null());
}

#[test]
fn workspace_is_rejected_with_an_explicit_file_universe() {
    let fixture = fixture_root("esm");
    let output = Command::new(env!("CARGO_BIN_EXE_orphanode"))
        .arg("scan")
        .arg("--root")
        .arg(&fixture)
        .args([
            "--entry",
            "src/index.js",
            "--file",
            "src/index.js",
            "--workspace",
            ".",
        ])
        .output()
        .expect("run orphanode");
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 error output");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(stderr.contains("--workspace cannot be combined with --file or --files-from"));
}

#[test]
fn project_only_options_are_rejected_with_an_explicit_file_universe() {
    let fixture = fixture_root("esm");
    let output = Command::new(env!("CARGO_BIN_EXE_orphanode"))
        .arg("scan")
        .arg("--root")
        .arg(&fixture)
        .args([
            "--entry",
            "src/index.js",
            "--file",
            "src/index.js",
            "--mode",
            "deep",
        ])
        .output()
        .expect("run orphanode");
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 error output");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(stderr.contains("--mode cannot be used with the explicit"));
}

#[test]
fn entry_only_project_scans_require_a_controlling_package() {
    let output = run_discovered_fixture(
        "nested-package-boundary",
        "src/index.js",
        ["--format", "json"],
    );
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 error output");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(stderr.contains("no controlling package.json exists at or above"));
}

#[test]
fn sarif_output_uses_the_standard_contract() {
    let output = run_fixture("esm", ["--format", "sarif"]);
    let sarif: Value = serde_json::from_slice(&output.stdout).expect("valid SARIF JSON");

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(sarif["version"], "2.1.0");
    assert_eq!(sarif["runs"][0]["tool"]["driver"]["name"], "OrphaNode");
    assert_eq!(sarif["runs"][0]["results"][0]["ruleId"], "ORP1001");
}

#[test]
fn timings_do_not_corrupt_machine_readable_output() {
    for format in ["json", "sarif"] {
        let output = run_fixture("esm", ["--format", format, "--timings"]);
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 timing output");

        serde_json::from_slice::<Value>(&output.stdout).expect("valid machine-readable JSON");
        assert!(stderr.contains("orphanode: timings: analysis"));
        assert!(stderr.contains("orphanode: timings: render"));
        assert!(stderr.contains("orphanode: timings: total"));
    }
}

#[test]
fn debug_reports_project_stages_counts_cache_and_diagnostics_on_stderr() {
    let project = TestProject::new("debug-telemetry");
    project.write(
        "package.json",
        "{\"name\":\"debug-telemetry\",\"private\":true,\"type\":\"module\",\"scripts\":{\"start\":\"node src/index.js\"}}\n",
    );
    project.write("src/index.js", "console.log('entry');\n");

    let output = Command::new(env!("CARGO_BIN_EXE_orphanode"))
        .args(["scan", "--root"])
        .arg(project.path())
        .args(["--format", "json", "--debug"])
        .output()
        .expect("run debug scan");
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 debug output");

    serde_json::from_slice::<Value>(&output.stdout).expect("valid machine-readable JSON");
    assert!(stderr.contains("orphanode: debug: stage=workspace_discovery"));
    assert!(stderr.contains("orphanode: debug: stage=file_discovery"));
    assert!(stderr.contains("orphanode: debug: cache hits="));
    assert!(stderr.contains("findings="));
    assert!(stderr.contains("diagnostics="));
}

#[test]
fn why_explains_a_reachable_file_with_a_deterministic_chain() {
    let fixture = fixture_root("esm");
    let output = Command::new(env!("CARGO_BIN_EXE_orphanode"))
        .arg("why")
        .arg("src/message.js")
        .arg("--root")
        .arg(&fixture)
        .arg("--files-from")
        .arg("files.json")
        .arg("--format")
        .arg("json")
        .output()
        .expect("run orphanode why");
    let explanation: Value =
        serde_json::from_slice(&output.stdout).expect("valid explanation JSON");

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(explanation["status"], "retained");
    assert_eq!(explanation["steps"][0]["path"], "src/index.js");
    assert_eq!(explanation["steps"][1]["path"], "src/message.js");
}

#[test]
fn bare_why_uses_project_discovery() {
    let fixture = fixture_root("package-private-app");
    let output = Command::new(env!("CARGO_BIN_EXE_orphanode"))
        .arg("why")
        .arg("src/message.ts")
        .arg("--root")
        .arg(&fixture)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run orphanode why");
    let explanation: Value =
        serde_json::from_slice(&output.stdout).expect("valid explanation JSON");

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(explanation["status"], "retained");
    assert_eq!(explanation["steps"][0]["path"], "src/index.ts");
    assert_eq!(explanation["steps"][1]["path"], "src/message.ts");
}

#[test]
fn explain_describes_a_stable_issue_identifier() {
    let output = Command::new(env!("CARGO_BIN_EXE_orphanode"))
        .args(["explain", "ORP1001", "--json"])
        .output()
        .expect("run orphanode explain");
    let explanation: Value =
        serde_json::from_slice(&output.stdout).expect("valid issue description JSON");

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(explanation["issueId"], "ORP1001");
    assert_eq!(explanation["title"], "Unreachable source files");
}

#[test]
fn whole_file_fixes_require_selection_preview_and_revalidate() {
    let project = TestProject::new("file-fix");
    project.write(
        "package.json",
        "{\"name\":\"file-fix\",\"private\":true,\"type\":\"module\",\"scripts\":{\"start\":\"node src/index.js\"}}\n",
    );
    project.write("src/index.js", "console.log('entry');\n");
    project.write("src/unused.js", "export const unused = true;\n");

    let report_output = Command::new(env!("CARGO_BIN_EXE_orphanode"))
        .args(["scan", "--root"])
        .arg(project.path())
        .args(["--issues", "files", "--format", "json"])
        .output()
        .expect("scan file fix project");
    let report: Value =
        serde_json::from_slice(&report_output.stdout).expect("valid file fix report");
    let unused_file = report["findings"]
        .as_array()
        .and_then(|findings| {
            findings.iter().find(|finding| {
                finding["issueType"] == "unusedFiles"
                    && finding["paths"]
                        .as_array()
                        .is_some_and(|paths| paths.iter().any(|path| path == "src/unused.js"))
            })
        })
        .expect("unused file finding");
    assert_eq!(unused_file["fixEligibility"], "eligible", "{report:#}");

    let preview = Command::new(env!("CARGO_BIN_EXE_orphanode"))
        .args(["scan", "--root"])
        .arg(project.path())
        .args(["--issues", "files", "--fix", "--fix-file", "src/unused.js"])
        .output()
        .expect("preview file fix");
    let preview_text = String::from_utf8(preview.stdout).expect("UTF-8 preview");
    assert_eq!(
        preview.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&preview.stderr)
    );
    assert!(preview_text.contains("FILE CHANGES (1)"));
    assert!(preview_text.contains("delete  src/unused.js"));
    assert!(preview_text.contains("reason  src/unused.js is unreachable"));
    assert!(project.path().join("src/unused.js").is_file());

    let applied = Command::new(env!("CARGO_BIN_EXE_orphanode"))
        .args(["scan", "--root"])
        .arg(project.path())
        .args([
            "--issues",
            "files",
            "--fix",
            "--apply",
            "--fix-file",
            "src/unused.js",
        ])
        .output()
        .expect("apply file fix");
    let applied_text = String::from_utf8(applied.stdout).expect("UTF-8 apply output");
    assert_eq!(applied.status.code(), Some(0));
    assert!(applied_text.contains("POST-APPLY SCAN"));
    assert!(!project.path().join("src/unused.js").exists());
}

#[test]
fn dependency_fix_preview_groups_workspace_changes_and_explains_each_removal() {
    let project = TestProject::new("dependency-fix-preview");
    project.write(
        "package.json",
        "{\"name\":\"dependency-fix-preview\",\"private\":true,\"type\":\"module\",\"scripts\":{\"start\":\"node src/index.js\"},\"dependencies\":{\"unused\":\"1.0.0\"}}\n",
    );
    project.write("package-lock.json", "{\"lockfileVersion\":3}\n");
    project.write("src/index.js", "console.log('entry');\n");

    let preview = Command::new(env!("CARGO_BIN_EXE_orphanode"))
        .args(["scan", "--root"])
        .arg(project.path())
        .args([
            "--issues",
            "dependencies",
            "--fix",
            "--fix-dependency",
            "unused",
        ])
        .output()
        .expect("preview dependency fix");
    let stdout = String::from_utf8(preview.stdout).expect("UTF-8 preview");

    assert_eq!(preview.status.code(), Some(1));
    assert!(stdout.contains("DEPENDENCY CHANGES (1)"));
    assert!(stdout.contains("workspace  ."));
    assert!(stdout.contains("manifest  package.json"));
    assert!(stdout.contains("remove  unused"));
    assert!(stdout.contains("reason  dependency unused has no reachable evidence"));
    assert!(stdout.contains("command  npm uninstall unused"));
}

fn run_fixture<const N: usize>(name: &str, extra_arguments: [&str; N]) -> std::process::Output {
    let fixture = fixture_root(name);
    let mut command = Command::new(env!("CARGO_BIN_EXE_orphanode"));
    command
        .arg("scan")
        .arg("--root")
        .arg(&fixture)
        .arg("--files-from")
        .arg("files.json")
        .args(extra_arguments);
    command.output().expect("run orphanode")
}

fn run_discovered_fixture<const N: usize>(
    name: &str,
    entry: &str,
    extra_arguments: [&str; N],
) -> std::process::Output {
    let fixture = fixture_root(name);
    Command::new(env!("CARGO_BIN_EXE_orphanode"))
        .arg("scan")
        .arg("--root")
        .arg(&fixture)
        .arg("--entry")
        .arg(entry)
        .args(extra_arguments)
        .output()
        .expect("run orphanode")
}

fn fixture_root(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

static TEST_PROJECT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TestProject {
    root: PathBuf,
}

impl TestProject {
    fn new(label: &str) -> Self {
        let sequence = TEST_PROJECT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "orphanode-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create isolated test project");
        Self { root }
    }

    fn path(&self) -> &Path {
        &self.root
    }

    fn write(&self, relative: &str, contents: &str) {
        let path = self.root.join(relative);
        fs::create_dir_all(path.parent().expect("test file has parent"))
            .expect("create test directory");
        fs::write(path, contents).expect("write test file");
    }
}

impl Drop for TestProject {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).expect("remove isolated test project");
    }
}
