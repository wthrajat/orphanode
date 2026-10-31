use std::fmt::Write as _;
use std::path::Path;

use orphanode::domain::report::AnalysisStatus;
use orphanode::{Explanation, ScanReport};

use crate::render::render_compact;

const LISTED_DIAGNOSTICS: usize = 5;

pub(super) fn scan_reply(root: &Path, mut report: ScanReport, max_findings: usize) -> String {
    let total_findings = report.findings.len();
    report.findings.truncate(max_findings);
    let mut reply = summary_line(root, &report);
    if total_findings == 0 {
        reply.push_str("\nNo dead code found.");
    } else {
        let shown = report.findings.len();
        let _ = writeln!(reply, "\n{total_findings} findings, showing {shown}:");
        reply.push_str(&render_compact(&report, root));
        reply.push_str("\nCall why with a path to see the evidence behind a finding.");
    }
    if report.status == AnalysisStatus::Incomplete {
        reply.push_str(&incomplete_note(&report));
    }
    reply
}

pub(super) fn why_reply(explanation: &Explanation) -> String {
    let mut reply = explanation.summary.clone();
    for step in &explanation.steps {
        let _ = write!(reply, "\n- {}", step.summary);
    }
    reply
}

fn summary_line(root: &Path, report: &ScanReport) -> String {
    let summary = &report.summary;
    let status = match report.status {
        AnalysisStatus::Complete => "complete",
        AnalysisStatus::Incomplete => "incomplete",
    };
    format!(
        "Scanned {} ({status}): {} files, {} reachable, {} unreachable, {} incomplete, {} diagnostics.",
        root.display(),
        summary.files,
        summary.reachable_files,
        summary.unreachable_files,
        summary.incomplete_files,
        summary.diagnostics,
    )
}

fn incomplete_note(report: &ScanReport) -> String {
    let mut note = String::from(
        "\n\nAnalysis is incomplete, so some dead code may be missing. First diagnostics:",
    );
    for diagnostic in report.diagnostics.iter().take(LISTED_DIAGNOSTICS) {
        let _ = write!(
            note,
            "\n- {} {}: {}",
            diagnostic.code, diagnostic.path, diagnostic.message
        );
    }
    note
}
