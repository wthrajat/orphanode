use std::{
    collections::{BTreeSet, HashMap},
    fmt::Write as _,
    path::Path,
};

use orphanode::{
    ScanReport,
    domain::{
        facts::DiagnosticSeverity,
        report::{AnalysisStatus, Confidence, UnusedFilesFinding},
    },
};

const ANSI_RESET: &str = "\u{1b}[0m";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenderOptions {
    pub color: bool,
    pub unicode: bool,
}

#[must_use]
pub fn render_human(report: &ScanReport, options: RenderOptions) -> String {
    Renderer::new(options).render(report)
}

/// Renders one ts-prune-style line per finding:
/// `path:line:column - CODE 'name' is unused`.
#[must_use]
pub fn render_compact(report: &ScanReport, root: &Path) -> String {
    let mut sources = HashMap::new();
    let mut output = String::new();
    for finding in &report.findings {
        let name = finding
            .symbol
            .as_deref()
            .or(finding.dependency.as_deref())
            .unwrap_or(finding.issue_type);
        for path in &finding.paths {
            let position = if finding.paths.len() == 1 {
                finding
                    .span
                    .map(|span| source_position(&mut sources, root, path, span.start))
                    .map_or_else(String::new, |(line, column)| format!(":{line}:{column}"))
            } else {
                String::new()
            };
            let _ = writeln!(
                output,
                "{path}{position} - {} '{name}' is unused",
                finding.issue_id
            );
        }
    }
    output
}

fn source_position(
    sources: &mut HashMap<String, Vec<u8>>,
    root: &Path,
    path: &str,
    offset: u32,
) -> (u32, u32) {
    let bytes = sources
        .entry(path.to_owned())
        .or_insert_with(|| std::fs::read(root.join(path)).unwrap_or_default());
    if bytes.is_empty() {
        return (0, 0);
    }
    let offset = (offset as usize).min(bytes.len());
    let before = &bytes[..offset];
    // A one-shot line count over one small source file does not warrant a
    // SIMD byte-count dependency.
    #[allow(clippy::naive_bytecount)]
    let newlines = before.iter().filter(|byte| **byte == b'\n').count();
    let line = 1 + u32::try_from(newlines).unwrap_or(u32::MAX);
    let line_start = before
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |position| position + 1);
    let column = std::str::from_utf8(&before[line_start..])
        .map_or(before.len() - line_start, |text| text.chars().count())
        + 1;
    (line, u32::try_from(column).unwrap_or(u32::MAX))
}

#[derive(Debug, Clone, Copy)]
enum Style {
    Brand,
    Heading,
    Success,
    Warning,
    Error,
    Muted,
}

impl Style {
    const fn ansi_code(self) -> &'static str {
        match self {
            Self::Brand | Self::Warning => "1;38;5;214",
            Self::Heading => "1",
            Self::Success => "1;32",
            Self::Error => "1;31",
            Self::Muted => "38;5;245",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Glyphs {
    pointer: &'static str,
    separator: &'static str,
    finding: &'static str,
    branch: &'static str,
    last_branch: &'static str,
    empty: &'static str,
    success: &'static str,
    warning: &'static str,
    error: &'static str,
    hint: &'static str,
}

impl Glyphs {
    const fn new(unicode: bool) -> Self {
        if unicode {
            Self {
                pointer: "›",
                separator: "·",
                finding: "●",
                branch: "├─",
                last_branch: "└─",
                empty: "—",
                success: "✓",
                warning: "▲",
                error: "✕",
                hint: "↳",
            }
        } else {
            Self {
                pointer: ">",
                separator: "|",
                finding: "*",
                branch: "|-",
                last_branch: "`-",
                empty: "-",
                success: "[OK]",
                warning: "!",
                error: "x",
                hint: "->",
            }
        }
    }
}

struct Renderer {
    output: String,
    options: RenderOptions,
    glyphs: Glyphs,
}

impl Renderer {
    fn new(options: RenderOptions) -> Self {
        Self {
            output: String::new(),
            options,
            glyphs: Glyphs::new(options.unicode),
        }
    }

    fn render(mut self, report: &ScanReport) -> String {
        self.render_header(report);
        self.render_findings(report);
        self.render_diagnostics(report);
        self.render_footer(report.status);
        self.output
    }

    fn render_header(&mut self, report: &ScanReport) {
        self.write_styled("ORPHANODE", Style::Brand);
        self.output.push_str("  ");
        self.write_styled("reachability scan", Style::Muted);
        self.output.push_str("\n\n");

        self.render_entries(&report.entries);

        if let Some(project) = &report.project {
            self.output.push_str("  ");
            self.write_styled("Mode", Style::Muted);
            self.output.push_str("  ");
            self.write_safe_text(&project.mode, "balanced");
            self.write_metric_separator();
            write!(
                self.output,
                "{} workspace{}",
                project.workspaces.len(),
                if project.workspaces.len() == 1 {
                    ""
                } else {
                    "s"
                }
            )
            .expect("writing to a String cannot fail");
            let worlds = project.worlds.values().collect::<BTreeSet<_>>();
            if let Some(world) = worlds.iter().next()
                && worlds.len() == 1
            {
                self.output.push_str(" (");
                self.write_safe_text(world, "unknown");
                self.output.push(')');
            } else if !worlds.is_empty() {
                self.output.push_str(" (mixed world)");
            }
            self.write_metric_separator();
            write!(
                self.output,
                "{} target profiles",
                project.target_profiles.len()
            )
            .expect("writing to a String cannot fail");
            if !project.detected_plugins.is_empty() {
                self.write_metric_separator();
                write!(self.output, "{} plugins", project.detected_plugins.len())
                    .expect("writing to a String cannot fail");
            }
            self.output.push('\n');
        }

        self.output.push_str("  ");
        self.write_metric(report.summary.reachable_files, "reachable", Style::Success);
        self.write_metric_separator();
        self.write_metric(
            report.summary.unreachable_files,
            "unreachable",
            if report.summary.unreachable_files == 0 {
                Style::Muted
            } else {
                Style::Warning
            },
        );
        self.write_metric_separator();
        self.write_metric(
            report.summary.incomplete_files,
            "incomplete",
            if report.summary.incomplete_files == 0 {
                Style::Muted
            } else {
                Style::Warning
            },
        );
        self.write_metric_separator();

        let diagnostic_style = if report.diagnostics.is_empty() {
            Style::Muted
        } else if report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
        {
            Style::Error
        } else {
            Style::Warning
        };
        self.write_metric(report.summary.diagnostics, "diagnostics", diagnostic_style);
        self.output.push('\n');
        if let Some(cache) = &report.cache {
            self.output.push_str("  ");
            self.write_styled("Cache", Style::Muted);
            write!(
                self.output,
                "  {} hit{} {} miss{}",
                cache.hits,
                if cache.hits == 1 { "" } else { "s" },
                cache.misses,
                if cache.misses == 1 { "" } else { "es" }
            )
            .expect("writing to a String cannot fail");
            if cache.generation_written {
                self.output.push_str("  updated");
            }
            self.output.push('\n');
        }
    }

    fn render_entries(&mut self, entries: &[String]) {
        self.write_styled(self.glyphs.pointer, Style::Brand);
        match entries {
            [] => {
                self.output.push_str(" Entries  ");
                self.write_styled("none configured", Style::Warning);
                self.output.push('\n');
            }
            [entry] => {
                self.output.push_str(" Entry  ");
                self.write_safe_text(entry, "<not provided>");
                self.output.push('\n');
            }
            _ => {
                writeln!(self.output, " Entries  {} configured", entries.len())
                    .expect("writing to a String cannot fail");
                let visible_count = entries.len().min(3);
                for (index, entry) in entries.iter().take(visible_count).enumerate() {
                    let has_more = entries.len() > visible_count;
                    let is_last = index + 1 == visible_count && !has_more;
                    self.output.push_str("    ");
                    self.write_styled(
                        if is_last {
                            self.glyphs.last_branch
                        } else {
                            self.glyphs.branch
                        },
                        Style::Muted,
                    );
                    self.output.push(' ');
                    self.write_safe_text(entry, "<empty>");
                    self.output.push('\n');
                }
                if entries.len() > visible_count {
                    self.output.push_str("    ");
                    self.write_styled(self.glyphs.last_branch, Style::Muted);
                    self.output.push(' ');
                    let overflow_marker = if self.options.unicode { "…" } else { "..." };
                    writeln!(
                        self.output,
                        "{overflow_marker} {} more",
                        entries.len() - visible_count
                    )
                    .expect("writing to a String cannot fail");
                }
            }
        }
    }

    fn render_findings(&mut self, report: &ScanReport) {
        self.write_section_heading("FINDINGS");

        if report.findings.is_empty() {
            self.write_empty_state("None reported");
            return;
        }

        for (index, finding) in report.findings.iter().enumerate() {
            if index > 0 {
                self.output.push('\n');
            }
            self.render_finding(finding);
        }
    }

    fn render_finding(&mut self, finding: &UnusedFilesFinding) {
        self.write_styled(self.glyphs.finding, Style::Warning);
        self.output.push(' ');
        let issue_id = safe_text(finding.issue_id, "UNKNOWN");
        self.write_styled(&issue_id, Style::Warning);
        self.output.push_str("  ");
        self.write_styled(confidence_label(finding.confidence), Style::Heading);
        self.output.push_str(" confidence\n");

        self.output.push_str("  ");
        self.write_styled("Scope", Style::Muted);
        self.output.push_str("  ");
        self.write_safe_text(&finding.workspace, ".");
        self.output.push_str(if self.options.unicode {
            "  ·  "
        } else {
            "  |  "
        });
        self.write_safe_text(&finding.target_profiles.join(", "), "default");
        self.output.push_str(if self.options.unicode {
            "  ·  fix "
        } else {
            "  |  fix "
        });
        self.write_styled(fix_eligibility_label(finding.fix_eligibility), Style::Muted);
        self.output.push('\n');

        if !finding.summary.is_empty() {
            self.output.push_str("  ");
            self.write_safe_text(&finding.summary, "<no summary>");
            self.output.push('\n');
        }

        if let Some(symbol) = &finding.symbol {
            self.output.push_str("  ");
            self.write_styled("Symbol", Style::Muted);
            self.output.push_str("  ");
            self.write_safe_text(symbol, "<unknown>");
            self.output.push('\n');
        }
        if let Some(dependency) = &finding.dependency {
            self.output.push_str("  ");
            self.write_styled("Dependency", Style::Muted);
            self.output.push_str("  ");
            self.write_safe_text(dependency, "<unknown>");
            self.output.push('\n');
        }

        self.render_text_list("Paths", &finding.paths, "No paths reported");
        self.render_text_list("Evidence", &finding.evidence, "No evidence provided");
        if !finding.blockers.is_empty() {
            self.render_text_list("Blockers", &finding.blockers, "No blockers");
        }
        if !finding.suggested_actions.is_empty() {
            self.render_text_list("Next", &finding.suggested_actions, "No action suggested");
        }
    }

    fn render_text_list(&mut self, label: &str, items: &[String], empty_message: &str) {
        self.output.push_str("  ");
        self.write_styled(label, Style::Muted);
        self.output.push('\n');

        if items.is_empty() {
            self.output.push_str("    ");
            self.write_styled(self.glyphs.empty, Style::Muted);
            self.output.push(' ');
            self.write_styled(empty_message, Style::Muted);
            self.output.push('\n');
            return;
        }

        for (index, item) in items.iter().enumerate() {
            let is_last = index + 1 == items.len();
            let branch = if is_last {
                self.glyphs.last_branch
            } else {
                self.glyphs.branch
            };
            self.output.push_str("    ");
            self.write_styled(branch, Style::Muted);
            self.output.push(' ');
            self.write_safe_text(item, "<empty>");
            self.output.push('\n');
        }
    }

    fn render_diagnostics(&mut self, report: &ScanReport) {
        self.write_section_heading("DIAGNOSTICS");

        if report.diagnostics.is_empty() {
            self.write_empty_state("None reported");
            return;
        }

        for (index, diagnostic) in report.diagnostics.iter().enumerate() {
            if index > 0 {
                self.output.push('\n');
            }

            let (symbol, label, style) = match diagnostic.severity {
                DiagnosticSeverity::Error => (self.glyphs.error, "ERROR", Style::Error),
                DiagnosticSeverity::Warning => (self.glyphs.warning, "WARNING", Style::Warning),
            };

            self.write_styled(symbol, style);
            self.output.push(' ');
            self.write_styled(label, style);
            self.output.push_str("  ");
            self.write_safe_text(&diagnostic.path, "<unknown>");
            match diagnostic.span {
                Some(span) => {
                    write!(self.output, ":{}-{}", span.start, span.end)
                        .expect("writing to a String cannot fail");
                }
                None => self.output.push_str(":?-?"),
            }
            self.output.push_str("  ");
            let code = safe_text(&diagnostic.code, "UNKNOWN");
            self.write_styled(&code, Style::Heading);
            self.output.push('\n');

            self.output.push_str("  ");
            self.write_safe_text(&diagnostic.message, "<no message>");
            self.output.push('\n');
        }
    }

    fn render_footer(&mut self, status: AnalysisStatus) {
        self.output.push('\n');
        match status {
            AnalysisStatus::Complete => {
                self.write_styled(self.glyphs.success, Style::Success);
                self.output.push(' ');
                self.write_styled("COMPLETE", Style::Success);
                self.output.push_str("  Reachability analysis finished.\n");
            }
            AnalysisStatus::Incomplete => {
                self.write_styled(self.glyphs.warning, Style::Warning);
                self.output.push(' ');
                self.write_styled("INCOMPLETE", Style::Warning);
                self.output
                    .push_str("  Resolve coverage diagnostics, then scan again.\n");
            }
        }

        self.output.push_str("  ");
        self.write_styled(self.glyphs.hint, Style::Muted);
        self.output
            .push_str(" JSON: run again with --format json for machine-readable output.\n");
    }

    fn write_section_heading(&mut self, heading: &str) {
        self.output.push('\n');
        self.write_styled(heading, Style::Heading);
        self.output.push('\n');
    }

    fn write_empty_state(&mut self, message: &str) {
        self.output.push_str("  ");
        self.write_styled(self.glyphs.empty, Style::Muted);
        self.output.push(' ');
        self.write_styled(message, Style::Muted);
        self.output.push('\n');
    }

    fn write_metric(&mut self, count: usize, label: &str, style: Style) {
        self.write_styled(&count.to_string(), style);
        self.output.push(' ');
        self.output.push_str(label);
    }

    fn write_metric_separator(&mut self) {
        self.output.push(' ');
        self.write_styled(self.glyphs.separator, Style::Muted);
        self.output.push(' ');
    }

    fn write_safe_text(&mut self, text: &str, fallback: &str) {
        self.output.push_str(&safe_text(text, fallback));
    }

    fn write_styled(&mut self, text: &str, style: Style) {
        if self.options.color {
            write!(
                self.output,
                "\u{1b}[{}m{text}{ANSI_RESET}",
                style.ansi_code()
            )
            .expect("writing to a String cannot fail");
        } else {
            self.output.push_str(text);
        }
    }
}

const fn confidence_label(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::High => "HIGH",
        Confidence::Medium => "MEDIUM",
        Confidence::Low => "LOW",
        Confidence::Incomplete => "INCOMPLETE",
    }
}

const fn fix_eligibility_label(
    eligibility: orphanode::domain::report::FixEligibility,
) -> &'static str {
    use orphanode::domain::report::FixEligibility;

    match eligibility {
        FixEligibility::NotAvailable => "not available",
        FixEligibility::PreviewOnly => "preview only",
        FixEligibility::Eligible => "eligible",
        FixEligibility::Blocked => "blocked",
    }
}

pub(crate) fn safe_text(text: &str, fallback: &str) -> String {
    let sanitized = sanitize_terminal_text(text);
    if sanitized.is_empty() {
        fallback.to_owned()
    } else {
        sanitized
    }
}

fn sanitize_terminal_text(text: &str) -> String {
    let mut sanitized = String::with_capacity(text.len());

    for character in text.chars() {
        match character {
            '\n' => sanitized.push_str("\\n"),
            '\r' => sanitized.push_str("\\r"),
            '\t' => sanitized.push_str("\\t"),
            _ if is_unsafe_terminal_character(character) => {
                sanitized.extend(character.escape_unicode());
            }
            _ => sanitized.push(character),
        }
    }

    sanitized
}

fn is_unsafe_terminal_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{00ad}'
                | '\u{061c}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2060}'
                | '\u{2066}'..='\u{2069}'
                | '\u{feff}'
        )
}

#[cfg(test)]
mod tests {
    use orphanode::domain::{
        facts::{AnalysisDiagnostic, DiagnosticSeverity, SourceSpan},
        report::{
            AnalysisStatus, Confidence, FixEligibility, REPORT_SCHEMA_VERSION, ReportSummary,
            ScanReport, UnusedFilesFinding,
        },
    };

    use std::path::Path;

    use super::{RenderOptions, render_compact, render_human};

    #[test]
    fn colorless_output_contains_no_ansi_sequences() {
        let output = render_human(
            &sample_report(),
            RenderOptions {
                color: false,
                unicode: true,
            },
        );

        assert!(!output.contains('\u{1b}'));
        assert!(output.contains("ORPHANODE"));
        assert!(output.contains("ORP1001"));
    }

    #[test]
    fn ascii_mode_uses_only_ascii_with_ascii_input() {
        let output = render_human(
            &sample_report(),
            RenderOptions {
                color: false,
                unicode: false,
            },
        );

        assert!(output.is_ascii());
        assert!(output.contains("|- src/unused.ts"));
        assert!(output.contains("`- src/legacy.ts"));
        assert!(output.contains("! WARNING"));
    }

    #[test]
    fn compact_output_uses_ts_prune_style_positions() {
        let temporary =
            std::env::temp_dir().join(format!("orphanode-render-compact-{}", std::process::id()));
        std::fs::create_dir_all(temporary.join("src")).expect("create temp project");
        let source = "export const alpha = 1;\nexport const beta = 2;\n";
        std::fs::write(temporary.join("src/one.ts"), source).expect("write temp source");

        let mut report = sample_report();
        report.findings = vec![UnusedFilesFinding {
            issue_id: "ORP1002",
            issue_type: "unusedExport",
            workspace: ".".to_owned(),
            target_profiles: vec!["default".to_owned()],
            paths: vec!["src/one.ts".to_owned()],
            span: Some(SourceSpan::new(
                u32::try_from(source.find("beta").unwrap()).unwrap_or(0),
                20,
            )),
            symbol: Some("beta".to_owned()),
            dependency: None,
            confidence: Confidence::High,
            summary: "unused export".to_owned(),
            evidence: Vec::new(),
            blockers: Vec::new(),
            suggested_actions: Vec::new(),
            fix_eligibility: FixEligibility::NotAvailable,
        }];

        let output = render_compact(&report, &temporary);

        assert_eq!(output, "src/one.ts:2:14 - ORP1002 'beta' is unused\n");
        std::fs::remove_dir_all(&temporary).expect("cleanup temp project");
    }

    #[test]
    fn compact_multi_path_groups_list_every_path_without_positions() {
        let report = sample_report();

        let output = render_compact(&report, Path::new("/nonexistent"));

        assert!(output.contains("src/unused.ts - ORP1001 'unused_files' is unused"));
        assert!(output.contains("src/legacy.ts - ORP1001 'unused_files' is unused"));
        assert!(!output.contains(':'));
    }

    #[test]
    fn source_control_characters_are_rendered_inert() {
        let mut report = sample_report();
        report.entries[0] = "src/\u{1b}[31mowned\nfile.ts".to_owned();
        report.findings[0].paths[0] = "src/bad\tpath.ts".to_owned();
        report.findings[0].evidence[0] = "bell\u{0007}\u{202e}txt".to_owned();
        report.diagnostics[0].message = "first\rsecond".to_owned();

        let output = render_human(
            &report,
            RenderOptions {
                color: false,
                unicode: true,
            },
        );

        assert!(!output.contains('\u{1b}'));
        assert!(!output.contains('\u{0007}'));
        assert!(!output.contains('\u{202e}'));
        assert!(output.contains(r"src/\u{1b}[31mowned\nfile.ts"));
        assert!(output.contains(r"src/bad\tpath.ts"));
        assert!(output.contains(r"bell\u{7}\u{202e}txt"));
        assert!(output.contains(r"first\rsecond"));
    }

    #[test]
    fn incomplete_empty_report_has_explicit_states_and_json_hint() {
        let report = ScanReport {
            schema_version: REPORT_SCHEMA_VERSION,
            status: AnalysisStatus::Incomplete,
            entries: Vec::new(),
            summary: ReportSummary {
                files: 0,
                reachable_files: 0,
                unreachable_files: 0,
                incomplete_files: 0,
                diagnostics: 0,
            },
            files: Vec::new(),
            findings: Vec::new(),
            retentions: Vec::new(),
            project: None,
            cache: None,
            diagnostics: Vec::new(),
        };

        let output = render_human(
            &report,
            RenderOptions {
                color: false,
                unicode: false,
            },
        );

        assert!(output.contains("> Entries  none configured"));
        assert_eq!(output.matches("None reported").count(), 2);
        assert!(output.contains("0 reachable | 0 unreachable | 0 incomplete | 0 diagnostics"));
        assert!(output.contains("! INCOMPLETE  Resolve coverage diagnostics, then scan again."));
        assert!(output.contains("--format json"));
    }

    #[test]
    fn multiple_entries_are_compact_and_scannable() {
        let mut report = sample_report();
        report.entries = vec![
            "app/layout.tsx".to_owned(),
            "app/page.tsx".to_owned(),
            "app/about/page.tsx".to_owned(),
            "tests/routing.test.ts".to_owned(),
        ];

        let output = render_human(
            &report,
            RenderOptions {
                color: false,
                unicode: false,
            },
        );

        assert!(output.contains("> Entries  4 configured"));
        assert!(output.contains("|- app/layout.tsx"));
        assert!(output.contains("`- ... 1 more"));
    }

    fn sample_report() -> ScanReport {
        ScanReport {
            schema_version: REPORT_SCHEMA_VERSION,
            status: AnalysisStatus::Complete,
            entries: vec!["src/index.ts".to_owned()],
            summary: ReportSummary {
                files: 3,
                reachable_files: 1,
                unreachable_files: 2,
                incomplete_files: 0,
                diagnostics: 1,
            },
            files: Vec::new(),
            findings: vec![UnusedFilesFinding {
                issue_id: "ORP1001",
                issue_type: "unused_files",
                workspace: "workspace".to_owned(),
                target_profiles: vec!["default".to_owned()],
                paths: vec!["src/unused.ts".to_owned(), "src/legacy.ts".to_owned()],
                span: None,
                symbol: None,
                dependency: None,
                confidence: Confidence::High,
                summary: "2 files are unreachable from the entry point".to_owned(),
                evidence: vec![
                    "No inbound path from src/index.ts".to_owned(),
                    "Static imports were fully resolved".to_owned(),
                ],
                blockers: Vec::new(),
                suggested_actions: Vec::new(),
                fix_eligibility: FixEligibility::NotAvailable,
            }],
            retentions: Vec::new(),
            project: None,
            cache: None,
            diagnostics: vec![AnalysisDiagnostic {
                code: "ORP2001".to_owned(),
                path: "src/index.ts".to_owned(),
                severity: DiagnosticSeverity::Warning,
                span: Some(SourceSpan::new(8, 21)),
                message: "Dynamic import cannot be resolved statically".to_owned(),
                blocks_reachability: true,
            }],
        }
    }
}
