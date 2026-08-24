use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::Serialize;

use crate::domain::report::{FileStatus, ResolutionStatus, ScanReport};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExplanationStatus {
    Retained,
    Reported,
    Incomplete,
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExplanationStep {
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Explanation {
    pub query: String,
    pub status: ExplanationStatus,
    pub summary: String,
    pub steps: Vec<ExplanationStep>,
}

/// Explains why a file or external package is retained, reported, or incomplete.
#[must_use]
pub fn explain(report: &ScanReport, query: &str) -> Explanation {
    if let Some(retention) = report
        .retentions
        .iter()
        .find(|retention| retention.item == query)
    {
        return Explanation {
            query: query.to_owned(),
            status: ExplanationStatus::Retained,
            summary: retention.summary.clone(),
            steps: retention
                .evidence
                .iter()
                .map(|summary| ExplanationStep {
                    summary: summary.clone(),
                    path: None,
                })
                .collect(),
        };
    }

    if let Some(finding) = report.findings.iter().find(|finding| {
        finding.symbol.as_deref() == Some(query)
            || finding.dependency.as_deref() == Some(query)
            || finding.workspace == query
            || finding.paths.iter().any(|path| path == query)
    }) {
        return Explanation {
            query: query.to_owned(),
            status: ExplanationStatus::Reported,
            summary: finding.summary.clone(),
            steps: finding
                .evidence
                .iter()
                .map(|summary| ExplanationStep {
                    summary: summary.clone(),
                    path: finding.paths.first().cloned(),
                })
                .collect(),
        };
    }

    if let Some(file) = report.files.iter().find(|file| file.path == query) {
        return explain_file(report, &file.path, file.status);
    }

    let package_evidence = report
        .files
        .iter()
        .filter(|file| file.status == FileStatus::Reachable)
        .flat_map(|file| {
            file.imports
                .iter()
                .filter(|import| import.status == ResolutionStatus::External)
                .filter_map(move |import| {
                    (package_name(&import.specifier) == Some(query)).then_some((file, import))
                })
        })
        .min_by_key(|(file, import)| (&file.path, import.span.start, &import.specifier));
    if let Some((file, import)) = package_evidence {
        return Explanation {
            query: query.to_owned(),
            status: ExplanationStatus::Retained,
            summary: format!("{query} is retained by a reachable external import"),
            steps: vec![
                ExplanationStep {
                    summary: format!("{} is reachable", file.path),
                    path: Some(file.path.clone()),
                },
                ExplanationStep {
                    summary: format!("imports {}", import.specifier),
                    path: Some(file.path.clone()),
                },
            ],
        };
    }

    Explanation {
        query: query.to_owned(),
        status: ExplanationStatus::NotFound,
        summary: format!("No analyzed file, finding, or retained package matches `{query}`"),
        steps: Vec::new(),
    }
}

fn explain_file(report: &ScanReport, path: &str, status: FileStatus) -> Explanation {
    match status {
        FileStatus::Reachable => {
            let path_steps = shortest_file_path(report, path);
            Explanation {
                query: path.to_owned(),
                status: ExplanationStatus::Retained,
                summary: format!("{path} is reachable from a configured entry"),
                steps: path_steps
                    .into_iter()
                    .enumerate()
                    .map(|(index, item)| ExplanationStep {
                        summary: if index == 0 {
                            format!("configured entry {item}")
                        } else {
                            format!("resolved import reaches {item}")
                        },
                        path: Some(item),
                    })
                    .collect(),
            }
        }
        FileStatus::Unreachable => {
            let finding = report
                .findings
                .iter()
                .find(|finding| finding.paths.iter().any(|item| item == path));
            Explanation {
                query: path.to_owned(),
                status: ExplanationStatus::Reported,
                summary: finding.map_or_else(
                    || format!("{path} has no path from a configured entry"),
                    |finding| finding.summary.clone(),
                ),
                steps: finding.map_or_else(Vec::new, |finding| {
                    finding
                        .evidence
                        .iter()
                        .map(|summary| ExplanationStep {
                            summary: summary.clone(),
                            path: Some(path.to_owned()),
                        })
                        .collect()
                }),
            }
        }
        FileStatus::Incomplete => Explanation {
            query: path.to_owned(),
            status: ExplanationStatus::Incomplete,
            summary: format!("Analysis cannot decide whether {path} is reachable"),
            steps: report
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.path == path || diagnostic.blocks_reachability)
                .map(|diagnostic| ExplanationStep {
                    summary: format!("{}: {}", diagnostic.code, diagnostic.message),
                    path: Some(diagnostic.path.clone()),
                })
                .collect(),
        },
    }
}

fn shortest_file_path(report: &ScanReport, target: &str) -> Vec<String> {
    let mut outgoing = BTreeMap::<&str, BTreeSet<&str>>::new();
    for file in &report.files {
        for import in &file.imports {
            if import.status == ResolutionStatus::Resolved
                && let Some(destination) = import.target.as_deref()
            {
                outgoing
                    .entry(file.path.as_str())
                    .or_default()
                    .insert(destination);
            }
        }
    }

    let mut queue = VecDeque::new();
    let mut previous = BTreeMap::<&str, Option<&str>>::new();
    for entry in &report.entries {
        if previous.insert(entry, None).is_none() {
            queue.push_back(entry.as_str());
        }
    }
    while let Some(current) = queue.pop_front() {
        if current == target {
            break;
        }
        for next in outgoing.get(current).into_iter().flatten() {
            if !previous.contains_key(next) {
                previous.insert(next, Some(current));
                queue.push_back(next);
            }
        }
    }
    if !previous.contains_key(target) {
        return Vec::new();
    }

    let mut path = vec![target.to_owned()];
    let mut current = target;
    while let Some(Some(parent)) = previous.get(current) {
        path.push((*parent).to_owned());
        current = parent;
    }
    path.reverse();
    path
}

fn package_name(specifier: &str) -> Option<&str> {
    if specifier.starts_with('.')
        || specifier.starts_with('/')
        || specifier.starts_with('#')
        || specifier.starts_with("node:")
    {
        return None;
    }
    if specifier.starts_with('@') {
        let mut segments = specifier.split('/');
        let scope = segments.next()?;
        let name = segments.next()?;
        let end = scope.len() + 1 + name.len();
        specifier.get(..end)
    } else {
        specifier.split('/').next()
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::{
        facts::{Activation, ImportKind, ModuleKind, ResolutionMode, SourceKind, SourceSpan},
        report::{
            AnalysisStatus, FileReport, FileStatus, ImportReport, REPORT_SCHEMA_VERSION,
            ReportSummary, ResolutionStatus, ScanReport,
        },
    };

    use super::{ExplanationStatus, explain};

    #[test]
    fn explains_the_shortest_reachable_file_chain() {
        let report = report_with_files();
        let explanation = explain(&report, "src/feature.ts");

        assert_eq!(explanation.status, ExplanationStatus::Retained);
        assert_eq!(explanation.steps.len(), 3);
        assert_eq!(explanation.steps[0].path.as_deref(), Some("src/index.ts"));
        assert_eq!(explanation.steps[2].path.as_deref(), Some("src/feature.ts"));
    }

    #[test]
    fn explains_external_package_evidence() {
        let mut report = report_with_files();
        report.files[0].imports.push(ImportReport {
            specifier: "@scope/tool/subpath".to_owned(),
            kind: ImportKind::Static,
            resolution_mode: ResolutionMode::Esm,
            activation: Activation::Module,
            type_only: false,
            status: ResolutionStatus::External,
            target: None,
            span: SourceSpan::new(0, 1),
            target_profiles: vec!["default".to_owned()],
        });

        let explanation = explain(&report, "@scope/tool");
        assert_eq!(explanation.status, ExplanationStatus::Retained);
        assert!(explanation.summary.contains("external import"));
    }

    fn report_with_files() -> ScanReport {
        let files = [
            ("src/index.ts", "src/middle.ts"),
            ("src/middle.ts", "src/feature.ts"),
            ("src/feature.ts", ""),
        ]
        .into_iter()
        .map(|(path, target)| FileReport {
            path: path.to_owned(),
            status: FileStatus::Reachable,
            target_statuses: [("default".to_owned(), FileStatus::Reachable)]
                .into_iter()
                .collect(),
            source_kind: SourceKind::TypeScript,
            module_kind: ModuleKind::Esm,
            byte_len: 0,
            line_count: 0,
            content_digest: "0".repeat(64),
            imports: if target.is_empty() {
                Vec::new()
            } else {
                vec![ImportReport {
                    specifier: target.to_owned(),
                    kind: ImportKind::Static,
                    resolution_mode: ResolutionMode::Esm,
                    activation: Activation::Module,
                    type_only: false,
                    status: ResolutionStatus::Resolved,
                    target_profiles: vec!["default".to_owned()],
                    target: Some(target.to_owned()),
                    span: SourceSpan::new(0, 1),
                }]
            },
            exports: Vec::new(),
        })
        .collect();
        ScanReport {
            schema_version: REPORT_SCHEMA_VERSION,
            status: AnalysisStatus::Complete,
            entries: vec!["src/index.ts".to_owned()],
            summary: ReportSummary {
                files: 3,
                reachable_files: 3,
                unreachable_files: 0,
                incomplete_files: 0,
                diagnostics: 0,
            },
            files,
            findings: Vec::new(),
            retentions: Vec::new(),
            project: None,
            cache: None,
            diagnostics: Vec::new(),
        }
    }
}
