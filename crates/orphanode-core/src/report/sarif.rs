use std::fmt::Write as _;

use serde_json::{Value, json};

use crate::domain::report::ScanReport;

/// Renders a deterministic SARIF 2.1.0 log for code-scanning integrations.
#[must_use]
pub fn render_sarif(report: &ScanReport) -> Value {
    let mut results = Vec::new();
    for finding in &report.findings {
        for path in &finding.paths {
            let mut physical_location = json!({
                "artifactLocation": { "uri": relative_artifact_uri(path) }
            });
            if finding.paths.first() == Some(path)
                && let Some(span) = finding.span
            {
                physical_location["region"] = json!({
                    "byteOffset": span.start,
                    "byteLength": span.end.saturating_sub(span.start)
                });
            }
            results.push(json!({
                "ruleId": finding.issue_id,
                "level": "warning",
                "message": { "text": finding.summary },
                "locations": [{
                    "physicalLocation": physical_location
                }],
                "properties": {
                    "schemaVersion": report.schema_version,
                    "workspace": finding.workspace,
                    "confidence": finding.confidence,
                    "issueType": finding.issue_type,
                    "targetProfiles": finding.target_profiles,
                    "symbol": finding.symbol,
                    "dependency": finding.dependency,
                    "evidence": finding.evidence,
                    "blockers": finding.blockers,
                    "suggestedActions": finding.suggested_actions,
                    "fixEligibility": finding.fix_eligibility
                }
            }));
        }
    }
    for diagnostic in &report.diagnostics {
        let mut physical_location = json!({
            "artifactLocation": {
                "uri": relative_artifact_uri(&diagnostic.path)
            }
        });
        if let Some(span) = diagnostic.span {
            physical_location["region"] = json!({
                "byteOffset": span.start,
                "byteLength": span.end.saturating_sub(span.start)
            });
        }
        results.push(json!({
            "ruleId": diagnostic.code,
            "level": match diagnostic.severity {
                crate::domain::facts::DiagnosticSeverity::Error => "error",
                crate::domain::facts::DiagnosticSeverity::Warning => "warning",
            },
            "message": { "text": diagnostic.message },
            "locations": [{ "physicalLocation": physical_location }],
            "properties": {
                "blocksReachability": diagnostic.blocks_reachability
            }
        }));
    }
    results.sort_by(|left, right| sarif_result_key(left).cmp(&sarif_result_key(right)));

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "OrphaNode",
                    "informationUri": "https://github.com/wthrajat/orphanode",
                    "semanticVersion": env!("CARGO_PKG_VERSION"),
                    "rules": [
                        {
                            "id": "ORP1001",
                            "name": "unusedFiles",
                            "shortDescription": { "text": "Unreachable source file" },
                            "defaultConfiguration": { "level": "warning" }
                        },
                        {
                            "id": "ORP1002",
                            "name": "unusedExport",
                            "shortDescription": { "text": "Unconsumed module export" },
                            "defaultConfiguration": { "level": "warning" }
                        },
                        {
                            "id": "ORP1003",
                            "name": "unusedDeclaration",
                            "shortDescription": { "text": "Unreachable declaration or dead recursive group" },
                            "defaultConfiguration": { "level": "warning" }
                        },
                        {
                            "id": "ORP1004",
                            "name": "unusedMember",
                            "shortDescription": { "text": "Unused class member" },
                            "defaultConfiguration": { "level": "warning" }
                        },
                        {
                            "id": "ORP2001",
                            "name": "unusedDependency",
                            "shortDescription": { "text": "Unused manifest dependency" },
                            "defaultConfiguration": { "level": "warning" }
                        },
                        {
                            "id": "ORP2002",
                            "name": "dependencyDeclaration",
                            "shortDescription": { "text": "Unlisted or misplaced dependency" },
                            "defaultConfiguration": { "level": "warning" }
                        },
                        {
                            "id": "ORP3001",
                            "name": "unusedWorkspace",
                            "shortDescription": { "text": "Unused private workspace package" },
                            "defaultConfiguration": { "level": "warning" }
                        }
                    ]
                }
            },
            "results": results,
            "properties": {
                "orphanodeSchemaVersion": report.schema_version,
                "analysisStatus": report.status
            }
        }]
    })
}

/// Encodes a normalized project-relative path as an RFC 3986 relative URI.
///
/// SARIF consumers resolve a relative artifact URI against the checkout. An
/// invented absolute base such as `file:///` would instead point at the host
/// filesystem root and make code-scanning locations unusable.
fn relative_artifact_uri(path: &str) -> String {
    let mut uri = String::with_capacity(path.len());
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/') {
            uri.push(char::from(byte));
        } else {
            write!(uri, "%{byte:02X}").expect("writing to a String cannot fail");
        }
    }
    uri
}

fn sarif_result_key(result: &Value) -> (String, String, u64) {
    let path = result
        .pointer("/locations/0/physicalLocation/artifactLocation/uri")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let rule = result
        .get("ruleId")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let offset = result
        .pointer("/locations/0/physicalLocation/region/byteOffset")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    (path, rule, offset)
}

#[cfg(test)]
mod tests {
    use crate::domain::report::{
        AnalysisStatus, Confidence, Finding, FixEligibility, REPORT_SCHEMA_VERSION, ReportSummary,
        ScanReport,
    };

    use super::render_sarif;

    #[test]
    fn sarif_has_a_stable_contract_even_for_a_clean_report() {
        let report = ScanReport {
            schema_version: REPORT_SCHEMA_VERSION,
            status: AnalysisStatus::Complete,
            entries: vec!["src/index.ts".to_owned()],
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

        let sarif = render_sarif(&report);
        assert_eq!(sarif["version"], "2.1.0");
        assert_eq!(sarif["runs"][0]["tool"]["driver"]["name"], "OrphaNode");
        assert_eq!(sarif["runs"][0]["properties"]["analysisStatus"], "complete");
    }

    #[test]
    fn sarif_preserves_finding_explanation_fields() {
        let report = ScanReport {
            schema_version: REPORT_SCHEMA_VERSION,
            status: AnalysisStatus::Complete,
            entries: vec!["src/index.ts".to_owned()],
            summary: ReportSummary {
                files: 1,
                reachable_files: 1,
                unreachable_files: 0,
                incomplete_files: 0,
                diagnostics: 0,
            },
            files: Vec::new(),
            findings: vec![Finding {
                issue_id: "ORP2001",
                issue_type: "unusedDependency",
                workspace: "packages/app".to_owned(),
                target_profiles: vec!["node".to_owned()],
                paths: vec!["packages/app/package.json".to_owned()],
                span: None,
                symbol: None,
                dependency: Some("unused-package".to_owned()),
                confidence: Confidence::High,
                summary: "dependency is unused".to_owned(),
                evidence: vec!["no reachable evidence".to_owned()],
                blockers: Vec::new(),
                suggested_actions: vec!["review removal".to_owned()],
                fix_eligibility: FixEligibility::Eligible,
            }],
            retentions: Vec::new(),
            project: None,
            cache: None,
            diagnostics: Vec::new(),
        };

        let sarif = render_sarif(&report);
        let properties = &sarif["runs"][0]["results"][0]["properties"];
        assert_eq!(properties["schemaVersion"], REPORT_SCHEMA_VERSION);
        assert_eq!(properties["workspace"], "packages/app");
        assert_eq!(properties["dependency"], "unused-package");
        assert_eq!(properties["suggestedActions"][0], "review removal");
    }

    #[test]
    fn sarif_uses_encoded_checkout_relative_artifact_uris() {
        let mut report = ScanReport {
            schema_version: REPORT_SCHEMA_VERSION,
            status: AnalysisStatus::Complete,
            entries: vec!["src/index.ts".to_owned()],
            summary: ReportSummary {
                files: 1,
                reachable_files: 0,
                unreachable_files: 1,
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
        report.findings.push(Finding {
            issue_id: "ORP1001",
            issue_type: "unusedFiles",
            workspace: ".".to_owned(),
            target_profiles: vec!["node".to_owned()],
            paths: vec!["src/space #100%.ts".to_owned()],
            span: None,
            symbol: None,
            dependency: None,
            confidence: Confidence::High,
            summary: "file is unreachable".to_owned(),
            evidence: Vec::new(),
            blockers: Vec::new(),
            suggested_actions: Vec::new(),
            fix_eligibility: FixEligibility::Eligible,
        });

        let sarif = render_sarif(&report);
        let artifact =
            &sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"];
        assert_eq!(artifact["uri"], "src/space%20%23100%25.ts");
        assert!(artifact.get("uriBaseId").is_none());
        assert!(sarif["runs"][0].get("originalUriBaseIds").is_none());
    }
}
