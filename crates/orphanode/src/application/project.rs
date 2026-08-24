use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use ignore::{WalkBuilder, gitignore::GitignoreBuilder};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

use crate::{
    analysis::dependencies::{
        DependencyAnalysisInput, DependencyBlocker, DependencyCategory, DependencyConfidence,
        DependencyEvidence, DependencyEvidenceKind, DependencyEvidenceScope, DependencyManifest,
        DependencyOutcomeKind, analyze_dependencies, package_name,
    },
    analysis::members::{AnalysisMode as MemberAnalysisMode, DeepResolution},
    cache::{
        CacheEntry, CacheKey, CacheLimits, CacheSchema, CanonicalFileIdentity, ConfigDigest,
        ContentDigest, Digest, PersistentCache, ProfileDigest,
    },
    discovery::{
        DiscoveryError,
        configuration::{
            AnalysisMode, ConfidenceLevel, ConfigurationError, ConfigurationLayers,
            ConfigurationOverride, ProjectConfiguration, ProjectConfigurationKind,
            TargetConfiguration, WorldMode, discover_project_configurations,
            load_orphanode_configuration, merge_configuration_layers, parse_jsonc_value,
            stale_ignore_rules, stale_retain_rules,
        },
        discover_package_source_files,
        manifest::{
            BinaryDeclaration, EntryTargetProfile, ManifestError, PackageEntryRoot,
            PackageManifest, package_entry_roots,
        },
        scripts::{ScriptAnalysis, ScriptReferenceKind, UnmodeledScriptKind, analyze_scripts},
        workspace::{WorkspaceDiscovery, WorkspaceError, WorkspacePackage, discover_workspace},
    },
    domain::{
        facts::{AnalysisDiagnostic, DiagnosticSeverity},
        report::{
            AnalysisStatus, Confidence, FileStatus, Finding, FixEligibility, ProjectReport,
            ResolutionStatus, RetentionReport, ScanReport,
        },
    },
    javascript::parse_file_with_limits,
    limits::AnalysisLimits,
    plugins::{
        BuiltinDetectionInput, DECLARATIVE_PLUGIN_API_VERSION, DeclarativePlugin,
        DetectedBuiltinPlugin, DetectionEvidenceKind, DetectionRules,
        EXECUTABLE_PLUGIN_PROTOCOL_VERSION, ExecutablePluginConfig, FileTransformContribution,
        HostConfigFact, HostConfigFormat, HostManifestFacts, HostPackageFact, HostPackageKind,
        HostPackageType, HostRequest, HostResponse, PluginCapability, PluginContributions,
        PluginDiagnosticSeverity, PluginValidationError, ReferenceKind, builtin_plugins,
        detect_builtin_plugins, validate_host_request, validate_host_response,
    },
};

use super::{
    ScanError, ScanRequest, TypeScriptWorkerHost, TypeScriptWorkerOptions,
    scan::{
        AdditionalFileEdge, DeepMemberEvidence, FactCache, ScanStageMetrics, SourceUniverseKind,
        WorkspaceModuleTarget, apply_deep_member_evidence, scan_with_fact_cache_measured,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AnalysisIssue {
    Files,
    Exports,
    Declarations,
    Members,
    Dependencies,
    Workspaces,
}

impl AnalysisIssue {
    #[must_use]
    pub fn all() -> BTreeSet<Self> {
        [
            Self::Files,
            Self::Exports,
            Self::Declarations,
            Self::Members,
            Self::Dependencies,
            Self::Workspaces,
        ]
        .into_iter()
        .collect()
    }
}

#[derive(Debug, Clone)]
pub struct ProjectScanRequest {
    pub root: PathBuf,
    pub workspace: Option<PathBuf>,
    pub entries: Vec<PathBuf>,
    pub mode: Option<AnalysisMode>,
    pub closed_world: Option<bool>,
    pub target_profiles: Vec<String>,
    pub issues: BTreeSet<AnalysisIssue>,
    pub limits: AnalysisLimits,
    /// Report findings whose paths are test files. Tests always stay in the
    /// reachability graph as roots; this only hides findings about them.
    pub report_tests: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProjectStageMetrics {
    pub duration: Duration,
    pub count: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProjectCacheMetrics {
    pub hits: usize,
    pub misses: usize,
    pub generation_writes: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectScanMetrics {
    pub workspace_discovery: ProjectStageMetrics,
    pub configuration_loading: ProjectStageMetrics,
    pub file_discovery: ProjectStageMetrics,
    pub plugin_discovery: ProjectStageMetrics,
    pub fact_loading: ProjectStageMetrics,
    pub module_resolution_graph: ProjectStageMetrics,
    pub reachability_rules_report: ProjectStageMetrics,
    pub cache_persistence: ProjectStageMetrics,
    pub deep_analysis: ProjectStageMetrics,
    pub profile_analysis: ProjectStageMetrics,
    pub policy: ProjectStageMetrics,
    /// Aggregate static-fact and deep-evidence cache activity.
    pub cache: ProjectCacheMetrics,
}

#[derive(Debug)]
pub struct ProjectScanOutput {
    pub report: ScanReport,
    pub metrics: ProjectScanMetrics,
    /// Normalized per-workspace configuration used by this scan.
    ///
    /// This is kept outside [`ScanReport`] so diagnostic telemetry can expose
    /// the effective policy without adding process-local observability data to
    /// the deterministic report contract.
    pub effective_configuration: BTreeMap<String, ConfigurationOverride>,
}

impl ProjectScanRequest {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            workspace: None,
            entries: Vec::new(),
            mode: None,
            closed_world: None,
            target_profiles: default_target_profiles(),
            issues: AnalysisIssue::all(),
            limits: AnalysisLimits::default(),
            report_tests: false,
        }
    }
}

#[derive(Debug, Error)]
pub enum ProjectScanError {
    #[error(transparent)]
    Workspace(#[from] WorkspaceError),
    #[error(transparent)]
    Configuration(#[from] ConfigurationError),
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error(transparent)]
    Discovery(#[from] DiscoveryError),
    #[error(transparent)]
    Plugin(#[from] PluginValidationError),
    #[error(transparent)]
    Scan(#[from] ScanError),
    #[error("cannot normalize effective configuration for the fact cache: {0}")]
    SerializeConfiguration(#[from] serde_json::Error),
    #[error("workspace `{0}` is not declared by the controlling package")]
    UnknownWorkspace(PathBuf),
    #[error("project discovery found source files but no supported entry root")]
    NoEntryRoots,
    #[error("project discovery found no supported JavaScript or TypeScript source files")]
    NoSourceFiles,
    #[error("target profile `{0}` is neither built in nor defined by effective configuration")]
    UnknownTargetProfile(String),
    #[error("target profile inheritance contains a cycle at `{0}`")]
    TargetProfileCycle(String),
    #[error("configured plugin `{plugin}` could not be loaded: {message}")]
    ConfiguredPlugin { plugin: String, message: String },
}

struct PackageContext<'a> {
    package: &'a WorkspacePackage,
    workspace_name: String,
    effective: ConfigurationOverride,
    configured_entries: Vec<PathBuf>,
    ignore_base: PathBuf,
    retain_base: PathBuf,
    scripts: ScriptAnalysis,
    plugins: Vec<DetectedBuiltinPlugin>,
    plugins_by_profile: BTreeMap<String, Vec<DetectedBuiltinPlugin>>,
}

type DeepMemberRawEvidence = BTreeMap<(String, u32), DeepRawResolution>;

#[derive(Clone, Copy)]
struct DeepMemberEvidenceRequest<'a> {
    workspace_root: &'a Path,
    files: &'a [PathBuf],
    project_configurations: &'a [ProjectConfiguration],
    effective_config_bytes: &'a [u8],
    source_report: &'a ScanReport,
    candidates: &'a BTreeSet<(String, u32)>,
    limits: AnalysisLimits,
}

#[derive(Clone, Copy)]
struct DeepConfigurationEvidenceRequest<'a> {
    workspace_root: &'a Path,
    typescript_resolution_root: &'a Path,
    worker_script: &'a Path,
    configuration_path: &'a Path,
    query_keys: &'a [(String, u32)],
    effective_config_bytes: &'a [u8],
    source_digest: Digest,
    allowed_source_paths: &'a BTreeSet<String>,
    limits: AnalysisLimits,
}

struct DependencyFindingInput<'a> {
    issue_id: &'static str,
    issue_type: &'static str,
    workspace: &'a str,
    dependency: &'a str,
    summary: String,
    confidence: DependencyConfidence,
    categories: &'a [DependencyCategory],
    package_manager_supported: bool,
    target_profiles: &'a [String],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum DeepRawResolution {
    Unavailable {
        capability_note: String,
    },
    Resolved {
        references: Vec<DeepSourceSpan>,
        overrides: Vec<DeepOverrideRelationship>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeepSourceSpan {
    path: String,
    start: u32,
    end: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeepSymbolIdentity {
    id: String,
    name: String,
    declarations: Vec<DeepSourceSpan>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeepOverrideRelationship {
    symbol: DeepSymbolIdentity,
    owner: Option<DeepSymbolIdentity>,
    owner_exported: bool,
    references: Vec<DeepSourceSpan>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CachedDeepEvidence {
    schema_version: u32,
    config_path: String,
    typescript_identity: String,
    facts: Vec<CachedDeepFact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CachedDeepFact {
    path: String,
    position: u32,
    resolution: DeepRawResolution,
}

/// Runs the complete static project-discovery path before the graph scan.
///
/// The orchestrator never executes source, package scripts, or configuration.
///
/// # Errors
///
/// Returns [`ProjectScanError`] when discovery, configuration, or analysis
/// fails, or when the selected project has no source files or entry roots.
pub fn scan_project(request: &ProjectScanRequest) -> Result<ScanReport, ProjectScanError> {
    scan_project_measured(request).map(|output| output.report)
}

/// Runs project discovery and returns non-reporting stage measurements separately.
///
/// Durations deliberately do not enter [`ScanReport`], preserving deterministic
/// machine output while allowing the CLI to render diagnostics for local profiling.
///
/// # Errors
///
/// Returns [`ProjectScanError`] when discovery, configuration, or analysis
/// fails, or when the selected project has no source files or entry roots.
// This function deliberately keeps the full scan pipeline visible in execution order.
#[allow(clippy::too_many_lines)]
pub fn scan_project_measured(
    request: &ProjectScanRequest,
) -> Result<ProjectScanOutput, ProjectScanError> {
    let mut metrics = ProjectScanMetrics::default();
    let stage_started = Instant::now();
    let workspace = discover_workspace(&request.root)?;
    let selected = selected_packages(&workspace, request.workspace.as_deref())?;
    metrics.workspace_discovery = ProjectStageMetrics {
        duration: stage_started.elapsed(),
        count: selected.len(),
    };

    let stage_started = Instant::now();
    let loaded_configuration = load_orphanode_configuration(&workspace.workspace_root)?;
    let project_configurations = discover_project_configurations(&workspace.workspace_root)?;
    metrics.configuration_loading = ProjectStageMetrics {
        duration: stage_started.elapsed(),
        count: loaded_configuration.sources.len() + project_configurations.len(),
    };

    let stage_started = Instant::now();
    let mut files = discover_workspace_files(&workspace, &selected, request.limits)?;
    if files.is_empty() {
        return Err(ProjectScanError::NoSourceFiles);
    }
    metrics.file_discovery = ProjectStageMetrics {
        duration: stage_started.elapsed(),
        count: files.len(),
    };

    let mut contexts = Vec::new();
    let mut pending_diagnostics = Vec::new();
    let cli_override = cli_configuration(request);
    let profiles = normalized_profiles(&request.target_profiles);
    let mut plugin_duration = Duration::ZERO;

    for package in &selected {
        let workspace_name = display_workspace(&package.root);
        let inferred = ConfigurationOverride {
            mode: Some(AnalysisMode::Balanced),
            world: Some(if package.manifest.private {
                WorldMode::Closed
            } else {
                WorldMode::Open
            }),
            ..ConfigurationOverride::default()
        };
        let empty = ConfigurationOverride::default();
        let package_configuration = loaded_configuration
            .configuration
            .workspaces
            .get(&workspace_name)
            .unwrap_or(&empty);
        let effective = merge_configuration_layers(ConfigurationLayers {
            inferred: &inferred,
            root: &loaded_configuration.configuration.root,
            workspace: package_configuration,
            cli: &cli_override,
        });
        let configured_entries = if package.root.as_os_str().is_empty() {
            effective.entry.clone().unwrap_or_default()
        } else {
            package_configuration.entry.clone().unwrap_or_default()
        };
        let ignore_base =
            if package.root.as_os_str().is_empty() || package_configuration.ignore.is_none() {
                PathBuf::new()
            } else {
                package.root.clone()
            };
        let retain_base =
            if package.root.as_os_str().is_empty() || package_configuration.retain.is_none() {
                PathBuf::new()
            } else {
                package.root.clone()
            };
        let scripts = analyze_scripts(&package.manifest.scripts, &[]);
        append_script_diagnostics(&mut pending_diagnostics, &workspace_name, &scripts);
        let mut plugins_by_profile = BTreeMap::new();
        for profile in &profiles {
            let plugin_started = Instant::now();
            plugins_by_profile.insert(
                profile.clone(),
                detect_plugins(
                    package,
                    &files,
                    &effective,
                    &workspace.workspace_root,
                    std::slice::from_ref(profile),
                    request.limits,
                )?,
            );
            plugin_duration += plugin_started.elapsed();
        }
        let plugins = plugins_by_profile
            .values()
            .flatten()
            .cloned()
            .collect::<Vec<_>>();
        append_plugin_diagnostics(&mut pending_diagnostics, &workspace_name, &plugins);
        contexts.push(PackageContext {
            package,
            workspace_name,
            effective,
            configured_entries,
            ignore_base,
            retain_base,
            scripts,
            plugins,
            plugins_by_profile,
        });
    }
    metrics.plugin_discovery = ProjectStageMetrics {
        duration: plugin_duration,
        count: contexts
            .iter()
            .flat_map(|context| &context.plugins)
            .map(|plugin| plugin.plugin.id.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
    };

    let transform_discovery_started = Instant::now();
    let transform_source_files = if contexts.iter().any(|context| {
        context
            .plugins
            .iter()
            .any(|detected| !detected.plugin.contributions.file_transforms.is_empty())
    }) {
        let (physical_files, diagnostic) =
            discover_transform_source_files(&workspace.workspace_root, request.limits);
        if let Some(diagnostic) = diagnostic {
            pending_diagnostics.push(diagnostic);
        }
        physical_files
    } else {
        files.clone()
    };
    metrics.plugin_discovery.duration += transform_discovery_started.elapsed();
    let pre_ignore_files = files.clone();
    apply_ignore_rules(&mut files, &workspace, &contexts);
    if files.is_empty() {
        return Err(ProjectScanError::NoSourceFiles);
    }
    let file_set = files.iter().cloned().collect::<BTreeSet<_>>();
    let resolver_conditions = resolve_target_conditions(&profiles, &contexts)?;
    let entries_by_profile = collect_profile_entries(
        &workspace,
        &contexts,
        &project_configurations,
        &file_set,
        request,
        &profiles,
        &mut pending_diagnostics,
    )?;
    let declared_external_packages = declared_package_names(&workspace);

    let effective_configuration = contexts
        .iter()
        .map(|context| (context.workspace_name.clone(), context.effective.clone()))
        .collect::<BTreeMap<_, _>>();
    let config_bytes = serde_json::to_vec(&effective_configuration)?;
    let member_modes = member_modes_by_file(&files, &workspace, &contexts);
    let deep_enabled = contexts
        .iter()
        .any(|context| context.effective.mode == Some(AnalysisMode::Deep));
    let mut deep_member_evidence = DeepMemberRawEvidence::new();

    let profile_bytes = resolver_conditions
        .iter()
        .chain(profiles.iter())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join("\0")
        .into_bytes();
    let cache = FactCache::new(&workspace.workspace_root, &config_bytes, &profile_bytes)
        .map_err(ScanError::from)?;
    let mut profile_reports = Vec::new();
    let profile_started = Instant::now();
    for profile in &profiles {
        let entries = entries_by_profile
            .get(profile)
            .cloned()
            .ok_or(ProjectScanError::NoEntryRoots)?;
        let profile_conditions =
            resolve_target_conditions(std::slice::from_ref(profile), &contexts)?;
        let open_world_entries = open_world_entries(&entries, &workspace, &contexts);
        let workspace_module_targets = workspace_module_targets(
            &workspace,
            &contexts,
            &project_configurations,
            &file_set,
            profile,
        )?;
        let additional_file_edges = collect_plugin_file_edges(
            &workspace,
            &contexts,
            &files,
            &transform_source_files,
            profile,
            request.limits,
            &mut pending_diagnostics,
        );
        let (mut initial_report, initial_measurements) = scan_with_fact_cache_measured(
            &ScanRequest {
                root: workspace.workspace_root.clone(),
                entries,
                files: files.clone(),
            },
            request.limits,
            &cache,
            MemberAnalysisMode::Balanced,
            Some(&member_modes),
            None,
            &profile_conditions,
            Some(&open_world_entries),
            &additional_file_edges,
            Some(&declared_external_packages),
            &workspace_module_targets,
            has_yarn_pnp_manifest(&workspace.package_manager.yarn_plug_and_play),
            SourceUniverseKind::Discovered,
        )?;
        aggregate_scan_measurements(&mut metrics, initial_measurements);
        let deep_candidates = if deep_enabled {
            deep_member_candidates(&initial_report, &member_modes)
        } else {
            BTreeSet::new()
        };
        let report = if deep_candidates.is_empty() {
            initial_report
        } else {
            let uncached_candidates = deep_candidates
                .iter()
                .filter(|candidate| !deep_member_evidence.contains_key(*candidate))
                .cloned()
                .collect::<BTreeSet<_>>();
            if !uncached_candidates.is_empty() {
                let deep_started = Instant::now();
                let (additional_evidence, diagnostic) = collect_deep_member_evidence(
                    DeepMemberEvidenceRequest {
                        workspace_root: &workspace.workspace_root,
                        files: &files,
                        project_configurations: &project_configurations,
                        effective_config_bytes: &config_bytes,
                        source_report: &initial_report,
                        candidates: &uncached_candidates,
                        limits: request.limits,
                    },
                    &mut metrics,
                );
                metrics.deep_analysis.duration += deep_started.elapsed();
                metrics.deep_analysis.count += uncached_candidates.len();
                deep_member_evidence.extend(additional_evidence);
                if let Some(diagnostic) = diagnostic {
                    pending_diagnostics.push(diagnostic);
                }
            }
            let resolved_evidence = resolve_deep_member_evidence(
                &deep_member_evidence,
                &initial_report,
                &workspace,
                &contexts,
            );
            let deep_rules_started = Instant::now();
            let decision_count =
                apply_deep_member_evidence(&mut initial_report, &cache, &resolved_evidence)?;
            metrics.reachability_rules_report.duration += deep_rules_started.elapsed();
            metrics.reachability_rules_report.count += decision_count;
            initial_report
        };
        profile_reports.push((profile.clone(), report));
    }
    metrics.profile_analysis = ProjectStageMetrics {
        duration: profile_started.elapsed(),
        count: profile_reports.len(),
    };
    let mut report = merge_profile_reports(profile_reports)?;

    let policy_started = Instant::now();
    assign_project_context(&mut report, &workspace, &profiles);
    append_configuration_diagnostics(
        &mut pending_diagnostics,
        &workspace,
        &contexts,
        &pre_ignore_files,
        &report,
    )?;
    report.diagnostics.extend(pending_diagnostics);
    enforce_project_diagnostic_limit(&mut report.diagnostics, request.limits.max_diagnostics);
    sort_diagnostics(&mut report.diagnostics);

    if !request.issues.contains(&AnalysisIssue::Files) {
        report
            .findings
            .retain(|finding| finding.issue_type != "unusedFiles");
    }
    if request.issues.contains(&AnalysisIssue::Dependencies) {
        append_dependency_results(
            &workspace,
            &contexts,
            &project_configurations,
            &profiles,
            &mut report,
        );
    }
    if request.issues.contains(&AnalysisIssue::Workspaces) {
        append_workspace_results(&workspace, &contexts, &profiles, &mut report);
    }
    assign_project_context(&mut report, &workspace, &profiles);
    apply_file_fix_eligibility(&contexts, &profiles, &mut report);
    suppress_blocked_findings(&workspace, &mut report);
    apply_retain_rules(&contexts, &mut report);
    apply_confidence_thresholds(&contexts, &workspace, &mut report);
    report.findings.retain(|finding| match finding.issue_type {
        "unusedFiles" => request.issues.contains(&AnalysisIssue::Files),
        "unusedExport" => request.issues.contains(&AnalysisIssue::Exports),
        "unusedDeclaration" => request.issues.contains(&AnalysisIssue::Declarations),
        "unusedMember" => request.issues.contains(&AnalysisIssue::Members),
        "unusedDependency" | "unlistedDependency" | "misplacedDependency" => {
            request.issues.contains(&AnalysisIssue::Dependencies)
        }
        "unusedWorkspace" => request.issues.contains(&AnalysisIssue::Workspaces),
        _ => true,
    });
    if !request.report_tests {
        report
            .findings
            .retain(|finding| !finding.paths.iter().any(|path| is_test_path(path)));
    }
    sort_findings(&mut report.findings);
    report.project = Some(ProjectReport {
        mode: project_mode_name(&contexts),
        workspaces: contexts
            .iter()
            .map(|context| context.workspace_name.clone())
            .collect(),
        worlds: contexts
            .iter()
            .map(|context| {
                (
                    context.workspace_name.clone(),
                    match context.effective.world.unwrap_or(WorldMode::Closed) {
                        WorldMode::Open => "open".to_owned(),
                        WorldMode::Closed => "closed".to_owned(),
                    },
                )
            })
            .collect(),
        target_profiles: profiles,
        failure_thresholds: failure_thresholds(&contexts),
        detected_plugins: contexts
            .iter()
            .flat_map(|context| {
                context
                    .plugins
                    .iter()
                    .map(|plugin| plugin.plugin.id.clone())
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        configuration_sources: loaded_configuration
            .sources
            .iter()
            .map(|source| normalize_path(&source.path, &workspace.workspace_root))
            .collect(),
    });
    refresh_report_state(&mut report);
    metrics.policy = ProjectStageMetrics {
        duration: policy_started.elapsed(),
        count: report.findings.len() + report.retentions.len() + report.diagnostics.len(),
    };
    if let Some(cache) = &report.cache {
        metrics.cache.hits += cache.hits;
        metrics.cache.misses += cache.misses;
        metrics.cache.generation_writes += usize::from(cache.generation_written);
    }
    Ok(ProjectScanOutput {
        report,
        metrics,
        effective_configuration,
    })
}

fn declared_package_names(workspace: &WorkspaceDiscovery) -> BTreeSet<String> {
    workspace
        .packages
        .iter()
        .flat_map(|package| {
            package
                .manifest
                .dependencies
                .keys()
                .chain(package.manifest.dev_dependencies.keys())
                .chain(package.manifest.peer_dependencies.keys())
                .chain(package.manifest.optional_dependencies.keys())
                .cloned()
                .chain(package.manifest.name.iter().cloned())
        })
        .collect()
}

fn workspace_module_targets(
    workspace: &WorkspaceDiscovery,
    contexts: &[PackageContext<'_>],
    project_configurations: &[ProjectConfiguration],
    file_set: &BTreeSet<PathBuf>,
    profile: &str,
) -> Result<Vec<WorkspaceModuleTarget>, ProjectScanError> {
    let empty_targets = BTreeMap::new();
    let mut targets = BTreeMap::<String, WorkspaceModuleTarget>::new();
    for package in &workspace.packages {
        let Some(package_name) = package.manifest.name.as_ref() else {
            continue;
        };
        let configured_targets = contexts
            .iter()
            .find(|context| context.package.root == package.root)
            .map_or(&empty_targets, |context| &context.effective.targets);
        let selected_profiles = [profile.to_owned()];
        let target_conditions =
            resolve_conditions_for_targets(&selected_profiles, configured_targets)?;
        let entry_profiles = manifest_profiles(&selected_profiles, configured_targets)?;
        for entry_profile in entry_profiles {
            for entry in package_entry_roots(&package.manifest, entry_profile)? {
                let candidate = package.root.join(entry.path);
                let Some(source) =
                    map_entry_to_source(&candidate, project_configurations, file_set)
                else {
                    continue;
                };
                let display = source.to_string_lossy().replace('\\', "/");
                add_workspace_module_target(
                    &mut targets,
                    package_name,
                    package_name,
                    entry_profile,
                    display,
                );
            }
            for (export_key, export_target) in
                package_subpath_exports(&package.manifest, entry_profile, &target_conditions)
            {
                for (specifier, source) in expand_workspace_export(
                    package,
                    package_name,
                    &export_key,
                    &export_target,
                    project_configurations,
                    file_set,
                ) {
                    add_workspace_module_target(
                        &mut targets,
                        package_name,
                        &specifier,
                        entry_profile,
                        source,
                    );
                }
            }
        }
        targets
            .entry(package_name.clone())
            .or_insert_with(|| WorkspaceModuleTarget {
                package: package_name.clone(),
                specifier: package_name.clone(),
                esm: Vec::new(),
                common_js: Vec::new(),
            });
    }
    for target in targets.values_mut() {
        deduplicate_preserving_order(&mut target.esm);
        deduplicate_preserving_order(&mut target.common_js);
    }
    Ok(targets.into_values().collect())
}

fn deduplicate_preserving_order(values: &mut Vec<String>) {
    let mut seen = BTreeSet::new();
    values.retain(|value| seen.insert(value.clone()));
}

fn add_workspace_module_target(
    targets: &mut BTreeMap<String, WorkspaceModuleTarget>,
    package: &str,
    specifier: &str,
    profile: EntryTargetProfile,
    source: String,
) {
    let target = targets
        .entry(specifier.to_owned())
        .or_insert_with(|| WorkspaceModuleTarget {
            package: package.to_owned(),
            specifier: specifier.to_owned(),
            esm: Vec::new(),
            common_js: Vec::new(),
        });
    let paths = if profile == EntryTargetProfile::NodeRequire {
        &mut target.common_js
    } else {
        &mut target.esm
    };
    paths.push(source);
}

fn package_subpath_exports(
    manifest: &PackageManifest,
    profile: EntryTargetProfile,
    target_conditions: &BTreeSet<String>,
) -> Vec<(String, String)> {
    let Some(Value::Object(exports)) = manifest.exports.as_ref() else {
        return Vec::new();
    };
    if !exports.keys().any(|key| key.starts_with('.')) {
        return Vec::new();
    }
    let profile_conditions: &[&str] = match profile {
        EntryTargetProfile::NodeImport => &["node", "import"],
        EntryTargetProfile::NodeRequire => &["node", "require"],
        EntryTargetProfile::Bundler => &["import", "module"],
        EntryTargetProfile::Browser => &["browser", "import"],
        EntryTargetProfile::Types => &["types"],
        EntryTargetProfile::CommandLine => &[],
    };
    let mut conditions = target_conditions.clone();
    conditions.extend(
        profile_conditions
            .iter()
            .map(|condition| (*condition).to_owned()),
    );
    let mut selected = Vec::new();
    for (key, value) in exports {
        if key == "." || !key.starts_with("./") {
            continue;
        }
        let mut values = Vec::new();
        collect_conditional_export_targets(value, &conditions, &mut values);
        selected.extend(values.into_iter().map(|value| (key.clone(), value)));
    }
    selected
}

fn collect_conditional_export_targets(
    value: &Value,
    conditions: &BTreeSet<String>,
    targets: &mut Vec<String>,
) {
    match value {
        Value::String(target) => targets.push(target.clone()),
        Value::Array(values) => {
            for value in values {
                collect_conditional_export_targets(value, conditions, targets);
            }
        }
        Value::Object(values) => {
            let selected = values.iter().find_map(|(condition, value)| {
                (condition == "default" || conditions.contains(condition)).then_some(value)
            });
            if let Some(selected) = selected {
                collect_conditional_export_targets(selected, conditions, targets);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn expand_workspace_export(
    package: &WorkspacePackage,
    package_name: &str,
    export_key: &str,
    export_target: &str,
    project_configurations: &[ProjectConfiguration],
    file_set: &BTreeSet<PathBuf>,
) -> Vec<(String, String)> {
    let normalized_target = export_target.strip_prefix("./").unwrap_or(export_target);
    if !export_key.contains('*') && !normalized_target.contains('*') {
        let candidate = package.root.join(normalized_target);
        return map_entry_to_source(&candidate, project_configurations, file_set)
            .map(|source| {
                (
                    format!("{package_name}/{}", export_key.trim_start_matches("./")),
                    source.to_string_lossy().replace('\\', "/"),
                )
            })
            .into_iter()
            .collect();
    }
    if export_key.matches('*').count() != 1 || normalized_target.matches('*').count() != 1 {
        return Vec::new();
    }

    let target_pattern = package.root.join(normalized_target);
    let target_pattern = target_pattern.to_string_lossy().replace('\\', "/");
    let mut expanded = BTreeSet::new();
    for source in file_set
        .iter()
        .filter(|path| path.starts_with(&package.root))
    {
        for emitted in emitted_source_variants(source, project_configurations) {
            let emitted = emitted.to_string_lossy().replace('\\', "/");
            let Some(capture) = single_wildcard_capture(&target_pattern, &emitted) else {
                continue;
            };
            let subpath = export_key.replacen('*', capture, 1);
            expanded.insert((
                format!("{package_name}/{}", subpath.trim_start_matches("./")),
                source.to_string_lossy().replace('\\', "/"),
            ));
        }
    }
    expanded.into_iter().collect()
}

fn emitted_source_variants(
    source: &Path,
    project_configurations: &[ProjectConfiguration],
) -> BTreeSet<PathBuf> {
    let mut variants = BTreeSet::from([normalize_relative(source), runtime_output_path(source)]);
    for configuration in project_configurations {
        let (Some(root_dir), Some(out_dir)) = (&configuration.root_dir, &configuration.out_dir)
        else {
            continue;
        };
        if let Ok(relative) = source.strip_prefix(root_dir) {
            let output = out_dir.join(relative);
            variants.insert(output.clone());
            variants.insert(runtime_output_path(&output));
        }
    }
    variants
}

fn runtime_output_path(path: &Path) -> PathBuf {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("ts" | "tsx") => path.with_extension("js"),
        Some("mts") => path.with_extension("mjs"),
        Some("cts") => path.with_extension("cjs"),
        _ => path.to_path_buf(),
    }
}

fn single_wildcard_capture<'a>(pattern: &str, value: &'a str) -> Option<&'a str> {
    let (prefix, suffix) = pattern.split_once('*')?;
    value
        .strip_prefix(prefix)
        .and_then(|value| value.strip_suffix(suffix))
}

fn selected_packages<'a>(
    workspace: &'a WorkspaceDiscovery,
    requested: Option<&Path>,
) -> Result<Vec<&'a WorkspacePackage>, ProjectScanError> {
    let Some(requested) = requested else {
        return Ok(workspace.packages.iter().collect());
    };
    let normalized = normalize_relative(requested);
    workspace
        .packages
        .iter()
        .find(|package| package.root == normalized)
        .map(|package| vec![package])
        .ok_or_else(|| ProjectScanError::UnknownWorkspace(requested.to_path_buf()))
}

fn context_for_path<'a, 'workspace>(
    workspace: &WorkspaceDiscovery,
    contexts: &'a [PackageContext<'workspace>],
    path: &Path,
) -> Option<&'a PackageContext<'workspace>> {
    let owner = workspace.package_for_path(path)?;
    contexts
        .iter()
        .find(|context| context.package.root == owner.root)
}

fn apply_ignore_rules(
    files: &mut Vec<PathBuf>,
    workspace: &WorkspaceDiscovery,
    contexts: &[PackageContext<'_>],
) {
    files.retain(|path| {
        let Some(context) = context_for_path(workspace, contexts, path) else {
            return true;
        };
        let configured_relative = path.strip_prefix(&context.ignore_base).unwrap_or(path);
        let package_relative = path.strip_prefix(&context.package.root).unwrap_or(path);
        let configured_root = workspace.workspace_root.join(&context.ignore_base);
        let package_root = workspace.workspace_root.join(&context.package.root);
        let configured_ignore = context
            .effective
            .ignore
            .iter()
            .flatten()
            .any(|rule| pattern_matches(&configured_root, &rule.pattern, configured_relative));
        let plugin_exclusion = !context.plugins_by_profile.is_empty()
            && context.plugins_by_profile.values().all(|plugins| {
                plugins.iter().any(|plugin| {
                    plugin
                        .plugin
                        .contributions
                        .exclusion_patterns
                        .iter()
                        .any(|rule| pattern_matches(&package_root, &rule.pattern, package_relative))
                })
            });
        !configured_ignore && !plugin_exclusion
    });
}

fn discover_transform_source_files(
    workspace_root: &Path,
    limits: AnalysisLimits,
) -> (Vec<PathBuf>, Option<AnalysisDiagnostic>) {
    let filter_root = workspace_root.to_path_buf();
    let mut builder = WalkBuilder::new(workspace_root);
    builder
        .hidden(false)
        .ignore(true)
        .git_ignore(true)
        .require_git(false)
        .follow_links(false)
        .sort_by_file_path(Path::cmp)
        .filter_entry(move |entry| {
            entry.depth() == 0
                || !entry.file_type().is_some_and(|kind| kind.is_dir())
                || ![
                    "node_modules",
                    ".git",
                    ".hg",
                    ".svn",
                    "target",
                    "dist",
                    "build",
                    "coverage",
                    ".next",
                    ".nuxt",
                    ".svelte-kit",
                    ".turbo",
                    ".cache",
                    ".orphanode",
                ]
                .iter()
                .any(|name| entry.file_name() == std::ffi::OsStr::new(name))
        });
    let mut files = Vec::new();
    for result in builder.build() {
        let Ok(entry) = result else {
            return (
                Vec::new(),
                Some(plugin_transform_discovery_diagnostic(
                    "the workspace walk encountered an unreadable entry",
                )),
            );
        };
        if entry.path_is_symlink() || !entry.file_type().is_some_and(|kind| kind.is_file()) {
            continue;
        }
        let Ok(relative) = entry.path().strip_prefix(&filter_root) else {
            return (
                Vec::new(),
                Some(plugin_transform_discovery_diagnostic(
                    "the workspace walk escaped the analysis root",
                )),
            );
        };
        files.push(relative.to_path_buf());
        if files.len() > limits.max_discovered_files {
            return (
                Vec::new(),
                Some(plugin_transform_discovery_diagnostic(&format!(
                    "the physical candidate count exceeded the configured limit of {}",
                    limits.max_discovered_files
                ))),
            );
        }
    }
    (files, None)
}

fn plugin_transform_discovery_diagnostic(message: &str) -> AnalysisDiagnostic {
    AnalysisDiagnostic {
        code: "plugin_transform_discovery_incomplete".to_owned(),
        path: "<project>".to_owned(),
        severity: DiagnosticSeverity::Error,
        span: None,
        message: format!("Plugin transform source discovery is incomplete: {message}"),
        blocks_reachability: true,
    }
}

fn collect_plugin_file_edges(
    workspace: &WorkspaceDiscovery,
    contexts: &[PackageContext<'_>],
    files: &[PathBuf],
    discovered_files: &[PathBuf],
    profile: &str,
    limits: AnalysisLimits,
    diagnostics: &mut Vec<AnalysisDiagnostic>,
) -> Vec<AdditionalFileEdge> {
    let mut edges = BTreeSet::new();
    for context in contexts {
        let package_root = workspace.workspace_root.join(&context.package.root);
        let package_files = files
            .iter()
            .filter(|path| path.starts_with(&context.package.root))
            .map(|path| {
                (
                    path,
                    path.strip_prefix(&context.package.root).unwrap_or(path),
                )
            })
            .collect::<Vec<_>>();
        let discovered_package_files = discovered_files
            .iter()
            .filter(|path| path.starts_with(&context.package.root))
            .map(|path| path.strip_prefix(&context.package.root).unwrap_or(path))
            .collect::<Vec<_>>();
        for detected in context
            .plugins_by_profile
            .get(profile)
            .into_iter()
            .flatten()
        {
            let contributions = &detected.plugin.contributions;
            for edge in &contributions.file_edges {
                let sources = package_files.iter().filter(|(_, relative)| {
                    pattern_matches(&package_root, &edge.from_pattern, relative)
                });
                let targets = package_files
                    .iter()
                    .filter(|(_, relative)| {
                        pattern_matches(&package_root, &edge.to_pattern, relative)
                    })
                    .collect::<Vec<_>>();
                for (source, _) in sources {
                    for (target, _) in &targets {
                        edges.insert(AdditionalFileEdge {
                            from: source.to_string_lossy().replace('\\', "/"),
                            to: target.to_string_lossy().replace('\\', "/"),
                            reason: format!("{}: {}", detected.plugin.display_name, edge.reason),
                        });
                    }
                }
            }
            for dynamic in &contributions.dynamic_imports {
                let sources = package_files.iter().filter(|(_, relative)| {
                    pattern_matches(&package_root, &dynamic.importer_pattern, relative)
                });
                let targets = package_files
                    .iter()
                    .filter(|(_, relative)| {
                        pattern_matches(&package_root, &dynamic.specifier_pattern, relative)
                    })
                    .collect::<Vec<_>>();
                for (source, _) in sources {
                    for (target, _) in &targets {
                        edges.insert(AdditionalFileEdge {
                            from: source.to_string_lossy().replace('\\', "/"),
                            to: target.to_string_lossy().replace('\\', "/"),
                            reason: format!(
                                "{} dynamic import: {}",
                                detected.plugin.display_name, dynamic.reason
                            ),
                        });
                    }
                }
            }
            for transform in &contributions.file_transforms {
                append_file_transform_edges(
                    &mut edges,
                    diagnostics,
                    &package_root,
                    &context.workspace_name,
                    &detected.plugin.display_name,
                    transform,
                    &package_files,
                    &discovered_package_files,
                );
            }
        }
    }

    if edges.len() > limits.max_pattern_expansions {
        diagnostics.push(AnalysisDiagnostic {
            code: "plugin_pattern_limit_exceeded".to_owned(),
            path: "orphanode.jsonc".to_owned(),
            severity: DiagnosticSeverity::Error,
            span: None,
            message: format!(
                "Plugin edge expansion produced {} edges, exceeding the configured limit of {}",
                edges.len(),
                limits.max_pattern_expansions
            ),
            blocks_reachability: true,
        });
        return Vec::new();
    }
    edges.into_iter().collect()
}

#[allow(clippy::too_many_arguments)]
fn append_file_transform_edges(
    edges: &mut BTreeSet<AdditionalFileEdge>,
    diagnostics: &mut Vec<AnalysisDiagnostic>,
    package_root: &Path,
    workspace_name: &str,
    plugin_display_name: &str,
    transform: &FileTransformContribution,
    package_files: &[(&PathBuf, &Path)],
    discovered_package_files: &[&Path],
) {
    let matched_sources = package_files
        .iter()
        .filter(|(_, relative)| pattern_matches(package_root, &transform.source_pattern, relative))
        .collect::<Vec<_>>();
    let has_discovered_source = discovered_package_files
        .iter()
        .any(|relative| pattern_matches(package_root, &transform.source_pattern, relative));
    if matched_sources.is_empty() && has_discovered_source {
        diagnostics.push(AnalysisDiagnostic {
            code: "plugin_transform_source_unmodeled".to_owned(),
            path: workspace_manifest_path(workspace_name),
            severity: DiagnosticSeverity::Error,
            span: None,
            message: format!(
                "{plugin_display_name} file transform pattern `{}` matched no analyzable source file",
                transform.source_pattern
            ),
            blocks_reachability: true,
        });
    }
    for (source, relative) in matched_sources {
        let mut materialized_outputs = 0_usize;
        for extension in &transform.output_extensions {
            let output = relative.with_extension(extension.trim_start_matches('.'));
            let Some((target, _)) = package_files
                .iter()
                .find(|(_, relative)| **relative == output)
            else {
                continue;
            };
            materialized_outputs += 1;
            if source != target {
                edges.insert(AdditionalFileEdge {
                    from: source.to_string_lossy().replace('\\', "/"),
                    to: target.to_string_lossy().replace('\\', "/"),
                    reason: format!("{plugin_display_name} file transform: {}", transform.reason),
                });
            }
        }
        if materialized_outputs == 0 {
            diagnostics.push(AnalysisDiagnostic {
                code: "plugin_transform_output_missing".to_owned(),
                path: source.to_string_lossy().replace('\\', "/"),
                severity: DiagnosticSeverity::Error,
                span: None,
                message: format!(
                    "{plugin_display_name} file transform could not materialize a declared output for `{}`",
                    source.to_string_lossy()
                ),
                blocks_reachability: true,
            });
        }
    }
}

fn member_modes_by_file(
    files: &[PathBuf],
    workspace: &WorkspaceDiscovery,
    contexts: &[PackageContext<'_>],
) -> BTreeMap<String, MemberAnalysisMode> {
    files
        .iter()
        .filter_map(|path| {
            let context = context_for_path(workspace, contexts, path)?;
            let mode = context.effective.mode.unwrap_or(AnalysisMode::Balanced);
            Some((
                path.to_string_lossy().replace('\\', "/"),
                member_analysis_mode(mode),
            ))
        })
        .collect()
}

fn open_world_entries(
    entries: &[PathBuf],
    workspace: &WorkspaceDiscovery,
    contexts: &[PackageContext<'_>],
) -> BTreeSet<String> {
    entries
        .iter()
        .filter(|entry| {
            context_for_path(workspace, contexts, entry).is_some_and(|context| {
                context.effective.world.unwrap_or(WorldMode::Closed) == WorldMode::Open
            })
        })
        .map(|entry| entry.to_string_lossy().replace('\\', "/"))
        .collect()
}

fn project_mode_name(contexts: &[PackageContext<'_>]) -> String {
    let modes = contexts
        .iter()
        .map(|context| analysis_mode_name(context.effective.mode.unwrap_or(AnalysisMode::Balanced)))
        .collect::<BTreeSet<_>>();
    if modes.len() == 1 {
        modes.into_iter().next().unwrap_or("balanced").to_owned()
    } else {
        "mixed".to_owned()
    }
}

#[allow(clippy::too_many_arguments)]
fn collect_profile_entries(
    workspace: &WorkspaceDiscovery,
    contexts: &[PackageContext<'_>],
    project_configurations: &[ProjectConfiguration],
    file_set: &BTreeSet<PathBuf>,
    request: &ProjectScanRequest,
    profiles: &[String],
    diagnostics: &mut Vec<AnalysisDiagnostic>,
) -> Result<BTreeMap<String, Vec<PathBuf>>, ProjectScanError> {
    if !request.entries.is_empty() {
        let entries = normalize_requested_entries(workspace, request, file_set)?;
        if entries.is_empty() {
            return Err(ProjectScanError::NoEntryRoots);
        }
        return Ok(profiles
            .iter()
            .map(|profile| (profile.clone(), entries.clone()))
            .collect());
    }

    let mut entries_by_profile = BTreeMap::new();
    for profile in profiles {
        let mut entries = BTreeSet::new();
        for context in contexts {
            let plugins = context
                .plugins_by_profile
                .get(profile)
                .map(Vec::as_slice)
                .unwrap_or_default();
            collect_package_entries(
                workspace,
                context.package,
                &context.effective,
                &context.configured_entries,
                &context.scripts,
                plugins,
                project_configurations,
                file_set,
                request,
                std::slice::from_ref(profile),
                &mut entries,
                diagnostics,
            )?;
        }
        if entries.is_empty() {
            return Err(ProjectScanError::NoEntryRoots);
        }
        entries_by_profile.insert(profile.clone(), entries.into_iter().collect());
    }
    Ok(entries_by_profile)
}

// Profile merging is intentionally centralized to preserve deterministic ordering.
#[allow(clippy::too_many_lines)]
fn merge_profile_reports(
    mut reports: Vec<(String, ScanReport)>,
) -> Result<ScanReport, ProjectScanError> {
    if reports.is_empty() {
        return Err(ProjectScanError::NoEntryRoots);
    }
    let (first_profile, mut aggregate) = reports.remove(0);
    tag_profile_report(&mut aggregate, &first_profile);
    for (profile, mut report) in reports {
        tag_profile_report(&mut report, &profile);
        aggregate.entries.extend(report.entries);
        aggregate.entries.sort();
        aggregate.entries.dedup();

        for mut file in report.files {
            let Some(existing) = aggregate
                .files
                .iter_mut()
                .find(|existing| existing.path == file.path)
            else {
                aggregate.files.push(file);
                continue;
            };
            existing.status = merge_file_status(existing.status, file.status);
            existing.target_statuses.append(&mut file.target_statuses);
            existing.imports.append(&mut file.imports);
            existing.imports.sort_by(|left, right| {
                (
                    &left.specifier,
                    left.kind,
                    left.resolution_mode,
                    left.activation,
                    left.type_only,
                    left.status,
                    &left.target_profiles,
                    &left.target,
                    left.span,
                )
                    .cmp(&(
                        &right.specifier,
                        right.kind,
                        right.resolution_mode,
                        right.activation,
                        right.type_only,
                        right.status,
                        &right.target_profiles,
                        &right.target,
                        right.span,
                    ))
            });
            existing.imports.dedup_by(|left, right| {
                left.specifier == right.specifier
                    && left.kind == right.kind
                    && left.resolution_mode == right.resolution_mode
                    && left.activation == right.activation
                    && left.type_only == right.type_only
                    && left.status == right.status
                    && left.target_profiles == right.target_profiles
                    && left.target == right.target
                    && left.span == right.span
            });
            existing.exports.append(&mut file.exports);
            existing.exports.sort_by(|left, right| {
                (&left.name, left.kind, left.type_only, left.span).cmp(&(
                    &right.name,
                    right.kind,
                    right.type_only,
                    right.span,
                ))
            });
            existing.exports.dedup();
        }

        for finding in report.findings {
            if let Some(existing) = aggregate
                .findings
                .iter_mut()
                .find(|existing| same_finding(existing, &finding))
            {
                existing.target_profiles.extend(finding.target_profiles);
                existing.target_profiles.sort();
                existing.target_profiles.dedup();
            } else {
                aggregate.findings.push(finding);
            }
        }
        for retention in report.retentions {
            if let Some(existing) = aggregate.retentions.iter_mut().find(|existing| {
                existing.item == retention.item
                    && existing.item_type == retention.item_type
                    && existing.workspace == retention.workspace
                    && existing.summary == retention.summary
            }) {
                existing.target_profiles.extend(retention.target_profiles);
                existing.target_profiles.sort();
                existing.target_profiles.dedup();
                existing.evidence.extend(retention.evidence);
                existing.evidence.sort();
                existing.evidence.dedup();
            } else {
                aggregate.retentions.push(retention);
            }
        }
        aggregate.diagnostics.extend(report.diagnostics);
        if let (Some(aggregate_cache), Some(report_cache)) = (&mut aggregate.cache, report.cache) {
            aggregate_cache.hits += report_cache.hits;
            aggregate_cache.misses += report_cache.misses;
            aggregate_cache.generation_written |= report_cache.generation_written;
        }
    }
    aggregate
        .files
        .sort_by(|left, right| left.path.cmp(&right.path));
    sort_findings(&mut aggregate.findings);
    merge_duplicate_diagnostics(&mut aggregate.diagnostics);
    aggregate.summary.files = aggregate.files.len();
    aggregate.summary.reachable_files = aggregate
        .files
        .iter()
        .filter(|file| file.status == FileStatus::Reachable)
        .count();
    aggregate.summary.unreachable_files = aggregate
        .files
        .iter()
        .filter(|file| file.status == FileStatus::Unreachable)
        .count();
    aggregate.summary.incomplete_files = aggregate
        .files
        .iter()
        .filter(|file| file.status == FileStatus::Incomplete)
        .count();
    aggregate.summary.diagnostics = aggregate.diagnostics.len();
    aggregate.status = if aggregate
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.blocks_reachability)
    {
        AnalysisStatus::Incomplete
    } else {
        AnalysisStatus::Complete
    };
    Ok(aggregate)
}

fn tag_profile_report(report: &mut ScanReport, profile: &str) {
    for file in &mut report.files {
        file.target_statuses.clear();
        file.target_statuses.insert(profile.to_owned(), file.status);
        for import in &mut file.imports {
            import.target_profiles = vec![profile.to_owned()];
        }
    }
    for finding in &mut report.findings {
        finding.target_profiles = vec![profile.to_owned()];
    }
    for retention in &mut report.retentions {
        retention.target_profiles = vec![profile.to_owned()];
    }
    for diagnostic in &mut report.diagnostics {
        diagnostic.message = format!("[target {profile}] {}", diagnostic.message);
    }
}

fn merge_file_status(left: FileStatus, right: FileStatus) -> FileStatus {
    if left == FileStatus::Reachable || right == FileStatus::Reachable {
        FileStatus::Reachable
    } else if left == FileStatus::Incomplete || right == FileStatus::Incomplete {
        FileStatus::Incomplete
    } else {
        FileStatus::Unreachable
    }
}

fn same_finding(left: &Finding, right: &Finding) -> bool {
    left.issue_id == right.issue_id
        && left.issue_type == right.issue_type
        && left.workspace == right.workspace
        && left.paths == right.paths
        && left.span == right.span
        && left.symbol == right.symbol
        && left.dependency == right.dependency
}

fn discover_workspace_files(
    workspace: &WorkspaceDiscovery,
    selected: &[&WorkspacePackage],
    limits: AnalysisLimits,
) -> Result<Vec<PathBuf>, DiscoveryError> {
    let mut files = BTreeSet::new();
    for package in selected {
        let package_root = workspace.workspace_root.join(&package.root);
        let nested = workspace
            .packages
            .iter()
            .filter_map(|candidate| {
                (candidate.root != package.root)
                    .then(|| candidate.root.strip_prefix(&package.root).ok())
                    .flatten()
                    .filter(|path| !path.as_os_str().is_empty())
                    .map(Path::to_path_buf)
            })
            .collect::<Vec<_>>();
        for source in discover_package_source_files(&package_root, &nested, limits)? {
            files.insert(package.root.join(source));
            if files.len() > limits.max_discovered_files {
                return Err(DiscoveryError::FileLimitExceeded {
                    root: workspace.workspace_root.clone(),
                    limit: limits.max_discovered_files,
                });
            }
        }
    }
    Ok(files.into_iter().collect())
}

#[allow(clippy::too_many_arguments)]
fn collect_package_entries(
    workspace: &WorkspaceDiscovery,
    package: &WorkspacePackage,
    effective: &ConfigurationOverride,
    configured_entries: &[PathBuf],
    scripts: &ScriptAnalysis,
    plugins: &[DetectedBuiltinPlugin],
    project_configurations: &[ProjectConfiguration],
    file_set: &BTreeSet<PathBuf>,
    request: &ProjectScanRequest,
    profiles: &[String],
    entries: &mut BTreeSet<PathBuf>,
    diagnostics: &mut Vec<AnalysisDiagnostic>,
) -> Result<(), ProjectScanError> {
    for entry in configured_entries {
        add_entry_candidate(
            &package.root.join(entry),
            "static Orphanode configuration",
            project_configurations,
            file_set,
            entries,
            diagnostics,
        );
    }

    let root_package = package.root.as_os_str().is_empty();
    let explicitly_selected = request
        .workspace
        .as_deref()
        .is_some_and(|selected| normalize_relative(selected) == package.root);
    if !package.manifest.private || root_package || explicitly_selected {
        for profile in manifest_profiles(profiles, &effective.targets)? {
            for entry in package_entry_roots(&package.manifest, profile)? {
                add_manifest_entry(
                    package,
                    entry,
                    project_configurations,
                    file_set,
                    entries,
                    diagnostics,
                );
            }
        }
    }

    for reference in &scripts.references {
        if reference.kind == ScriptReferenceKind::File {
            add_entry_candidate(
                &package
                    .root
                    .join(normalize_relative(Path::new(&reference.value))),
                &format!("package script `{}`", reference.script),
                project_configurations,
                file_set,
                entries,
                diagnostics,
            );
        }
    }
    for detected in plugins {
        for pattern in detected
            .plugin
            .contributions
            .entry_patterns
            .iter()
            .chain(&detected.plugin.contributions.project_file_patterns)
            .chain(&detected.plugin.contributions.config_file_patterns)
        {
            for path in file_set
                .iter()
                .filter(|path| path.starts_with(&package.root))
            {
                let relative = path.strip_prefix(&package.root).unwrap_or(path);
                if pattern_matches(
                    &workspace.workspace_root.join(&package.root),
                    &pattern.pattern,
                    relative,
                ) {
                    entries.insert(path.clone());
                }
            }
        }
    }

    for profile in profiles {
        add_conventional_profile_entries(package, profile, file_set, entries);
    }

    if !entries.iter().any(|entry| entry.starts_with(&package.root))
        && (root_package || explicitly_selected)
    {
        for conventional in [
            "src/index.ts",
            "src/index.tsx",
            "src/index.js",
            "src/main.ts",
            "src/main.js",
            "src/cli.ts",
            "src/cli/index.ts",
            "index.ts",
            "index.js",
        ] {
            let candidate = package.root.join(conventional);
            if file_set.contains(&candidate) {
                entries.insert(candidate);
            }
        }
    }
    Ok(())
}

fn add_conventional_profile_entries(
    package: &WorkspacePackage,
    profile: &str,
    file_set: &BTreeSet<PathBuf>,
    entries: &mut BTreeSet<PathBuf>,
) {
    for path in file_set
        .iter()
        .filter(|path| path.starts_with(&package.root))
    {
        let relative = path.strip_prefix(&package.root).unwrap_or(path);
        let display = relative.to_string_lossy().replace('\\', "/");
        let file_name = relative
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        let is_test = display.starts_with("test/")
            || display.starts_with("tests/")
            || display.contains("/__tests__/")
            || file_name.contains(".test.")
            || file_name.contains(".spec.");
        let is_benchmark = display.starts_with("benchmark/")
            || display.starts_with("benchmarks/")
            || file_name.contains(".bench.")
            || file_name.contains(".benchmark.");
        let is_story = display.starts_with("stories/")
            || display.starts_with(".storybook/")
            || display.contains("/.storybook/")
            || file_name.contains(".stories.")
            || file_name.contains(".story.");
        let is_example = display.starts_with("example/")
            || display.starts_with("examples/")
            || display.contains("/examples/");

        let is_profile_root = match profile {
            "test" => is_test || is_benchmark,
            "browser" | "bundler" => is_story || is_example,
            "node" | "development" => is_example,
            _ => false,
        };
        if is_profile_root {
            entries.insert(path.clone());
        }
    }
}

fn add_manifest_entry(
    package: &WorkspacePackage,
    entry: PackageEntryRoot,
    project_configurations: &[ProjectConfiguration],
    file_set: &BTreeSet<PathBuf>,
    entries: &mut BTreeSet<PathBuf>,
    diagnostics: &mut Vec<AnalysisDiagnostic>,
) {
    add_entry_candidate(
        &package.root.join(entry.path),
        &format!("package.json {:?} entry", entry.field),
        project_configurations,
        file_set,
        entries,
        diagnostics,
    );
}

fn add_entry_candidate(
    candidate: &Path,
    evidence: &str,
    project_configurations: &[ProjectConfiguration],
    file_set: &BTreeSet<PathBuf>,
    entries: &mut BTreeSet<PathBuf>,
    diagnostics: &mut Vec<AnalysisDiagnostic>,
) {
    if let Some(source) = map_entry_to_source(candidate, project_configurations, file_set) {
        entries.insert(source);
    } else {
        diagnostics.push(AnalysisDiagnostic {
            code: "entry_source_not_found".to_owned(),
            path: normalize_relative(candidate)
                .to_string_lossy()
                .replace('\\', "/"),
            severity: DiagnosticSeverity::Warning,
            span: None,
            message: format!("{evidence} does not map to a discovered source file"),
            // The candidate names no discovered source, so no file's coverage
            // is uncertain. The gap stays visible without suppressing findings.
            blocks_reachability: false,
        });
    }
}

fn map_entry_to_source(
    candidate: &Path,
    project_configurations: &[ProjectConfiguration],
    file_set: &BTreeSet<PathBuf>,
) -> Option<PathBuf> {
    for direct in source_variants(candidate) {
        if file_set.contains(&direct) {
            return Some(direct);
        }
    }
    for configuration in project_configurations {
        let (Some(out_dir), Some(root_dir)) = (&configuration.out_dir, &configuration.root_dir)
        else {
            continue;
        };
        let Ok(relative_output) = candidate.strip_prefix(out_dir) else {
            continue;
        };
        for mapped in source_variants(&root_dir.join(relative_output)) {
            if file_set.contains(&mapped) {
                return Some(mapped);
            }
        }
    }
    None
}

fn source_variants(path: &Path) -> Vec<PathBuf> {
    let mut variants = BTreeSet::from([normalize_relative(path)]);
    let extension = path.extension().and_then(|value| value.to_str());
    let replacements: &[&str] = match extension {
        Some("js") => &["ts", "tsx", "js", "jsx"],
        Some("mjs") => &["mts", "mjs"],
        Some("cjs") => &["cts", "cjs"],
        None => &["ts", "tsx", "mts", "cts", "js", "jsx", "mjs", "cjs"],
        _ => &[],
    };
    for replacement in replacements {
        variants.insert(path.with_extension(replacement));
    }
    variants.into_iter().collect()
}

fn detect_plugins(
    package: &WorkspacePackage,
    files: &[PathBuf],
    effective: &ConfigurationOverride,
    workspace_root: &Path,
    target_profiles: &[String],
    limits: AnalysisLimits,
) -> Result<Vec<DetectedBuiltinPlugin>, ProjectScanError> {
    let package_names = package
        .manifest
        .dependencies
        .keys()
        .chain(package.manifest.dev_dependencies.keys())
        .chain(package.manifest.peer_dependencies.keys())
        .chain(package.manifest.optional_dependencies.keys())
        .cloned()
        .collect();
    let config_files = package_configuration_files(&workspace_root.join(&package.root));
    let detection_input = BuiltinDetectionInput {
        package_names,
        config_files,
    };
    let Some(configured) = effective.plugins.as_ref() else {
        return detect_builtin_plugins(&detection_input).map_err(ProjectScanError::from);
    };

    let available = builtin_plugins()
        .into_iter()
        .map(|plugin| (plugin.id.clone(), plugin))
        .collect::<BTreeMap<_, _>>();
    let mut selected = BTreeMap::new();
    for configured_plugin in configured {
        let plugin = if let Some(plugin) = available.get(configured_plugin) {
            plugin.clone()
        } else {
            load_configured_plugin(
                workspace_root,
                package,
                files,
                target_profiles,
                configured_plugin,
                limits,
            )?
        };
        plugin.validate()?;
        selected.insert(
            plugin.id.clone(),
            DetectedBuiltinPlugin {
                plugin,
                evidence: Vec::new(),
            },
        );
    }
    Ok(selected.into_values().collect())
}

fn package_configuration_files(package_root: &Path) -> BTreeSet<String> {
    let mut files = BTreeSet::new();
    let Ok(entries) = fs::read_dir(package_root) else {
        return files;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if path.is_file() {
            files.insert(name);
        } else if name == ".storybook"
            && path.is_dir()
            && let Ok(children) = fs::read_dir(path)
        {
            files.extend(children.flatten().filter_map(|child| {
                child
                    .path()
                    .is_file()
                    .then(|| format!(".storybook/{}", child.file_name().to_string_lossy()))
            }));
        }
    }
    files
}

fn load_configured_plugin(
    workspace_root: &Path,
    package: &WorkspacePackage,
    files: &[PathBuf],
    target_profiles: &[String],
    configured_plugin: &str,
    limits: AnalysisLimits,
) -> Result<DeclarativePlugin, ProjectScanError> {
    let configured_path = configured_plugin
        .strip_prefix("exec:")
        .unwrap_or(configured_plugin);
    let requested = workspace_root.join(configured_path);
    let path = requested
        .canonicalize()
        .map_err(|error| ProjectScanError::ConfiguredPlugin {
            plugin: configured_plugin.to_owned(),
            message: error.to_string(),
        })?;
    if !path.starts_with(workspace_root) || !path.is_file() {
        return Err(ProjectScanError::ConfiguredPlugin {
            plugin: configured_plugin.to_owned(),
            message: "plugin path must name a regular file inside the workspace".to_owned(),
        });
    }
    let source = fs::read_to_string(&path).map_err(|error| ProjectScanError::ConfiguredPlugin {
        plugin: configured_plugin.to_owned(),
        message: error.to_string(),
    })?;
    if configured_plugin.starts_with("exec:") {
        let config = serde_json::from_str::<ExecutablePluginConfig>(&source).map_err(|error| {
            ProjectScanError::ConfiguredPlugin {
                plugin: configured_plugin.to_owned(),
                message: error.to_string(),
            }
        })?;
        return execute_configured_plugin(
            workspace_root,
            package,
            files,
            target_profiles,
            configured_plugin,
            &config,
            limits,
        );
    }
    serde_json::from_str(&source).map_err(|error| ProjectScanError::ConfiguredPlugin {
        plugin: configured_plugin.to_owned(),
        message: error.to_string(),
    })
}

fn execute_configured_plugin(
    workspace_root: &Path,
    package: &WorkspacePackage,
    files: &[PathBuf],
    target_profiles: &[String],
    configured_plugin: &str,
    config: &ExecutablePluginConfig,
    limits: AnalysisLimits,
) -> Result<DeclarativePlugin, ProjectScanError> {
    config
        .validate(workspace_root)
        .map_err(|error| configured_plugin_error(configured_plugin, error))?;
    let capabilities = all_plugin_capabilities();
    let manifest = executable_manifest_facts(package);
    let config_files = executable_config_facts(workspace_root, package, files, limits);
    let mut contributions = PluginContributions::default();
    for profile in target_profiles {
        let request = HostRequest {
            protocol_version: EXECUTABLE_PLUGIN_PROTOCOL_VERSION,
            request_id: config.id.clone(),
            plugin_id: config.id.clone(),
            plugin_version: config.version.clone(),
            workspace_root: ".".to_owned(),
            target_profile: profile.clone(),
            manifest: Some(manifest.clone()),
            config_files: config_files.clone(),
            capabilities: capabilities.clone(),
        };
        if let Err(error) = validate_host_request(&request) {
            contributions
                .diagnostics
                .push(crate::plugins::PluginDiagnostic {
                    path: None,
                    code: "plugin_host_invalid_request".to_owned(),
                    severity: PluginDiagnosticSeverity::Error,
                    message: error.to_string(),
                    blocks_reachability: true,
                });
            break;
        }
        let response = match run_plugin_host(
            workspace_root,
            config,
            &request,
            limits.max_protocol_message_bytes,
        ) {
            Ok(response) => response,
            Err(message) => {
                contributions
                    .diagnostics
                    .push(crate::plugins::PluginDiagnostic {
                        path: None,
                        code: "plugin_host_failure".to_owned(),
                        severity: PluginDiagnosticSeverity::Error,
                        message,
                        blocks_reachability: true,
                    });
                break;
            }
        };
        if let Err(error) = validate_host_response(workspace_root, &request, &response) {
            contributions
                .diagnostics
                .push(crate::plugins::PluginDiagnostic {
                    path: None,
                    code: "plugin_host_invalid_response".to_owned(),
                    severity: PluginDiagnosticSeverity::Error,
                    message: error.to_string(),
                    blocks_reachability: true,
                });
            break;
        }
        merge_plugin_contributions(&mut contributions, response.contributions);
    }
    contributions.canonicalize();
    let mut declared_capabilities = contributions.used_capabilities();
    if !declared_capabilities.contains(&PluginCapability::Diagnostics) {
        declared_capabilities.push(PluginCapability::Diagnostics);
        declared_capabilities.sort();
    }
    let mut plugin = DeclarativePlugin {
        schema: None,
        api_version: DECLARATIVE_PLUGIN_API_VERSION.to_owned(),
        id: config.id.clone(),
        version: config.version.clone(),
        display_name: config.id.clone(),
        capabilities: declared_capabilities,
        detection: DetectionRules::default(),
        contributions,
        unsupported_cases: Vec::new(),
    };
    plugin.canonicalize();
    plugin
        .validate()
        .map_err(|error| configured_plugin_error(configured_plugin, error))?;
    Ok(plugin)
}

fn configured_plugin_error(
    configured_plugin: &str,
    error: impl std::fmt::Display,
) -> ProjectScanError {
    ProjectScanError::ConfiguredPlugin {
        plugin: configured_plugin.to_owned(),
        message: error.to_string(),
    }
}

fn all_plugin_capabilities() -> Vec<PluginCapability> {
    vec![
        PluginCapability::Entries,
        PluginCapability::ProjectFiles,
        PluginCapability::ConfigFiles,
        PluginCapability::Exclusions,
        PluginCapability::FileEdges,
        PluginCapability::References,
        PluginCapability::ExportRoots,
        PluginCapability::MemberRoots,
        PluginCapability::GeneratedFiles,
        PluginCapability::DynamicImports,
        PluginCapability::TargetConditions,
        PluginCapability::FileTransforms,
        PluginCapability::Diagnostics,
    ]
}

fn executable_manifest_facts(package: &WorkspacePackage) -> HostManifestFacts {
    let mut packages = Vec::new();
    for (kind, dependencies) in [
        (HostPackageKind::Dependency, &package.manifest.dependencies),
        (
            HostPackageKind::Development,
            &package.manifest.dev_dependencies,
        ),
        (HostPackageKind::Peer, &package.manifest.peer_dependencies),
        (
            HostPackageKind::Optional,
            &package.manifest.optional_dependencies,
        ),
    ] {
        packages.extend(dependencies.iter().map(|(name, version)| HostPackageFact {
            name: name.clone(),
            version: Some(version.clone()),
            kind,
        }));
    }
    packages.sort();
    packages.dedup();
    HostManifestFacts {
        path: if package.root.as_os_str().is_empty() {
            "package.json".to_owned()
        } else {
            format!("{}/package.json", display_workspace(&package.root))
        },
        name: package.manifest.name.clone(),
        private: Some(package.manifest.private),
        package_type: match package.manifest.r#type.as_deref() {
            Some("module") => Some(HostPackageType::Module),
            Some("commonjs") => Some(HostPackageType::CommonJs),
            _ => None,
        },
        packages,
    }
}

fn executable_config_facts(
    workspace_root: &Path,
    package: &WorkspacePackage,
    files: &[PathBuf],
    limits: AnalysisLimits,
) -> Vec<HostConfigFact> {
    let mut facts = files
        .iter()
        .filter(|path| path.starts_with(&package.root))
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.contains("config") || name.starts_with('.'))
        })
        .map(|path| executable_config_fact(workspace_root, path, limits))
        .collect::<Vec<_>>();
    facts.extend(
        package_configuration_files(&workspace_root.join(&package.root))
            .into_iter()
            .map(|path| package.root.join(path))
            .map(|path| executable_config_fact(workspace_root, &path, limits)),
    );
    facts.sort();
    facts.dedup();
    facts
}

fn executable_config_fact(
    workspace_root: &Path,
    path: &Path,
    limits: AnalysisLimits,
) -> HostConfigFact {
    let format = match path.extension().and_then(|extension| extension.to_str()) {
        Some("json" | "jsonc") => HostConfigFormat::Json,
        Some("js" | "cjs" | "mjs") => HostConfigFormat::JavaScript,
        Some("ts" | "cts" | "mts") => HostConfigFormat::TypeScript,
        _ => HostConfigFormat::Unknown,
    };
    let physical_path = workspace_root.join(path);
    let mut referenced_packages = BTreeSet::new();
    if let Ok(source) = fs::read_to_string(&physical_path) {
        match format {
            HostConfigFormat::JavaScript | HostConfigFormat::TypeScript => {
                let display_path = path.to_string_lossy().replace('\\', "/");
                let facts = parse_file_with_limits(&display_path, &physical_path, &source, limits);
                referenced_packages.extend(
                    facts
                        .imports
                        .iter()
                        .filter_map(|import| package_name(&import.specifier)),
                );
            }
            HostConfigFormat::Json => {
                if let Ok(value) = parse_jsonc_value(&source) {
                    collect_static_config_packages(&value, None, &mut referenced_packages);
                }
            }
            HostConfigFormat::Unknown => {}
        }
    }
    HostConfigFact {
        path: path.to_string_lossy().replace('\\', "/"),
        format,
        referenced_packages: referenced_packages.into_iter().collect(),
    }
}

fn collect_static_config_packages(
    value: &Value,
    property: Option<&str>,
    packages: &mut BTreeSet<String>,
) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                collect_static_config_packages(value, Some(key), packages);
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_static_config_packages(value, property, packages);
            }
        }
        Value::String(reference) if property.is_some_and(config_property_references_package) => {
            if let Some(package) = package_name(reference) {
                packages.insert(package);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn config_property_references_package(property: &str) -> bool {
    let property = property.to_ascii_lowercase();
    [
        "extends",
        "environment",
        "importsource",
        "parser",
        "plugin",
        "preset",
        "resolver",
        "runner",
        "setup",
        "transform",
        "types",
    ]
    .iter()
    .any(|fragment| property.contains(fragment))
}

fn run_plugin_host(
    workspace_root: &Path,
    config: &ExecutablePluginConfig,
    request: &HostRequest,
    request_limit: usize,
) -> Result<HostResponse, String> {
    let mut encoded = serde_json::to_vec(request)
        .map_err(|error| format!("could not encode plugin request: {error}"))?;
    if encoded.len() > request_limit {
        return Err(format!(
            "plugin request exceeded the configured {request_limit}-byte protocol limit"
        ));
    }
    encoded.push(b'\n');

    let executable = workspace_root.join(&config.executable);
    let mut child = Command::new(executable)
        .args(&config.arguments)
        .current_dir(workspace_root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("could not spawn plugin host: {error}"))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "plugin host stdin was unavailable".to_owned())?;
    stdin
        .write_all(&encoded)
        .map_err(|error| format!("could not write plugin request: {error}"))?;
    drop(stdin);

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "plugin host stdout was unavailable".to_owned())?;
    let response_limit = config.max_response_bytes;
    let reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(response_limit.saturating_add(1))
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let deadline = Instant::now() + Duration::from_millis(config.timeout_milliseconds);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return Err(format!(
                    "plugin host exceeded {}ms timeout",
                    config.timeout_milliseconds
                ));
            }
            Err(error) => return Err(format!("could not wait for plugin host: {error}")),
        }
    };
    let bytes = reader
        .join()
        .map_err(|_| "plugin response reader panicked".to_owned())?
        .map_err(|error| format!("could not read plugin response: {error}"))?;
    if !status.success() {
        return Err(format!("plugin host exited with status {status}"));
    }
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > config.max_response_bytes {
        return Err(format!(
            "plugin response exceeded {} bytes",
            config.max_response_bytes
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("plugin host returned invalid JSON: {error}"))
}

fn merge_plugin_contributions(
    aggregate: &mut PluginContributions,
    mut additional: PluginContributions,
) {
    aggregate
        .entry_patterns
        .append(&mut additional.entry_patterns);
    aggregate
        .project_file_patterns
        .append(&mut additional.project_file_patterns);
    aggregate
        .config_file_patterns
        .append(&mut additional.config_file_patterns);
    aggregate
        .exclusion_patterns
        .append(&mut additional.exclusion_patterns);
    aggregate
        .generated_file_patterns
        .append(&mut additional.generated_file_patterns);
    aggregate.file_edges.append(&mut additional.file_edges);
    aggregate.references.append(&mut additional.references);
    aggregate.export_roots.append(&mut additional.export_roots);
    aggregate.member_roots.append(&mut additional.member_roots);
    aggregate
        .dynamic_imports
        .append(&mut additional.dynamic_imports);
    aggregate
        .target_conditions
        .append(&mut additional.target_conditions);
    aggregate
        .file_transforms
        .append(&mut additional.file_transforms);
    aggregate.diagnostics.append(&mut additional.diagnostics);
}

fn append_plugin_diagnostics(
    diagnostics: &mut Vec<AnalysisDiagnostic>,
    workspace: &str,
    plugins: &[DetectedBuiltinPlugin],
) {
    for detected in plugins {
        for diagnostic in &detected.plugin.contributions.diagnostics {
            let path = diagnostic.path.as_deref().map_or_else(
                || workspace_manifest_path(workspace),
                |path| workspace_path(workspace, path),
            );
            diagnostics.push(AnalysisDiagnostic {
                code: diagnostic.code.clone(),
                path,
                severity: match diagnostic.severity {
                    PluginDiagnosticSeverity::Warning => DiagnosticSeverity::Warning,
                    PluginDiagnosticSeverity::Error => DiagnosticSeverity::Error,
                },
                span: None,
                message: format!("{}: {}", detected.plugin.display_name, diagnostic.message),
                blocks_reachability: diagnostic.blocks_reachability,
            });
        }

        let has_intrinsic_coverage_gap = matches!(
            detected.plugin.id.as_str(),
            "astro" | "next" | "nuxt" | "storybook" | "sveltekit" | "vite"
        );
        let unsupported_case_is_present = detected.evidence.is_empty()
            || has_intrinsic_coverage_gap
            || detected
                .evidence
                .iter()
                .any(|item| item.kind == DetectionEvidenceKind::ConfigFile);
        if unsupported_case_is_present {
            for unsupported in &detected.plugin.unsupported_cases {
                diagnostics.push(AnalysisDiagnostic {
                    code: unsupported.code.clone(),
                    path: workspace_manifest_path(workspace),
                    severity: DiagnosticSeverity::Warning,
                    span: None,
                    message: format!("{}: {}", detected.plugin.display_name, unsupported.summary),
                    blocks_reachability: unsupported.blocks_reachability,
                });
            }
        }
    }
}

fn workspace_manifest_path(workspace: &str) -> String {
    workspace_path(workspace, "package.json")
}

fn workspace_path(workspace: &str, relative: &str) -> String {
    if workspace == "." {
        relative.to_owned()
    } else {
        format!("{workspace}/{relative}")
    }
}

// Dependency evidence collection and result projection share one ordered policy pass.
#[allow(clippy::too_many_lines)]
fn append_dependency_results(
    workspace: &WorkspaceDiscovery,
    contexts: &[PackageContext<'_>],
    project_configurations: &[ProjectConfiguration],
    target_profiles: &[String],
    report: &mut ScanReport,
) {
    let manifests = contexts
        .iter()
        .map(|context| DependencyManifest {
            workspace: context.workspace_name.clone(),
            dependencies: context.package.manifest.dependencies.clone(),
            dev_dependencies: context.package.manifest.dev_dependencies.clone(),
            peer_dependencies: context.package.manifest.peer_dependencies.clone(),
            optional_dependencies: context.package.manifest.optional_dependencies.clone(),
            bundled_dependencies: context.package.manifest.bundled_dependencies.clone(),
        })
        .collect::<Vec<_>>();
    let mut evidence = source_dependency_evidence(workspace, contexts, report);
    let mut blockers = Vec::new();
    let mut binary_owners = BTreeMap::new();

    for context in contexts {
        for reference in &context.scripts.references {
            let (kind, scope) = match reference.kind {
                ScriptReferenceKind::Binary => (
                    DependencyEvidenceKind::Binary,
                    DependencyEvidenceScope::Development,
                ),
                ScriptReferenceKind::Package => (
                    DependencyEvidenceKind::Script,
                    DependencyEvidenceScope::Development,
                ),
                ScriptReferenceKind::File => continue,
            };
            evidence.push(DependencyEvidence {
                workspace: context.workspace_name.clone(),
                reference: reference.value.clone(),
                kind,
                scope,
                source: format!("package.json scripts.{}", reference.script),
                reachable: true,
            });
        }
        if !context.scripts.unmodeled.is_empty() {
            blockers.push(DependencyBlocker {
                workspace: context.workspace_name.clone(),
                package: None,
                reason: "one or more reachable package-script spans were not modeled".to_owned(),
            });
        }
        for plugin in &context.plugins {
            for reference in &plugin.plugin.contributions.references {
                evidence.push(DependencyEvidence {
                    workspace: context.workspace_name.clone(),
                    reference: reference.name.clone(),
                    kind: match reference.kind {
                        ReferenceKind::Package => DependencyEvidenceKind::Config,
                        ReferenceKind::Binary => DependencyEvidenceKind::Binary,
                    },
                    scope: DependencyEvidenceScope::Development,
                    source: format!("{} plugin convention", plugin.plugin.id),
                    reachable: true,
                });
            }
        }
        collect_binary_owners(
            &workspace.workspace_root.join(&context.package.root),
            &context.package.manifest,
            &mut binary_owners,
        );
    }

    for configuration in project_configurations {
        let workspace_name = workspace.package_for_path(&configuration.path).map_or_else(
            || ".".to_owned(),
            |package| display_workspace(&package.root),
        );
        for dependency in &configuration.dependency_evidence {
            evidence.push(DependencyEvidence {
                workspace: workspace_name.clone(),
                reference: dependency.specifier.clone(),
                kind: DependencyEvidenceKind::Config,
                scope: DependencyEvidenceScope::Development,
                source: configuration.path.to_string_lossy().replace('\\', "/"),
                reachable: true,
            });
        }
    }
    for diagnostic in &report.diagnostics {
        if diagnostic.blocks_reachability {
            let workspace_name = workspace
                .package_for_path(Path::new(&diagnostic.path))
                .map_or_else(
                    || ".".to_owned(),
                    |package| display_workspace(&package.root),
                );
            blockers.push(DependencyBlocker {
                workspace: workspace_name,
                package: None,
                reason: format!("{}: {}", diagnostic.code, diagnostic.message),
            });
        }
    }

    let analysis = analyze_dependencies(DependencyAnalysisInput {
        root_workspace: ".",
        manifests: &manifests,
        evidence: &evidence,
        binary_owners: &binary_owners,
        blockers: &blockers,
    });
    let dependency_fixes_supported = matches!(
        workspace.package_manager.selected.as_ref(),
        Some(
            crate::discovery::workspace::PackageManager::Npm
                | crate::discovery::workspace::PackageManager::Pnpm
                | crate::discovery::workspace::PackageManager::Yarn
                | crate::discovery::workspace::PackageManager::Bun
        )
    );
    for outcome in analysis.outcomes {
        match outcome.kind {
            DependencyOutcomeKind::Retained => {
                report.retentions.push(RetentionReport {
                    item: outcome.package.clone(),
                    item_type: "dependency",
                    workspace: outcome.workspace,
                    target_profiles: target_profiles.to_vec(),
                    summary: format!("{} is retained by reachable evidence", outcome.package),
                    evidence: outcome
                        .evidence
                        .into_iter()
                        .map(|evidence| evidence.source)
                        .collect(),
                });
            }
            DependencyOutcomeKind::Unused
            | DependencyOutcomeKind::UnreferencedPeer
            | DependencyOutcomeKind::UnreferencedOptional => {
                report
                    .findings
                    .push(dependency_finding(DependencyFindingInput {
                        issue_id: "ORP2001",
                        issue_type: "unusedDependency",
                        workspace: &outcome.workspace,
                        dependency: &outcome.package,
                        summary: dependency_summary(outcome.kind, &outcome.package),
                        confidence: outcome.confidence,
                        categories: &outcome.categories,
                        package_manager_supported: dependency_fixes_supported,
                        target_profiles,
                    }));
            }
            DependencyOutcomeKind::Unlisted | DependencyOutcomeKind::Misplaced => {
                let issue_type = if outcome.kind == DependencyOutcomeKind::Misplaced {
                    "misplacedDependency"
                } else {
                    "unlistedDependency"
                };
                let summary = if let Some(owner) = outcome.declared_workspace {
                    format!(
                        "{} is used by {} but declared in {}",
                        outcome.package, outcome.workspace, owner
                    )
                } else {
                    format!(
                        "{} is used by {} without a direct declaration",
                        outcome.package, outcome.workspace
                    )
                };
                report
                    .findings
                    .push(dependency_finding(DependencyFindingInput {
                        issue_id: "ORP2002",
                        issue_type,
                        workspace: &outcome.workspace,
                        dependency: &outcome.package,
                        summary,
                        confidence: outcome.confidence,
                        categories: &outcome.categories,
                        package_manager_supported: dependency_fixes_supported,
                        target_profiles,
                    }));
            }
            DependencyOutcomeKind::Undetermined => {
                report.retentions.push(RetentionReport {
                    item: outcome.package.clone(),
                    item_type: "dependency",
                    workspace: outcome.workspace,
                    target_profiles: target_profiles.to_vec(),
                    summary: format!(
                        "{} is retained because dependency analysis is incomplete",
                        outcome.package
                    ),
                    evidence: outcome.blockers,
                });
            }
        }
    }
    report.retentions.sort_by(|left, right| {
        (&left.workspace, &left.item_type, &left.item).cmp(&(
            &right.workspace,
            &right.item_type,
            &right.item,
        ))
    });
}

fn assign_project_context(
    report: &mut ScanReport,
    workspace: &WorkspaceDiscovery,
    profiles: &[String],
) {
    for finding in &mut report.findings {
        if let Some(path) = finding.paths.first() {
            finding.workspace = workspace.package_for_path(Path::new(path)).map_or_else(
                || ".".to_owned(),
                |package| display_workspace(&package.root),
            );
        }
        if finding.target_profiles.len() == 1 && finding.target_profiles[0] == "default" {
            finding.target_profiles = profiles.to_vec();
        }
    }
    for retention in &mut report.retentions {
        if retention.target_profiles.len() == 1 && retention.target_profiles[0] == "default" {
            retention.target_profiles = profiles.to_vec();
        }
    }
}

fn apply_file_fix_eligibility(
    contexts: &[PackageContext<'_>],
    profiles: &[String],
    report: &mut ScanReport,
) {
    let selected_profiles = profiles.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let file_statuses = report
        .files
        .iter()
        .map(|file| (file.path.as_str(), file.status))
        .collect::<BTreeMap<_, _>>();
    for finding in &mut report.findings {
        if finding.issue_type != "unusedFiles" || finding.confidence != Confidence::High {
            continue;
        }
        let closed_world = contexts
            .iter()
            .find(|context| context.workspace_name == finding.workspace)
            .is_some_and(|context| {
                context.effective.world.unwrap_or(WorldMode::Closed) == WorldMode::Closed
            });
        let finding_profiles = finding
            .target_profiles
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let unused_in_every_profile = finding_profiles == selected_profiles;
        let unreachable_in_merged_graph = finding
            .paths
            .iter()
            .all(|path| file_statuses.get(path.as_str()).copied() == Some(FileStatus::Unreachable));
        finding.fix_eligibility =
            if closed_world && unused_in_every_profile && unreachable_in_merged_graph {
                FixEligibility::Eligible
            } else {
                FixEligibility::PreviewOnly
            };
    }
}

fn append_workspace_results(
    workspace: &WorkspaceDiscovery,
    contexts: &[PackageContext<'_>],
    target_profiles: &[String],
    report: &mut ScanReport,
) {
    for context in contexts {
        if context.package.root.as_os_str().is_empty() {
            continue;
        }
        let package_label = context
            .package
            .manifest
            .name
            .clone()
            .unwrap_or_else(|| context.workspace_name.clone());
        let reachable_file = report.files.iter().any(|file| {
            file.status == FileStatus::Reachable
                && workspace
                    .package_for_path(Path::new(&file.path))
                    .is_some_and(|owner| owner.root == context.package.root)
        });
        let imported_by_workspace = context
            .package
            .manifest
            .name
            .as_deref()
            .is_some_and(|name| {
                report.files.iter().any(|file| {
                    workspace
                        .package_for_path(Path::new(&file.path))
                        .is_some_and(|owner| owner.root != context.package.root)
                        && file
                            .imports
                            .iter()
                            .any(|import| package_name(&import.specifier).as_deref() == Some(name))
                })
            });
        let referenced_by_script = contexts.iter().any(|candidate| {
            candidate.scripts.references.iter().any(|reference| {
                reference.value == package_label
                    || Path::new(&reference.value) == context.package.root
            })
        });
        let public_contract = !context.package.manifest.private;
        let blocking_diagnostic = report.diagnostics.iter().any(|diagnostic| {
            diagnostic.blocks_reachability
                && (diagnostic.path == "package.json"
                    || workspace
                        .package_for_path(Path::new(&diagnostic.path))
                        .is_some_and(|owner| owner.root == context.package.root))
        });
        let evidence = if public_contract {
            Some("The package is publishable and therefore open world".to_owned())
        } else if reachable_file {
            Some("At least one package file is reachable from a configured root".to_owned())
        } else if imported_by_workspace {
            Some("Another workspace imports the package by its declared name".to_owned())
        } else if referenced_by_script {
            Some("A reachable package script references the workspace".to_owned())
        } else if blocking_diagnostic {
            Some("Coverage is incomplete for this workspace".to_owned())
        } else {
            None
        };

        if let Some(evidence) = evidence {
            report.retentions.push(RetentionReport {
                item: package_label,
                item_type: "workspace",
                workspace: context.workspace_name.clone(),
                target_profiles: target_profiles.to_vec(),
                summary: "Workspace retained by live or conservative evidence".to_owned(),
                evidence: vec![evidence],
            });
            continue;
        }

        report.findings.push(Finding {
            issue_id: "ORP3001",
            issue_type: "unusedWorkspace",
            workspace: context.workspace_name.clone(),
            target_profiles: target_profiles.to_vec(),
            paths: vec![format!("{}/package.json", context.workspace_name)],
            span: None,
            symbol: None,
            dependency: None,
            confidence: Confidence::High,
            summary: format!("workspace {package_label} has no live root or consumer"),
            evidence: vec![
                "No reachable file, package-name import, package script, or public contract retains this private workspace"
                    .to_owned(),
            ],
            blockers: Vec::new(),
            suggested_actions: vec![
                "Review workspace consumers and configuration before removing the package"
                    .to_owned(),
            ],
            fix_eligibility: FixEligibility::NotAvailable,
        });
    }
}

fn suppress_blocked_findings(workspace: &WorkspaceDiscovery, report: &mut ScanReport) {
    let blocking_workspaces = report
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.blocks_reachability)
        .map(|diagnostic| {
            workspace
                .package_for_path(Path::new(&diagnostic.path))
                .map_or_else(
                    || ".".to_owned(),
                    |package| display_workspace(&package.root),
                )
        })
        .collect::<BTreeSet<_>>();
    if blocking_workspaces.is_empty() {
        return;
    }

    let root_is_blocked = blocking_workspaces.contains(".");
    for file in &mut report.files {
        let file_workspace = workspace
            .package_for_path(Path::new(&file.path))
            .map_or_else(
                || ".".to_owned(),
                |package| display_workspace(&package.root),
            );
        if file.status == FileStatus::Unreachable
            && (root_is_blocked || blocking_workspaces.contains(&file_workspace))
        {
            file.status = FileStatus::Incomplete;
            for target_status in file.target_statuses.values_mut() {
                if *target_status == FileStatus::Unreachable {
                    *target_status = FileStatus::Incomplete;
                }
            }
        }
    }
    report.summary.reachable_files = report
        .files
        .iter()
        .filter(|file| file.status == FileStatus::Reachable)
        .count();
    report.summary.unreachable_files = report
        .files
        .iter()
        .filter(|file| file.status == FileStatus::Unreachable)
        .count();
    report.summary.incomplete_files = report
        .files
        .iter()
        .filter(|file| file.status == FileStatus::Incomplete)
        .count();
    let mut retained = Vec::new();
    report.findings.retain(|finding| {
        let blocked = root_is_blocked || blocking_workspaces.contains(&finding.workspace);
        if blocked {
            retained.extend(retentions_for_finding(
                finding,
                "Potential issue retained because coverage is incomplete",
                &["A blocking diagnostic could provide an unmodeled path to this item".to_owned()],
            ));
        }
        !blocked
    });
    report.retentions.extend(retained);
}

fn apply_retain_rules(contexts: &[PackageContext<'_>], report: &mut ScanReport) {
    let mut retained = Vec::new();
    let mut remaining = Vec::new();
    for mut finding in report.findings.drain(..) {
        let Some(context) = contexts
            .iter()
            .find(|context| context.workspace_name == finding.workspace)
        else {
            remaining.push(finding);
            continue;
        };
        let issue = configuration_issue_name(finding.issue_type);
        let configured = context.effective.retain.iter().flatten().find(|rule| {
            (rule.issues.is_empty() || rule.issues.contains(issue))
                && finding_paths_match_rule(&finding, context, &rule.pattern)
        });
        if let Some(rule) = configured {
            retained.extend(retentions_for_finding(
                &finding,
                "Item retained by an explicit static contract",
                &[format!("Configured retain rule: {}", rule.reason)],
            ));
            continue;
        }
        let original_profiles = std::mem::take(&mut finding.target_profiles);
        let mut live_profiles = Vec::new();
        for profile in original_profiles {
            if let Some(reason) = plugin_retention_reason(&finding, context, &profile) {
                finding.target_profiles = vec![profile];
                retained.extend(retentions_for_finding(
                    &finding,
                    "Item retained by an explicit static contract",
                    &[reason],
                ));
            } else {
                live_profiles.push(profile);
            }
        }
        finding.target_profiles = live_profiles;
        if !finding.target_profiles.is_empty() {
            remaining.push(finding);
        }
    }
    report.findings = remaining;
    report.retentions.extend(retained);
}

fn finding_paths_match_rule(
    finding: &Finding,
    context: &PackageContext<'_>,
    pattern: &str,
) -> bool {
    let root = &context.retain_base;
    finding.paths.iter().all(|path| {
        let path = Path::new(path);
        let relative = path.strip_prefix(root).unwrap_or(path);
        pattern_matches(Path::new("."), pattern, relative)
    })
}

fn plugin_retention_reason(
    finding: &Finding,
    context: &PackageContext<'_>,
    profile: &str,
) -> Option<String> {
    let path = finding.paths.first().map(Path::new)?;
    let relative = if context.workspace_name == "." {
        path
    } else {
        path.strip_prefix(Path::new(&context.workspace_name))
            .unwrap_or(path)
    };
    for detected in context
        .plugins_by_profile
        .get(profile)
        .into_iter()
        .flatten()
    {
        let contributions = &detected.plugin.contributions;
        if let Some(pattern) = contributions
            .generated_file_patterns
            .iter()
            .find(|pattern| pattern_matches(Path::new("."), &pattern.pattern, relative))
        {
            return Some(format!(
                "{} generated-file contract: {}",
                detected.plugin.display_name, pattern.reason
            ));
        }
        if finding.issue_type == "unusedExport"
            && let Some(root) = contributions.export_roots.iter().find(|root| {
                pattern_matches(Path::new("."), &root.module_pattern, relative)
                    && finding.symbol.as_deref() == Some(root.export_name.as_str())
            })
        {
            return Some(format!(
                "{} export contract: {}",
                detected.plugin.display_name, root.reason
            ));
        }
        if finding.issue_type == "unusedMember"
            && let Some(root) = contributions.member_roots.iter().find(|root| {
                pattern_matches(Path::new("."), &root.module_pattern, relative)
                    && finding.symbol.as_deref().is_some_and(|symbol| {
                        symbol == format!("{}.{}", root.export_name, root.member_name)
                            || symbol.ends_with(&format!(".{}", root.member_name))
                    })
            })
        {
            return Some(format!(
                "{} member contract: {}",
                detected.plugin.display_name, root.reason
            ));
        }
    }
    None
}

fn configuration_issue_name(issue_type: &str) -> &str {
    match issue_type {
        "unusedFiles" => "files",
        "unusedExport" => "exports",
        "unusedDeclaration" => "declarations",
        "unusedMember" => "members",
        "unusedDependency" | "unlistedDependency" | "misplacedDependency" => "dependencies",
        "unusedWorkspace" => "workspaces",
        other => other,
    }
}

fn finding_item(finding: &Finding) -> String {
    finding
        .symbol
        .clone()
        .or_else(|| finding.dependency.clone())
        .unwrap_or_else(|| finding.paths.join(", "))
}

fn retentions_for_finding(
    finding: &Finding,
    summary: &str,
    evidence: &[String],
) -> Vec<RetentionReport> {
    let items = if finding.issue_type == "unusedFiles" {
        finding.paths.clone()
    } else {
        vec![finding_item(finding)]
    };
    items
        .into_iter()
        .map(|item| RetentionReport {
            item,
            item_type: retention_item_type(finding.issue_type),
            workspace: finding.workspace.clone(),
            target_profiles: finding.target_profiles.clone(),
            summary: summary.to_owned(),
            evidence: evidence.to_vec(),
        })
        .collect()
}

fn retention_item_type(issue_type: &str) -> &'static str {
    match issue_type {
        "unusedFiles" => "file",
        "unusedExport" => "export",
        "unusedDeclaration" => "declaration",
        "unusedMember" => "member",
        "unusedDependency" | "unlistedDependency" | "misplacedDependency" => "dependency",
        "unusedWorkspace" => "workspace",
        _ => "item",
    }
}

fn apply_confidence_thresholds(
    contexts: &[PackageContext<'_>],
    _workspace: &WorkspaceDiscovery,
    report: &mut ScanReport,
) {
    report.findings.retain(|finding| {
        let threshold = contexts
            .iter()
            .find(|context| context.workspace_name == finding.workspace)
            .and_then(|context| context.effective.confidence.as_ref())
            .and_then(|confidence| confidence.report)
            .unwrap_or(ConfidenceLevel::Medium);
        confidence_rank(finding.confidence) >= configuration_confidence_rank(threshold)
    });
}

fn failure_thresholds(contexts: &[PackageContext<'_>]) -> BTreeMap<String, Confidence> {
    contexts
        .iter()
        .map(|context| {
            let configured = context
                .effective
                .confidence
                .as_ref()
                .and_then(|confidence| confidence.fail)
                .unwrap_or(ConfidenceLevel::High);
            (
                context.workspace_name.clone(),
                configuration_confidence(configured),
            )
        })
        .collect()
}

fn configuration_confidence(confidence: ConfidenceLevel) -> Confidence {
    match confidence {
        ConfidenceLevel::Low => Confidence::Low,
        ConfidenceLevel::Medium => Confidence::Medium,
        ConfidenceLevel::High => Confidence::High,
    }
}

fn configuration_confidence_rank(confidence: ConfidenceLevel) -> u8 {
    confidence_rank(configuration_confidence(confidence))
}

fn confidence_rank(confidence: Confidence) -> u8 {
    match confidence {
        Confidence::Incomplete => 0,
        Confidence::Low => 1,
        Confidence::Medium => 2,
        Confidence::High => 3,
    }
}

fn source_dependency_evidence(
    workspace: &WorkspaceDiscovery,
    _contexts: &[PackageContext<'_>],
    report: &ScanReport,
) -> Vec<DependencyEvidence> {
    let mut evidence = Vec::new();
    for file in &report.files {
        let reachable = file.status == FileStatus::Reachable;
        let workspace_name = workspace
            .package_for_path(Path::new(&file.path))
            .map_or_else(
                || ".".to_owned(),
                |package| display_workspace(&package.root),
            );
        for import in &file.imports {
            let Some(package) = package_name(&import.specifier) else {
                continue;
            };
            // An import the resolver mapped to a project file is an internal
            // module edge, such as a tsconfig path alias, not consumption of
            // an npm package. An external status that still records a project
            // target resolved into a policy-excluded project path and is the
            // same kind of internal edge.
            if import.status == ResolutionStatus::Resolved
                || (import.status == ResolutionStatus::External && import.target.is_some())
            {
                continue;
            }
            evidence.push(DependencyEvidence {
                workspace: workspace_name.clone(),
                reference: package,
                kind: if import.type_only {
                    DependencyEvidenceKind::TypeOnlyImport
                } else {
                    DependencyEvidenceKind::SourceImport
                },
                scope: if import.type_only {
                    DependencyEvidenceScope::Contract
                } else {
                    DependencyEvidenceScope::Runtime
                },
                source: format!("{} imports {}", file.path, import.specifier),
                reachable,
            });
        }
    }
    evidence
}

fn collect_binary_owners(
    package_root: &Path,
    manifest: &PackageManifest,
    owners: &mut BTreeMap<String, String>,
) {
    for dependency in manifest
        .dependencies
        .keys()
        .chain(manifest.dev_dependencies.keys())
        .chain(manifest.optional_dependencies.keys())
    {
        let manifest_path = package_root
            .join("node_modules")
            .join(dependency)
            .join("package.json");
        let Ok(installed) = crate::discovery::manifest::read_package_manifest(&manifest_path)
        else {
            continue;
        };
        match installed.bin {
            BinaryDeclaration::Absent => {}
            BinaryDeclaration::Single(_) => {
                let binary = installed
                    .name
                    .as_deref()
                    .and_then(|name| name.rsplit('/').next())
                    .unwrap_or(dependency);
                owners.insert(binary.to_owned(), dependency.clone());
            }
            BinaryDeclaration::Named(binaries) => {
                for binary in binaries.into_keys() {
                    owners.insert(binary, dependency.clone());
                }
            }
        }
    }
}

fn dependency_finding(input: DependencyFindingInput<'_>) -> Finding {
    let DependencyFindingInput {
        issue_id,
        issue_type,
        workspace,
        dependency,
        summary,
        confidence,
        categories,
        package_manager_supported,
        target_profiles,
    } = input;
    let otherwise_eligible = confidence == DependencyConfidence::High && issue_id == "ORP2001";
    let mut blockers = Vec::new();
    if otherwise_eligible && !package_manager_supported {
        blockers.push(
            "No unambiguous supported npm, pnpm, Yarn, or Bun package manager was detected"
                .to_owned(),
        );
    }
    Finding {
        issue_id,
        issue_type,
        workspace: workspace.to_owned(),
        target_profiles: target_profiles.to_vec(),
        paths: vec![if workspace == "." {
            "package.json".to_owned()
        } else {
            format!("{workspace}/package.json")
        }],
        span: None,
        symbol: None,
        dependency: Some(dependency.to_owned()),
        confidence: match confidence {
            DependencyConfidence::High => Confidence::High,
            DependencyConfidence::Medium => Confidence::Medium,
            DependencyConfidence::NotApplicable => Confidence::Incomplete,
        },
        summary,
        evidence: vec![format!("Declared categories: {categories:?}")],
        blockers,
        suggested_actions: vec![
            "Review the owning workspace and run a fix preview before changing the manifest"
                .to_owned(),
        ],
        fix_eligibility: if otherwise_eligible && package_manager_supported {
            FixEligibility::Eligible
        } else if confidence == DependencyConfidence::High {
            FixEligibility::PreviewOnly
        } else {
            FixEligibility::Blocked
        },
    }
}

fn dependency_summary(kind: DependencyOutcomeKind, package: &str) -> String {
    match kind {
        DependencyOutcomeKind::UnreferencedPeer => {
            format!("peer dependency {package} has no reachable contract evidence")
        }
        DependencyOutcomeKind::UnreferencedOptional => {
            format!("optional dependency {package} has no reachable conditional evidence")
        }
        _ => format!("dependency {package} has no reachable evidence"),
    }
}

fn append_script_diagnostics(
    diagnostics: &mut Vec<AnalysisDiagnostic>,
    workspace: &str,
    analysis: &ScriptAnalysis,
) {
    for unmodeled in &analysis.unmodeled {
        diagnostics.push(AnalysisDiagnostic {
            code: "unmodeled_package_script".to_owned(),
            path: if workspace == "." {
                "package.json".to_owned()
            } else {
                format!("{workspace}/package.json")
            },
            severity: DiagnosticSeverity::Warning,
            span: None,
            message: format!(
                "scripts.{} contains an unmodeled {:?} span at bytes {}..{}",
                unmodeled.script, unmodeled.kind, unmodeled.span.start, unmodeled.span.end
            ),
            blocks_reachability: matches!(
                unmodeled.kind,
                UnmodeledScriptKind::ShellExpansion
                    | UnmodeledScriptKind::GlobExpansion
                    | UnmodeledScriptKind::UnsupportedShellSyntax
                    | UnmodeledScriptKind::UnsupportedShellWrapper
            ),
        });
    }
    for missing in &analysis.missing_scripts {
        diagnostics.push(AnalysisDiagnostic {
            code: "missing_package_script".to_owned(),
            path: if workspace == "." {
                "package.json".to_owned()
            } else {
                format!("{workspace}/package.json")
            },
            severity: DiagnosticSeverity::Warning,
            span: None,
            message: format!(
                "scripts.{} invokes missing script {}",
                missing.caller, missing.callee
            ),
            // A broken script chain names no source file, so it stays a
            // visible warning instead of suppressing every finding.
            blocks_reachability: false,
        });
    }
}

fn append_configuration_diagnostics(
    diagnostics: &mut Vec<AnalysisDiagnostic>,
    workspace: &WorkspaceDiscovery,
    contexts: &[PackageContext<'_>],
    pre_ignore_files: &[PathBuf],
    report: &ScanReport,
) -> Result<(), ConfigurationError> {
    for context in contexts {
        let paths = report
            .files
            .iter()
            .map(|file| PathBuf::from(&file.path))
            .filter_map(|path| {
                if context.package.root.as_os_str().is_empty() {
                    Some(path)
                } else {
                    path.strip_prefix(&context.retain_base)
                        .ok()
                        .map(Path::to_path_buf)
                }
            })
            .collect::<Vec<_>>();
        for stale in stale_retain_rules(
            &workspace.workspace_root.join(&context.retain_base),
            context.effective.retain.as_deref().unwrap_or(&[]),
            &paths,
        )? {
            diagnostics.push(AnalysisDiagnostic {
                code: "stale_retain_rule".to_owned(),
                path: "orphanode.jsonc".to_owned(),
                severity: DiagnosticSeverity::Warning,
                span: None,
                message: format!(
                    "retain rule `{}` matches no discovered file ({})",
                    stale.pattern, stale.reason
                ),
                blocks_reachability: false,
            });
        }
        let ignore_paths = pre_ignore_files
            .iter()
            .filter_map(|path| {
                if context.package.root.as_os_str().is_empty() {
                    Some(path.clone())
                } else {
                    path.strip_prefix(&context.ignore_base)
                        .ok()
                        .map(Path::to_path_buf)
                }
            })
            .collect::<Vec<_>>();
        for stale in stale_ignore_rules(
            &workspace.workspace_root.join(&context.ignore_base),
            context.effective.ignore.as_deref().unwrap_or(&[]),
            &ignore_paths,
        )? {
            diagnostics.push(AnalysisDiagnostic {
                code: "stale_ignore_rule".to_owned(),
                path: "orphanode.jsonc".to_owned(),
                severity: DiagnosticSeverity::Warning,
                span: None,
                message: format!(
                    "ignore rule `{}` matches no discovered file ({})",
                    stale.pattern, stale.reason
                ),
                blocks_reachability: false,
            });
        }
    }
    Ok(())
}

fn normalize_requested_entries(
    workspace: &WorkspaceDiscovery,
    request: &ProjectScanRequest,
    file_set: &BTreeSet<PathBuf>,
) -> Result<Vec<PathBuf>, ProjectScanError> {
    let base = request.workspace.as_ref().map_or_else(
        || workspace.workspace_root.clone(),
        |path| workspace.workspace_root.join(path),
    );
    let mut entries = BTreeSet::new();
    for entry in &request.entries {
        let candidate = if entry.is_absolute() {
            entry.clone()
        } else {
            base.join(entry)
        };
        let relative = candidate
            .strip_prefix(&workspace.workspace_root)
            .unwrap_or(&candidate)
            .to_path_buf();
        if file_set.contains(&relative) {
            entries.insert(relative);
        } else {
            return Err(ProjectScanError::Scan(ScanError::EntryNotSupplied(
                entry.clone(),
            )));
        }
    }
    Ok(entries.into_iter().collect())
}

fn cli_configuration(request: &ProjectScanRequest) -> ConfigurationOverride {
    ConfigurationOverride {
        mode: request.mode,
        world: request.closed_world.map(|closed| {
            if closed {
                WorldMode::Closed
            } else {
                WorldMode::Open
            }
        }),
        ..ConfigurationOverride::default()
    }
}

fn manifest_profiles(
    profiles: &[String],
    targets: &BTreeMap<String, TargetConfiguration>,
) -> Result<Vec<EntryTargetProfile>, ProjectScanError> {
    let conditions = resolve_conditions_for_targets(profiles, targets)?;
    let mut result = Vec::new();
    for profile in conditions {
        match profile.as_str() {
            "node" | "production" | "worker" => {
                push_profile(&mut result, EntryTargetProfile::NodeImport);
                push_profile(&mut result, EntryTargetProfile::NodeRequire);
            }
            "browser" | "bundler" => {
                push_profile(&mut result, EntryTargetProfile::Browser);
                push_profile(&mut result, EntryTargetProfile::Bundler);
            }
            "types" => {
                push_profile(&mut result, EntryTargetProfile::Types);
            }
            "cli" => {
                push_profile(&mut result, EntryTargetProfile::CommandLine);
            }
            _ => {}
        }
    }
    if result.is_empty() {
        push_profile(&mut result, EntryTargetProfile::NodeImport);
    }
    Ok(result)
}

fn resolve_target_conditions(
    profiles: &[String],
    contexts: &[PackageContext<'_>],
) -> Result<Vec<String>, ProjectScanError> {
    let mut conditions = BTreeSet::new();
    for profile in profiles {
        for context in contexts {
            conditions.extend(resolve_conditions_for_targets(
                std::slice::from_ref(profile),
                &context.effective.targets,
            )?);
            for plugin in context
                .plugins_by_profile
                .get(profile)
                .into_iter()
                .flatten()
            {
                conditions.extend(
                    plugin
                        .plugin
                        .contributions
                        .target_conditions
                        .iter()
                        .cloned(),
                );
            }
        }
    }
    conditions.insert("default".to_owned());
    Ok(conditions.into_iter().collect())
}

fn resolve_conditions_for_targets(
    profiles: &[String],
    targets: &BTreeMap<String, TargetConfiguration>,
) -> Result<BTreeSet<String>, ProjectScanError> {
    let mut conditions = BTreeSet::new();
    let mut resolved = BTreeSet::new();
    let mut visiting = BTreeSet::new();
    for profile in profiles {
        resolve_target_condition(
            profile,
            targets,
            &mut visiting,
            &mut resolved,
            &mut conditions,
        )?;
    }
    Ok(conditions)
}

fn resolve_target_condition(
    profile: &str,
    targets: &BTreeMap<String, TargetConfiguration>,
    visiting: &mut BTreeSet<String>,
    resolved: &mut BTreeSet<String>,
    conditions: &mut BTreeSet<String>,
) -> Result<(), ProjectScanError> {
    if resolved.contains(profile) {
        return Ok(());
    }
    if !visiting.insert(profile.to_owned()) {
        return Err(ProjectScanError::TargetProfileCycle(profile.to_owned()));
    }

    let built_in = matches!(
        profile,
        "node"
            | "production"
            | "worker"
            | "browser"
            | "bundler"
            | "types"
            | "cli"
            | "test"
            | "development"
    );
    if built_in {
        conditions.insert(profile.to_owned());
        match profile {
            "production" | "worker" | "cli" | "test" | "development" => {
                conditions.insert("node".to_owned());
            }
            "bundler" => {
                conditions.insert("browser".to_owned());
            }
            _ => {}
        }
    }
    if let Some(target) = targets.get(profile) {
        if let Some(parent) = target.extends.as_deref() {
            resolve_target_condition(parent, targets, visiting, resolved, conditions)?;
        }
        conditions.extend(target.conditions.iter().cloned());
    } else if !built_in {
        return Err(ProjectScanError::UnknownTargetProfile(profile.to_owned()));
    }

    visiting.remove(profile);
    resolved.insert(profile.to_owned());
    Ok(())
}

fn push_profile(profiles: &mut Vec<EntryTargetProfile>, profile: EntryTargetProfile) {
    if !profiles.contains(&profile) {
        profiles.push(profile);
    }
}

fn default_target_profiles() -> Vec<String> {
    ["node", "browser", "types", "cli", "test"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn has_yarn_pnp_manifest(discovered_paths: &[PathBuf]) -> bool {
    discovered_paths
        .iter()
        .any(|path| path == Path::new(".pnp.cjs"))
}

fn normalized_profiles(profiles: &[String]) -> Vec<String> {
    if profiles.is_empty() {
        return default_target_profiles();
    }
    profiles
        .iter()
        .map(|profile| profile.trim().to_ascii_lowercase())
        .filter(|profile| !profile.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn display_workspace(root: &Path) -> String {
    if root.as_os_str().is_empty() {
        ".".to_owned()
    } else {
        root.to_string_lossy().replace('\\', "/")
    }
}

fn normalize_relative(path: &Path) -> PathBuf {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value),
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => None,
        })
        .collect()
}

fn normalize_path(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn pattern_matches(root: &Path, pattern: &str, path: &Path) -> bool {
    let mut builder = GitignoreBuilder::new(root);
    if builder.add_line(None, pattern).is_err() {
        return false;
    }
    builder.build().is_ok_and(|matcher| {
        matcher
            .matched_path_or_any_parents(root.join(path), false)
            .is_ignore()
    })
}

fn collect_deep_member_evidence(
    request: DeepMemberEvidenceRequest<'_>,
    metrics: &mut ProjectScanMetrics,
) -> (DeepMemberRawEvidence, Option<AnalysisDiagnostic>) {
    let DeepMemberEvidenceRequest {
        workspace_root,
        files,
        project_configurations,
        effective_config_bytes,
        source_report,
        candidates,
        limits,
    } = request;
    let mut evidence = DeepMemberRawEvidence::new();
    let mut query_groups = BTreeMap::<PathBuf, Vec<(String, u32)>>::new();
    let mut unconfigured_files = BTreeSet::new();
    for (display_path, position) in candidates {
        evidence.insert(
            (display_path.clone(), *position),
            DeepRawResolution::Unavailable {
                capability_note: "deep TypeScript evidence could not be resolved".to_owned(),
            },
        );
        if !matches!(
            Path::new(display_path)
                .extension()
                .and_then(|extension| extension.to_str()),
            Some("ts" | "tsx" | "mts" | "cts")
        ) {
            continue;
        }
        let key = (display_path.clone(), *position);
        if let Some(configuration) =
            typescript_configuration_for_path(Path::new(display_path), project_configurations)
        {
            query_groups
                .entry(configuration.path.clone())
                .or_default()
                .push(key);
        } else {
            unconfigured_files.insert(display_path.clone());
        }
    }
    if query_groups.is_empty() && unconfigured_files.is_empty() {
        return (evidence, None);
    }
    let Some(worker_script) = typescript_worker_script() else {
        return (
            evidence,
            Some(deep_worker_diagnostic(
                "set ORPHANODE_TYPESCRIPT_WORKER to the shipped worker entrypoint",
            )),
        );
    };
    let source_digest = deep_source_digest(workspace_root, source_report, project_configurations);
    let allowed_source_paths = files
        .iter()
        .map(|path| path.to_string_lossy().replace('\\', "/"))
        .collect::<BTreeSet<_>>();
    let mut failures = Vec::new();
    if !unconfigured_files.is_empty() {
        failures.push(format!(
            "no owning tsconfig was found for {}",
            unconfigured_files
                .into_iter()
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    for (configuration, query_keys) in query_groups {
        let configuration_path = if configuration.is_absolute() {
            configuration.clone()
        } else {
            workspace_root.join(&configuration)
        };
        let typescript_resolution_root = configuration_path.parent().unwrap_or(workspace_root);
        if let Err(message) = collect_deep_configuration_evidence(
            DeepConfigurationEvidenceRequest {
                workspace_root,
                typescript_resolution_root,
                worker_script: &worker_script,
                configuration_path: &configuration_path,
                query_keys: &query_keys,
                effective_config_bytes,
                source_digest,
                allowed_source_paths: &allowed_source_paths,
                limits,
            },
            &mut evidence,
            metrics,
        ) {
            failures.push(format!("{}: {message}", configuration.to_string_lossy()));
        }
    }
    let diagnostic = (!failures.is_empty()).then(|| deep_worker_diagnostic(&failures.join("; ")));
    (evidence, diagnostic)
}

fn typescript_configuration_for_path<'a>(
    path: &Path,
    configurations: &'a [ProjectConfiguration],
) -> Option<&'a ProjectConfiguration> {
    configurations
        .iter()
        .filter(|configuration| configuration.kind == ProjectConfigurationKind::TypeScript)
        .filter(|configuration| path.starts_with(&configuration.root))
        .max_by_key(|configuration| configuration.root.components().count())
}

// Worker handshake, cache lookup, query, and persistence form one transaction.
#[allow(clippy::too_many_lines)]
fn collect_deep_configuration_evidence(
    request: DeepConfigurationEvidenceRequest<'_>,
    evidence: &mut DeepMemberRawEvidence,
    metrics: &mut ProjectScanMetrics,
) -> Result<(), String> {
    let DeepConfigurationEvidenceRequest {
        workspace_root,
        typescript_resolution_root,
        worker_script,
        configuration_path,
        query_keys,
        effective_config_bytes,
        source_digest,
        allowed_source_paths,
        limits,
    } = request;
    let mut worker = TypeScriptWorkerHost::spawn(
        TypeScriptWorkerOptions::new(worker_script).with_limits(limits),
    )
    .map_err(|error| format!("the worker process could not start: {error}"))?;
    let capabilities = match worker.capabilities() {
        Ok(reply) => reply.result,
        Err(error) => return Err(format!("the worker capability handshake failed: {error}")),
    };
    let supports_member_usage = capabilities
        .get("queryKinds")
        .and_then(Value::as_array)
        .is_some_and(|kinds| kinds.iter().any(|kind| kind == "memberUsage"));
    if !supports_member_usage {
        return Err("the worker does not implement the memberUsage capability".to_owned());
    }
    let initialization = match worker.initialize_from(
        workspace_root,
        typescript_resolution_root,
        configuration_path,
        true,
    ) {
        Ok(reply) if reply.result.get("status").and_then(Value::as_str) == Some("ready") => {
            reply.result
        }
        Ok(reply) => {
            let note = reply
                .result
                .get("capabilityNote")
                .and_then(Value::as_str)
                .unwrap_or("the TypeScript worker is unavailable");
            return Err(note.to_owned());
        }
        Err(error) => {
            return Err(format!("the worker initialization failed: {error}"));
        }
    };
    let typescript_identity = initialization
        .get("typescriptIdentity")
        .and_then(Value::as_str)
        .filter(|identity| !identity.is_empty() && identity.len() <= 256)
        .ok_or_else(|| {
            "the worker did not provide a bounded TypeScript compiler identity".to_owned()
        })?;
    let configuration_display = normalize_path(configuration_path, workspace_root);
    let cache_key = deep_cache_key(
        effective_config_bytes,
        typescript_identity,
        &configuration_display,
        source_digest,
    )?;
    let cache_load_started = Instant::now();
    let cached = load_cached_deep_evidence(
        workspace_root,
        &cache_key,
        &configuration_display,
        typescript_identity,
        query_keys,
        allowed_source_paths,
    );
    metrics.fact_loading.duration += cache_load_started.elapsed();
    metrics.fact_loading.count += query_keys.len();
    if let Some(cached) = cached {
        metrics.cache.hits += query_keys.len();
        evidence.extend(cached);
        return Ok(());
    }
    metrics.cache.misses += query_keys.len();

    for chunk in query_keys.chunks(128) {
        let queries = chunk
            .iter()
            .enumerate()
            .map(|(index, (path, position))| {
                json!({
                    "id": index,
                    "kind": "memberUsage",
                    "file": path,
                    "position": position,
                })
            })
            .collect::<Vec<_>>();
        let reply = match worker.query(queries) {
            Ok(reply) => reply,
            Err(error) => {
                return Err(format!("a deep query batch failed: {error}"));
            }
        };
        let Some(results) = reply.result.get("results").and_then(Value::as_array) else {
            return Err("the worker returned an invalid deep-query result".to_owned());
        };
        for result in results {
            let Some(index) = result
                .get("queryId")
                .and_then(Value::as_u64)
                .and_then(|index| usize::try_from(index).ok())
            else {
                continue;
            };
            let Some(key) = chunk.get(index) else {
                continue;
            };
            if result.get("status").and_then(Value::as_str) == Some("resolved") {
                let mut references = serde_json::from_value::<Vec<DeepSourceSpan>>(
                    result
                        .get("references")
                        .cloned()
                        .unwrap_or(Value::Array(Vec::new())),
                )
                .map_err(|error| format!("invalid deep reference facts: {error}"))?;
                let mut overrides = serde_json::from_value::<Vec<DeepOverrideRelationship>>(
                    result
                        .get("overrides")
                        .cloned()
                        .unwrap_or(Value::Array(Vec::new())),
                )
                .map_err(|error| format!("invalid deep override facts: {error}"))?;
                canonicalize_deep_facts(&mut references, &mut overrides, allowed_source_paths)?;
                evidence.insert(
                    key.clone(),
                    DeepRawResolution::Resolved {
                        references,
                        overrides,
                    },
                );
            } else if let Some(note) = result.get("capabilityNote").and_then(Value::as_str) {
                evidence.insert(
                    key.clone(),
                    DeepRawResolution::Unavailable {
                        capability_note: note.to_owned(),
                    },
                );
            }
        }
    }
    let cache_persist_started = Instant::now();
    if store_cached_deep_evidence(
        workspace_root,
        cache_key,
        &configuration_display,
        typescript_identity,
        query_keys,
        evidence,
    ) {
        metrics.cache.generation_writes += 1;
        metrics.cache_persistence.count += query_keys.len();
    }
    metrics.cache_persistence.duration += cache_persist_started.elapsed();
    Ok(())
}

fn deep_cache_key(
    effective_config_bytes: &[u8],
    typescript_identity: &str,
    configuration_display: &str,
    source_digest: Digest,
) -> Result<CacheKey, String> {
    Ok(CacheKey::new(
        ConfigDigest::of_bytes(effective_config_bytes),
        ProfileDigest::of_bytes(typescript_identity.as_bytes()),
        CanonicalFileIdentity::new(configuration_display.to_owned()).map_err(str::to_owned)?,
        ContentDigest(source_digest),
        Vec::new(),
    ))
}

fn deep_source_digest(
    workspace_root: &Path,
    source_report: &ScanReport,
    project_configurations: &[ProjectConfiguration],
) -> Digest {
    let mut input = Vec::new();
    for file in &source_report.files {
        input.extend_from_slice(file.path.as_bytes());
        input.push(0);
        input.extend_from_slice(file.content_digest.as_bytes());
        input.push(0xff);
    }
    for configuration in project_configurations {
        let display = configuration.path.to_string_lossy().replace('\\', "/");
        input.extend_from_slice(display.as_bytes());
        input.push(0);
        match fs::read(workspace_root.join(&configuration.path)) {
            Ok(bytes) => input.extend_from_slice(Digest::of_bytes(&bytes).to_hex().as_bytes()),
            Err(_) => input.extend_from_slice(b"unreadable"),
        }
        input.push(0xff);
    }
    Digest::of_bytes(&input)
}

fn canonicalize_deep_facts(
    references: &mut Vec<DeepSourceSpan>,
    overrides: &mut Vec<DeepOverrideRelationship>,
    allowed_source_paths: &BTreeSet<String>,
) -> Result<(), String> {
    references.retain(|reference| allowed_source_paths.contains(&reference.path));
    validate_deep_spans(references)?;
    references.sort();
    references.dedup();
    for relationship in overrides.iter_mut() {
        relationship
            .references
            .retain(|reference| allowed_source_paths.contains(&reference.path));
        validate_deep_spans(&relationship.references)?;
        validate_deep_spans(&relationship.symbol.declarations)?;
        if let Some(owner) = &relationship.owner {
            validate_deep_spans(&owner.declarations)?;
        }
        relationship.references.sort();
        relationship.references.dedup();
    }
    overrides.sort();
    overrides.dedup();
    Ok(())
}

fn validate_deep_spans(spans: &[DeepSourceSpan]) -> Result<(), String> {
    for span in spans {
        let path = Path::new(&span.path);
        if span.path.is_empty()
            || span.path.len() > 16 * 1024
            || path.is_absolute()
            || path
                .components()
                .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
            || span.start > span.end
        {
            return Err("the worker returned an unsafe path or span".to_owned());
        }
    }
    Ok(())
}

fn deep_cache_store(workspace_root: &Path) -> Option<PersistentCache> {
    PersistentCache::new(
        workspace_root.join(".orphanode").join("cache").join("deep"),
        CacheSchema::current(env!("CARGO_PKG_VERSION"), "typescript-worker-raw-v1"),
        CacheLimits::default(),
    )
    .ok()
}

fn load_cached_deep_evidence(
    workspace_root: &Path,
    key: &CacheKey,
    configuration_path: &str,
    typescript_identity: &str,
    query_keys: &[(String, u32)],
    allowed_source_paths: &BTreeSet<String>,
) -> Option<DeepMemberRawEvidence> {
    let store = deep_cache_store(workspace_root)?;
    let snapshot = store.load().ok()?;
    let payload = snapshot.get(key)?;
    let cached = serde_json::from_slice::<CachedDeepEvidence>(payload).ok()?;
    if cached.schema_version != 1
        || cached.config_path != configuration_path
        || cached.typescript_identity != typescript_identity
    {
        return None;
    }
    let requested = query_keys.iter().cloned().collect::<BTreeSet<_>>();
    let mut evidence = BTreeMap::new();
    for fact in cached.facts {
        let key = (fact.path, fact.position);
        if !requested.contains(&key) {
            continue;
        }
        let mut resolution = fact.resolution;
        if let DeepRawResolution::Resolved {
            references,
            overrides,
        } = &mut resolution
        {
            canonicalize_deep_facts(references, overrides, allowed_source_paths).ok()?;
        }
        if evidence.insert(key, resolution).is_some() {
            return None;
        }
    }
    (evidence.len() == requested.len()).then_some(evidence)
}

fn store_cached_deep_evidence(
    workspace_root: &Path,
    key: CacheKey,
    configuration_path: &str,
    typescript_identity: &str,
    query_keys: &[(String, u32)],
    evidence: &DeepMemberRawEvidence,
) -> bool {
    let Some(store) = deep_cache_store(workspace_root) else {
        return false;
    };
    let mut facts_by_key = query_keys
        .iter()
        .filter_map(|(path, position)| {
            evidence
                .get(&(path.clone(), *position))
                .cloned()
                .map(|resolution| CachedDeepFact {
                    path: path.clone(),
                    position: *position,
                    resolution,
                })
        })
        .map(|fact| ((fact.path.clone(), fact.position), fact))
        .collect::<BTreeMap<_, _>>();
    if facts_by_key.len() != query_keys.len() {
        return false;
    }
    let snapshot = store.load().ok();
    if let Some(existing) = snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.get(&key))
        .and_then(|payload| serde_json::from_slice::<CachedDeepEvidence>(payload).ok())
        .filter(|cached| {
            cached.schema_version == 1
                && cached.config_path == configuration_path
                && cached.typescript_identity == typescript_identity
        })
    {
        for fact in existing.facts {
            facts_by_key
                .entry((fact.path.clone(), fact.position))
                .or_insert(fact);
        }
    }
    let payload = CachedDeepEvidence {
        schema_version: 1,
        config_path: configuration_path.to_owned(),
        typescript_identity: typescript_identity.to_owned(),
        facts: facts_by_key.into_values().collect(),
    };
    let Ok(payload) = serde_json::to_vec(&payload) else {
        return false;
    };
    let mut entries = snapshot
        .into_iter()
        .flat_map(|snapshot| {
            snapshot
                .iter()
                .filter(|(existing, _)| *existing != &key)
                .map(|(key, payload)| CacheEntry::new(key.clone(), payload.to_vec()))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    entries.push(CacheEntry::new(key, payload));
    store.commit(entries).is_ok()
}

fn resolve_deep_member_evidence(
    raw_evidence: &DeepMemberRawEvidence,
    reachability_report: &ScanReport,
    workspace: &WorkspaceDiscovery,
    contexts: &[PackageContext<'_>],
) -> DeepMemberEvidence {
    let reachable = reachability_report
        .files
        .iter()
        .filter(|file| file.status == FileStatus::Reachable)
        .map(|file| file.path.as_str())
        .collect::<BTreeSet<_>>();
    raw_evidence
        .iter()
        .map(|(key, resolution)| {
            let resolution = resolve_deep_raw_resolution(resolution, &reachable, &|path| {
                path_has_open_world_contract(path, workspace, contexts)
            });
            (key.clone(), resolution)
        })
        .collect()
}

fn resolve_deep_raw_resolution(
    resolution: &DeepRawResolution,
    reachable: &BTreeSet<&str>,
    path_has_open_contract: &impl Fn(&Path) -> bool,
) -> DeepResolution {
    match resolution {
        DeepRawResolution::Unavailable { capability_note } => DeepResolution::Unavailable {
            capability_note: capability_note.clone(),
        },
        DeepRawResolution::Resolved {
            references,
            overrides,
        } => DeepResolution::Resolved {
            receiver_may_reference_member: references
                .iter()
                .any(|reference| reachable.contains(reference.path.as_str())),
            live_override_contract: overrides.iter().any(|relationship| {
                relationship.symbol.declarations.is_empty()
                    || relationship
                        .references
                        .iter()
                        .any(|reference| reachable.contains(reference.path.as_str()))
                    || (relationship.owner_exported
                        && relationship.owner.as_ref().is_some_and(|owner| {
                            owner.declarations.iter().any(|declaration| {
                                path_has_open_contract(Path::new(&declaration.path))
                            })
                        }))
            }),
        },
    }
}

fn deep_member_candidates(
    report: &ScanReport,
    member_modes: &BTreeMap<String, MemberAnalysisMode>,
) -> BTreeSet<(String, u32)> {
    let report_files = report
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect::<BTreeSet<_>>();
    report
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.code == "member_analysis_deferred")
        .filter(|diagnostic| report_files.contains(diagnostic.path.as_str()))
        .filter(|diagnostic| member_modes.get(&diagnostic.path) == Some(&MemberAnalysisMode::Deep))
        .filter_map(|diagnostic| {
            diagnostic
                .span
                .map(|span| (diagnostic.path.clone(), span.start))
        })
        .collect()
}

fn path_has_open_world_contract(
    path: &Path,
    workspace: &WorkspaceDiscovery,
    contexts: &[PackageContext<'_>],
) -> bool {
    context_for_path(workspace, contexts, path).is_some_and(|context| {
        context.effective.world.unwrap_or(WorldMode::Closed) == WorldMode::Open
    })
}

fn aggregate_scan_measurements(aggregate: &mut ProjectScanMetrics, measurements: ScanStageMetrics) {
    aggregate.fact_loading.duration += measurements.fact_loading.duration;
    aggregate.fact_loading.count += measurements.fact_loading.count;
    aggregate.module_resolution_graph.duration += measurements.module_resolution_graph.duration;
    aggregate.module_resolution_graph.count += measurements.module_resolution_graph.count;
    aggregate.reachability_rules_report.duration += measurements.reachability_rules_report.duration;
    aggregate.reachability_rules_report.count += measurements.reachability_rules_report.count;
    aggregate.cache_persistence.duration += measurements.cache_persist.duration;
    aggregate.cache_persistence.count += measurements.cache_persist.count;
}

fn typescript_worker_script() -> Option<PathBuf> {
    env::var_os("ORPHANODE_TYPESCRIPT_WORKER")
        .map(PathBuf::from)
        .filter(|path| path.is_file())
        .or_else(|| {
            let development_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../../packages/typescript-worker/src/worker.mjs");
            development_path.is_file().then_some(development_path)
        })
}

fn deep_worker_diagnostic(message: &str) -> AnalysisDiagnostic {
    AnalysisDiagnostic {
        code: "deep_worker_unavailable".to_owned(),
        path: "tsconfig.json".to_owned(),
        severity: DiagnosticSeverity::Warning,
        span: None,
        message: format!("Deep member analysis is conservative: {message}"),
        blocks_reachability: false,
    }
}

fn analysis_mode_name(mode: AnalysisMode) -> &'static str {
    match mode {
        AnalysisMode::Fast => "fast",
        AnalysisMode::Balanced => "balanced",
        AnalysisMode::Deep => "deep",
    }
}

fn member_analysis_mode(mode: AnalysisMode) -> MemberAnalysisMode {
    match mode {
        AnalysisMode::Fast => MemberAnalysisMode::Fast,
        AnalysisMode::Balanced => MemberAnalysisMode::Balanced,
        AnalysisMode::Deep => MemberAnalysisMode::Deep,
    }
}

fn enforce_project_diagnostic_limit(
    diagnostics: &mut Vec<AnalysisDiagnostic>,
    configured_limit: usize,
) {
    let limit = configured_limit.max(1);
    if diagnostics.len() <= limit {
        return;
    }
    diagnostics.sort_by(|left, right| {
        (&left.path, &left.code, &left.message).cmp(&(&right.path, &right.code, &right.message))
    });
    let omitted = diagnostics.len() - limit + 1;
    diagnostics.truncate(limit - 1);
    diagnostics.push(AnalysisDiagnostic {
        code: "diagnostic_limit_exceeded".to_owned(),
        path: "<project>".to_owned(),
        severity: DiagnosticSeverity::Error,
        span: None,
        message: format!(
            "Project analysis omitted {omitted} diagnostics after reaching the configured limit of {limit}"
        ),
        blocks_reachability: true,
    });
}

fn sort_diagnostics(diagnostics: &mut Vec<AnalysisDiagnostic>) {
    diagnostics.sort_by(|left, right| {
        (
            &left.path,
            left.span.map_or(u32::MAX, |span| span.start),
            &left.code,
            &left.message,
        )
            .cmp(&(
                &right.path,
                right.span.map_or(u32::MAX, |span| span.start),
                &right.code,
                &right.message,
            ))
    });
    diagnostics.dedup();
}

// Every profile rescans the same sources, and profile tagging rewrites the
// diagnostic message, so identical findings from different profiles differ only
// in their `[target ...]` prefix. Collapse them into one diagnostic whose
// prefix names every reporting profile.
fn merge_duplicate_diagnostics(diagnostics: &mut Vec<AnalysisDiagnostic>) {
    sort_diagnostics(diagnostics);
    let mut merged: Vec<AnalysisDiagnostic> = Vec::with_capacity(diagnostics.len());
    for diagnostic in diagnostics.drain(..) {
        match merged.last_mut() {
            Some(previous)
                if previous.code == diagnostic.code
                    && previous.path == diagnostic.path
                    && previous.span == diagnostic.span
                    && previous.severity == diagnostic.severity
                    && previous.blocks_reachability == diagnostic.blocks_reachability
                    && strip_target_prefix(&previous.message)
                        == strip_target_prefix(&diagnostic.message) =>
            {
                let profiles = union_target_profiles(&previous.message, &diagnostic.message);
                previous.message = format!(
                    "[target {profiles}] {}",
                    strip_target_prefix(&diagnostic.message)
                );
            }
            _ => merged.push(diagnostic),
        }
    }
    *diagnostics = merged;
}

fn strip_target_prefix(message: &str) -> &str {
    message
        .strip_prefix("[target ")
        .and_then(|rest| rest.split_once("] "))
        .map_or(message, |(_, stripped)| stripped)
}

fn union_target_profiles(left_message: &str, right_message: &str) -> String {
    [left_message, right_message]
        .iter()
        .filter_map(|message| {
            message
                .strip_prefix("[target ")
                .and_then(|rest| rest.split_once("] "))
                .map(|(profiles, _)| profiles)
        })
        .flat_map(|profiles| profiles.split(", "))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(", ")
}

// Test conventions follow common runner defaults: Jest, Vitest, Node's test
// runner, Playwright, and Storybook all use these file or directory names.
fn is_test_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    let file_name = normalized.rsplit('/').next().unwrap_or(&normalized);
    let extension = [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"]
        .iter()
        .find_map(|extension| file_name.strip_suffix(extension));
    let stem = extension.unwrap_or(file_name);
    let test_file_name = ["test", "spec"].contains(&stem)
        || [".test", ".spec", ".e2e-spec", ".stories"]
            .iter()
            .any(|marker| stem.ends_with(marker))
        || stem.ends_with("_test");
    let in_test_directory = normalized.split('/').any(|segment| {
        matches!(
            segment,
            "__tests__" | "__mocks__" | "test" | "tests" | "e2e"
        )
    });
    test_file_name || in_test_directory
}

fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|left, right| {
        (
            &left.workspace,
            left.paths.first(),
            left.span.map_or(u32::MAX, |span| span.start),
            left.issue_id,
            &left.symbol,
            &left.dependency,
        )
            .cmp(&(
                &right.workspace,
                right.paths.first(),
                right.span.map_or(u32::MAX, |span| span.start),
                right.issue_id,
                &right.symbol,
                &right.dependency,
            ))
    });
}

fn refresh_report_state(report: &mut ScanReport) {
    report.summary.diagnostics = report.diagnostics.len();
    report.status = if report
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.blocks_reachability)
    {
        AnalysisStatus::Incomplete
    } else {
        AnalysisStatus::Complete
    };
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        path::{Path, PathBuf},
    };

    use super::{
        AnalysisIssue, DeepOverrideRelationship, DeepRawResolution, DeepSourceSpan,
        DeepSymbolIdentity, append_file_transform_edges, collect_static_config_packages,
        deep_cache_key, has_yarn_pnp_manifest, is_test_path, map_entry_to_source,
        merge_duplicate_diagnostics, resolve_deep_raw_resolution, source_variants,
    };
    use crate::discovery::configuration::{ProjectConfiguration, ProjectConfigurationKind};
    use crate::{
        analysis::members::DeepResolution,
        cache::Digest,
        domain::facts::{AnalysisDiagnostic, DiagnosticSeverity, SourceSpan},
        plugins::FileTransformContribution,
    };

    #[test]
    fn test_paths_follow_common_runner_conventions() {
        for path in [
            "src/service.test.ts",
            "src/service.test.js",
            "src/service.spec.tsx",
            "apps/backend/test/app.e2e-spec.ts",
            "tests/helpers/setup.ts",
            "test/jest.setup.ts",
            "components/__tests__/button.tsx",
            "stories/Button.stories.ts",
            "e2e/login.ts",
        ] {
            assert!(is_test_path(path), "`{path}` should be a test path");
        }
        for path in [
            "src/service.ts",
            "src/contest.ts",
            "lib/latest.ts",
            "src/testing.ts",
            "src/specification.ts",
            "src/main.mts",
        ] {
            assert!(!is_test_path(path), "`{path}` should not be a test path");
        }
    }

    #[test]
    fn all_issue_selection_contains_every_public_rule_family() {
        let issues = AnalysisIssue::all();
        assert_eq!(issues.len(), 6);
        assert!(issues.contains(&AnalysisIssue::Members));
    }

    #[test]
    fn profile_merge_collapses_diagnostics_that_differ_only_by_target_prefix() {
        let make_diagnostic = |message: String| AnalysisDiagnostic {
            code: "outside_file_universe".to_owned(),
            path: "src/index.ts".to_owned(),
            severity: DiagnosticSeverity::Error,
            span: Some(SourceSpan { start: 8, end: 30 }),
            message,
            blocks_reachability: true,
        };
        let mut diagnostics = vec![
            make_diagnostic("[target node] `a` resolved nowhere".to_owned()),
            make_diagnostic("`b` is not analyzable".to_owned()),
            make_diagnostic("[target browser] `a` resolved nowhere".to_owned()),
            make_diagnostic("[target cli] `a` resolved nowhere".to_owned()),
        ];

        merge_duplicate_diagnostics(&mut diagnostics);

        assert_eq!(diagnostics.len(), 2);
        assert_eq!(
            diagnostics[0].message,
            "[target browser, cli, node] `a` resolved nowhere"
        );
        assert_eq!(diagnostics[1].message, "`b` is not analyzable");
    }

    #[test]
    fn emitted_javascript_entry_maps_back_to_typescript_source() {
        let files = [std::path::PathBuf::from("src/cli/index.ts")]
            .into_iter()
            .collect();
        let configurations = [ProjectConfiguration {
            path: "tsconfig.json".into(),
            root: Path::new("").into(),
            kind: ProjectConfigurationKind::TypeScript,
            extends: None,
            references: Vec::new(),
            files: Vec::new(),
            include: Vec::new(),
            exclude: Vec::new(),
            root_dir: Some("src".into()),
            out_dir: Some("dist".into()),
            dependency_evidence: Vec::new(),
        }];

        assert_eq!(
            map_entry_to_source(Path::new("dist/cli/index.js"), &configurations, &files),
            Some("src/cli/index.ts".into())
        );
    }

    #[test]
    fn extensionless_entries_expand_deterministically() {
        let variants = source_variants(Path::new("src/index"));
        assert!(variants.contains(&"src/index.ts".into()));
        assert!(variants.contains(&"src/index.js".into()));
    }

    #[test]
    fn yarn_pnp_requires_the_manifest_not_only_the_esm_loader() {
        assert!(!has_yarn_pnp_manifest(&[".pnp.loader.mjs".into()]));
        assert!(has_yarn_pnp_manifest(&[
            ".pnp.loader.mjs".into(),
            ".pnp.cjs".into(),
        ]));
    }

    #[test]
    fn file_transform_materializes_every_existing_declared_output() {
        let files: Vec<PathBuf> = vec![
            "src/view.vue".into(),
            "src/view.js".into(),
            "src/view.ts".into(),
        ];
        let package_files = files
            .iter()
            .map(|path| (path, path.as_path()))
            .collect::<Vec<_>>();
        let discovered_files = files
            .iter()
            .map(std::path::PathBuf::as_path)
            .collect::<Vec<_>>();
        let transform = FileTransformContribution {
            source_pattern: "src/*.vue".to_owned(),
            output_extensions: vec!["js".to_owned(), "ts".to_owned()],
            reason: "compiled component".to_owned(),
        };
        let mut edges = BTreeSet::new();
        let mut diagnostics = Vec::new();

        append_file_transform_edges(
            &mut edges,
            &mut diagnostics,
            Path::new("/workspace"),
            ".",
            "Vue",
            &transform,
            &package_files,
            &discovered_files,
        );

        assert_eq!(edges.len(), 2);
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn file_transform_blocks_when_a_matched_source_has_no_output() {
        let files: Vec<PathBuf> = vec!["src/view.vue".into()];
        let package_files = files
            .iter()
            .map(|path| (path, path.as_path()))
            .collect::<Vec<_>>();
        let discovered_files = files
            .iter()
            .map(std::path::PathBuf::as_path)
            .collect::<Vec<_>>();
        let transform = FileTransformContribution {
            source_pattern: "src/*.vue".to_owned(),
            output_extensions: vec!["js".to_owned()],
            reason: "compiled component".to_owned(),
        };
        let mut edges = BTreeSet::new();
        let mut diagnostics = Vec::new();

        append_file_transform_edges(
            &mut edges,
            &mut diagnostics,
            Path::new("/workspace"),
            ".",
            "Vue",
            &transform,
            &package_files,
            &discovered_files,
        );

        assert!(edges.is_empty());
        assert_eq!(diagnostics[0].code, "plugin_transform_output_missing");
        assert!(diagnostics[0].blocks_reachability);
    }

    #[test]
    fn deep_evidence_from_dead_files_and_dead_bases_does_not_retain() {
        let raw = DeepRawResolution::Resolved {
            references: vec![DeepSourceSpan {
                path: "src/dead-reference.ts".to_owned(),
                start: 4,
                end: 8,
            }],
            overrides: vec![DeepOverrideRelationship {
                symbol: DeepSymbolIdentity {
                    id: "base:member".to_owned(),
                    name: "member".to_owned(),
                    declarations: vec![DeepSourceSpan {
                        path: "src/dead-base.ts".to_owned(),
                        start: 10,
                        end: 16,
                    }],
                },
                owner: Some(DeepSymbolIdentity {
                    id: "base".to_owned(),
                    name: "Base".to_owned(),
                    declarations: vec![DeepSourceSpan {
                        path: "src/dead-base.ts".to_owned(),
                        start: 0,
                        end: 20,
                    }],
                }),
                owner_exported: true,
                references: vec![DeepSourceSpan {
                    path: "src/dead-reference.ts".to_owned(),
                    start: 4,
                    end: 8,
                }],
            }],
        };
        let reachable = ["src/entry.ts"].into_iter().collect();

        assert_eq!(
            resolve_deep_raw_resolution(&raw, &reachable, &|_| false),
            DeepResolution::Resolved {
                receiver_may_reference_member: false,
                live_override_contract: false,
            }
        );
    }

    #[test]
    fn deep_cache_identity_covers_effective_config_source_and_compiler() {
        let source = Digest::of_bytes(b"source-a");
        let baseline = deep_cache_key(b"config-a", "typescript-a", "tsconfig.json", source)
            .expect("baseline cache key");

        assert_ne!(
            baseline,
            deep_cache_key(b"config-b", "typescript-a", "tsconfig.json", source)
                .expect("config cache key")
        );
        assert_ne!(
            baseline,
            deep_cache_key(b"config-a", "typescript-b", "tsconfig.json", source)
                .expect("compiler cache key")
        );
        assert_ne!(
            baseline,
            deep_cache_key(
                b"config-a",
                "typescript-a",
                "tsconfig.json",
                Digest::of_bytes(b"source-b"),
            )
            .expect("source cache key")
        );
    }

    #[test]
    fn executable_config_package_references_are_static_and_normalized() {
        let config = serde_json::json!({
            "plugins": ["@scope/plugin/preset", "./local-plugin.js"],
            "parser": "typescript-parser"
        });
        let mut packages = BTreeSet::new();

        collect_static_config_packages(&config, None, &mut packages);

        assert_eq!(
            packages,
            ["@scope/plugin".to_owned(), "typescript-parser".to_owned()]
                .into_iter()
                .collect()
        );
    }
}
