use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    ffi::OsStr,
    fs, io,
    path::{Component, Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant},
};

use serde::Deserialize;
use thiserror::Error;

use crate::{
    analysis::{
        dependencies::package_name,
        members::{
            AnalysisMode as MemberAnalysisMode, DeepResolution, InheritanceFacts, MemberCandidate,
            MemberDecision, MemberHazards, MemberId, MemberKind, MemberLanguage, MemberScope,
            MemberVisibility, analyze_member,
        },
        symbols::{
            ResolvedSymbolLink, SymbolAnalysisInput, SymbolAnalysisResult, SymbolKey, SymbolRoot,
            analyze_symbols,
        },
    },
    cache::{
        CacheEntry, CacheError, CacheKey, CacheLimits, CacheLoadStatus, CacheSchema,
        CanonicalFileIdentity, ConfigDigest, ContentDigest, PersistentCache, ProfileDigest,
    },
    domain::{
        facts::{
            Activation, AnalysisDiagnostic, ClassMemberFact, ClassMemberKind,
            ClassMemberVisibility, DiagnosticSeverity, ExportBindingKind, FileFacts,
            ImportBindingKind, SourceKind, SourceSpan, UsageKind,
        },
        graph::{FileGraph, FileId},
        report::{
            AnalysisStatus, CacheReport, Confidence, FileReport, FileStatus, Finding,
            FixEligibility, ImportReport, REPORT_SCHEMA_VERSION, ReportSummary, ResolutionStatus,
            RetentionReport, ScanReport, UnusedFilesFinding,
        },
    },
    javascript::parse_file_with_limits,
    limits::AnalysisLimits,
    resolution::{ModuleResolution, ModuleResolver, OxcModuleResolver, is_relative},
};

#[derive(Debug, Clone)]
pub struct ScanRequest {
    pub root: PathBuf,
    pub entries: Vec<PathBuf>,
    pub files: Vec<PathBuf>,
}

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("cannot resolve project root `{path}`: {source}")]
    Root {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("project root `{0}` is not a directory")]
    RootIsNotDirectory(PathBuf),
    #[error("cannot resolve source file `{path}`: {source}")]
    SourcePath {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("source file `{0}` is outside the physical project root")]
    SourceOutsideRoot(PathBuf),
    #[error("source file path `{0}` is not valid UTF-8 and cannot be represented safely")]
    NonUtf8SourcePath(PathBuf),
    #[error("source file `{0}` was supplied more than once")]
    DuplicateSource(PathBuf),
    #[error("source files collapse to the same displayed path `{0}`")]
    DuplicateDisplayPath(String),
    #[error("cannot read source file `{path}` as UTF-8: {source}")]
    ReadSource {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(
        "source file `{path}` is {bytes} bytes, exceeding the configured per-file limit of {limit} bytes"
    )]
    SourceFileTooLarge {
        path: PathBuf,
        bytes: u64,
        limit: u64,
    },
    #[error("entry `{0}` is not present in the supplied file universe")]
    EntryNotSupplied(PathBuf),
    #[error("an entry was supplied more than once: `{0}`")]
    DuplicateEntry(PathBuf),
    #[error("at least one entry file must be supplied")]
    EmptyEntries,
    #[error("at least one source file must be supplied")]
    EmptyFileUniverse,
    #[error(
        "the supplied file universe contains {files} files, exceeding the configured limit of {limit}"
    )]
    FileUniverseTooLarge { files: usize, limit: usize },
    #[error("cannot read package manifest `{path}`: {source}")]
    ReadPackageManifest {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("invalid package manifest `{path}`: {source}")]
    ParsePackageManifest {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error(transparent)]
    Cache(#[from] CacheError),
    #[error("cannot create fact-cache identity for `{path}`: {message}")]
    CacheIdentity { path: String, message: &'static str },
    #[error("parser worker panicked while analyzing `{0}`")]
    ParserWorkerPanicked(String),
    #[error("parser worker returned no facts for `{0}`")]
    MissingParsedFact(String),
}

/// Persistent facts plus the immutable source snapshot shared by profile passes.
///
/// Reusing a fact from `memory` counts as a cache hit. Only persistent misses
/// count as misses or trigger a new generation, so later profile/deep passes do
/// not reread, rehash, reparse, or rewrite unchanged facts.
pub(crate) struct FactCache {
    store: PersistentCache,
    config: ConfigDigest,
    profile: ProfileDigest,
    memory: Mutex<BTreeMap<String, MemoryCachedFact>>,
}

#[derive(Debug, Clone)]
struct MemoryCachedFact {
    facts: FileFacts,
    content_digest: ContentDigest,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ScanStageMetrics {
    pub fact_loading: StageMeasurement,
    pub module_resolution_graph: StageMeasurement,
    pub reachability_rules_report: StageMeasurement,
    pub cache_persist: StageMeasurement,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct StageMeasurement {
    pub duration: Duration,
    pub count: usize,
}

pub(crate) type DeepMemberEvidence = BTreeMap<(String, u32), DeepResolution>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct AdditionalFileEdge {
    pub from: String,
    pub to: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct WorkspaceModuleTarget {
    pub package: String,
    pub specifier: String,
    pub esm: Vec<String>,
    pub common_js: Vec<String>,
}

impl FactCache {
    pub(crate) fn new(
        project_root: &Path,
        config_bytes: &[u8],
        profile_bytes: &[u8],
    ) -> Result<Self, CacheError> {
        Ok(Self {
            store: PersistentCache::new(
                project_root.join(".orphanode").join("cache"),
                CacheSchema::current(env!("CARGO_PKG_VERSION"), "oxc-0.144.0"),
                CacheLimits::default(),
            )?,
            config: ConfigDigest::of_bytes(config_bytes),
            profile: ProfileDigest::of_bytes(profile_bytes),
            memory: Mutex::new(BTreeMap::new()),
        })
    }
}

/// Scans the supplied source-file universe with the default analysis limits.
///
/// # Errors
///
/// Returns an error when the request is invalid, source or manifest input cannot
/// be read, a configured limit is exceeded, or the persistent cache fails.
pub fn scan(request: &ScanRequest) -> Result<ScanReport, ScanError> {
    scan_with_limits(request, AnalysisLimits::default())
}

/// Scans the supplied source-file universe with explicit analysis limits.
///
/// # Errors
///
/// Returns an error when the request is invalid, source or manifest input cannot
/// be read, an analysis limit is exceeded, or the persistent cache fails.
pub fn scan_with_limits(
    request: &ScanRequest,
    limits: AnalysisLimits,
) -> Result<ScanReport, ScanError> {
    scan_internal(
        request,
        limits,
        None,
        MemberAnalysisMode::Balanced,
        None,
        None,
        &["default".to_owned()],
        None,
        &[],
        None,
        &[],
        false,
        SourceUniverseKind::Explicit,
    )
    .map(|(report, _)| report)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn scan_with_fact_cache_measured(
    request: &ScanRequest,
    limits: AnalysisLimits,
    cache: &FactCache,
    member_mode: MemberAnalysisMode,
    member_modes_by_file: Option<&BTreeMap<String, MemberAnalysisMode>>,
    deep_member_evidence: Option<&DeepMemberEvidence>,
    target_profiles: &[String],
    open_world_entries: Option<&BTreeSet<String>>,
    additional_file_edges: &[AdditionalFileEdge],
    declared_external_packages: Option<&BTreeSet<String>>,
    workspace_module_targets: &[WorkspaceModuleTarget],
    yarn_pnp: bool,
    universe_kind: SourceUniverseKind,
) -> Result<(ScanReport, ScanStageMetrics), ScanError> {
    scan_internal(
        request,
        limits,
        Some(cache),
        member_mode,
        member_modes_by_file,
        deep_member_evidence,
        target_profiles,
        open_world_entries,
        additional_file_edges,
        declared_external_packages,
        workspace_module_targets,
        yarn_pnp,
        universe_kind,
    )
}

pub(crate) fn apply_deep_member_evidence(
    report: &mut ScanReport,
    cache: &FactCache,
    evidence: &DeepMemberEvidence,
) -> Result<usize, ScanError> {
    let candidates = report
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.code == "member_analysis_deferred")
        .filter_map(|diagnostic| {
            diagnostic
                .span
                .map(|span| (diagnostic.path.clone(), span.start))
        })
        .filter(|candidate| evidence.contains_key(candidate))
        .collect::<BTreeSet<_>>();
    report.diagnostics.retain(|diagnostic| {
        diagnostic.code != "member_analysis_deferred"
            || diagnostic
                .span
                .is_none_or(|span| !candidates.contains(&(diagnostic.path.clone(), span.start)))
    });

    let memory = cache
        .memory
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for (path, position) in &candidates {
        let facts = memory
            .get(path)
            .map(|cached| &cached.facts)
            .ok_or_else(|| ScanError::MissingParsedFact(path.clone()))?;
        let member = facts
            .member_facts
            .iter()
            .find(|member| member.span.start == *position)
            .ok_or_else(|| ScanError::MissingParsedFact(format!("{path}:{position}")))?;
        let resolution = evidence
            .get(&(path.clone(), *position))
            .expect("candidate keys were filtered by deep evidence");
        // A member that reached the deep-deferral set already passed the
        // open-world, escaped-surface, direct-reference, and hazard retainers.
        let candidate = member_candidate(
            member,
            facts.source_kind,
            false,
            MemberAnalysisMode::Deep,
            Some(resolution),
        );
        append_deep_member_decision(
            report,
            facts,
            member,
            analyze_member(MemberAnalysisMode::Deep, &candidate),
        );
    }
    drop(memory);
    sort_findings(&mut report.findings);
    report
        .retentions
        .sort_by(|left, right| (&left.workspace, &left.item).cmp(&(&right.workspace, &right.item)));
    sort_diagnostics(&mut report.diagnostics);
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
    Ok(candidates.len())
}

fn append_deep_member_decision(
    report: &mut ScanReport,
    facts: &FileFacts,
    member: &ClassMemberFact,
    decision: MemberDecision,
) {
    let symbol = format!("{}.{}", member.declaring_class, member.name);
    match decision {
        MemberDecision::Finding(finding) => report.findings.push(Finding {
            issue_id: "ORP1004",
            issue_type: "unusedMember",
            workspace: ".".to_owned(),
            target_profiles: vec!["default".to_owned()],
            paths: vec![facts.path.clone()],
            span: Some(member.span),
            symbol: Some(symbol),
            dependency: None,
            confidence: Confidence::High,
            summary: format!(
                "member {}.{} has no live reference",
                member.declaring_class, member.name
            ),
            evidence: finding
                .evidence
                .iter()
                .map(|evidence| member_evidence(*evidence).to_owned())
                .collect(),
            blockers: Vec::new(),
            suggested_actions: vec![
                "Review the member and request a fix preview before editing".to_owned(),
            ],
            fix_eligibility: FixEligibility::PreviewOnly,
        }),
        MemberDecision::Retained(retention) => report.retentions.push(RetentionReport {
            item: symbol,
            item_type: "member",
            workspace: ".".to_owned(),
            target_profiles: vec!["default".to_owned()],
            summary: "Member retained by conservative safety policy".to_owned(),
            evidence: vec![member_retention_reason(retention.reason).to_owned()],
        }),
        MemberDecision::Deferred(deferral) => report.diagnostics.push(AnalysisDiagnostic {
            code: "member_analysis_deferred".to_owned(),
            path: facts.path.clone(),
            severity: DiagnosticSeverity::Warning,
            span: Some(member.span),
            message: format!(
                "Member analysis for {symbol} was deferred: {}{}",
                member_deferral_reason(deferral.reason),
                deferral
                    .capability_note
                    .map_or_else(String::new, |note| format!("; {note}"))
            ),
            blocks_reachability: false,
        }),
    }
}

// This is the ordered scan pipeline: keeping its configuration explicit and its
// stages together makes measurement boundaries and shared state transitions clear.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn scan_internal(
    request: &ScanRequest,
    limits: AnalysisLimits,
    cache: Option<&FactCache>,
    member_mode: MemberAnalysisMode,
    member_modes_by_file: Option<&BTreeMap<String, MemberAnalysisMode>>,
    deep_member_evidence: Option<&DeepMemberEvidence>,
    target_profiles: &[String],
    open_world_entries: Option<&BTreeSet<String>>,
    additional_file_edges: &[AdditionalFileEdge],
    declared_external_packages: Option<&BTreeSet<String>>,
    workspace_module_targets: &[WorkspaceModuleTarget],
    yarn_pnp: bool,
    universe_kind: SourceUniverseKind,
) -> Result<(ScanReport, ScanStageMetrics), ScanError> {
    let mut measurements = ScanStageMetrics::default();
    let root = canonical_root(&request.root)?;
    if request.files.len() > limits.max_discovered_files {
        return Err(ScanError::FileUniverseTooLarge {
            files: request.files.len(),
            limit: limits.max_discovered_files,
        });
    }
    let prepared_files = prepare_files(request, &root)?;
    let entry_ids = prepare_entries(request, &root, &prepared_files)?;
    let entries = entry_ids
        .iter()
        .map(|entry| prepared_files[entry.0].display_path.clone())
        .collect::<Vec<_>>();
    let manifest = package_manifest_evidence(&root)?;

    let (mut facts, content_digests, cache_report, parse_measurements) =
        parse_files(&prepared_files, limits, cache)?;
    measurements.fact_loading = parse_measurements.fact_loading;
    measurements.cache_persist = parse_measurements.cache_persist;
    enforce_diagnostic_limit(&mut facts, limits.max_diagnostics.max(1));
    let module_started = Instant::now();
    let resolver = if yarn_pnp {
        OxcModuleResolver::for_profiles_with_yarn_pnp(target_profiles, &root)
    } else {
        OxcModuleResolver::for_profiles(target_profiles)
    };
    let (mut graph, mut imports) = resolve_imports(
        &root,
        &prepared_files,
        &mut facts,
        &resolver,
        target_profiles,
        declared_external_packages.unwrap_or(&manifest.packages),
        workspace_module_targets,
        yarn_pnp,
        universe_kind,
    );
    add_additional_file_edges(&mut graph, &mut imports, &facts, additional_file_edges);
    graph.finish();
    measurements.module_resolution_graph = StageMeasurement {
        duration: module_started.elapsed(),
        count: imports.iter().map(Vec::len).sum(),
    };
    let reachability_started = Instant::now();
    let reachable = graph.reachable_from_many(&entry_ids);

    let links = build_symbol_links(&facts, &imports);
    let open_world_files =
        open_world_files(&facts, &entry_ids, manifest.open_world, open_world_entries);
    let explicit_symbol_roots = open_world_reexport_roots(&facts, &imports, &open_world_files);
    let symbol_analysis = analyze_symbols(&SymbolAnalysisInput {
        files: &facts,
        reachable_files: &reachable,
        open_world_files: &open_world_files,
        links: &links,
        explicit_roots: &explicit_symbol_roots,
    });

    let has_reachable_blocker = facts.iter().enumerate().any(|(index, file)| {
        reachable[index]
            && file
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.blocks_reachability)
    });
    let file_statuses = classify_files(&facts, &reachable, has_reachable_blocker);
    let mut findings = build_findings(
        &graph,
        &facts,
        &file_statuses,
        &entries,
        has_reachable_blocker,
    );
    let mut retentions = Vec::new();
    if !has_reachable_blocker {
        findings.extend(build_symbol_findings(
            &facts,
            &reachable,
            &open_world_files,
            &links,
            &symbol_analysis,
        ));
        let member_results = build_member_results(
            &facts,
            &reachable,
            &open_world_files,
            member_mode,
            member_modes_by_file,
            deep_member_evidence,
        );
        findings.extend(member_results.findings);
        retentions.extend(member_results.retentions);
        diagnostics_for_members(&mut facts, member_results.deferrals);
        sort_findings(&mut findings);
    }
    let mut diagnostics = facts
        .iter()
        .flat_map(|file| file.diagnostics.iter().cloned())
        .collect::<Vec<_>>();
    sort_diagnostics(&mut diagnostics);

    let files = facts
        .into_iter()
        .zip(file_statuses.iter().copied())
        .zip(imports)
        .zip(content_digests)
        .map(|(((facts, status), imports), content_digest)| FileReport {
            path: facts.path,
            status,
            target_statuses: target_profiles
                .iter()
                .cloned()
                .map(|profile| (profile, status))
                .collect(),
            source_kind: facts.source_kind,
            module_kind: facts.module_kind,
            byte_len: facts.byte_len,
            line_count: facts.line_count,
            content_digest,
            imports,
            exports: facts.exports,
        })
        .collect::<Vec<_>>();
    let summary = ReportSummary {
        files: files.len(),
        reachable_files: file_statuses
            .iter()
            .filter(|status| **status == FileStatus::Reachable)
            .count(),
        unreachable_files: file_statuses
            .iter()
            .filter(|status| **status == FileStatus::Unreachable)
            .count(),
        incomplete_files: file_statuses
            .iter()
            .filter(|status| **status == FileStatus::Incomplete)
            .count(),
        diagnostics: diagnostics.len(),
    };
    let status = if diagnostics
        .iter()
        .any(|diagnostic| diagnostic.blocks_reachability)
    {
        AnalysisStatus::Incomplete
    } else {
        AnalysisStatus::Complete
    };

    let report = ScanReport {
        schema_version: REPORT_SCHEMA_VERSION,
        status,
        entries,
        summary,
        files,
        findings,
        retentions,
        project: None,
        cache: cache_report,
        diagnostics,
    };
    measurements.reachability_rules_report = StageMeasurement {
        duration: reachability_started.elapsed(),
        count: report.findings.len(),
    };
    Ok((report, measurements))
}

fn prepare_entries(
    request: &ScanRequest,
    root: &Path,
    prepared_files: &[PreparedFile],
) -> Result<Vec<FileId>, ScanError> {
    if request.entries.is_empty() {
        return Err(ScanError::EmptyEntries);
    }

    let ids_by_path = prepared_files
        .iter()
        .enumerate()
        .map(|(index, file)| (file.physical_path.clone(), FileId(index)))
        .collect::<HashMap<_, _>>();
    let mut entry_ids = BTreeSet::new();
    for entry in &request.entries {
        let physical_path = canonical_source(root, entry)?;
        let Some(entry_id) = ids_by_path.get(&physical_path).copied() else {
            return Err(ScanError::EntryNotSupplied(entry.clone()));
        };
        if !entry_ids.insert(entry_id) {
            return Err(ScanError::DuplicateEntry(entry.clone()));
        }
    }
    Ok(entry_ids.into_iter().collect())
}

#[derive(Debug)]
struct PreparedFile {
    physical_path: PathBuf,
    display_path: String,
}

fn canonical_root(root: &Path) -> Result<PathBuf, ScanError> {
    let canonical = root.canonicalize().map_err(|source| ScanError::Root {
        path: root.to_path_buf(),
        source,
    })?;
    if !canonical.is_dir() {
        return Err(ScanError::RootIsNotDirectory(canonical));
    }
    Ok(canonical)
}

fn prepare_files(request: &ScanRequest, root: &Path) -> Result<Vec<PreparedFile>, ScanError> {
    if request.files.is_empty() {
        return Err(ScanError::EmptyFileUniverse);
    }

    let mut by_display_path = BTreeMap::new();
    let mut physical_paths = HashMap::new();
    for supplied_path in &request.files {
        let physical_path = canonical_source(root, supplied_path)?;
        let display_path = display_path(root, &physical_path)?;
        if let Some(first_display) =
            physical_paths.insert(physical_path.clone(), display_path.clone())
        {
            return Err(ScanError::DuplicateSource(PathBuf::from(first_display)));
        }
        let replaced = by_display_path.insert(
            display_path.clone(),
            PreparedFile {
                physical_path,
                display_path: display_path.clone(),
            },
        );
        if replaced.is_some() {
            return Err(ScanError::DuplicateDisplayPath(display_path));
        }
    }
    Ok(by_display_path.into_values().collect())
}

fn canonical_source(root: &Path, supplied_path: &Path) -> Result<PathBuf, ScanError> {
    let candidate = if supplied_path.is_absolute() {
        supplied_path.to_path_buf()
    } else {
        root.join(supplied_path)
    };
    let physical_path = candidate
        .canonicalize()
        .map_err(|source| ScanError::SourcePath {
            path: supplied_path.to_path_buf(),
            source,
        })?;
    if !physical_path.starts_with(root) {
        return Err(ScanError::SourceOutsideRoot(supplied_path.to_path_buf()));
    }
    Ok(physical_path)
}

fn display_path(root: &Path, physical_path: &Path) -> Result<String, ScanError> {
    let relative = physical_path
        .strip_prefix(root)
        .map_err(|_| ScanError::SourceOutsideRoot(physical_path.to_path_buf()))?;
    let mut parts = Vec::new();
    for component in relative.components() {
        if let Component::Normal(part) = component {
            let part = part
                .to_str()
                .ok_or_else(|| ScanError::NonUtf8SourcePath(physical_path.to_path_buf()))?;
            parts.push(part.to_owned());
        }
    }
    Ok(parts.join("/"))
}

type ParsedFiles = (
    Vec<FileFacts>,
    Vec<String>,
    Option<CacheReport>,
    ParseMeasurements,
);

// Cache lookup, bounded parallel parsing, and atomic generation persistence are
// intentionally kept in one routine so their counters and timings cannot diverge.
#[allow(clippy::too_many_lines)]
fn parse_files(
    prepared_files: &[PreparedFile],
    limits: AnalysisLimits,
    cache: Option<&FactCache>,
) -> Result<ParsedFiles, ScanError> {
    let fact_loading_started = Instant::now();
    let snapshot = cache.map(|cache| cache.store.load()).transpose()?;
    let cache_status = snapshot.as_ref().map(|snapshot| match &snapshot.status {
        CacheLoadStatus::Empty => "empty",
        CacheLoadStatus::Active { .. } => "active",
        CacheLoadStatus::Recovered { .. } => "recovered",
        CacheLoadStatus::Reset { .. } => "reset",
    });
    let mut parsed = (0..prepared_files.len())
        .map(|_| None)
        .collect::<Vec<Option<ParsedFile>>>();
    let mut pending = Vec::new();
    let mut hits = 0_usize;
    let mut misses = 0_usize;
    let worker_limit = std::thread::available_parallelism()
        .map_or(1, usize::from)
        .clamp(1, 8);
    let byte_budget = 16 * 1024 * 1024_usize;
    let mut pending_bytes = 0_usize;

    for (index, file) in prepared_files.iter().enumerate() {
        let memory_cached = cache.and_then(|cache| {
            cache
                .memory
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&file.display_path)
                .cloned()
        });
        if let Some(memory_cached) = memory_cached {
            hits += 1;
            let key = cache
                .map(|cache| fact_cache_key(cache, file, memory_cached.content_digest))
                .transpose()?;
            parsed[index] = Some(ParsedFile {
                facts: memory_cached.facts,
                content_digest: memory_cached.content_digest,
                key,
            });
            continue;
        }
        let bytes = fs::metadata(&file.physical_path)
            .map_err(|source| ScanError::ReadSource {
                path: file.physical_path.clone(),
                source,
            })?
            .len();
        if bytes > limits.max_source_file_bytes {
            return Err(ScanError::SourceFileTooLarge {
                path: file.physical_path.clone(),
                bytes,
                limit: limits.max_source_file_bytes,
            });
        }
        let source_text =
            fs::read_to_string(&file.physical_path).map_err(|source| ScanError::ReadSource {
                path: file.physical_path.clone(),
                source,
            })?;
        let source_bytes = u64::try_from(source_text.len()).unwrap_or(u64::MAX);
        if source_bytes > limits.max_source_file_bytes {
            return Err(ScanError::SourceFileTooLarge {
                path: file.physical_path.clone(),
                bytes: source_bytes,
                limit: limits.max_source_file_bytes,
            });
        }
        let content_digest = ContentDigest::of_bytes(source_text.as_bytes());
        let key = cache
            .map(|cache| fact_cache_key(cache, file, content_digest))
            .transpose()?;
        let cached = key
            .as_ref()
            .and_then(|key| snapshot.as_ref().and_then(|snapshot| snapshot.get(key)))
            .and_then(|payload| serde_json::from_slice::<FileFacts>(payload).ok());
        if let Some(cached) = cached {
            hits += 1;
            parsed[index] = Some(ParsedFile {
                facts: cached,
                content_digest,
                key,
            });
        } else {
            if cache.is_some() {
                misses += 1;
            }
            pending_bytes = pending_bytes.saturating_add(source_text.len());
            pending.push(PendingParse {
                index,
                display_path: file.display_path.clone(),
                physical_path: file.physical_path.clone(),
                source_text,
                content_digest,
                key,
            });
            if pending.len() >= worker_limit || pending_bytes >= byte_budget {
                parse_pending_files(&mut pending, &mut parsed, limits)?;
                pending_bytes = 0;
            }
        }
    }
    parse_pending_files(&mut pending, &mut parsed, limits)?;
    let fact_loading_duration = fact_loading_started.elapsed();

    let mut facts = Vec::with_capacity(parsed.len());
    let mut content_digests = Vec::with_capacity(parsed.len());
    let mut cache_entries = Vec::with_capacity(parsed.len());
    let will_persist_generation = cache.is_some() && misses > 0;
    for (index, parsed) in parsed.into_iter().enumerate() {
        let parsed = parsed.ok_or_else(|| {
            ScanError::MissingParsedFact(prepared_files[index].display_path.clone())
        })?;
        if will_persist_generation && let Some(key) = parsed.key {
            let payload = serde_json::to_vec(&parsed.facts).map_err(CacheError::Encode)?;
            cache_entries.push(CacheEntry::new(key, payload));
        }
        if let Some(cache) = cache {
            cache
                .memory
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(
                    prepared_files[index].display_path.clone(),
                    MemoryCachedFact {
                        facts: parsed.facts.clone(),
                        content_digest: parsed.content_digest,
                    },
                );
        }
        facts.push(parsed.facts);
        content_digests.push(parsed.content_digest.0.to_hex());
    }

    let persisted_entry_count = cache_entries.len();
    let persist_started = Instant::now();
    let generation_written = if let Some(cache) = cache
        && misses > 0
    {
        cache.store.commit(cache_entries)?;
        true
    } else {
        false
    };
    let persist_duration = persist_started.elapsed();
    let report = cache.map(|_| CacheReport {
        status: cache_status.unwrap_or("empty").to_owned(),
        hits,
        misses,
        generation_written,
    });
    Ok((
        facts,
        content_digests,
        report,
        ParseMeasurements {
            fact_loading: StageMeasurement {
                duration: fact_loading_duration,
                count: prepared_files.len(),
            },
            cache_persist: StageMeasurement {
                duration: persist_duration,
                count: if generation_written {
                    persisted_entry_count
                } else {
                    0
                },
            },
        },
    ))
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ParseMeasurements {
    fact_loading: StageMeasurement,
    cache_persist: StageMeasurement,
}

struct PendingParse {
    index: usize,
    display_path: String,
    physical_path: PathBuf,
    source_text: String,
    content_digest: ContentDigest,
    key: Option<CacheKey>,
}

struct ParsedFile {
    facts: FileFacts,
    content_digest: ContentDigest,
    key: Option<CacheKey>,
}

fn parse_pending_files(
    pending: &mut Vec<PendingParse>,
    parsed: &mut [Option<ParsedFile>],
    limits: AnalysisLimits,
) -> Result<(), ScanError> {
    let batch = std::mem::take(pending);
    std::thread::scope(|scope| {
        let handles = batch
            .into_iter()
            .map(|input| {
                let display_path = input.display_path.clone();
                (
                    display_path,
                    scope.spawn(move || {
                        let facts = parse_file_with_limits(
                            &input.display_path,
                            &input.physical_path,
                            &input.source_text,
                            limits,
                        );
                        (
                            input.index,
                            ParsedFile {
                                facts,
                                content_digest: input.content_digest,
                                key: input.key,
                            },
                        )
                    }),
                )
            })
            .collect::<Vec<_>>();
        for (display_path, handle) in handles {
            let (index, result) = handle
                .join()
                .map_err(|_| ScanError::ParserWorkerPanicked(display_path))?;
            parsed[index] = Some(result);
        }
        Ok(())
    })
}

fn fact_cache_key(
    cache: &FactCache,
    file: &PreparedFile,
    content_digest: ContentDigest,
) -> Result<CacheKey, ScanError> {
    let identity = CanonicalFileIdentity::new(file.display_path.clone()).map_err(|message| {
        ScanError::CacheIdentity {
            path: file.display_path.clone(),
            message,
        }
    })?;
    Ok(CacheKey::new(
        cache.config,
        cache.profile,
        identity,
        content_digest,
        Vec::new(),
    ))
}

fn enforce_diagnostic_limit(facts: &mut [FileFacts], limit: usize) {
    let diagnostic_count = facts
        .iter()
        .map(|file| file.diagnostics.len())
        .sum::<usize>();
    if diagnostic_count <= limit {
        return;
    }

    let mut remaining = limit.saturating_sub(1);
    let mut first_omitted_path = None;
    for file in facts.iter_mut() {
        if remaining == 0 {
            if first_omitted_path.is_none() && !file.diagnostics.is_empty() {
                first_omitted_path = Some(file.path.clone());
            }
            file.diagnostics.clear();
        } else if file.diagnostics.len() <= remaining {
            remaining -= file.diagnostics.len();
        } else {
            first_omitted_path = Some(file.path.clone());
            file.diagnostics.truncate(remaining);
            remaining = 0;
        }
    }
    let path = first_omitted_path.unwrap_or_else(|| "<project>".to_owned());
    if let Some(first) = facts.first_mut() {
        first.diagnostics.push(AnalysisDiagnostic {
            code: "diagnostic_limit_exceeded".to_owned(),
            path,
            severity: DiagnosticSeverity::Error,
            span: None,
            message: format!(
                "Analysis produced more than {limit} diagnostics; narrow the project or raise the explicit diagnostic limit"
            ),
            blocks_reachability: true,
        });
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PackageManifest {
    #[serde(default)]
    private: bool,
    #[serde(default)]
    dependencies: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    dev_dependencies: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    peer_dependencies: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    optional_dependencies: BTreeMap<String, serde_json::Value>,
}

struct PackageManifestEvidence {
    packages: BTreeSet<String>,
    open_world: bool,
}

fn package_manifest_evidence(root: &Path) -> Result<PackageManifestEvidence, ScanError> {
    let manifest_path = root.join("package.json");
    let manifest_source = match fs::read_to_string(&manifest_path) {
        Ok(source) => source,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Ok(PackageManifestEvidence {
                packages: BTreeSet::new(),
                open_world: false,
            });
        }
        Err(source) => {
            return Err(ScanError::ReadPackageManifest {
                path: manifest_path,
                source,
            });
        }
    };
    let manifest = serde_json::from_str::<PackageManifest>(&manifest_source).map_err(|source| {
        ScanError::ParsePackageManifest {
            path: manifest_path,
            source,
        }
    })?;
    Ok(PackageManifestEvidence {
        packages: manifest
            .dependencies
            .into_keys()
            .chain(manifest.dev_dependencies.into_keys())
            .chain(manifest.peer_dependencies.into_keys())
            .chain(manifest.optional_dependencies.into_keys())
            .collect(),
        open_world: !manifest.private,
    })
}

/// How the analyzed source universe was produced.
///
/// Discovered universes come from project discovery, which deliberately applies
/// policy boundaries such as ignore rules, skipped directories, and workspace
/// package ownership. Explicit universes are caller-owned file lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceUniverseKind {
    Discovered,
    Explicit,
}

// Import resolution updates diagnostics, graph edges, and report rows together;
// splitting those mutations would make their one-to-one correspondence fragile.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn resolve_imports(
    root: &Path,
    prepared_files: &[PreparedFile],
    facts: &mut [FileFacts],
    resolver: &dyn ModuleResolver,
    target_profiles: &[String],
    external_packages: &BTreeSet<String>,
    workspace_module_targets: &[WorkspaceModuleTarget],
    yarn_pnp: bool,
    universe_kind: SourceUniverseKind,
) -> (FileGraph, Vec<Vec<ImportReport>>) {
    let ids_by_path = prepared_files
        .iter()
        .enumerate()
        .map(|(index, file)| (file.physical_path.clone(), FileId(index)))
        .collect::<HashMap<_, _>>();
    let mut graph = FileGraph::new(prepared_files.len());
    let mut all_imports = Vec::with_capacity(prepared_files.len());
    let ids_by_display_path = facts
        .iter()
        .enumerate()
        .map(|(index, facts)| (facts.path.clone(), FileId(index)))
        .collect::<BTreeMap<_, _>>();

    for file_index in 0..prepared_files.len() {
        let import_facts = facts[file_index].imports.clone();
        let source_path = facts[file_index].path.clone();
        let mut import_reports = Vec::with_capacity(import_facts.len());
        for import in import_facts {
            let imported_package = package_name(&import.specifier);
            let workspace_package = imported_package.as_deref().and_then(|package| {
                workspace_module_targets
                    .iter()
                    .find(|target| target.package == package)
            });
            let workspace_targets = workspace_module_targets
                .iter()
                .find(|target| target.specifier == import.specifier)
                .map(|target| match import.resolution_mode {
                    crate::domain::facts::ResolutionMode::Esm => target.esm.as_slice(),
                    crate::domain::facts::ResolutionMode::CommonJs => {
                        if target.common_js.is_empty() {
                            target.esm.as_slice()
                        } else {
                            target.common_js.as_slice()
                        }
                    }
                })
                .into_iter()
                .flatten()
                .filter_map(|path| ids_by_display_path.get(path.as_str()).copied())
                .collect::<Vec<_>>();
            let (status, target) = if import.activation == Activation::Deferred {
                (ResolutionStatus::Deferred, None)
            } else if !workspace_targets.is_empty() {
                for target_id in &workspace_targets {
                    graph.add_edge(FileId(file_index), *target_id);
                }
                (
                    ResolutionStatus::Resolved,
                    Some(facts[workspace_targets[0].0].path.clone()),
                )
            } else {
                match resolver.resolve(
                    &prepared_files[file_index].physical_path,
                    &import.specifier,
                    import.resolution_mode,
                ) {
                    Ok(ModuleResolution::External) if workspace_package.is_some() => {
                        facts[file_index].diagnostics.push(unresolved_diagnostic(
                            &source_path,
                            &import.specifier,
                            import.span,
                            "the workspace package target is not mapped into the analyzed source universe",
                        ));
                        (ResolutionStatus::Unresolved, None)
                    }
                    Ok(ModuleResolution::External) => (ResolutionStatus::External, None),
                    // Oxc resolves archive members through its PnP-aware filesystem,
                    // but std::fs cannot canonicalize paths inside those archives.
                    Ok(ModuleResolution::File(resolved_path))
                        if is_pnp_external_resolution(
                            &import.specifier,
                            &resolved_path,
                            workspace_package.is_some(),
                            yarn_pnp,
                        ) =>
                    {
                        (ResolutionStatus::External, None)
                    }
                    Ok(ModuleResolution::File(resolved_path)) => {
                        if let Ok(physical_target) = resolved_path.canonicalize() {
                            if let Some(target_id) = ids_by_path.get(&physical_target).copied() {
                                graph.add_edge(FileId(file_index), target_id);
                                (
                                    ResolutionStatus::Resolved,
                                    Some(facts[target_id.0].path.clone()),
                                )
                            } else if is_dependency_path(&physical_target) {
                                (ResolutionStatus::External, None)
                            } else if !physical_target.starts_with(root) {
                                facts[file_index].diagnostics.push(
                                    outside_analysis_root_diagnostic(
                                        &source_path,
                                        &import.specifier,
                                        import.span,
                                    ),
                                );
                                (ResolutionStatus::Unresolved, None)
                            } else if is_inert_asset(&physical_target) {
                                (ResolutionStatus::External, None)
                            } else if !is_analyzable_source(&physical_target) {
                                facts[file_index].diagnostics.push(
                                    unsupported_imported_source_diagnostic(
                                        &source_path,
                                        &import.specifier,
                                        import.span,
                                    ),
                                );
                                (ResolutionStatus::Unsupported, None)
                            } else if universe_kind == SourceUniverseKind::Discovered {
                                // Discovery deliberately excludes ignored paths,
                                // skipped directories, and nested workspace
                                // packages. A resolution that lands there is an
                                // opaque boundary like a dependency, so it stays
                                // visible without suppressing other findings.
                                facts[file_index].diagnostics.push(excluded_path_diagnostic(
                                    &source_path,
                                    &import.specifier,
                                    &physical_target,
                                    root,
                                    import.span,
                                ));
                                // The recorded target tells downstream
                                // dependency analysis that this external edge
                                // still resolves inside the project.
                                let target_display = physical_target
                                    .strip_prefix(root)
                                    .unwrap_or(&physical_target)
                                    .display()
                                    .to_string()
                                    .replace('\\', "/");
                                (ResolutionStatus::External, Some(target_display))
                            } else {
                                facts[file_index]
                                    .diagnostics
                                    .push(outside_universe_diagnostic(
                                        &source_path,
                                        &import.specifier,
                                        import.span,
                                    ));
                                (ResolutionStatus::Unresolved, None)
                            }
                        } else {
                            facts[file_index].diagnostics.push(unresolved_diagnostic(
                                &source_path,
                                &import.specifier,
                                import.span,
                                "the resolved target could not be canonicalized",
                            ));
                            (ResolutionStatus::Unresolved, None)
                        }
                    }
                    Err(_) => {
                        if workspace_package.is_some() {
                            facts[file_index].diagnostics.push(unresolved_diagnostic(
                                &source_path,
                                &import.specifier,
                                import.span,
                                "the workspace package or subpath has no source target under the configured resolution profile",
                            ));
                            (ResolutionStatus::Unresolved, None)
                        } else if is_declared_external(&import.specifier, external_packages) {
                            (ResolutionStatus::External, None)
                        } else if is_relative(&import.specifier) {
                            facts[file_index].diagnostics.push(unresolved_diagnostic(
                                &source_path,
                                &import.specifier,
                                import.span,
                                "no matching file exists under the configured resolution profile",
                            ));
                            (ResolutionStatus::Unresolved, None)
                        } else {
                            facts[file_index]
                                .diagnostics
                                .push(unsupported_specifier_diagnostic(
                                    &source_path,
                                    &import.specifier,
                                    import.span,
                                ));
                            (ResolutionStatus::Unsupported, None)
                        }
                    }
                }
            };
            import_reports.push(ImportReport {
                specifier: import.specifier,
                kind: import.kind,
                resolution_mode: import.resolution_mode,
                activation: import.activation,
                type_only: import.type_only,
                status,
                target_profiles: target_profiles.to_vec(),
                target,
                span: import.span,
            });
        }
        sort_diagnostics(&mut facts[file_index].diagnostics);
        all_imports.push(import_reports);
    }

    (graph, all_imports)
}

fn add_additional_file_edges(
    graph: &mut FileGraph,
    imports: &mut [Vec<ImportReport>],
    facts: &[FileFacts],
    edges: &[AdditionalFileEdge],
) {
    let ids_by_path = facts
        .iter()
        .enumerate()
        .map(|(index, facts)| (facts.path.as_str(), FileId(index)))
        .collect::<BTreeMap<_, _>>();
    for edge in edges {
        let (Some(source), Some(target)) = (
            ids_by_path.get(edge.from.as_str()).copied(),
            ids_by_path.get(edge.to.as_str()).copied(),
        ) else {
            continue;
        };
        graph.add_edge(source, target);
        imports[source.0].push(ImportReport {
            specifier: format!("plugin: {}", edge.reason),
            kind: crate::domain::facts::ImportKind::Plugin,
            resolution_mode: crate::domain::facts::ResolutionMode::Esm,
            activation: Activation::Module,
            type_only: false,
            status: ResolutionStatus::Resolved,
            target_profiles: Vec::new(),
            target: Some(edge.to.clone()),
            span: SourceSpan { start: 0, end: 0 },
        });
    }
    for file_imports in imports {
        file_imports.sort_by(|left, right| {
            (
                left.span.start,
                left.span.end,
                &left.specifier,
                &left.target,
            )
                .cmp(&(
                    right.span.start,
                    right.span.end,
                    &right.specifier,
                    &right.target,
                ))
        });
    }
}

fn build_symbol_links(
    facts: &[FileFacts],
    imports: &[Vec<ImportReport>],
) -> Vec<ResolvedSymbolLink> {
    let files_by_path = facts
        .iter()
        .enumerate()
        .map(|(index, facts)| (facts.path.as_str(), index))
        .collect::<BTreeMap<_, _>>();
    let mut links = Vec::new();
    for (source_file, file_facts) in facts.iter().enumerate() {
        for binding in &file_facts.symbol_facts.imports {
            let Some(target_file) =
                resolved_target_file(source_file, &binding.source, imports, &files_by_path)
            else {
                continue;
            };
            let source_usage = if binding.type_only {
                UsageKind::Type
            } else {
                UsageKind::Runtime
            };
            let target_names = match binding.kind {
                ImportBindingKind::Default => vec!["default".to_owned()],
                ImportBindingKind::Named => {
                    binding.imported.clone().into_iter().collect::<Vec<_>>()
                }
                ImportBindingKind::Namespace | ImportBindingKind::CommonJs => {
                    exported_names(target_file, facts, imports, &files_by_path)
                }
            };
            for target_name in target_names {
                let mut visited = BTreeSet::new();
                for (target, target_usage) in resolve_export_targets(
                    target_file,
                    &target_name,
                    facts,
                    imports,
                    &files_by_path,
                    &mut visited,
                ) {
                    links.push(ResolvedSymbolLink {
                        source: SymbolKey {
                            file: source_file,
                            symbol: binding.local,
                        },
                        source_usage,
                        target,
                        target_usage,
                    });
                }
            }
        }
    }
    links.sort_by_key(|link| {
        (
            link.source,
            link.source_usage,
            link.target,
            link.target_usage,
        )
    });
    links.dedup();
    links
}

fn exported_names(
    file: usize,
    facts: &[FileFacts],
    imports: &[Vec<ImportReport>],
    files_by_path: &BTreeMap<&str, usize>,
) -> Vec<String> {
    let mut names = BTreeSet::new();
    let mut pending = vec![file];
    let mut visited = BTreeSet::new();
    while let Some(current) = pending.pop() {
        if !visited.insert(current) {
            continue;
        }
        for binding in &facts[current].symbol_facts.exports {
            if binding.kind == ExportBindingKind::Star {
                if let Some(source) = binding.source.as_deref()
                    && let Some(target) =
                        resolved_target_file(current, source, imports, files_by_path)
                {
                    pending.push(target);
                }
            } else {
                names.insert(binding.exported.clone());
            }
        }
    }
    names.into_iter().collect()
}

fn resolve_export_targets(
    file: usize,
    name: &str,
    facts: &[FileFacts],
    imports: &[Vec<ImportReport>],
    files_by_path: &BTreeMap<&str, usize>,
    visited: &mut BTreeSet<(usize, String)>,
) -> Vec<(SymbolKey, UsageKind)> {
    if !visited.insert((file, name.to_owned())) {
        return Vec::new();
    }
    let mut targets = BTreeSet::new();
    for binding in &facts[file].symbol_facts.exports {
        if binding.exported != name && binding.kind != ExportBindingKind::Star {
            continue;
        }
        if let Some(local) = binding.local {
            targets.insert((
                SymbolKey {
                    file,
                    symbol: local,
                },
                if binding.type_only {
                    UsageKind::Type
                } else {
                    UsageKind::Runtime
                },
            ));
        }
        let Some(source) = binding.source.as_deref() else {
            continue;
        };
        let Some(target_file) = resolved_target_file(file, source, imports, files_by_path) else {
            continue;
        };
        let imported = if binding.kind == ExportBindingKind::Star {
            name
        } else {
            binding.imported.as_deref().unwrap_or(name)
        };
        targets.extend(resolve_export_targets(
            target_file,
            imported,
            facts,
            imports,
            files_by_path,
            visited,
        ));
    }
    targets.into_iter().collect()
}

fn resolved_target_file(
    source_file: usize,
    specifier: &str,
    imports: &[Vec<ImportReport>],
    files_by_path: &BTreeMap<&str, usize>,
) -> Option<usize> {
    imports
        .get(source_file)?
        .iter()
        .find(|import| import.specifier == specifier && import.status == ResolutionStatus::Resolved)
        .and_then(|import| import.target.as_deref())
        .and_then(|target| files_by_path.get(target).copied())
}

fn open_world_files(
    facts: &[FileFacts],
    entries: &[FileId],
    fallback_open_world: bool,
    explicit_open_world_entries: Option<&BTreeSet<String>>,
) -> Vec<bool> {
    let mut files = vec![false; facts.len()];
    for entry in entries {
        let entry_path = &facts[entry.0].path;
        files[entry.0] = explicit_open_world_entries
            .map_or(fallback_open_world, |paths| paths.contains(entry_path));
    }
    files
}

fn open_world_reexport_roots(
    facts: &[FileFacts],
    imports: &[Vec<ImportReport>],
    open_world_files: &[bool],
) -> Vec<SymbolRoot> {
    let files_by_path = facts
        .iter()
        .enumerate()
        .map(|(index, facts)| (facts.path.as_str(), index))
        .collect::<BTreeMap<_, _>>();
    let mut roots = BTreeSet::new();
    for (file, is_open_world) in open_world_files.iter().copied().enumerate() {
        if !is_open_world {
            continue;
        }
        for binding in &facts[file].symbol_facts.exports {
            if binding.local.is_some() {
                continue;
            }
            let names = if binding.kind == ExportBindingKind::Star {
                binding
                    .source
                    .as_deref()
                    .and_then(|source| resolved_target_file(file, source, imports, &files_by_path))
                    .map_or_else(Vec::new, |target| {
                        exported_names(target, facts, imports, &files_by_path)
                    })
            } else {
                vec![binding.exported.clone()]
            };
            for name in names {
                let mut visited = BTreeSet::new();
                for (symbol, usage) in resolve_export_targets(
                    file,
                    &name,
                    facts,
                    imports,
                    &files_by_path,
                    &mut visited,
                ) {
                    roots.insert((symbol, usage));
                }
            }
        }
    }
    roots
        .into_iter()
        .map(|(symbol, usage)| SymbolRoot { symbol, usage })
        .collect()
}

fn is_declared_external(specifier: &str, packages: &BTreeSet<String>) -> bool {
    package_name(specifier).is_some_and(|package| packages.contains(&package))
}

fn is_dependency_path(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, Component::Normal(value) if value == "node_modules"))
}

fn is_pnp_virtual_dependency_path(path: &Path) -> bool {
    let mut inside_archive = false;
    for component in path.components() {
        let Component::Normal(value) = component else {
            continue;
        };
        if Path::new(value).extension() == Some(OsStr::new("zip")) {
            inside_archive = true;
        } else if inside_archive && value == OsStr::new("node_modules") {
            return true;
        }
    }
    false
}

fn is_pnp_external_resolution(
    specifier: &str,
    resolved_path: &Path,
    is_workspace_package: bool,
    yarn_pnp: bool,
) -> bool {
    yarn_pnp
        && !is_workspace_package
        && package_name(specifier).is_some()
        && is_pnp_virtual_dependency_path(resolved_path)
}

fn is_analyzable_source(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" | "mts" | "cts")
    )
}

fn is_inert_asset(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some(
            "avif"
                | "css"
                | "gif"
                | "ico"
                | "jpeg"
                | "jpg"
                | "json"
                | "less"
                | "otf"
                | "png"
                | "sass"
                | "scss"
                | "styl"
                | "svg"
                | "ttf"
                | "wasm"
                | "webp"
                | "woff"
                | "woff2"
        )
    )
}

fn classify_files(
    facts: &[FileFacts],
    reachable: &[bool],
    has_reachable_blocker: bool,
) -> Vec<FileStatus> {
    facts
        .iter()
        .enumerate()
        .map(|(index, file)| {
            if has_fatal_file_diagnostic(file) || (has_reachable_blocker && !reachable[index]) {
                FileStatus::Incomplete
            } else if reachable[index] {
                FileStatus::Reachable
            } else {
                FileStatus::Unreachable
            }
        })
        .collect()
}

fn build_findings(
    graph: &FileGraph,
    facts: &[FileFacts],
    statuses: &[FileStatus],
    entries: &[String],
    has_reachable_blocker: bool,
) -> Vec<UnusedFilesFinding> {
    if has_reachable_blocker {
        return Vec::new();
    }

    let included = statuses
        .iter()
        .map(|status| *status == FileStatus::Unreachable)
        .collect::<Vec<_>>();
    graph
        .components_within(&included)
        .into_iter()
        .map(|component| {
            let paths = component
                .iter()
                .map(|file| facts[file.0].path.clone())
                .collect::<Vec<_>>();
            let summary = if paths.len() > 1 {
                format!("{} files form an unreachable cycle", paths.len())
            } else {
                format!("{} is unreachable", paths[0])
            };
            let entry_evidence = if entries.len() == 1 {
                format!("No resolved path from configured entry {}", entries[0])
            } else {
                format!(
                    "No resolved path from any of the {} configured entries",
                    entries.len()
                )
            };
            let mut evidence = vec![entry_evidence];
            if paths.len() > 1 {
                evidence
                    .push("The files retain one another but have no live incoming edge".to_owned());
            }
            UnusedFilesFinding {
                issue_id: "ORP1001",
                issue_type: "unusedFiles",
                workspace: ".".to_owned(),
                target_profiles: vec!["default".to_owned()],
                paths,
                span: None,
                symbol: None,
                dependency: None,
                confidence: Confidence::High,
                summary,
                evidence,
                blockers: Vec::new(),
                suggested_actions: vec![
                    "Review the files or configure an additional entry before removal".to_owned(),
                ],
                fix_eligibility: FixEligibility::PreviewOnly,
            }
        })
        .collect()
}

fn build_symbol_findings(
    facts: &[FileFacts],
    reachable: &[bool],
    open_world_files: &[bool],
    links: &[ResolvedSymbolLink],
    analysis: &SymbolAnalysisResult,
) -> Vec<Finding> {
    let mut findings =
        build_unused_export_findings(facts, reachable, open_world_files, links, analysis);

    for group in &analysis.dead_groups {
        let mut members = group
            .members
            .iter()
            .filter_map(|key| {
                let file = facts.get(key.file)?;
                let symbol = file
                    .symbol_facts
                    .symbols
                    .iter()
                    .find(|symbol| symbol.id == key.symbol)?;
                (!matches!(symbol.kind, crate::domain::facts::DeclarationKind::Import))
                    .then_some((key, file, symbol))
            })
            .collect::<Vec<_>>();
        if members.is_empty() {
            continue;
        }
        members.sort_by_key(|(key, _, symbol)| (**key, symbol.span.start));
        let paths = members
            .iter()
            .map(|(_, file, _)| file.path.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let names = members
            .iter()
            .map(|(_, _, symbol)| symbol.name.clone())
            .collect::<Vec<_>>();
        let safe_removal = members.len() == 1
            && members.iter().all(|(_, _, symbol)| {
                symbol.flags.safe_removal_span && !symbol.flags.initializer_effectful
            });
        let summary = if members.len() == 1 {
            format!("declaration {} has no live reference", names[0])
        } else if group.cyclic {
            format!(
                "{} declarations form a dead recursive group: {}",
                members.len(),
                names.join(", ")
            )
        } else {
            format!("{} declarations are unreachable", members.len())
        };
        let first_symbol = members[0].2;
        findings.push(Finding {
            issue_id: "ORP1003",
            issue_type: "unusedDeclaration",
            workspace: ".".to_owned(),
            target_profiles: vec!["default".to_owned()],
            paths,
            span: Some(first_symbol.span),
            symbol: Some(names.join(", ")),
            dependency: None,
            confidence: Confidence::High,
            summary,
            evidence: vec![if group.cyclic {
                "The declarations reference one another but no live root reaches the group"
                    .to_owned()
            } else {
                "No reachable execution region, import, export contract, or live declaration reaches this binding"
                    .to_owned()
            }],
            blockers: Vec::new(),
            suggested_actions: vec![if safe_removal {
                "Inspect the exact declaration span in a fix preview".to_owned()
            } else {
                "The binding may be unused while its initializer or attached trivia still requires review"
                    .to_owned()
            }],
            fix_eligibility: FixEligibility::PreviewOnly,
        });
    }
    findings
}

fn build_unused_export_findings(
    facts: &[FileFacts],
    reachable: &[bool],
    open_world_files: &[bool],
    links: &[ResolvedSymbolLink],
    analysis: &SymbolAnalysisResult,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let consumed_exports = links
        .iter()
        .map(|link| (link.target, link.target_usage))
        .collect::<BTreeSet<_>>();

    for (file, file_facts) in facts.iter().enumerate() {
        if !reachable.get(file).copied().unwrap_or(false)
            || open_world_files.get(file).copied().unwrap_or(false)
            || !analysis
                .files
                .get(file)
                .is_some_and(|state| state.exports_complete)
        {
            continue;
        }
        for export in &file_facts.symbol_facts.exports {
            let Some(local) = export.local else {
                continue;
            };
            let usage = if export.type_only {
                UsageKind::Type
            } else {
                UsageKind::Runtime
            };
            if consumed_exports.contains(&(
                SymbolKey {
                    file,
                    symbol: local,
                },
                usage,
            )) {
                continue;
            }
            findings.push(Finding {
                issue_id: "ORP1002",
                issue_type: "unusedExport",
                workspace: ".".to_owned(),
                target_profiles: vec!["default".to_owned()],
                paths: vec![file_facts.path.clone()],
                span: Some(export.span),
                symbol: Some(export.exported.clone()),
                dependency: None,
                confidence: Confidence::High,
                summary: format!(
                    "export {} from {} has no live consumer",
                    export.exported, file_facts.path
                ),
                evidence: vec![
                    "No resolved import or re-export reaches this export binding".to_owned(),
                    "The package is analyzed as closed world for this entry".to_owned(),
                ],
                blockers: Vec::new(),
                suggested_actions: vec![
                    "Review the public contract and request a fix preview before editing"
                        .to_owned(),
                ],
                fix_eligibility: FixEligibility::PreviewOnly,
            });
        }
    }

    findings
}

struct MemberResults {
    findings: Vec<Finding>,
    retentions: Vec<RetentionReport>,
    deferrals: Vec<MemberDeferralDiagnostic>,
}

struct MemberDeferralDiagnostic {
    file_index: usize,
    span: SourceSpan,
    symbol: String,
    reason: String,
    capability_note: Option<String>,
}

fn build_member_results(
    facts: &[FileFacts],
    reachable: &[bool],
    open_world_files: &[bool],
    default_mode: MemberAnalysisMode,
    member_modes_by_file: Option<&BTreeMap<String, MemberAnalysisMode>>,
    deep_member_evidence: Option<&DeepMemberEvidence>,
) -> MemberResults {
    let mut results = MemberResults {
        findings: Vec::new(),
        retentions: Vec::new(),
        deferrals: Vec::new(),
    };
    for (file_index, file) in facts.iter().enumerate() {
        if !reachable.get(file_index).copied().unwrap_or(false) {
            continue;
        }
        let mode = member_modes_by_file
            .and_then(|modes| modes.get(&file.path))
            .copied()
            .unwrap_or(default_mode);
        for member in &file.member_facts {
            let candidate = member_candidate(
                member,
                file.source_kind,
                open_world_files.get(file_index).copied().unwrap_or(false),
                mode,
                deep_member_evidence
                    .and_then(|evidence| evidence.get(&(file.path.clone(), member.span.start))),
            );
            let symbol = format!("{}.{}", member.declaring_class, member.name);
            match analyze_member(mode, &candidate) {
                MemberDecision::Finding(finding) => {
                    results.findings.push(Finding {
                        issue_id: "ORP1004",
                        issue_type: "unusedMember",
                        workspace: ".".to_owned(),
                        target_profiles: vec!["default".to_owned()],
                        paths: vec![file.path.clone()],
                        span: Some(member.span),
                        symbol: Some(symbol.clone()),
                        dependency: None,
                        confidence: Confidence::High,
                        summary: format!("member {symbol} has no live reference"),
                        evidence: finding
                            .evidence
                            .iter()
                            .map(|evidence| member_evidence(*evidence).to_owned())
                            .collect(),
                        blockers: Vec::new(),
                        suggested_actions: vec![
                            "Review the member and request a fix preview before editing".to_owned(),
                        ],
                        fix_eligibility: FixEligibility::PreviewOnly,
                    });
                }
                MemberDecision::Retained(retention) => {
                    results.retentions.push(RetentionReport {
                        item: symbol,
                        item_type: "member",
                        workspace: ".".to_owned(),
                        target_profiles: vec!["default".to_owned()],
                        summary: "Member retained by conservative safety policy".to_owned(),
                        evidence: vec![member_retention_reason(retention.reason).to_owned()],
                    });
                }
                MemberDecision::Deferred(deferral) => {
                    results.deferrals.push(MemberDeferralDiagnostic {
                        file_index,
                        span: member.span,
                        symbol,
                        reason: member_deferral_reason(deferral.reason).to_owned(),
                        capability_note: deferral.capability_note,
                    });
                }
            }
        }
    }
    results
        .retentions
        .sort_by(|left, right| (&left.workspace, &left.item).cmp(&(&right.workspace, &right.item)));
    results
}

fn member_candidate(
    member: &ClassMemberFact,
    source_kind: SourceKind,
    open_world: bool,
    mode: MemberAnalysisMode,
    deep_resolution: Option<&DeepResolution>,
) -> MemberCandidate {
    MemberCandidate {
        id: MemberId {
            declaring_class: member.declaring_class.clone(),
            name: member.name.clone(),
            scope: if member.r#static {
                MemberScope::Static
            } else {
                MemberScope::Instance
            },
        },
        language: if matches!(source_kind, SourceKind::TypeScript | SourceKind::Tsx) {
            MemberLanguage::TypeScript
        } else {
            MemberLanguage::JavaScript
        },
        visibility: match member.visibility {
            ClassMemberVisibility::JavaScriptPrivate => MemberVisibility::JavaScriptPrivate,
            ClassMemberVisibility::TypeScriptPrivate => MemberVisibility::TypeScriptPrivate,
            ClassMemberVisibility::Protected => MemberVisibility::Protected,
            ClassMemberVisibility::Public => MemberVisibility::Public,
        },
        kind: match member.kind {
            ClassMemberKind::Method => MemberKind::Method,
            ClassMemberKind::Field => MemberKind::Field,
            ClassMemberKind::Getter => MemberKind::Getter,
            ClassMemberKind::Setter => MemberKind::Setter,
            ClassMemberKind::Accessor => MemberKind::Accessor,
        },
        directly_referenced: member.directly_referenced,
        framework_root: false,
        class_exported: member.class_exported,
        class_escaped: member.class_escaped,
        open_world,
        receiver_targets_complete: member.r#static
            || member.visibility == ClassMemberVisibility::JavaScriptPrivate,
        hazards: MemberHazards {
            decorated: member.decorated,
            emitted_decorator_metadata: member.emitted_decorator_metadata,
            unknown_bracket_access: member.unknown_bracket_access,
            reflected_or_enumerated: member.reflected_or_enumerated,
            serialized: member.serialized,
            object_spread: member.object_spread,
            proxied: member.proxied,
            passed_to_unknown_code: member.passed_to_unknown_code,
        },
        inheritance: InheritanceFacts {
            participates_in_inheritance: member.participates_in_inheritance,
            relationships_complete: member.relationships_complete,
            overrides_live_base_member: member.overrides_live_base_member,
            has_live_override: member.has_live_override,
            implements_external_contract: member.implements_external_contract,
        },
        deep_resolution: if mode == MemberAnalysisMode::Deep {
            deep_resolution
                .cloned()
                .unwrap_or_else(|| DeepResolution::Unavailable {
                    capability_note: "TypeScript deep evidence was unavailable for this candidate"
                        .to_owned(),
                })
        } else {
            DeepResolution::NotRequested
        },
    }
}

fn diagnostics_for_members(facts: &mut [FileFacts], deferrals: Vec<MemberDeferralDiagnostic>) {
    for deferral in deferrals {
        let Some(file) = facts.get_mut(deferral.file_index) else {
            continue;
        };
        let capability = deferral
            .capability_note
            .map_or_else(String::new, |note| format!("; {note}"));
        file.diagnostics.push(AnalysisDiagnostic {
            code: "member_analysis_deferred".to_owned(),
            path: file.path.clone(),
            severity: DiagnosticSeverity::Warning,
            span: Some(deferral.span),
            message: format!(
                "Member analysis for {} was deferred: {}{}",
                deferral.symbol, deferral.reason, capability
            ),
            blocks_reachability: false,
        });
    }
}

fn member_evidence(evidence: crate::analysis::members::FindingEvidence) -> &'static str {
    use crate::analysis::members::FindingEvidence;
    match evidence {
        FindingEvidence::NoSemanticReference => "No semantic reference reaches the member",
        FindingEvidence::JavaScriptPrivateIsLexicallyScoped => {
            "JavaScript private names are lexically scoped to their declaring class"
        }
        FindingEvidence::TypeScriptPrivateSurfaceDoesNotEscape => {
            "The TypeScript-private surface does not escape"
        }
        FindingEvidence::ClosedWorldClass => "The declaring class is analyzed as closed world",
        FindingEvidence::ClassDoesNotEscape => "The declaring class does not escape",
        FindingEvidence::StaticReceiverIsExplicit => "Static receiver resolution is explicit",
        FindingEvidence::ReceiverTargetsComplete => "Receiver targets are complete",
        FindingEvidence::OverrideRelationshipsComplete => "Override relationships are complete",
        FindingEvidence::DeepReceiverExcludesMember => {
            "Deep receiver analysis excludes this member"
        }
        FindingEvidence::DeepOverrideRelationshipsComplete => {
            "Deep override analysis found no live contract"
        }
    }
}

fn member_retention_reason(reason: crate::analysis::members::RetentionReason) -> &'static str {
    use crate::analysis::members::RetentionReason;
    match reason {
        RetentionReason::DirectReference => "A direct reference reaches the member",
        RetentionReason::FrameworkContract => "A framework contract retains the member",
        RetentionReason::OpenWorldPublicSurface => "The member belongs to an open public surface",
        RetentionReason::EscapedPublicSurface => "The public class surface escapes",
        RetentionReason::EscapedTypeScriptPrivateSurface => {
            "The TypeScript-private class surface escapes at runtime"
        }
        RetentionReason::DecoratorContract => "A decorator may observe the member",
        RetentionReason::EmittedDecoratorMetadata => "Emitted decorator metadata names the member",
        RetentionReason::UnknownBracketAccess => "A computed access may target the member",
        RetentionReason::ReflectionOrEnumeration => "Reflection or enumeration may observe it",
        RetentionReason::Serialization => "Serialization may observe the member",
        RetentionReason::ObjectSpread => "Object spread may copy the member",
        RetentionReason::Proxy => "A proxy may observe the member",
        RetentionReason::UnknownExternalCall => "Unknown external code may observe the member",
        RetentionReason::ExternalInterfaceContract => "An external interface requires the member",
        RetentionReason::LiveBaseContract => "A live base contract requires the override",
        RetentionReason::LiveOverride => "A live override depends on the member",
        RetentionReason::DeepReceiverReference => "Deep receiver analysis found a reference",
        RetentionReason::DeepLiveOverrideContract => "Deep analysis found a live override contract",
    }
}

fn member_deferral_reason(reason: crate::analysis::members::DeferralReason) -> &'static str {
    use crate::analysis::members::DeferralReason;
    match reason {
        DeferralReason::ModeDoesNotAnalyzeVisibility => {
            "the selected mode does not analyze this visibility"
        }
        DeferralReason::ReceiverTargetsAmbiguous => "receiver targets are ambiguous",
        DeferralReason::OverrideRelationshipsIncomplete => "override relationships are incomplete",
        DeferralReason::DeepEvidenceMissing => "deep TypeScript evidence was not requested",
        DeferralReason::DeepWorkerUnavailable => "the deep TypeScript worker is unavailable",
    }
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

fn has_fatal_file_diagnostic(facts: &FileFacts) -> bool {
    facts.diagnostics.iter().any(|diagnostic| {
        matches!(
            diagnostic.code.as_str(),
            "parse_failure" | "semantic_failure" | "unsupported_source_type"
        )
    })
}

fn unsupported_specifier_diagnostic(
    path: &str,
    specifier: &str,
    span: SourceSpan,
) -> AnalysisDiagnostic {
    AnalysisDiagnostic {
        code: "unsupported_specifier".to_owned(),
        path: path.to_owned(),
        severity: DiagnosticSeverity::Warning,
        span: Some(span),
        message: format!(
            "`{specifier}` is neither a declared external package nor a statically resolved local module"
        ),
        blocks_reachability: true,
    }
}

fn outside_universe_diagnostic(
    path: &str,
    specifier: &str,
    span: SourceSpan,
) -> AnalysisDiagnostic {
    AnalysisDiagnostic {
        code: "outside_file_universe".to_owned(),
        path: path.to_owned(),
        severity: DiagnosticSeverity::Error,
        span: Some(span),
        message: format!(
            "`{specifier}` resolved to a file that was not included in the supplied file universe"
        ),
        blocks_reachability: true,
    }
}

fn excluded_path_diagnostic(
    path: &str,
    specifier: &str,
    target: &Path,
    root: &Path,
    span: SourceSpan,
) -> AnalysisDiagnostic {
    let target_display = target.strip_prefix(root).map_or_else(
        |_| target.display().to_string(),
        |relative| relative.display().to_string(),
    );
    AnalysisDiagnostic {
        code: "resolved_into_excluded_path".to_owned(),
        path: path.to_owned(),
        severity: DiagnosticSeverity::Warning,
        span: Some(span),
        message: format!(
            "`{specifier}` resolved to `{target_display}`, which discovery excludes from the \
             source universe; it is treated as an external boundary"
        ),
        blocks_reachability: false,
    }
}

fn outside_analysis_root_diagnostic(
    path: &str,
    specifier: &str,
    span: SourceSpan,
) -> AnalysisDiagnostic {
    AnalysisDiagnostic {
        code: "outside_analysis_root".to_owned(),
        path: path.to_owned(),
        severity: DiagnosticSeverity::Error,
        span: Some(span),
        message: format!("`{specifier}` resolved to source outside the configured project root"),
        blocks_reachability: true,
    }
}

fn unsupported_imported_source_diagnostic(
    path: &str,
    specifier: &str,
    span: SourceSpan,
) -> AnalysisDiagnostic {
    AnalysisDiagnostic {
        code: "unsupported_imported_source".to_owned(),
        path: path.to_owned(),
        severity: DiagnosticSeverity::Warning,
        span: Some(span),
        message: format!(
            "`{specifier}` resolved to a source format whose embedded module graph is not modeled"
        ),
        blocks_reachability: true,
    }
}

fn unresolved_diagnostic(
    path: &str,
    specifier: &str,
    span: SourceSpan,
    reason: &str,
) -> AnalysisDiagnostic {
    AnalysisDiagnostic {
        code: "unresolved_import".to_owned(),
        path: path.to_owned(),
        severity: DiagnosticSeverity::Error,
        span: Some(span),
        message: format!("Could not resolve `{specifier}`: {reason}"),
        blocks_reachability: true,
    }
}

fn sort_diagnostics(diagnostics: &mut [AnalysisDiagnostic]) {
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
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        process,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::{
        FactCache, ScanRequest, SourceUniverseKind, is_analyzable_source, is_inert_asset,
        is_pnp_external_resolution, is_pnp_virtual_dependency_path, package_name,
        scan_with_fact_cache_measured,
    };
    use crate::{
        analysis::members::AnalysisMode,
        domain::{
            facts::DiagnosticSeverity,
            report::{Finding, ResolutionStatus},
        },
        limits::AnalysisLimits,
    };

    static NEXT_PROJECT_ID: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn extracts_package_names_without_mistaking_common_aliases_for_packages() {
        assert_eq!(package_name("chalk"), Some("chalk".to_owned()));
        assert_eq!(
            package_name("@scope/package/subpath"),
            Some("@scope/package".to_owned())
        );
        assert_eq!(package_name("@/components/button"), None);
        assert_eq!(package_name("./local.js"), None);
    }

    #[test]
    fn distinguishes_inert_assets_from_embedded_code_formats() {
        assert!(is_inert_asset(Path::new("styles.module.css")));
        assert!(!is_inert_asset(Path::new("component.vue")));
        assert!(!is_inert_asset(Path::new("native-addon.node")));
        assert!(is_analyzable_source(Path::new("component.tsx")));
    }

    #[test]
    fn pnp_archive_dependencies_are_external_before_host_canonicalization() {
        let virtual_dependency =
            Path::new("/workspace/.yarn/cache/chalk.zip/node_modules/chalk/source/index.js");

        assert!(is_pnp_virtual_dependency_path(virtual_dependency));
        assert!(is_pnp_external_resolution(
            "chalk",
            virtual_dependency,
            false,
            true,
        ));
        assert!(is_pnp_external_resolution(
            "undeclared",
            virtual_dependency,
            false,
            true,
        ));
        assert!(!is_pnp_external_resolution(
            "chalk",
            virtual_dependency,
            true,
            true,
        ));
        assert!(!is_pnp_external_resolution(
            "./chalk",
            virtual_dependency,
            false,
            true,
        ));
        assert!(!is_pnp_external_resolution(
            "chalk",
            virtual_dependency,
            false,
            false,
        ));
        assert!(!is_pnp_virtual_dependency_path(Path::new(
            "/workspace/archive.zip/src/index.js"
        )));
        assert!(!is_pnp_virtual_dependency_path(Path::new(
            "/workspace/src/node_modules-helper.js"
        )));
    }

    #[test]
    fn fact_cache_reuses_one_scan_snapshot_without_rereading_sources() {
        let project = TestProject::new();
        let source = project.root.join("index.js");
        fs::write(&source, "export const value = 1;\n").expect("write initial source");
        fs::write(project.root.join("package.json"), r#"{"private":true}"#)
            .expect("write manifest");
        let cache = FactCache::new(&project.root, b"config", b"profile").expect("create cache");
        let request = ScanRequest {
            root: project.root.clone(),
            entries: vec![source.clone()],
            files: vec![source.clone()],
        };
        let profiles = vec!["default".to_owned()];
        let (first, _) = scan_with_fact_cache_measured(
            &request,
            AnalysisLimits::default(),
            &cache,
            AnalysisMode::Balanced,
            None,
            None,
            &profiles,
            None,
            &[],
            None,
            &[],
            false,
            SourceUniverseKind::Explicit,
        )
        .expect("first scan");

        fs::write(&source, "this is not valid JavaScript {{{\n").expect("replace source");
        let (second, _) = scan_with_fact_cache_measured(
            &request,
            AnalysisLimits::default(),
            &cache,
            AnalysisMode::Balanced,
            None,
            None,
            &profiles,
            None,
            &[],
            None,
            &[],
            false,
            SourceUniverseKind::Explicit,
        )
        .expect("second scan");

        assert_eq!(
            first.files[0].content_digest,
            second.files[0].content_digest
        );
        assert_eq!(second.cache.as_ref().map(|cache| cache.hits), Some(1));
        assert_eq!(second.cache.as_ref().map(|cache| cache.misses), Some(0));
    }

    #[test]
    fn discovered_universes_treat_excluded_resolutions_as_external_boundaries() {
        let project = TestProject::new();
        fs::write(project.root.join("package.json"), r#"{"private":true}"#)
            .expect("write manifest");
        let entry = project.root.join("src/index.ts");
        fs::create_dir_all(project.root.join("src/generated/client"))
            .expect("create generated directory");
        fs::write(
            project.root.join("src/generated/client/index.js"),
            "export const value = 1;\n",
        )
        .expect("write generated client");
        fs::write(
            &entry,
            "import { value } from './generated/client';\nexport const main = value;\n",
        )
        .expect("write entry source");
        let unused = project.root.join("src/unused.ts");
        fs::write(&unused, "export const dead = 1;\n").expect("write unused source");

        let request = ScanRequest {
            root: project.root.clone(),
            entries: vec![entry.clone()],
            files: vec![entry.clone(), unused],
        };
        let cache = FactCache::new(&project.root, b"config", b"profile").expect("create cache");
        let (report, _) = scan_with_fact_cache_measured(
            &request,
            AnalysisLimits::default(),
            &cache,
            AnalysisMode::Balanced,
            None,
            None,
            &["default".to_owned()],
            None,
            &[],
            None,
            &[],
            false,
            SourceUniverseKind::Discovered,
        )
        .expect("discovered scan");

        let entry_file = report
            .files
            .iter()
            .find(|file| file.path.ends_with("src/index.ts"))
            .expect("entry file report");
        assert_eq!(
            entry_file.imports[0].status,
            ResolutionStatus::External,
            "an import into an excluded path stays an external boundary"
        );
        let diagnostic = report
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "resolved_into_excluded_path")
            .expect("excluded-path warning");
        assert_eq!(diagnostic.severity, DiagnosticSeverity::Warning);
        assert!(
            !diagnostic.blocks_reachability,
            "an excluded boundary must not suppress other findings"
        );
        assert_unreachable_file_finding(&report.findings, "src/unused.ts");
    }

    #[test]
    fn explicit_universes_still_report_resolutions_outside_the_universe() {
        let project = TestProject::new();
        fs::write(project.root.join("package.json"), r#"{"private":true}"#)
            .expect("write manifest");
        let entry = project.root.join("src/index.ts");
        fs::create_dir_all(project.root.join("src/generated/client"))
            .expect("create generated directory");
        fs::write(
            project.root.join("src/generated/client/index.js"),
            "export const value = 1;\n",
        )
        .expect("write generated client");
        fs::write(
            &entry,
            "import { value } from './generated/client';\nexport const main = value;\n",
        )
        .expect("write entry source");

        let request = ScanRequest {
            root: project.root.clone(),
            entries: vec![entry.clone()],
            files: vec![entry],
        };
        let report = crate::application::scan::scan(&request).expect("explicit scan");

        let entry_file = report
            .files
            .iter()
            .find(|file| file.path.ends_with("src/index.ts"))
            .expect("entry file report");
        assert_eq!(entry_file.imports[0].status, ResolutionStatus::Unresolved);
        let diagnostic = report
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "outside_file_universe")
            .expect("outside-universe error");
        assert_eq!(diagnostic.severity, DiagnosticSeverity::Error);
        assert!(diagnostic.blocks_reachability);
    }

    fn assert_unreachable_file_finding(findings: &[Finding], relative_path: &str) {
        assert!(
            findings.iter().any(|finding| {
                finding.paths.iter().any(|path| path == relative_path)
                    && finding.issue_id == "ORP1001"
            }),
            "expected an unreachable-file finding for `{relative_path}` in {findings:?}"
        );
    }

    struct TestProject {
        root: PathBuf,
    }

    impl TestProject {
        fn new() -> Self {
            loop {
                let id = NEXT_PROJECT_ID.fetch_add(1, Ordering::Relaxed);
                let root = std::env::temp_dir()
                    .join(format!("orphanode-scan-cache-test-{}-{id}", process::id()));
                match fs::create_dir(&root) {
                    Ok(()) => return Self { root },
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("create test project `{}`: {error}", root.display()),
                }
            }
        }
    }

    impl Drop for TestProject {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
