mod render;

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    error::Error,
    fmt::{self, Write as _},
    fs,
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
    process::{Command as ProcessCommand, ExitCode},
    time::{Duration, Instant},
};

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
use orphanode::{
    AnalysisIssue, DiscoveryError, Explanation, ExplanationStatus, ProjectScanError,
    ProjectScanMetrics, ProjectScanRequest, ProjectStageMetrics, ScanRequest,
    discover_source_files, explain, render_sarif, scan, scan_project, scan_project_measured,
};
use orphanode::{
    cache::{ContentDigest, Digest},
    discovery::{
        configuration::{
            AnalysisMode, ConfigurationError, ConfigurationLayers, ConfigurationOverride,
            WorldMode, discover_project_configurations, load_orphanode_configuration,
            merge_configuration_layers,
        },
        workspace::{PackageManager as DetectedPackageManager, WorkspaceError, discover_workspace},
    },
    fixes::{
        AnalysisConfidence, ApplyReport, CommandExecution, CommandExecutor, DependencyKind,
        DependencyRemoval, DirectDependency, EligibilityDecision, ExplicitFileFixScope,
        FixCandidate, FixEngine, FixError, FixPlan, FixPlanError, PackageManager,
        PackageManagerCommand, PreviewChangeKind, ProjectPath, PublicApiExposure,
        RevalidationOutcome, RevalidationRequest, Revalidator, WorldAssumption,
    },
};
use serde::Deserialize;

use crate::render::{RenderOptions, render_compact, render_human, safe_text};

#[derive(Debug, Parser)]
#[command(
    name = "orphanode",
    version,
    about = "Accuracy-first reachability analysis for JavaScript and TypeScript",
    long_about = "Find unreachable JavaScript and TypeScript files without executing project code. Every result includes its evidence, and incomplete analysis never becomes unsafe cleanup advice."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Analyze discovered or explicitly supplied source files from configured entries.
    Scan(ScanArgs),

    /// Explain why a file or package is retained, reported, or incomplete.
    Why(WhyArgs),

    /// Describe an `Orphanode` issue code and its safety policy.
    Explain(ExplainArgs),

    /// Validate and display the effective static project configuration.
    Config(ConfigArgs),

    /// Inspect or clean the project-local persistent cache.
    Cache(CacheArgs),
}

#[derive(Debug, Args)]
#[allow(clippy::struct_excessive_bools)]
struct ScanArgs {
    #[command(flatten)]
    universe: UniverseArgs,

    /// Output presentation. Human is designed for terminals; JSON and SARIF are stable for tools.
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    format: OutputFormat,

    /// Include findings whose paths are test files. Tests always stay in the
    /// reachability graph; this only controls whether they are reported.
    #[arg(long)]
    report_tests: bool,

    /// Color policy for human output. `NO_COLOR` is honored in auto mode.
    #[arg(long, value_enum, default_value_t = ColorChoice::Auto)]
    color: ColorChoice,

    /// Use ASCII structural characters in human output.
    #[arg(long)]
    ascii: bool,

    /// Pretty-print JSON or SARIF. Ignored for human output.
    #[arg(long)]
    pretty: bool,

    /// Analyze one declared workspace, relative to the controlling package.
    #[arg(long, value_name = "PATH")]
    workspace: Option<PathBuf>,

    /// Issue families to run.
    #[arg(long, value_enum, value_delimiter = ',')]
    issues: Vec<IssueChoice>,

    /// Analysis depth. Faster modes return fewer findings, never riskier findings.
    #[arg(long, value_enum)]
    mode: Option<ModeChoice>,

    /// Target profile; repeat or comma-separate to analyze a union.
    #[arg(long = "target", value_delimiter = ',', value_name = "PROFILE")]
    targets: Vec<String>,

    /// Explicitly analyze public packages as closed world.
    #[arg(long, action = ArgAction::SetTrue, conflicts_with = "open_world")]
    closed_world: bool,

    /// Explicitly analyze private packages as open world.
    #[arg(long, action = ArgAction::SetTrue)]
    open_world: bool,

    /// Print a conservative fix plan. No project files are changed.
    #[arg(long)]
    fix: bool,

    /// Apply the displayed fix plan, then re-scan. Requires --fix.
    #[arg(long, requires = "fix")]
    apply: bool,

    /// Explicit project-relative unused file authorized for deletion; repeat as needed.
    #[arg(long = "fix-file", value_name = "PATH", requires = "fix")]
    fix_files: Vec<PathBuf>,

    /// Explicit unused dependency authorized for removal; use WORKSPACE:PACKAGE when ambiguous.
    #[arg(
        long = "fix-dependency",
        value_name = "[WORKSPACE:]PACKAGE",
        requires = "fix"
    )]
    fix_dependencies: Vec<String>,

    /// Include stage-level wall-clock timings without changing machine-readable stdout.
    #[arg(long)]
    timings: bool,

    /// Emit stage timings, counts, cache activity, and diagnostics to stderr.
    #[arg(long)]
    debug: bool,
}

#[derive(Debug, Args)]
struct UniverseArgs {
    /// Physical project root used for path safety and display normalization.
    #[arg(long, default_value = ".", value_name = "DIR")]
    root: PathBuf,

    /// Entry file, relative to --root unless absolute; repeat for multiple roots.
    #[arg(long = "entry", value_name = "PATH")]
    entries: Vec<PathBuf>,

    /// Source file in the project universe; repeat to override automatic discovery.
    #[arg(long = "file", value_name = "PATH")]
    files: Vec<PathBuf>,

    /// JSON manifest with entry/entries and a complete files array.
    #[arg(long, value_name = "PATH")]
    files_from: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct WhyArgs {
    /// Project-relative file path or npm package name to explain.
    query: String,

    #[command(flatten)]
    universe: UniverseArgs,

    /// Output presentation for the explanation.
    #[arg(long, value_enum, default_value_t = ExplanationFormat::Human)]
    format: ExplanationFormat,

    /// Pretty-print JSON output.
    #[arg(long)]
    pretty: bool,
}

#[derive(Debug, Args)]
struct ExplainArgs {
    /// Stable issue identifier such as ORP1001.
    issue_id: String,

    /// Emit JSON instead of human-readable text.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ConfigArgs {
    /// Requested project root.
    #[arg(long, default_value = ".", value_name = "DIR")]
    root: PathBuf,

    /// Validate configuration and emit normalized JSON.
    #[arg(long)]
    check: bool,

    /// Pretty-print normalized JSON.
    #[arg(long)]
    pretty: bool,
}

#[derive(Debug, Args)]
struct CacheArgs {
    #[command(subcommand)]
    command: CacheCommand,

    /// Project root whose cache is addressed.
    #[arg(long, default_value = ".", value_name = "DIR", global = true)]
    root: PathBuf,
}

#[derive(Debug, Subcommand)]
enum CacheCommand {
    /// Remove only the project-local .orphanode/cache directory.
    Clean,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Human,
    /// One ts-prune-style line per finding: `path:line:col - CODE 'name' is unused`.
    Compact,
    Json,
    Sarif,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ExplanationFormat {
    Human,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ColorChoice {
    Auto,
    Always,
    Never,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ModeChoice {
    Fast,
    Balanced,
    Deep,
}

impl From<ModeChoice> for AnalysisMode {
    fn from(value: ModeChoice) -> Self {
        match value {
            ModeChoice::Fast => Self::Fast,
            ModeChoice::Balanced => Self::Balanced,
            ModeChoice::Deep => Self::Deep,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum IssueChoice {
    Files,
    Exports,
    Declarations,
    Members,
    Dependencies,
    Workspaces,
}

impl From<IssueChoice> for AnalysisIssue {
    fn from(value: IssueChoice) -> Self {
        match value {
            IssueChoice::Files => Self::Files,
            IssueChoice::Exports => Self::Exports,
            IssueChoice::Declarations => Self::Declarations,
            IssueChoice::Members => Self::Members,
            IssueChoice::Dependencies => Self::Dependencies,
            IssueChoice::Workspaces => Self::Workspaces,
        }
    }
}

#[derive(Debug, Deserialize)]
struct FileManifest {
    #[serde(default)]
    entry: Option<PathBuf>,
    #[serde(default)]
    entries: Vec<PathBuf>,
    files: Vec<PathBuf>,
}

fn main() -> ExitCode {
    match run() {
        Ok(exit_code) => exit_code,
        Err(error) => {
            eprintln!("orphanode: error: {error}");
            error.exit_code()
        }
    }
}

fn run() -> Result<ExitCode, CliError> {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan(arguments) => run_scan(&arguments),
        Command::Why(arguments) => run_why(arguments),
        Command::Explain(arguments) => run_explain(&arguments),
        Command::Config(arguments) => run_config(&arguments),
        Command::Cache(arguments) => run_cache(&arguments),
    }
}

#[derive(Debug, Clone, Copy)]
struct StageTelemetry {
    name: &'static str,
    duration: Duration,
    count: usize,
}

#[derive(Debug, Default)]
struct ScanTelemetry {
    stages: Vec<StageTelemetry>,
    cache: Option<(usize, usize, usize)>,
    effective_configuration: Option<String>,
}

impl ScanTelemetry {
    fn push(&mut self, name: &'static str, duration: Duration, count: usize) {
        self.stages.push(StageTelemetry {
            name,
            duration,
            count,
        });
    }

    fn extend_project_metrics(&mut self, metrics: &ProjectScanMetrics) {
        for (name, stage) in [
            ("workspace_discovery", metrics.workspace_discovery),
            ("configuration_loading", metrics.configuration_loading),
            ("file_discovery", metrics.file_discovery),
            ("plugin_discovery", metrics.plugin_discovery),
            ("fact_loading", metrics.fact_loading),
            ("module_resolution_graph", metrics.module_resolution_graph),
            (
                "reachability_rules_report",
                metrics.reachability_rules_report,
            ),
            ("cache_persistence", metrics.cache_persistence),
            ("deep_analysis", metrics.deep_analysis),
            ("profile_analysis", metrics.profile_analysis),
            ("policy", metrics.policy),
        ] {
            self.push_project_stage(name, stage);
        }
        self.cache = Some((
            metrics.cache.hits,
            metrics.cache.misses,
            metrics.cache.generation_writes,
        ));
    }

    fn push_project_stage(&mut self, name: &'static str, stage: ProjectStageMetrics) {
        self.push(name, stage.duration, stage.count);
    }

    fn extend_revalidation_metrics(&mut self, metrics: &ProjectScanMetrics) {
        for (name, stage) in [
            (
                "revalidation_workspace_discovery",
                metrics.workspace_discovery,
            ),
            (
                "revalidation_configuration_loading",
                metrics.configuration_loading,
            ),
            ("revalidation_file_discovery", metrics.file_discovery),
            ("revalidation_plugin_discovery", metrics.plugin_discovery),
            ("revalidation_fact_loading", metrics.fact_loading),
            (
                "revalidation_module_resolution_graph",
                metrics.module_resolution_graph,
            ),
            (
                "revalidation_reachability_rules_report",
                metrics.reachability_rules_report,
            ),
            ("revalidation_cache_persistence", metrics.cache_persistence),
            ("revalidation_deep_analysis", metrics.deep_analysis),
            ("revalidation_profile_analysis", metrics.profile_analysis),
            ("revalidation_policy", metrics.policy),
        ] {
            self.push_project_stage(name, stage);
        }
        self.cache = Some((
            metrics.cache.hits,
            metrics.cache.misses,
            metrics.cache.generation_writes,
        ));
    }
}

#[allow(clippy::too_many_lines)]
fn run_scan(arguments: &ScanArgs) -> Result<ExitCode, CliError> {
    if (arguments.fix || arguments.apply) && arguments.format != OutputFormat::Human {
        return Err(CliError::InvalidArguments(
            "--fix and --apply currently require --format human so the plan is reviewed before execution"
                .to_owned(),
        ));
    }
    validate_scan_universe_options(arguments)?;
    let started = Instant::now();
    let mut telemetry = ScanTelemetry::default();
    let analyzed_manifests = if arguments.fix && !arguments.fix_dependencies.is_empty() {
        let stage_started = Instant::now();
        let manifests = capture_analyzed_manifests(&arguments.universe.root)?;
        telemetry.push(
            "fix_preconditions",
            stage_started.elapsed(),
            manifests.len(),
        );
        manifests
    } else {
        BTreeMap::new()
    };
    let issues = selected_scan_issues(arguments);
    let mut report = if should_use_project_discovery(arguments) {
        let mut request = ProjectScanRequest::new(&arguments.universe.root);
        request.workspace.clone_from(&arguments.workspace);
        request.entries.clone_from(&arguments.universe.entries);
        request.mode = arguments.mode.map(AnalysisMode::from);
        request.closed_world = if arguments.closed_world {
            Some(true)
        } else if arguments.open_world {
            Some(false)
        } else {
            None
        };
        request.target_profiles.clone_from(&arguments.targets);
        request.issues.clone_from(&issues);
        if arguments.debug || arguments.timings {
            let output = scan_project_measured(&request)?;
            telemetry.extend_project_metrics(&output.metrics);
            if arguments.debug {
                telemetry.effective_configuration =
                    Some(serde_json::to_string(&output.effective_configuration)?);
            }
            output.report
        } else {
            scan_project(&request)?
        }
    } else {
        let stage_started = Instant::now();
        let (entries, files) = load_file_universe(&arguments.universe)?;
        let mut report = scan(&ScanRequest {
            root: arguments.universe.root.clone(),
            entries,
            files,
        })?;
        filter_findings(&mut report, &issues);
        telemetry.push("analysis", stage_started.elapsed(), report.summary.files);
        report
    };
    if telemetry.cache.is_none()
        && let Some(cache) = &report.cache
    {
        telemetry.cache = Some((
            cache.hits,
            cache.misses,
            usize::from(cache.generation_written),
        ));
    }
    let exit_code = report_exit_code(&report);
    let render_started = Instant::now();
    let mut output = match arguments.format {
        OutputFormat::Human => render_human(
            &report,
            RenderOptions {
                color: should_colorize(arguments.color),
                unicode: should_use_unicode(arguments.ascii),
            },
        ),
        OutputFormat::Compact => render_compact(&report, &arguments.universe.root),
        OutputFormat::Json if arguments.pretty => serde_json::to_string_pretty(&report)?,
        OutputFormat::Json => serde_json::to_string(&report)?,
        OutputFormat::Sarif if arguments.pretty => {
            serde_json::to_string_pretty(&render_sarif(&report))?
        }
        OutputFormat::Sarif => serde_json::to_string(&render_sarif(&report))?,
    };
    telemetry.push("render", render_started.elapsed(), output.len());
    if arguments.fix {
        let stage_started = Instant::now();
        let fix_output = run_fix_workflow(
            &arguments.universe.root,
            &report,
            arguments.apply,
            arguments,
            &analyzed_manifests,
        )?;
        output.push_str(&fix_output.rendered);
        if let Some(metrics) = &fix_output.revalidation_metrics {
            telemetry.extend_revalidation_metrics(metrics);
        }
        if let Some(updated) = fix_output.report {
            report = updated;
            output.push_str("\nPOST-APPLY SCAN\n");
            output.push_str(&render_human(
                &report,
                RenderOptions {
                    color: should_colorize(arguments.color),
                    unicode: should_use_unicode(arguments.ascii),
                },
            ));
        }
        telemetry.push(
            "fix_workflow",
            stage_started.elapsed(),
            arguments.fix_files.len() + arguments.fix_dependencies.len(),
        );
    }
    let total = started.elapsed();
    if arguments.debug {
        emit_debug_telemetry(&telemetry, &report, total);
    }
    if arguments.timings {
        if arguments.format == OutputFormat::Human {
            append_human_timings(&mut output, &telemetry, total);
        } else {
            emit_machine_timings(&telemetry, total);
        }
    }
    write_stdout(&output)?;
    Ok(if arguments.apply {
        report_exit_code(&report)
    } else {
        exit_code
    })
}

fn append_human_timings(output: &mut String, telemetry: &ScanTelemetry, total: Duration) {
    output.push_str("\nTIMINGS\n");
    for stage in &telemetry.stages {
        let _ = writeln!(
            output,
            "  {:<24} {} ms",
            stage.name,
            stage.duration.as_millis()
        );
    }
    let _ = writeln!(output, "  {:<24} {} ms", "total", total.as_millis());
}

fn emit_machine_timings(telemetry: &ScanTelemetry, total: Duration) {
    for stage in &telemetry.stages {
        eprintln!(
            "orphanode: timings: {} {} ms",
            stage.name,
            stage.duration.as_millis()
        );
    }
    eprintln!("orphanode: timings: total {} ms", total.as_millis());
}

fn emit_debug_telemetry(
    telemetry: &ScanTelemetry,
    report: &orphanode::ScanReport,
    total: Duration,
) {
    for stage in &telemetry.stages {
        eprintln!(
            "orphanode: debug: stage={} elapsed_ms={} count={}",
            stage.name,
            stage.duration.as_millis(),
            stage.count
        );
    }
    eprintln!(
        "orphanode: debug: stage=total elapsed_ms={} count={}",
        total.as_millis(),
        report.summary.files
    );
    if let Some((hits, misses, generation_writes)) = telemetry.cache {
        eprintln!(
            "orphanode: debug: cache hits={hits} misses={misses} generation_writes={generation_writes}"
        );
    } else {
        eprintln!("orphanode: debug: cache unavailable");
    }
    if let Some(effective_configuration) = &telemetry.effective_configuration {
        eprintln!("orphanode: debug: effective_configuration={effective_configuration}");
    }
    eprintln!(
        "orphanode: debug: report files={} reachable={} unreachable={} incomplete={} findings={} diagnostics={}",
        report.summary.files,
        report.summary.reachable_files,
        report.summary.unreachable_files,
        report.summary.incomplete_files,
        report.findings.len(),
        report.diagnostics.len()
    );
    for diagnostic in &report.diagnostics {
        eprintln!(
            "orphanode: debug: diagnostic code={} path={} severity={:?} blocks_reachability={} message={}",
            safe_text(&diagnostic.code, "<invalid code>"),
            safe_text(&diagnostic.path, "<invalid path>"),
            diagnostic.severity,
            diagnostic.blocks_reachability,
            safe_text(&diagnostic.message, "<invalid message>")
        );
    }
}

fn selected_issues(choices: &[IssueChoice]) -> BTreeSet<AnalysisIssue> {
    if choices.is_empty() {
        return AnalysisIssue::all();
    }
    choices.iter().copied().map(AnalysisIssue::from).collect()
}

fn selected_scan_issues(arguments: &ScanArgs) -> BTreeSet<AnalysisIssue> {
    if uses_explicit_file_universe(&arguments.universe) && arguments.issues.is_empty() {
        return [
            AnalysisIssue::Files,
            AnalysisIssue::Exports,
            AnalysisIssue::Declarations,
            AnalysisIssue::Members,
        ]
        .into_iter()
        .collect();
    }
    selected_issues(&arguments.issues)
}

fn filter_findings(report: &mut orphanode::ScanReport, issues: &BTreeSet<AnalysisIssue>) {
    report.findings.retain(|finding| match finding.issue_type {
        "unusedFiles" => issues.contains(&AnalysisIssue::Files),
        "unusedExport" => issues.contains(&AnalysisIssue::Exports),
        "unusedDeclaration" => issues.contains(&AnalysisIssue::Declarations),
        "unusedMember" => issues.contains(&AnalysisIssue::Members),
        "unusedDependency" | "unlistedDependency" | "misplacedDependency" => {
            issues.contains(&AnalysisIssue::Dependencies)
        }
        "unusedWorkspace" => issues.contains(&AnalysisIssue::Workspaces),
        _ => true,
    });
}

fn should_use_project_discovery(arguments: &ScanArgs) -> bool {
    !uses_explicit_file_universe(&arguments.universe)
}

fn uses_explicit_file_universe(arguments: &UniverseArgs) -> bool {
    arguments.files_from.is_some() || !arguments.files.is_empty()
}

fn validate_scan_universe_options(arguments: &ScanArgs) -> Result<(), CliError> {
    if !uses_explicit_file_universe(&arguments.universe) {
        return Ok(());
    }
    if arguments.workspace.is_some() {
        return Err(CliError::InvalidArguments(
            "--workspace cannot be combined with --file or --files-from".to_owned(),
        ));
    }

    let mut unsupported = Vec::new();
    if arguments.mode.is_some() {
        unsupported.push("--mode");
    }
    if !arguments.targets.is_empty() {
        unsupported.push("--target");
    }
    if arguments.closed_world {
        unsupported.push("--closed-world");
    }
    if arguments.open_world {
        unsupported.push("--open-world");
    }
    if arguments
        .issues
        .iter()
        .any(|issue| matches!(issue, IssueChoice::Dependencies | IssueChoice::Workspaces))
    {
        unsupported.push("--issues dependencies/workspaces");
    }
    if arguments.fix || arguments.apply {
        unsupported.push("--fix/--apply");
    }
    if unsupported.is_empty() {
        return Ok(());
    }

    Err(CliError::InvalidArguments(format!(
        "{} cannot be used with the explicit --file/--files-from universe because the legacy scanner cannot honor those project options",
        unsupported.join(", ")
    )))
}

#[derive(Debug, Clone)]
struct AnalyzedManifest {
    working_directory: ProjectPath,
    content: ContentDigest,
}

struct FixWorkflowOutput {
    rendered: String,
    report: Option<orphanode::ScanReport>,
    revalidation_metrics: Option<ProjectScanMetrics>,
}

fn capture_analyzed_manifests(root: &Path) -> Result<BTreeMap<String, AnalyzedManifest>, CliError> {
    let workspace = discover_workspace(root)?;
    let mut manifests = BTreeMap::new();
    for package in &workspace.packages {
        let workspace_name = if package.root.as_os_str().is_empty() {
            ".".to_owned()
        } else {
            package.root.to_string_lossy().replace('\\', "/")
        };
        let working_directory = if workspace_name == "." {
            ProjectPath::root()
        } else {
            ProjectPath::new(workspace_name.clone())?
        };
        let bytes = fs::read(&package.manifest_path).map_err(|source| CliError::ReadManifest {
            path: package.manifest_path.clone(),
            source,
        })?;
        manifests.insert(
            workspace_name,
            AnalyzedManifest {
                working_directory,
                content: ContentDigest::of_bytes(&bytes),
            },
        );
    }
    Ok(manifests)
}

#[allow(clippy::too_many_lines)]
fn run_fix_workflow(
    root: &Path,
    report: &orphanode::ScanReport,
    apply: bool,
    arguments: &ScanArgs,
    analyzed_manifests: &BTreeMap<String, AnalyzedManifest>,
) -> Result<FixWorkflowOutput, CliError> {
    let requested_fix_files = arguments
        .fix_files
        .iter()
        .map(|path| {
            ProjectPath::new(path.to_string_lossy().into_owned())
                .map(|path| path.as_str().to_owned())
                .map_err(CliError::from)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let requested_fix_dependencies = arguments
        .fix_dependencies
        .iter()
        .map(|dependency| dependency.trim())
        .map(|dependency| {
            if dependency.is_empty() || dependency.chars().any(char::is_control) {
                Err(CliError::InvalidArguments(
                    "--fix-dependency values must be non-empty package selectors".to_owned(),
                ))
            } else {
                Ok(dependency.to_owned())
            }
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if apply && report.status != orphanode::domain::report::AnalysisStatus::Complete {
        return Err(CliError::InvalidArguments(
            "refusing to apply fixes while analysis is incomplete; resolve blocking diagnostics first"
                .to_owned(),
        ));
    }
    let workspace = discover_workspace(root)?;
    let manager = fix_package_manager(workspace.package_manager.selected.as_ref());
    let mut plan = FixPlan::new(
        "orphanode-scan-fix",
        "Remove selected eligible unused files and direct dependencies",
    )?;
    let mut selected_dependencies = BTreeSet::new();
    let mut selected_dependency_selectors = BTreeSet::new();
    let mut package_removals = BTreeMap::<String, Vec<DependencyRemoval>>::new();
    let mut selected_files = BTreeSet::new();
    for finding in &report.findings {
        if finding.issue_type == "unusedDependency"
            && dependency_fix_can_be_planned(finding.fix_eligibility, apply)
            && manager.is_some()
            && let Some(dependency) = finding.dependency.as_deref()
        {
            let qualified = format!("{}:{dependency}", finding.workspace);
            let requested = requested_fix_dependencies.contains(dependency)
                || requested_fix_dependencies.contains(&qualified);
            if !requested {
                continue;
            }
            if requested_fix_dependencies.contains(dependency)
                && report
                    .findings
                    .iter()
                    .filter(|candidate| {
                        candidate.issue_type == "unusedDependency"
                            && candidate.dependency.as_deref() == Some(dependency)
                            && dependency_fix_can_be_planned(candidate.fix_eligibility, apply)
                    })
                    .count()
                    > 1
            {
                return Err(CliError::InvalidArguments(format!(
                    "dependency selector `{dependency}` is ambiguous; use WORKSPACE:{dependency}"
                )));
            }
            let dependency = DirectDependency::new(dependency, DependencyKind::Production)
                .map_err(|message| CliError::InvalidArguments(message.to_owned()))?;
            selected_dependencies.insert(format!("{}:{}", finding.workspace, dependency.name));
            selected_dependency_selectors.insert(
                if requested_fix_dependencies.contains(&qualified) {
                    qualified
                } else {
                    dependency.name.clone()
                },
            );
            let removal = DependencyRemoval::new(dependency, finding.summary.clone())
                .map_err(|message| CliError::InvalidArguments(message.to_owned()))?;
            package_removals
                .entry(finding.workspace.clone())
                .or_default()
                .push(removal);
        }
        if finding.issue_type == "unusedFiles"
            && finding.fix_eligibility == orphanode::domain::report::FixEligibility::Eligible
        {
            for path in &finding.paths {
                if !requested_fix_files.contains(path) {
                    continue;
                }
                if !selected_files.insert(path.clone()) {
                    continue;
                }
                let file = report
                    .files
                    .iter()
                    .find(|file| file.path == *path)
                    .ok_or_else(|| {
                        CliError::InvalidArguments(format!(
                            "eligible file finding references missing report path `{path}`"
                        ))
                    })?;
                let digest = Digest::from_hex(&file.content_digest).map_err(|error| {
                    CliError::InvalidArguments(format!(
                        "report contains an invalid content digest for `{path}`: {error}"
                    ))
                })?;
                let decision = FixCandidate {
                    confidence: AnalysisConfidence::High,
                    world: WorldAssumption::Closed,
                    public_api: PublicApiExposure::OutsidePublicApi,
                    blockers: Vec::new(),
                    expected_content: Some(ContentDigest(digest)),
                    preserves_trivia_and_semantics: true,
                }
                .evaluate();
                let EligibilityDecision::Eligible(eligibility) = decision else {
                    return Err(CliError::InvalidArguments(format!(
                        "file `{path}` no longer satisfies the fix safety policy"
                    )));
                };
                plan.add_file_deletion(
                    eligibility,
                    ProjectPath::new(path.clone())?,
                    ExplicitFileFixScope::selected(),
                    finding.summary.clone(),
                )?;
            }
        }
    }
    let unavailable_files = requested_fix_files
        .difference(&selected_files)
        .cloned()
        .collect::<Vec<_>>();
    if !unavailable_files.is_empty() {
        return Err(CliError::InvalidArguments(format!(
            "--fix-file requires an eligible closed-world unused-file finding; unavailable: {}",
            unavailable_files.join(", ")
        )));
    }
    let unavailable_dependencies = requested_fix_dependencies
        .difference(&selected_dependency_selectors)
        .cloned()
        .collect::<Vec<_>>();
    if !unavailable_dependencies.is_empty() {
        return Err(CliError::InvalidArguments(format!(
            "--fix-dependency requires an eligible unused direct dependency and a supported package manager; unavailable: {}",
            unavailable_dependencies.join(", ")
        )));
    }
    if !package_removals.is_empty() {
        let Some(manager) = manager else {
            return Err(CliError::InvalidArguments(
                "selected dependency fixes require an unambiguous supported package manager"
                    .to_owned(),
            ));
        };
        for (workspace_name, removals) in package_removals {
            let analyzed_manifest = analyzed_manifests.get(&workspace_name).ok_or_else(|| {
                CliError::InvalidArguments(format!(
                    "dependency finding references unknown workspace `{workspace_name}`"
                ))
            })?;
            plan.add_package_command(
                PackageManagerCommand::remove_direct_dependencies(
                    manager,
                    analyzed_manifest.working_directory.clone(),
                    analyzed_manifest.content,
                    removals,
                )
                .map_err(|message| CliError::InvalidArguments(message.to_owned()))?,
            );
        }
    }
    if plan.package_commands.is_empty() && plan.file_changes.is_empty() {
        return Ok(FixWorkflowOutput {
            rendered: "\nFIX PREVIEW\n  No items selected. Add --fix-file PATH or --fix-dependency [WORKSPACE:]PACKAGE to preview an exact plan. Declaration and member findings remain review-only unless an exact, trivia-preserving edit is proven.\n"
                .to_owned(),
            report: None,
            revalidation_metrics: None,
        });
    }

    let engine = FixEngine::new(&workspace.workspace_root)?;
    let preview = engine.preview(&plan)?;
    let mut output = String::from("\nFIX PREVIEW\n");
    let _ = writeln!(output, "  fingerprint  {}", preview.fingerprint());
    if !preview.file_changes.is_empty() {
        let _ = writeln!(output, "  FILE CHANGES ({})", preview.file_changes.len());
    }
    for (change, planned) in preview
        .file_changes
        .iter()
        .zip(&preview.plan().file_changes)
    {
        let action = match change.kind {
            PreviewChangeKind::Modify => "modify",
            PreviewChangeKind::Delete => "delete",
        };
        let _ = writeln!(
            output,
            "    {action}  {}\n      reason  {}",
            safe_text(change.path.as_str(), "<invalid path>"),
            safe_text(planned.reason(), "<missing reason>")
        );
    }
    let dependency_change_count = preview
        .plan()
        .package_commands
        .iter()
        .map(|command| command.removals.len())
        .sum::<usize>();
    if dependency_change_count > 0 {
        let _ = writeln!(output, "  DEPENDENCY CHANGES ({dependency_change_count})");
    }
    for command in &preview.plan().package_commands {
        let _ = writeln!(
            output,
            "    workspace  {}\n      manifest  {}",
            safe_text(command.working_directory.as_str(), "."),
            safe_text(command.manifest_path.as_str(), "package.json")
        );
        for removal in &command.removals {
            let _ = writeln!(
                output,
                "      remove  {}\n        reason  {}",
                safe_text(&removal.dependency.name, "<invalid dependency>"),
                safe_text(&removal.reason, "<missing reason>")
            );
        }
        let _ = writeln!(
            output,
            "      command  {}",
            safe_text(&command.display_command(), "<invalid command>")
        );
    }
    if !apply {
        output.push_str(
            "  Preview only. Re-run with --fix --apply to authorize exactly this plan.\n",
        );
        return Ok(FixWorkflowOutput {
            rendered: output,
            report: None,
            revalidation_metrics: None,
        });
    }

    let mut executor = ProcessPackageManager;
    let mut revalidator = ProjectRevalidator {
        request: project_request_from_arguments(arguments),
        selected_dependencies,
        selected_files,
        baseline_findings: report.findings.iter().map(finding_key).collect(),
        baseline_diagnostics: report.diagnostics.iter().map(diagnostic_key).collect(),
        baseline_import_gaps: import_gap_keys(report),
        report: None,
        metrics: None,
    };
    let apply_report = engine.apply(
        &preview,
        preview.explicit_apply_authorization(),
        &mut executor,
        &mut revalidator,
    )?;
    render_apply_report(&mut output, &apply_report);
    if let RevalidationOutcome::Failed { diagnostics } = &apply_report.revalidation {
        return Err(CliError::FixRevalidation(format!(
            "fixes were applied but post-apply validation failed; changes were not rolled back: {}",
            diagnostics.join("; ")
        )));
    }
    Ok(FixWorkflowOutput {
        rendered: output,
        report: revalidator.report,
        revalidation_metrics: revalidator.metrics,
    })
}

fn dependency_fix_can_be_planned(
    eligibility: orphanode::domain::report::FixEligibility,
    apply: bool,
) -> bool {
    use orphanode::domain::report::FixEligibility;

    match eligibility {
        FixEligibility::Eligible => true,
        FixEligibility::PreviewOnly => !apply,
        FixEligibility::NotAvailable | FixEligibility::Blocked => false,
    }
}

fn project_request_from_arguments(arguments: &ScanArgs) -> ProjectScanRequest {
    let mut request = ProjectScanRequest::new(&arguments.universe.root);
    request.workspace.clone_from(&arguments.workspace);
    request.entries.clone_from(&arguments.universe.entries);
    request.mode = arguments.mode.map(AnalysisMode::from);
    request.closed_world = if arguments.closed_world {
        Some(true)
    } else if arguments.open_world {
        Some(false)
    } else {
        None
    };
    request.target_profiles.clone_from(&arguments.targets);
    request.issues = selected_issues(&arguments.issues);
    request.report_tests = arguments.report_tests;
    request
}

fn fix_package_manager(manager: Option<&DetectedPackageManager>) -> Option<PackageManager> {
    match manager? {
        DetectedPackageManager::Npm => Some(PackageManager::Npm),
        DetectedPackageManager::Pnpm => Some(PackageManager::Pnpm),
        DetectedPackageManager::Yarn => Some(PackageManager::Yarn),
        DetectedPackageManager::Bun => Some(PackageManager::Bun),
        DetectedPackageManager::Other(_) => None,
    }
}

struct ProcessPackageManager;

impl CommandExecutor for ProcessPackageManager {
    fn execute(
        &mut self,
        project_root: &Path,
        command: &PackageManagerCommand,
    ) -> CommandExecution {
        let working_directory = if command.working_directory.as_str() == "." {
            project_root.to_path_buf()
        } else {
            project_root.join(command.working_directory.as_path())
        };
        match ProcessCommand::new(&command.program)
            .args(&command.arguments)
            .current_dir(working_directory)
            .output()
        {
            Ok(output) => CommandExecution {
                command: command.clone(),
                success: output.status.success(),
                exit_code: output.status.code(),
                message: String::from_utf8_lossy(if output.status.success() {
                    &output.stdout
                } else {
                    &output.stderr
                })
                .trim()
                .to_owned(),
            },
            Err(error) => CommandExecution {
                command: command.clone(),
                success: false,
                exit_code: None,
                message: error.to_string(),
            },
        }
    }
}

struct ProjectRevalidator {
    request: ProjectScanRequest,
    selected_dependencies: BTreeSet<String>,
    selected_files: BTreeSet<String>,
    baseline_findings: BTreeSet<String>,
    baseline_diagnostics: BTreeSet<String>,
    baseline_import_gaps: BTreeSet<String>,
    report: Option<orphanode::ScanReport>,
    metrics: Option<ProjectScanMetrics>,
}

impl Revalidator for ProjectRevalidator {
    fn revalidate(&mut self, request: RevalidationRequest<'_>) -> RevalidationOutcome {
        let failed_commands = request
            .package_commands
            .iter()
            .filter(|execution| !execution.success)
            .map(|execution| execution.command.display_command())
            .collect::<Vec<_>>();
        if !failed_commands.is_empty() {
            return RevalidationOutcome::Failed {
                diagnostics: vec![format!(
                    "package-manager command failed: {}",
                    failed_commands.join(", ")
                )],
            };
        }
        match scan_project_measured(&self.request) {
            Ok(output) => {
                self.metrics = Some(output.metrics);
                let report = output.report;
                let mut failures = Vec::new();
                if report.status != orphanode::domain::report::AnalysisStatus::Complete {
                    failures.push(
                        "post-apply analysis is incomplete; inspect blocking diagnostics"
                            .to_owned(),
                    );
                }
                let residual_dependencies = report
                    .findings
                    .iter()
                    .filter_map(|finding| {
                        finding
                            .dependency
                            .as_ref()
                            .map(|dependency| format!("{}:{dependency}", finding.workspace))
                    })
                    .filter(|dependency| self.selected_dependencies.contains(dependency))
                    .collect::<Vec<_>>();
                let residual_files = report
                    .files
                    .iter()
                    .filter(|file| self.selected_files.contains(&file.path))
                    .map(|file| file.path.clone())
                    .collect::<Vec<_>>();
                let new_findings = report
                    .findings
                    .iter()
                    .map(finding_key)
                    .filter(|key| !self.baseline_findings.contains(key))
                    .collect::<Vec<_>>();
                let new_diagnostics = report
                    .diagnostics
                    .iter()
                    .map(diagnostic_key)
                    .filter(|key| !self.baseline_diagnostics.contains(key))
                    .collect::<Vec<_>>();
                let new_import_gaps = import_gap_keys(&report)
                    .difference(&self.baseline_import_gaps)
                    .cloned()
                    .collect::<Vec<_>>();
                self.report = Some(report);
                if !residual_dependencies.is_empty() || !residual_files.is_empty() {
                    let mut residual = residual_dependencies;
                    residual.extend(residual_files);
                    failures.push(format!("findings remain for: {}", residual.join(", ")));
                }
                if !new_findings.is_empty() {
                    failures.push(format!(
                        "new findings appeared: {}",
                        new_findings.join(", ")
                    ));
                }
                if !new_diagnostics.is_empty() {
                    failures.push(format!(
                        "new diagnostics appeared: {}",
                        new_diagnostics.join(", ")
                    ));
                }
                if !new_import_gaps.is_empty() {
                    failures.push(format!(
                        "new unresolved or unsupported imports appeared: {}",
                        new_import_gaps.join(", ")
                    ));
                }
                if failures.is_empty() {
                    RevalidationOutcome::Passed {
                        notes: vec![
                            "Post-apply scan is complete with no new findings, diagnostics, or import gaps"
                                .to_owned(),
                        ],
                    }
                } else {
                    RevalidationOutcome::Failed {
                        diagnostics: failures,
                    }
                }
            }
            Err(error) => RevalidationOutcome::Failed {
                diagnostics: vec![error.to_string()],
            },
        }
    }
}

fn finding_key(finding: &orphanode::domain::report::Finding) -> String {
    format!(
        "{}:{}:{}:{}:{}:{:?}",
        finding.issue_id,
        finding.workspace,
        finding.paths.join("|"),
        finding.symbol.as_deref().unwrap_or(""),
        finding.dependency.as_deref().unwrap_or(""),
        finding.confidence,
    )
}

fn diagnostic_key(diagnostic: &orphanode::domain::facts::AnalysisDiagnostic) -> String {
    format!(
        "{}:{}:{:?}:{}:{}",
        diagnostic.code,
        diagnostic.path,
        diagnostic.span,
        diagnostic.blocks_reachability,
        diagnostic.message,
    )
}

fn import_gap_keys(report: &orphanode::ScanReport) -> BTreeSet<String> {
    use orphanode::domain::report::ResolutionStatus;

    report
        .files
        .iter()
        .flat_map(|file| {
            file.imports
                .iter()
                .filter(|import| {
                    matches!(
                        import.status,
                        ResolutionStatus::Unresolved | ResolutionStatus::Unsupported
                    )
                })
                .map(|import| format!("{}:{}:{:?}", file.path, import.specifier, import.span))
        })
        .collect()
}

fn render_apply_report(output: &mut String, report: &ApplyReport) {
    output.push_str("\nAPPLY\n");
    for execution in &report.package_commands {
        let _ = writeln!(
            output,
            "  {}  {}",
            if execution.success { "ok" } else { "failed" },
            safe_text(&execution.command.display_command(), "<invalid command>")
        );
        if !execution.message.is_empty() {
            let _ = writeln!(
                output,
                "    {}",
                safe_text(&execution.message, "<no process output>")
            );
        }
    }
    match &report.revalidation {
        RevalidationOutcome::Passed { notes } => {
            output.push_str("  revalidation  passed\n");
            for note in notes {
                let _ = writeln!(output, "    {}", safe_text(note, "<empty note>"));
            }
        }
        RevalidationOutcome::Failed { diagnostics } => {
            output.push_str("  revalidation  failed\n");
            for diagnostic in diagnostics {
                let _ = writeln!(
                    output,
                    "    {}",
                    safe_text(diagnostic, "<empty diagnostic>")
                );
            }
        }
    }
}

fn run_why(arguments: WhyArgs) -> Result<ExitCode, CliError> {
    let report = if uses_explicit_file_universe(&arguments.universe) {
        let (entries, files) = load_file_universe(&arguments.universe)?;
        scan(&ScanRequest {
            root: arguments.universe.root,
            entries,
            files,
        })?
    } else {
        let mut request = ProjectScanRequest::new(&arguments.universe.root);
        request.entries.clone_from(&arguments.universe.entries);
        scan_project(&request)?
    };
    let explanation = explain(&report, &arguments.query);
    let exit_code = match explanation.status {
        ExplanationStatus::Incomplete => ExitCode::from(2),
        ExplanationStatus::NotFound => ExitCode::from(1),
        ExplanationStatus::Retained | ExplanationStatus::Reported => ExitCode::SUCCESS,
    };
    let output = match arguments.format {
        ExplanationFormat::Human => render_explanation(&explanation),
        ExplanationFormat::Json if arguments.pretty => serde_json::to_string_pretty(&explanation)?,
        ExplanationFormat::Json => serde_json::to_string(&explanation)?,
    };
    write_stdout(&output)?;
    Ok(exit_code)
}

fn run_explain(arguments: &ExplainArgs) -> Result<ExitCode, CliError> {
    let Some((title, policy)) = issue_description(&arguments.issue_id) else {
        return Err(CliError::InvalidArguments(format!(
            "unknown issue identifier `{}`",
            arguments.issue_id
        )));
    };
    let output = if arguments.json {
        serde_json::to_string_pretty(&serde_json::json!({
            "issueId": arguments.issue_id,
            "title": title,
            "policy": policy,
        }))?
    } else {
        format!("{}  {}\n\n{}", arguments.issue_id, title, policy)
    };
    write_stdout(&output)?;
    Ok(ExitCode::SUCCESS)
}

fn run_config(arguments: &ConfigArgs) -> Result<ExitCode, CliError> {
    let workspace = discover_workspace(&arguments.root)?;
    let configuration = load_orphanode_configuration(&workspace.workspace_root)?;
    let project_configurations = discover_project_configurations(&workspace.workspace_root)?;
    let empty = ConfigurationOverride::default();
    let effective = workspace
        .packages
        .iter()
        .map(|package| {
            let name = if package.root.as_os_str().is_empty() {
                ".".to_owned()
            } else {
                package.root.to_string_lossy().replace('\\', "/")
            };
            let inferred = ConfigurationOverride {
                mode: Some(AnalysisMode::Balanced),
                world: Some(if package.manifest.private {
                    WorldMode::Closed
                } else {
                    WorldMode::Open
                }),
                ..ConfigurationOverride::default()
            };
            let workspace_configuration = configuration
                .configuration
                .workspaces
                .get(&name)
                .unwrap_or(&empty);
            let value = merge_configuration_layers(ConfigurationLayers {
                inferred: &inferred,
                root: &configuration.configuration.root,
                workspace: workspace_configuration,
                cli: &empty,
            });
            (name, value)
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let value = serde_json::json!({
        "valid": true,
        "checked": arguments.check,
        "workspace": workspace,
        "orphanode": configuration,
        "effective": effective,
        "projectConfigurations": project_configurations,
    });
    let output = if arguments.pretty {
        serde_json::to_string_pretty(&value)?
    } else {
        serde_json::to_string(&value)?
    };
    write_stdout(&output)?;
    Ok(ExitCode::SUCCESS)
}

fn run_cache(arguments: &CacheArgs) -> Result<ExitCode, CliError> {
    match &arguments.command {
        CacheCommand::Clean => {
            let root = arguments
                .root
                .canonicalize()
                .map_err(|source| CliError::CacheIo {
                    path: arguments.root.clone(),
                    source,
                })?;
            if !root.is_dir() {
                return Err(CliError::InvalidArguments(format!(
                    "project root `{}` is not a directory",
                    root.display()
                )));
            }
            let cache = root.join(".orphanode").join("cache");
            match fs::symlink_metadata(&cache) {
                Ok(metadata) if metadata.file_type().is_symlink() || metadata.is_file() => {
                    fs::remove_file(&cache).map_err(|source| CliError::CacheIo {
                        path: cache.clone(),
                        source,
                    })?;
                    write_stdout("Orphanode cache link/file removed.")?;
                }
                Ok(metadata) if metadata.is_dir() => {
                    fs::remove_dir_all(&cache).map_err(|source| CliError::CacheIo {
                        path: cache.clone(),
                        source,
                    })?;
                    write_stdout("Orphanode cache removed.")?;
                }
                Ok(_) => {
                    return Err(CliError::InvalidArguments(format!(
                        "cache target `{}` is not a regular file, link, or directory",
                        cache.display()
                    )));
                }
                Err(source) if source.kind() == io::ErrorKind::NotFound => {
                    write_stdout("Orphanode cache is already empty.")?;
                }
                Err(source) => {
                    return Err(CliError::CacheIo {
                        path: cache,
                        source,
                    });
                }
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn load_file_universe(arguments: &UniverseArgs) -> Result<(Vec<PathBuf>, Vec<PathBuf>), CliError> {
    match (
        &arguments.files_from,
        arguments.entries.is_empty(),
        arguments.files.is_empty(),
    ) {
        (Some(_), false, _) | (Some(_), true, false) => Err(CliError::InvalidArguments(
            "--files-from cannot be combined with --entry or --file".to_owned(),
        )),
        (Some(manifest_path), true, true) => {
            let manifest_path = rooted_path(&arguments.root, manifest_path);
            let manifest_source =
                fs::read_to_string(&manifest_path).map_err(|source| CliError::ReadManifest {
                    path: manifest_path.clone(),
                    source,
                })?;
            let manifest =
                serde_json::from_str::<FileManifest>(&manifest_source).map_err(|source| {
                    CliError::ParseManifest {
                        path: manifest_path,
                        source,
                    }
                })?;
            let entries = match (manifest.entry, manifest.entries.is_empty()) {
                (Some(entry), true) => vec![entry],
                (None, false) => manifest.entries,
                (Some(_), false) => {
                    return Err(CliError::InvalidArguments(
                        "manifest cannot contain both `entry` and `entries`".to_owned(),
                    ));
                }
                (None, true) => {
                    return Err(CliError::InvalidArguments(
                        "manifest must contain `entry` or a non-empty `entries` array".to_owned(),
                    ));
                }
            };
            Ok((entries, manifest.files))
        }
        (None, false, false) => Ok((arguments.entries.clone(), arguments.files.clone())),
        (None, true, _) => Err(CliError::InvalidArguments(
            "provide --files-from or at least one --entry".to_owned(),
        )),
        (None, false, true) => Ok((
            arguments.entries.clone(),
            discover_source_files(&arguments.root)?,
        )),
    }
}

fn render_explanation(explanation: &Explanation) -> String {
    let mut output = format!(
        "ORPHANODE  WHY\n\n{}\n",
        safe_text(&explanation.summary, "No explanation available")
    );
    for (index, step) in explanation.steps.iter().enumerate() {
        let branch = if index + 1 == explanation.steps.len() {
            "└─"
        } else {
            "├─"
        };
        output.push_str(branch);
        output.push(' ');
        output.push_str(&safe_text(&step.summary, "No evidence provided"));
        output.push('\n');
    }
    output
}

fn issue_description(issue_id: &str) -> Option<(&'static str, &'static str)> {
    match issue_id {
        "ORP1001" => Some((
            "Unreachable source files",
            "Reported only when no supported path exists from any configured entry and no reachable coverage blocker could invalidate that conclusion. Review roots before removal.",
        )),
        "ORP1002" => Some((
            "Unused export",
            "Requires symbol-level linking and the applicable open- or closed-world package contract. Public exports are retained by default for publishable packages.",
        )),
        "ORP1003" => Some((
            "Unused declaration",
            "A dead binding is distinct from a removable initializer. Automatic changes require effect and comment-preservation proof.",
        )),
        "ORP1004" => Some((
            "Unused member",
            "Member findings are blocked by relevant escape, reflection, decorator, inheritance, override, and framework uncertainty.",
        )),
        "ORP2001" => Some((
            "Unused dependency",
            "A direct dependency is unused only when no reachable runtime, type, script, config, binary, plugin, peer, optional, or bundled contract retains it.",
        )),
        "ORP2002" => Some((
            "Unlisted or misplaced dependency",
            "A reachable package reference has no declaration in its owning workspace, or is declared in a different workspace. Hoisting is not treated as ownership.",
        )),
        "ORP3001" => Some((
            "Unused workspace package",
            "A private workspace is reported only when no live workspace, script, configuration, framework, or public root retains it. Its unreachable contents remain separate file findings.",
        )),
        _ => None,
    }
}

fn rooted_path(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

fn should_colorize(choice: ColorChoice) -> bool {
    match choice {
        ColorChoice::Always => true,
        ColorChoice::Never => false,
        ColorChoice::Auto => {
            io::stdout().is_terminal()
                && env::var_os("NO_COLOR").is_none()
                && env::var("TERM").map_or(true, |term| term != "dumb")
        }
    }
}

fn should_use_unicode(ascii: bool) -> bool {
    !ascii && env::var("TERM").map_or(true, |term| term != "dumb")
}

fn report_exit_code(report: &orphanode::ScanReport) -> ExitCode {
    use orphanode::domain::report::{AnalysisStatus, Confidence};

    if report.status == AnalysisStatus::Incomplete {
        ExitCode::from(2)
    } else if !report.findings.iter().any(|finding| {
        let threshold = report
            .project
            .as_ref()
            .and_then(|project| project.failure_thresholds.get(&finding.workspace))
            .copied()
            .unwrap_or(Confidence::Low);
        confidence_rank(finding.confidence) >= confidence_rank(threshold)
    }) {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn confidence_rank(confidence: orphanode::domain::report::Confidence) -> u8 {
    use orphanode::domain::report::Confidence;

    match confidence {
        Confidence::Incomplete => 0,
        Confidence::Low => 1,
        Confidence::Medium => 2,
        Confidence::High => 3,
    }
}

fn write_stdout(output: &str) -> Result<(), CliError> {
    let mut stdout = io::stdout().lock();
    let write_result = stdout.write_all(output.as_bytes()).and_then(|()| {
        if output.ends_with('\n') {
            Ok(())
        } else {
            stdout.write_all(b"\n")
        }
    });
    if let Err(error) = write_result {
        if error.kind() == io::ErrorKind::BrokenPipe {
            return Ok(());
        }
        return Err(CliError::WriteOutput(error));
    }
    Ok(())
}

#[derive(Debug)]
enum CliError {
    InvalidArguments(String),
    ReadManifest {
        path: PathBuf,
        source: io::Error,
    },
    ParseManifest {
        path: PathBuf,
        source: serde_json::Error,
    },
    Discovery(DiscoveryError),
    Workspace(WorkspaceError),
    Configuration(ConfigurationError),
    Project(ProjectScanError),
    Scan(orphanode::ScanError),
    FixPlan(FixPlanError),
    Fix(FixError),
    FixRevalidation(String),
    CacheIo {
        path: PathBuf,
        source: io::Error,
    },
    Serialize(serde_json::Error),
    WriteOutput(io::Error),
}

impl CliError {
    fn exit_code(&self) -> ExitCode {
        match self {
            Self::InvalidArguments(_)
            | Self::ReadManifest { .. }
            | Self::ParseManifest { .. }
            | Self::Discovery(_)
            | Self::Workspace(_)
            | Self::Configuration(_)
            | Self::Project(_)
            | Self::Scan(_) => ExitCode::from(2),
            Self::FixPlan(_)
            | Self::Fix(_)
            | Self::FixRevalidation(_)
            | Self::CacheIo { .. }
            | Self::Serialize(_)
            | Self::WriteOutput(_) => ExitCode::from(3),
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArguments(message) | Self::FixRevalidation(message) => {
                formatter.write_str(message)
            }
            Self::ReadManifest { path, source } => {
                write!(formatter, "cannot read `{}`: {source}", path.display())
            }
            Self::ParseManifest { path, source } => {
                write!(formatter, "invalid manifest `{}`: {source}", path.display())
            }
            Self::Discovery(error) => error.fmt(formatter),
            Self::Workspace(error) => error.fmt(formatter),
            Self::Configuration(error) => error.fmt(formatter),
            Self::Project(error) => error.fmt(formatter),
            Self::Scan(error) => error.fmt(formatter),
            Self::FixPlan(error) => error.fmt(formatter),
            Self::Fix(error) => error.fmt(formatter),
            Self::CacheIo { path, source } => {
                write!(
                    formatter,
                    "cache I/O failed for `{}`: {source}",
                    path.display()
                )
            }
            Self::Serialize(error) => write!(formatter, "cannot serialize report: {error}"),
            Self::WriteOutput(error) => write!(formatter, "cannot write report: {error}"),
        }
    }
}

impl Error for CliError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ReadManifest { source, .. }
            | Self::CacheIo { source, .. }
            | Self::WriteOutput(source) => Some(source),
            Self::ParseManifest { source, .. } | Self::Serialize(source) => Some(source),
            Self::Discovery(source) => Some(source),
            Self::Workspace(source) => Some(source),
            Self::Configuration(source) => Some(source),
            Self::Project(source) => Some(source),
            Self::Scan(source) => Some(source),
            Self::FixPlan(source) => Some(source),
            Self::Fix(source) => Some(source),
            Self::InvalidArguments(_) | Self::FixRevalidation(_) => None,
        }
    }
}

impl From<orphanode::ScanError> for CliError {
    fn from(error: orphanode::ScanError) -> Self {
        Self::Scan(error)
    }
}

impl From<DiscoveryError> for CliError {
    fn from(error: DiscoveryError) -> Self {
        Self::Discovery(error)
    }
}

impl From<WorkspaceError> for CliError {
    fn from(error: WorkspaceError) -> Self {
        Self::Workspace(error)
    }
}

impl From<ConfigurationError> for CliError {
    fn from(error: ConfigurationError) -> Self {
        Self::Configuration(error)
    }
}

impl From<ProjectScanError> for CliError {
    fn from(error: ProjectScanError) -> Self {
        Self::Project(error)
    }
}

impl From<FixPlanError> for CliError {
    fn from(error: FixPlanError) -> Self {
        Self::FixPlan(error)
    }
}

impl From<FixError> for CliError {
    fn from(error: FixError) -> Self {
        Self::Fix(error)
    }
}

impl From<serde_json::Error> for CliError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serialize(error)
    }
}

#[cfg(test)]
mod tests {
    use orphanode::domain::report::FixEligibility;

    use super::dependency_fix_can_be_planned;

    #[test]
    fn dependency_fix_eligibility_controls_preview_and_apply() {
        assert!(dependency_fix_can_be_planned(
            FixEligibility::PreviewOnly,
            false
        ));
        assert!(!dependency_fix_can_be_planned(
            FixEligibility::PreviewOnly,
            true
        ));
        assert!(dependency_fix_can_be_planned(
            FixEligibility::Eligible,
            false
        ));
        assert!(dependency_fix_can_be_planned(
            FixEligibility::Eligible,
            true
        ));
        assert!(!dependency_fix_can_be_planned(
            FixEligibility::NotAvailable,
            false
        ));
        assert!(!dependency_fix_can_be_planned(
            FixEligibility::Blocked,
            false
        ));
    }
}
