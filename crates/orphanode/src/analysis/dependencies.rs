use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DependencyCategory {
    Runtime,
    Development,
    Peer,
    Optional,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DependencyManifest {
    pub workspace: String,
    pub dependencies: BTreeMap<String, String>,
    pub dev_dependencies: BTreeMap<String, String>,
    pub peer_dependencies: BTreeMap<String, String>,
    pub optional_dependencies: BTreeMap<String, String>,
    pub bundled_dependencies: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DependencyEvidenceKind {
    Binary,
    Bundled,
    Config,
    PublicType,
    Script,
    SourceImport,
    TypeOnlyImport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DependencyEvidenceScope {
    Runtime,
    Development,
    Contract,
}

/// A statically known package or binary reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyEvidence {
    pub workspace: String,
    pub reference: String,
    pub kind: DependencyEvidenceKind,
    pub scope: DependencyEvidenceScope,
    pub source: String,
    pub reachable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyBlocker {
    pub workspace: String,
    /// `None` blocks workspace-wide unused conclusions. A package value may be
    /// a bare name or subpath and is normalized before matching.
    pub package: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Copy)]
pub struct DependencyAnalysisInput<'a> {
    pub root_workspace: &'a str,
    pub manifests: &'a [DependencyManifest],
    pub evidence: &'a [DependencyEvidence],
    /// Installed binary name to owning package name.
    pub binary_owners: &'a BTreeMap<String, String>,
    pub blockers: &'a [DependencyBlocker],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DependencyOutcomeKind {
    Retained,
    Unused,
    UnreferencedPeer,
    UnreferencedOptional,
    Unlisted,
    Misplaced,
    Undetermined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DependencyConfidence {
    NotApplicable,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NormalizedDependencyEvidence {
    pub workspace: String,
    pub package: String,
    pub kind: DependencyEvidenceKind,
    pub scope: DependencyEvidenceScope,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyOutcome {
    pub workspace: String,
    pub package: String,
    pub declared_workspace: Option<String>,
    pub categories: Vec<DependencyCategory>,
    pub kind: DependencyOutcomeKind,
    pub confidence: DependencyConfidence,
    pub evidence: Vec<NormalizedDependencyEvidence>,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct UnmappedBinary {
    pub workspace: String,
    pub binary: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyAnalysis {
    pub outcomes: Vec<DependencyOutcome>,
    pub unmapped_binaries: Vec<UnmappedBinary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct Declaration {
    categories: BTreeSet<DependencyCategory>,
    alias_targets: BTreeSet<String>,
    bundled: bool,
}

/// Extracts a direct npm package name from a bare import, a package subpath, or
/// an `npm:` alias requirement. Relative paths, URLs, package imports, and Node
/// built-ins are not npm dependency evidence.
#[must_use]
pub fn package_name(specifier: &str) -> Option<String> {
    let specifier = specifier.trim();
    if let Some(requirement) = specifier.strip_prefix("npm:") {
        return npm_requirement_package(requirement);
    }
    if specifier.is_empty()
        || specifier.starts_with('.')
        || specifier.starts_with('/')
        || specifier.starts_with('#')
        || specifier.starts_with("node:")
        || specifier.contains('\\')
        || specifier.contains("://")
    {
        return None;
    }

    let package = if specifier.starts_with('@') {
        let mut segments = specifier.split('/');
        let scope = segments.next()?;
        let name = segments.next()?;
        if scope.len() == 1
            || name.is_empty()
            || scope[1..].contains(['@', ':', '?', '#'])
            || name.contains(['@', ':', '?', '#'])
        {
            return None;
        }
        format!("{scope}/{name}")
    } else {
        let name = specifier.split('/').next()?;
        if name.is_empty() || name.contains(['@', ':', '?', '#']) {
            return None;
        }
        name.to_owned()
    };

    (!is_node_builtin(&package)).then_some(package)
}

/// Returns the real package targeted by an npm alias requirement such as
/// `npm:@scope/real-package@^2`.
#[must_use]
pub fn npm_alias_target(requirement: &str) -> Option<String> {
    npm_requirement_package(requirement.strip_prefix("npm:")?)
}

/// Classifies declared packages and reachable evidence without resolving or
/// executing project code.
///
/// A child-workspace reference satisfied only by the root manifest is reported
/// as misplaced. Unreachable evidence never retains a declaration. A blocker
/// changes an otherwise-unused result to `Undetermined`.
#[must_use]
pub fn analyze_dependencies(input: DependencyAnalysisInput<'_>) -> DependencyAnalysis {
    let declarations = collect_declarations(input.manifests);
    let alias_targets = collect_alias_targets(&declarations);
    let (normalized_evidence, unmapped_binaries) = normalize_evidence(
        input.evidence,
        input.binary_owners,
        &declarations,
        &alias_targets,
    );
    let evidence_by_package = group_evidence(&normalized_evidence);
    let mut blockers = normalize_blockers(input.blockers);
    for unmapped in &unmapped_binaries {
        blockers
            .entry(unmapped.workspace.clone())
            .or_default()
            .push((
                None,
                format!(
                    "reachable binary `{}` could not be mapped to an owning package ({})",
                    unmapped.binary, unmapped.source
                ),
            ));
    }
    sort_blockers(&mut blockers);
    let mut outcomes = Vec::new();

    for (workspace, workspace_declarations) in &declarations {
        for (package, declaration) in workspace_declarations {
            let mut package_evidence = evidence_by_package
                .get(&(workspace.clone(), package.clone()))
                .cloned()
                .unwrap_or_default();
            if declaration.bundled {
                package_evidence.push(NormalizedDependencyEvidence {
                    workspace: workspace.clone(),
                    package: package.clone(),
                    kind: DependencyEvidenceKind::Bundled,
                    scope: DependencyEvidenceScope::Runtime,
                    source: "package.json bundled dependencies".to_owned(),
                });
            }
            package_evidence.sort_unstable();
            package_evidence.dedup();

            let package_blockers = matching_blockers(&blockers, workspace, package);
            let (kind, confidence) =
                declaration_outcome(declaration, &package_evidence, &package_blockers);
            outcomes.push(DependencyOutcome {
                workspace: workspace.clone(),
                package: package.clone(),
                declared_workspace: Some(workspace.clone()),
                categories: declaration.categories.iter().copied().collect(),
                kind,
                confidence,
                evidence: package_evidence,
                blockers: package_blockers,
            });
        }
    }

    for ((workspace, package), package_evidence) in evidence_by_package {
        if declarations
            .get(&workspace)
            .is_some_and(|workspace_declarations| workspace_declarations.contains_key(&package))
        {
            continue;
        }

        let root_declaration = (workspace != input.root_workspace)
            .then(|| declarations.get(input.root_workspace))
            .flatten()
            .and_then(|root| root.get(&package));
        let (kind, declared_workspace, categories) = if let Some(declaration) = root_declaration {
            (
                DependencyOutcomeKind::Misplaced,
                Some(input.root_workspace.to_owned()),
                declaration.categories.iter().copied().collect(),
            )
        } else {
            (DependencyOutcomeKind::Unlisted, None, Vec::new())
        };
        outcomes.push(DependencyOutcome {
            workspace,
            package,
            declared_workspace,
            categories,
            kind,
            confidence: DependencyConfidence::High,
            evidence: package_evidence,
            blockers: Vec::new(),
        });
    }

    outcomes.sort_by(|left, right| {
        (&left.workspace, &left.package, left.kind).cmp(&(
            &right.workspace,
            &right.package,
            right.kind,
        ))
    });

    DependencyAnalysis {
        outcomes,
        unmapped_binaries,
    }
}

fn collect_declarations(
    manifests: &[DependencyManifest],
) -> BTreeMap<String, BTreeMap<String, Declaration>> {
    let mut declarations = BTreeMap::<String, BTreeMap<String, Declaration>>::new();
    for manifest in manifests {
        let workspace = declarations.entry(manifest.workspace.clone()).or_default();
        add_category(
            workspace,
            &manifest.dependencies,
            DependencyCategory::Runtime,
        );
        add_category(
            workspace,
            &manifest.dev_dependencies,
            DependencyCategory::Development,
        );
        add_category(
            workspace,
            &manifest.peer_dependencies,
            DependencyCategory::Peer,
        );
        add_category(
            workspace,
            &manifest.optional_dependencies,
            DependencyCategory::Optional,
        );
        for bundled in &manifest.bundled_dependencies {
            if let Some(package) = package_name(bundled)
                && let Some(declaration) = workspace.get_mut(&package)
            {
                declaration.bundled = true;
            }
        }
    }
    declarations
}

fn add_category(
    declarations: &mut BTreeMap<String, Declaration>,
    packages: &BTreeMap<String, String>,
    category: DependencyCategory,
) {
    for (declared_name, requirement) in packages {
        let Some(package) = package_name(declared_name) else {
            continue;
        };
        let declaration = declarations.entry(package).or_default();
        declaration.categories.insert(category);
        if let Some(alias_target) = npm_alias_target(requirement) {
            declaration.alias_targets.insert(alias_target);
        }
    }
}

fn collect_alias_targets(
    declarations: &BTreeMap<String, BTreeMap<String, Declaration>>,
) -> BTreeMap<String, BTreeMap<String, Vec<String>>> {
    let mut targets = BTreeMap::<String, BTreeMap<String, Vec<String>>>::new();
    for (workspace, workspace_declarations) in declarations {
        for (declared_name, declaration) in workspace_declarations {
            for target in &declaration.alias_targets {
                targets
                    .entry(workspace.clone())
                    .or_default()
                    .entry(target.clone())
                    .or_default()
                    .push(declared_name.clone());
            }
        }
    }
    targets
}

fn normalize_evidence(
    evidence: &[DependencyEvidence],
    binary_owners: &BTreeMap<String, String>,
    declarations: &BTreeMap<String, BTreeMap<String, Declaration>>,
    alias_targets: &BTreeMap<String, BTreeMap<String, Vec<String>>>,
) -> (Vec<NormalizedDependencyEvidence>, Vec<UnmappedBinary>) {
    let mut normalized = BTreeSet::new();
    let mut unmapped_binaries = BTreeSet::new();

    for item in evidence.iter().filter(|item| item.reachable) {
        let (package, binary_owner) = if item.kind == DependencyEvidenceKind::Binary {
            let binary = normalize_binary_name(&item.reference);
            let Some(owner) = binary_owners.get(&binary) else {
                unmapped_binaries.insert(UnmappedBinary {
                    workspace: item.workspace.clone(),
                    binary,
                    source: item.source.clone(),
                });
                continue;
            };
            (package_name(owner), true)
        } else {
            (package_name(&item.reference), false)
        };
        let Some(mut package) = package else {
            continue;
        };

        if binary_owner
            && !declarations
                .get(&item.workspace)
                .is_some_and(|workspace| workspace.contains_key(&package))
            && let Some(alias_names) = alias_targets
                .get(&item.workspace)
                .and_then(|workspace| workspace.get(&package))
            && let [alias_name] = alias_names.as_slice()
        {
            package.clone_from(alias_name);
        }

        normalized.insert(NormalizedDependencyEvidence {
            workspace: item.workspace.clone(),
            package,
            kind: item.kind,
            scope: item.scope,
            source: item.source.clone(),
        });
    }

    (
        normalized.into_iter().collect(),
        unmapped_binaries.into_iter().collect(),
    )
}

fn group_evidence(
    evidence: &[NormalizedDependencyEvidence],
) -> BTreeMap<(String, String), Vec<NormalizedDependencyEvidence>> {
    let mut grouped = BTreeMap::<(String, String), Vec<NormalizedDependencyEvidence>>::new();
    for item in evidence {
        grouped
            .entry((item.workspace.clone(), item.package.clone()))
            .or_default()
            .push(item.clone());
    }
    grouped
}

fn normalize_blockers(
    blockers: &[DependencyBlocker],
) -> BTreeMap<String, Vec<(Option<String>, String)>> {
    let mut normalized = BTreeMap::<String, Vec<(Option<String>, String)>>::new();
    for blocker in blockers {
        let package = match blocker.package.as_deref() {
            None => None,
            Some(package) => {
                let Some(package) = package_name(package) else {
                    continue;
                };
                Some(package)
            }
        };
        normalized
            .entry(blocker.workspace.clone())
            .or_default()
            .push((package, blocker.reason.clone()));
    }
    sort_blockers(&mut normalized);
    normalized
}

fn sort_blockers(blockers: &mut BTreeMap<String, Vec<(Option<String>, String)>>) {
    for workspace_blockers in blockers.values_mut() {
        workspace_blockers.sort_unstable();
        workspace_blockers.dedup();
    }
}

fn matching_blockers(
    blockers: &BTreeMap<String, Vec<(Option<String>, String)>>,
    workspace: &str,
    package: &str,
) -> Vec<String> {
    blockers
        .get(workspace)
        .into_iter()
        .flatten()
        .filter(|(blocked_package, _)| {
            blocked_package
                .as_ref()
                .is_none_or(|blocked_package| blocked_package == package)
        })
        .map(|(_, reason)| reason.clone())
        .collect()
}

fn declaration_outcome(
    declaration: &Declaration,
    evidence: &[NormalizedDependencyEvidence],
    blockers: &[String],
) -> (DependencyOutcomeKind, DependencyConfidence) {
    if !evidence.is_empty() {
        return (
            DependencyOutcomeKind::Retained,
            DependencyConfidence::NotApplicable,
        );
    }
    if !blockers.is_empty() {
        return (
            DependencyOutcomeKind::Undetermined,
            DependencyConfidence::NotApplicable,
        );
    }
    if declaration.categories.contains(&DependencyCategory::Peer) {
        return (
            DependencyOutcomeKind::UnreferencedPeer,
            DependencyConfidence::Medium,
        );
    }
    if declaration
        .categories
        .contains(&DependencyCategory::Optional)
    {
        return (
            DependencyOutcomeKind::UnreferencedOptional,
            DependencyConfidence::Medium,
        );
    }
    (DependencyOutcomeKind::Unused, DependencyConfidence::High)
}

fn npm_requirement_package(requirement: &str) -> Option<String> {
    let requirement = requirement.trim();
    if requirement.is_empty() {
        return None;
    }

    let package_end = if requirement.starts_with('@') {
        let slash = requirement.find('/')?;
        requirement[slash + 1..]
            .find('@')
            .map_or(requirement.len(), |offset| slash + 1 + offset)
    } else {
        requirement.find('@').unwrap_or(requirement.len())
    };
    package_name(&requirement[..package_end])
}

fn normalize_binary_name(binary: &str) -> String {
    let name = binary.rsplit(['/', '\\']).next().unwrap_or(binary);
    name.strip_suffix(".cmd")
        .or_else(|| name.strip_suffix(".exe"))
        .unwrap_or(name)
        .to_owned()
}

fn is_node_builtin(package: &str) -> bool {
    matches!(
        package,
        "assert"
            | "assert/strict"
            | "async_hooks"
            | "buffer"
            | "child_process"
            | "cluster"
            | "console"
            | "constants"
            | "crypto"
            | "dgram"
            | "diagnostics_channel"
            | "dns"
            | "dns/promises"
            | "domain"
            | "events"
            | "fs"
            | "fs/promises"
            | "http"
            | "http2"
            | "https"
            | "module"
            | "net"
            | "os"
            | "path"
            | "path/posix"
            | "path/win32"
            | "perf_hooks"
            | "process"
            | "punycode"
            | "querystring"
            | "readline"
            | "readline/promises"
            | "repl"
            | "sea"
            | "sqlite"
            | "stream"
            | "stream/consumers"
            | "stream/promises"
            | "stream/web"
            | "string_decoder"
            | "sys"
            | "timers"
            | "timers/promises"
            | "tls"
            | "trace_events"
            | "tty"
            | "url"
            | "util"
            | "util/types"
            | "v8"
            | "vm"
            | "wasi"
            | "worker_threads"
            | "zlib"
    )
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::{
        DependencyAnalysisInput, DependencyBlocker, DependencyCategory, DependencyEvidence,
        DependencyEvidenceKind, DependencyEvidenceScope, DependencyManifest, DependencyOutcomeKind,
        analyze_dependencies, npm_alias_target, package_name,
    };

    #[test]
    fn package_names_cover_scopes_subpaths_aliases_and_builtins() {
        assert_eq!(package_name("lodash/fp"), Some("lodash".to_owned()));
        assert_eq!(
            package_name("@scope/package/subpath"),
            Some("@scope/package".to_owned())
        );
        assert_eq!(
            package_name("npm:@scope/real@^2"),
            Some("@scope/real".to_owned())
        );
        assert_eq!(
            npm_alias_target("npm:real-package@~1.2"),
            Some("real-package".to_owned())
        );
        assert_eq!(package_name("node:test"), None);
        assert_eq!(package_name("fs/promises"), None);
        assert_eq!(package_name("./local.js"), None);
    }

    #[test]
    fn reachable_type_only_and_binary_evidence_retain_declarations() {
        let manifest = manifest(
            ".",
            [("typescript", "^6"), ("@types/node", "^24")],
            [],
            [],
            [],
        );
        let evidence = [
            evidence(
                ".",
                "@types/node/index.d.ts",
                DependencyEvidenceKind::TypeOnlyImport,
                "src/public.ts",
            ),
            evidence(".", "tsc", DependencyEvidenceKind::Binary, "scripts.build"),
        ];
        let binary_owners = BTreeMap::from([("tsc".to_owned(), "typescript".to_owned())]);

        let analysis = analyze_dependencies(input(&[manifest], &evidence, &binary_owners, &[]));

        assert!(
            analysis
                .outcomes
                .iter()
                .all(|outcome| { matches!(outcome.kind, DependencyOutcomeKind::Retained) })
        );
        assert!(analysis.unmapped_binaries.is_empty());
    }

    #[test]
    fn unused_categories_have_policy_specific_outcomes() {
        let manifest = manifest(
            ".",
            [("runtime", "1")],
            [("tool", "1")],
            [("peer", "1")],
            [("optional", "1")],
        );
        let manifests = [manifest];

        let analysis = analyze_dependencies(input(&manifests, &[], &BTreeMap::new(), &[]));

        assert_eq!(outcome(&analysis, "runtime"), DependencyOutcomeKind::Unused);
        assert_eq!(outcome(&analysis, "tool"), DependencyOutcomeKind::Unused);
        assert_eq!(
            outcome(&analysis, "peer"),
            DependencyOutcomeKind::UnreferencedPeer
        );
        assert_eq!(
            outcome(&analysis, "optional"),
            DependencyOutcomeKind::UnreferencedOptional
        );
    }

    #[test]
    fn bundled_dependencies_are_retained_without_other_evidence() {
        let mut manifest = manifest(".", [("bundled", "1")], [], [], []);
        manifest.bundled_dependencies = BTreeSet::from(["bundled".to_owned()]);
        let manifests = [manifest];

        let analysis = analyze_dependencies(input(&manifests, &[], &BTreeMap::new(), &[]));

        assert_eq!(
            outcome(&analysis, "bundled"),
            DependencyOutcomeKind::Retained
        );
    }

    #[test]
    fn child_use_of_a_root_declaration_is_misplaced_not_root_usage() {
        let manifests = [
            manifest(".", [("hoisted", "1")], [], [], []),
            manifest("packages/child", [], [], [], []),
        ];
        let evidence = [evidence(
            "packages/child",
            "hoisted/subpath",
            DependencyEvidenceKind::SourceImport,
            "packages/child/src/index.ts",
        )];

        let analysis = analyze_dependencies(input(&manifests, &evidence, &BTreeMap::new(), &[]));

        assert!(analysis.outcomes.iter().any(|outcome| {
            outcome.workspace == "packages/child"
                && outcome.package == "hoisted"
                && outcome.kind == DependencyOutcomeKind::Misplaced
                && outcome.declared_workspace.as_deref() == Some(".")
        }));
        assert!(analysis.outcomes.iter().any(|outcome| {
            outcome.workspace == "."
                && outcome.package == "hoisted"
                && outcome.kind == DependencyOutcomeKind::Unused
        }));
    }

    #[test]
    fn reachable_undeclared_packages_are_unlisted() {
        let manifests = [manifest(".", [], [], [], [])];
        let evidence = [evidence(
            ".",
            "missing/subpath",
            DependencyEvidenceKind::SourceImport,
            "src/index.ts",
        )];

        let analysis = analyze_dependencies(input(&manifests, &evidence, &BTreeMap::new(), &[]));

        assert_eq!(
            outcome(&analysis, "missing"),
            DependencyOutcomeKind::Unlisted
        );
    }

    #[test]
    fn blockers_prevent_high_confidence_unused_conclusions() {
        let manifests = [manifest(".", [("unknown", "1")], [], [], [])];
        let blockers = [DependencyBlocker {
            workspace: ".".to_owned(),
            package: Some("unknown/subpath".to_owned()),
            reason: "unresolved dynamic import".to_owned(),
        }];

        let analysis = analyze_dependencies(input(&manifests, &[], &BTreeMap::new(), &blockers));

        assert_eq!(
            outcome(&analysis, "unknown"),
            DependencyOutcomeKind::Undetermined
        );
    }

    #[test]
    fn an_unmapped_reachable_binary_blocks_workspace_unused_conclusions() {
        let manifests = [manifest(".", [], [("tool", "1")], [], [])];
        let evidence = [evidence(
            ".",
            "mystery-tool",
            DependencyEvidenceKind::Binary,
            "scripts.check",
        )];

        let analysis = analyze_dependencies(input(&manifests, &evidence, &BTreeMap::new(), &[]));

        assert_eq!(
            outcome(&analysis, "tool"),
            DependencyOutcomeKind::Undetermined
        );
        assert_eq!(analysis.unmapped_binaries[0].binary, "mystery-tool");
    }

    #[test]
    fn npm_alias_import_and_installed_binary_owner_retain_the_alias() {
        let manifest = manifest(".", [("pretty", "npm:prettier@^4")], [], [], []);
        let evidence = [
            evidence(
                ".",
                "pretty/plugins/babel",
                DependencyEvidenceKind::SourceImport,
                "prettier.config.js",
            ),
            evidence(
                ".",
                "prettier",
                DependencyEvidenceKind::Binary,
                "scripts.format",
            ),
        ];
        let binary_owners = BTreeMap::from([("prettier".to_owned(), "prettier".to_owned())]);

        let analysis = analyze_dependencies(input(&[manifest], &evidence, &binary_owners, &[]));

        assert_eq!(
            outcome(&analysis, "pretty"),
            DependencyOutcomeKind::Retained
        );
        assert!(
            !analysis
                .outcomes
                .iter()
                .any(|outcome| outcome.package == "prettier")
        );
    }

    fn manifest<const R: usize, const D: usize, const P: usize, const O: usize>(
        workspace: &str,
        runtime: [(&str, &str); R],
        development: [(&str, &str); D],
        peer: [(&str, &str); P],
        optional: [(&str, &str); O],
    ) -> DependencyManifest {
        DependencyManifest {
            workspace: workspace.to_owned(),
            dependencies: map(runtime),
            dev_dependencies: map(development),
            peer_dependencies: map(peer),
            optional_dependencies: map(optional),
            bundled_dependencies: BTreeSet::new(),
        }
    }

    fn map<const N: usize>(values: [(&str, &str); N]) -> BTreeMap<String, String> {
        values
            .into_iter()
            .map(|(name, requirement)| (name.to_owned(), requirement.to_owned()))
            .collect()
    }

    fn evidence(
        workspace: &str,
        reference: &str,
        kind: DependencyEvidenceKind,
        source: &str,
    ) -> DependencyEvidence {
        DependencyEvidence {
            workspace: workspace.to_owned(),
            reference: reference.to_owned(),
            kind,
            scope: DependencyEvidenceScope::Runtime,
            source: source.to_owned(),
            reachable: true,
        }
    }

    fn input<'a>(
        manifests: &'a [DependencyManifest],
        evidence: &'a [DependencyEvidence],
        binary_owners: &'a BTreeMap<String, String>,
        blockers: &'a [DependencyBlocker],
    ) -> DependencyAnalysisInput<'a> {
        DependencyAnalysisInput {
            root_workspace: ".",
            manifests,
            evidence,
            binary_owners,
            blockers,
        }
    }

    fn outcome(analysis: &super::DependencyAnalysis, package: &str) -> DependencyOutcomeKind {
        analysis
            .outcomes
            .iter()
            .find(|outcome| outcome.package == package)
            .unwrap_or_else(|| panic!("missing outcome for {package}"))
            .kind
    }

    #[test]
    fn categories_are_stably_ordered_when_manifest_fields_overlap() {
        let manifest = manifest(
            ".",
            [("shared", "1")],
            [("shared", "1")],
            [("shared", "1")],
            [],
        );
        let manifests = [manifest];

        let analysis = analyze_dependencies(input(&manifests, &[], &BTreeMap::new(), &[]));
        let shared = analysis
            .outcomes
            .iter()
            .find(|outcome| outcome.package == "shared")
            .expect("shared outcome");

        assert_eq!(
            shared.categories,
            [
                DependencyCategory::Runtime,
                DependencyCategory::Development,
                DependencyCategory::Peer,
            ]
        );
    }
}
