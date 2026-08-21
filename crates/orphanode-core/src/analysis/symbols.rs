use std::collections::{BTreeMap, VecDeque};

use crate::domain::facts::{
    DeclarationKind, ExecutionRegionId, FileFacts, ReferenceOwner, SemanticSymbolId,
    SymbolNamespace, UnknownGuardKind, UsageKind,
};

/// A symbol identity that remains unambiguous after per-file Oxc arenas are dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SymbolKey {
    pub file: usize,
    pub symbol: SemanticSymbolId,
}

/// A cross-module edge produced after import/export resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedSymbolLink {
    pub source: SymbolKey,
    pub source_usage: UsageKind,
    pub target: SymbolKey,
    pub target_usage: UsageKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymbolRoot {
    pub symbol: SymbolKey,
    pub usage: UsageKind,
}

pub struct SymbolAnalysisInput<'a> {
    pub files: &'a [FileFacts],
    /// File reachability from the module graph. Missing entries are treated as
    /// unreachable rather than silently becoming roots.
    pub reachable_files: &'a [bool],
    /// Files whose public exports can be consumed outside the analyzed graph.
    pub open_world_files: &'a [bool],
    pub links: &'a [ResolvedSymbolLink],
    pub explicit_roots: &'a [SymbolRoot],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymbolLiveness {
    pub symbol: SemanticSymbolId,
    pub runtime: bool,
    pub r#type: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSymbolReachability {
    pub symbols: Vec<SymbolLiveness>,
    /// False when direct eval or a dynamic scope can hide declaration uses.
    pub declarations_complete: bool,
    /// False when a computed `CommonJS` export can hide the public export set.
    pub exports_complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadSymbolGroup {
    pub members: Vec<SymbolKey>,
    pub cyclic: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolAnalysisResult {
    pub files: Vec<FileSymbolReachability>,
    pub dead_groups: Vec<DeadSymbolGroup>,
}

impl SymbolAnalysisResult {
    #[must_use]
    pub fn liveness(&self, key: SymbolKey) -> Option<SymbolLiveness> {
        self.files
            .get(key.file)?
            .symbols
            .iter()
            .find(|state| state.symbol == key.symbol)
            .copied()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Edge {
    source_usage: UsageKind,
    target: usize,
    target_usage: UsageKind,
}

#[must_use]
#[allow(
    clippy::too_many_lines,
    reason = "keeping the graph construction and traversal together makes its invariants explicit"
)]
pub fn analyze_symbols(input: &SymbolAnalysisInput<'_>) -> SymbolAnalysisResult {
    let mut node_by_key = BTreeMap::new();
    let mut keys = Vec::new();
    for (file, facts) in input.files.iter().enumerate() {
        for symbol in &facts.symbol_facts.symbols {
            let key = SymbolKey {
                file,
                symbol: symbol.id,
            };
            node_by_key.insert(key, keys.len());
            keys.push(key);
        }
    }

    let mut outgoing = vec![Vec::new(); keys.len()];
    for (file, facts) in input.files.iter().enumerate() {
        for reference in &facts.symbol_facts.references {
            let ReferenceOwner::Symbol(source_symbol) = reference.owner else {
                continue;
            };
            let source = SymbolKey {
                file,
                symbol: source_symbol,
            };
            let target = SymbolKey {
                file,
                symbol: reference.target,
            };
            let (Some(&source_node), Some(&target_node)) =
                (node_by_key.get(&source), node_by_key.get(&target))
            else {
                continue;
            };
            outgoing[source_node].push(Edge {
                source_usage: reference.usage,
                target: target_node,
                target_usage: reference.usage,
            });
        }
    }
    for link in input.links {
        let (Some(&source), Some(&target)) =
            (node_by_key.get(&link.source), node_by_key.get(&link.target))
        else {
            continue;
        };
        outgoing[source].push(Edge {
            source_usage: link.source_usage,
            target,
            target_usage: link.target_usage,
        });
    }
    for edges in &mut outgoing {
        edges.sort_unstable();
        edges.dedup();
    }

    let mut reachable = vec![[false; 2]; keys.len()];
    let mut queue = VecDeque::new();
    for root in input.explicit_roots {
        mark_reachable(
            &node_by_key,
            &mut reachable,
            &mut queue,
            root.symbol,
            root.usage,
        );
    }

    for (file, facts) in input.files.iter().enumerate() {
        if !file_flag(input.reachable_files, file) {
            continue;
        }
        let active_regions = active_eager_regions(facts);
        for reference in &facts.symbol_facts.references {
            if reference.usage != UsageKind::Runtime
                || !active_regions
                    .get(reference.region.0 as usize)
                    .copied()
                    .unwrap_or(false)
            {
                continue;
            }
            mark_reachable(
                &node_by_key,
                &mut reachable,
                &mut queue,
                SymbolKey {
                    file,
                    symbol: reference.target,
                },
                UsageKind::Runtime,
            );
        }

        if !file_flag(input.open_world_files, file) {
            continue;
        }
        for export in &facts.symbol_facts.exports {
            let Some(local) = export.local else {
                continue;
            };
            let key = SymbolKey {
                file,
                symbol: local,
            };
            if export.type_only {
                mark_reachable(
                    &node_by_key,
                    &mut reachable,
                    &mut queue,
                    key,
                    UsageKind::Type,
                );
                continue;
            }
            mark_reachable(
                &node_by_key,
                &mut reachable,
                &mut queue,
                key,
                UsageKind::Runtime,
            );
            if symbol_namespace(input.files, key)
                .is_some_and(|namespace| namespace != SymbolNamespace::Runtime)
            {
                mark_reachable(
                    &node_by_key,
                    &mut reachable,
                    &mut queue,
                    key,
                    UsageKind::Type,
                );
            }
        }
    }

    while let Some((source, usage)) = queue.pop_front() {
        for edge in &outgoing[source] {
            if edge.source_usage == usage {
                mark_node_reachable(&mut reachable, &mut queue, edge.target, edge.target_usage);
            }
        }
    }

    let completeness = input
        .files
        .iter()
        .enumerate()
        .map(|(file, facts)| {
            let reachable_file = file_flag(input.reachable_files, file);
            let declarations_complete = !reachable_file
                || !facts
                    .symbol_facts
                    .unknown_guards
                    .iter()
                    .any(|guard| guard.kind.blocks_declaration_reachability());
            let exports_complete = !reachable_file
                || !facts.symbol_facts.unknown_guards.iter().any(|guard| {
                    matches!(
                        guard.kind,
                        UnknownGuardKind::ComputedCommonJsExport
                            | UnknownGuardKind::OpaqueCommonJsExports
                    )
                });
            (declarations_complete, exports_complete)
        })
        .collect::<Vec<_>>();

    let dead_candidates = keys
        .iter()
        .enumerate()
        .map(|(node, key)| {
            file_flag(input.reachable_files, key.file)
                && completeness[key.file].0
                && !reachable[node][usage_index(UsageKind::Runtime)]
                && !reachable[node][usage_index(UsageKind::Type)]
                && is_reportable_declaration(input.files, *key)
        })
        .collect::<Vec<_>>();
    let dead_groups = dead_strongly_connected_components(&keys, &outgoing, &dead_candidates);

    let files = input
        .files
        .iter()
        .enumerate()
        .map(|(file, facts)| FileSymbolReachability {
            symbols: facts
                .symbol_facts
                .symbols
                .iter()
                .map(|symbol| {
                    let key = SymbolKey {
                        file,
                        symbol: symbol.id,
                    };
                    let state = node_by_key
                        .get(&key)
                        .map_or([false; 2], |node| reachable[*node]);
                    SymbolLiveness {
                        symbol: symbol.id,
                        runtime: state[usage_index(UsageKind::Runtime)],
                        r#type: state[usage_index(UsageKind::Type)],
                    }
                })
                .collect(),
            declarations_complete: completeness[file].0,
            exports_complete: completeness[file].1,
        })
        .collect();

    SymbolAnalysisResult { files, dead_groups }
}

fn file_flag(flags: &[bool], file: usize) -> bool {
    flags.get(file).copied().unwrap_or(false)
}

fn usage_index(usage: UsageKind) -> usize {
    match usage {
        UsageKind::Runtime => 0,
        UsageKind::Type => 1,
    }
}

fn mark_reachable(
    node_by_key: &BTreeMap<SymbolKey, usize>,
    reachable: &mut [[bool; 2]],
    queue: &mut VecDeque<(usize, UsageKind)>,
    key: SymbolKey,
    usage: UsageKind,
) {
    if let Some(&node) = node_by_key.get(&key) {
        mark_node_reachable(reachable, queue, node, usage);
    }
}

fn mark_node_reachable(
    reachable: &mut [[bool; 2]],
    queue: &mut VecDeque<(usize, UsageKind)>,
    node: usize,
    usage: UsageKind,
) {
    let usage_index = usage_index(usage);
    if !reachable[node][usage_index] {
        reachable[node][usage_index] = true;
        queue.push_back((node, usage));
    }
}

fn symbol_namespace(files: &[FileFacts], key: SymbolKey) -> Option<SymbolNamespace> {
    files
        .get(key.file)?
        .symbol_facts
        .symbols
        .iter()
        .find(|symbol| symbol.id == key.symbol)
        .map(|symbol| symbol.namespace)
}

fn active_eager_regions(facts: &FileFacts) -> Vec<bool> {
    let region_count = facts
        .symbol_facts
        .regions
        .iter()
        .map(|region| region.id.0 as usize)
        .max()
        .map_or(1, |last| last.saturating_add(1));
    let mut active = vec![false; region_count];
    active[ExecutionRegionId::MODULE.0 as usize] = true;
    let mut eager_children = vec![Vec::new(); region_count];
    for region in &facts.symbol_facts.regions {
        if region.eager
            && let Some(parent) = region.parent
            && let Some(children) = eager_children.get_mut(parent.0 as usize)
        {
            children.push(region.id.0 as usize);
        }
    }
    let mut queue = VecDeque::from([ExecutionRegionId::MODULE.0 as usize]);
    while let Some(parent) = queue.pop_front() {
        for &child in &eager_children[parent] {
            if !active[child] {
                active[child] = true;
                queue.push_back(child);
            }
        }
    }
    active
}

fn is_reportable_declaration(files: &[FileFacts], key: SymbolKey) -> bool {
    files
        .get(key.file)
        .and_then(|facts| {
            facts
                .symbol_facts
                .symbols
                .iter()
                .find(|symbol| symbol.id == key.symbol)
        })
        .is_some_and(|symbol| {
            !symbol.flags.ambient
                && !matches!(
                    symbol.kind,
                    DeclarationKind::CatchBinding
                        | DeclarationKind::EnumMember
                        | DeclarationKind::TypeParameter
                        | DeclarationKind::Unknown
                )
        })
}

fn dead_strongly_connected_components(
    keys: &[SymbolKey],
    outgoing: &[Vec<Edge>],
    candidate: &[bool],
) -> Vec<DeadSymbolGroup> {
    let mut visited = vec![false; keys.len()];
    let mut finish_order = Vec::new();
    for start in 0..keys.len() {
        if !candidate[start] || visited[start] {
            continue;
        }
        visited[start] = true;
        let mut stack = vec![(start, 0_usize)];
        while let Some((node, edge_index)) = stack.last_mut() {
            if let Some(edge) = outgoing[*node].get(*edge_index) {
                *edge_index += 1;
                if candidate[edge.target] && !visited[edge.target] {
                    visited[edge.target] = true;
                    stack.push((edge.target, 0));
                }
            } else {
                finish_order.push(*node);
                stack.pop();
            }
        }
    }

    let mut incoming = vec![Vec::new(); keys.len()];
    for (source, edges) in outgoing.iter().enumerate() {
        if !candidate[source] {
            continue;
        }
        for edge in edges {
            if candidate[edge.target] {
                incoming[edge.target].push(source);
            }
        }
    }
    for sources in &mut incoming {
        sources.sort_unstable();
        sources.dedup();
    }

    visited.fill(false);
    let mut groups = Vec::new();
    for &start in finish_order.iter().rev() {
        if visited[start] {
            continue;
        }
        visited[start] = true;
        let mut component = Vec::new();
        let mut stack = vec![start];
        while let Some(node) = stack.pop() {
            component.push(node);
            for &source in &incoming[node] {
                if !visited[source] {
                    visited[source] = true;
                    stack.push(source);
                }
            }
        }
        component.sort_unstable_by_key(|node| keys[*node]);
        let cyclic = component.len() > 1
            || outgoing[component[0]]
                .iter()
                .any(|edge| edge.target == component[0]);
        groups.push(DeadSymbolGroup {
            members: component.into_iter().map(|node| keys[node]).collect(),
            cyclic,
        });
    }
    groups.sort_by(|left, right| left.members.cmp(&right.members));
    groups
}

#[cfg(test)]
mod tests {
    use super::{ResolvedSymbolLink, SymbolAnalysisInput, SymbolKey, analyze_symbols};
    use crate::domain::facts::{
        DeclarationKind, ExecutionRegionFact, ExecutionRegionId, ExecutionRegionKind,
        ExportBindingFact, ExportBindingKind, FileFacts, ModuleKind, ReferenceOwner,
        SemanticSymbolId, SourceKind, SourceSpan, SymbolFact, SymbolFactFlags, SymbolFileFacts,
        SymbolNamespace, SymbolReferenceFact, UnknownGuardFact, UnknownGuardKind, UsageKind,
    };

    #[test]
    fn disconnected_mutual_recursion_is_one_dead_scc() {
        let mut file = facts_with_symbols(&[
            ("left", DeclarationKind::Function),
            ("right", DeclarationKind::Function),
        ]);
        file.symbol_facts.references = vec![
            reference(0, 1, UsageKind::Runtime),
            reference(1, 0, UsageKind::Runtime),
        ];
        let files = [file];
        let result = analyze_symbols(&input(&files, &[true], &[false], &[]));

        assert_eq!(result.dead_groups.len(), 1);
        assert!(result.dead_groups[0].cyclic);
        assert_eq!(result.dead_groups[0].members.len(), 2);
    }

    #[test]
    fn module_execution_reaches_a_symbol_chain_but_not_a_dead_cycle() {
        let mut file = facts_with_symbols(&[
            ("entry", DeclarationKind::Function),
            ("helper", DeclarationKind::Function),
            ("dead", DeclarationKind::Function),
        ]);
        file.symbol_facts.references = vec![
            SymbolReferenceFact {
                owner: ReferenceOwner::Region(ExecutionRegionId::MODULE),
                region: ExecutionRegionId::MODULE,
                target: SemanticSymbolId(0),
                usage: UsageKind::Runtime,
                read: true,
                write: false,
                call: true,
                escape: false,
                span: SourceSpan::new(1, 2),
            },
            reference(0, 1, UsageKind::Runtime),
            reference(2, 2, UsageKind::Runtime),
        ];
        let files = [file];
        let result = analyze_symbols(&input(&files, &[true], &[false], &[]));

        assert!(result.liveness(key(0, 0)).unwrap().runtime);
        assert!(result.liveness(key(0, 1)).unwrap().runtime);
        assert!(!result.liveness(key(0, 2)).unwrap().runtime);
        assert_eq!(result.dead_groups.len(), 1);
        assert!(result.dead_groups[0].cyclic);
    }

    #[test]
    fn open_world_exports_preserve_runtime_and_type_roots_separately() {
        let mut file = facts_with_symbols(&[
            ("run", DeclarationKind::Function),
            ("Shape", DeclarationKind::Interface),
        ]);
        file.symbol_facts.symbols[1].namespace = SymbolNamespace::Type;
        file.symbol_facts.exports = vec![export("run", 0, false), export("Shape", 1, true)];
        let files = [file];
        let result = analyze_symbols(&input(&files, &[true], &[true], &[]));

        assert!(result.liveness(key(0, 0)).unwrap().runtime);
        assert!(!result.liveness(key(0, 0)).unwrap().r#type);
        assert!(!result.liveness(key(0, 1)).unwrap().runtime);
        assert!(result.liveness(key(0, 1)).unwrap().r#type);
        assert!(result.dead_groups.is_empty());
    }

    #[test]
    fn resolved_import_links_cross_file_boundaries() {
        let mut importer = facts_with_symbols(&[("remote", DeclarationKind::Import)]);
        importer.symbol_facts.references = vec![SymbolReferenceFact {
            owner: ReferenceOwner::Region(ExecutionRegionId::MODULE),
            region: ExecutionRegionId::MODULE,
            target: SemanticSymbolId(0),
            usage: UsageKind::Runtime,
            read: true,
            write: false,
            call: false,
            escape: false,
            span: SourceSpan::new(1, 2),
        }];
        let exporter = facts_with_symbols(&[("remote", DeclarationKind::Function)]);
        let files = [importer, exporter];
        let links = [ResolvedSymbolLink {
            source: key(0, 0),
            source_usage: UsageKind::Runtime,
            target: key(1, 0),
            target_usage: UsageKind::Runtime,
        }];
        let result = analyze_symbols(&input(&files, &[true, true], &[false, false], &links));

        assert!(result.liveness(key(1, 0)).unwrap().runtime);
        assert!(result.dead_groups.is_empty());
    }

    #[test]
    fn direct_eval_suppresses_dead_declaration_groups() {
        let mut file = facts_with_symbols(&[("maybeUsed", DeclarationKind::Variable)]);
        file.symbol_facts.unknown_guards = vec![UnknownGuardFact {
            kind: UnknownGuardKind::DirectEval,
            region: Some(ExecutionRegionId::MODULE),
            span: SourceSpan::new(0, 4),
        }];
        let files = [file];
        let result = analyze_symbols(&input(&files, &[true], &[false], &[]));

        assert!(!result.files[0].declarations_complete);
        assert!(result.dead_groups.is_empty());
    }

    #[test]
    fn common_js_export_unknowns_do_not_hide_local_dead_declarations() {
        let mut file = facts_with_symbols(&[("local", DeclarationKind::Variable)]);
        file.symbol_facts.unknown_guards = vec![UnknownGuardFact {
            kind: UnknownGuardKind::ComputedCommonJsExport,
            region: Some(ExecutionRegionId::MODULE),
            span: SourceSpan::new(0, 4),
        }];
        let files = [file];
        let result = analyze_symbols(&input(&files, &[true], &[false], &[]));

        assert!(result.files[0].declarations_complete);
        assert!(!result.files[0].exports_complete);
        assert_eq!(result.dead_groups.len(), 1);
    }

    fn input<'a>(
        files: &'a [FileFacts],
        reachable_files: &'a [bool],
        open_world_files: &'a [bool],
        links: &'a [ResolvedSymbolLink],
    ) -> SymbolAnalysisInput<'a> {
        SymbolAnalysisInput {
            files,
            reachable_files,
            open_world_files,
            links,
            explicit_roots: &[],
        }
    }

    fn key(file: usize, symbol: u32) -> SymbolKey {
        SymbolKey {
            file,
            symbol: SemanticSymbolId(symbol),
        }
    }

    fn facts_with_symbols(symbols: &[(&str, DeclarationKind)]) -> FileFacts {
        FileFacts {
            path: "src/file.ts".to_owned(),
            source_kind: SourceKind::TypeScript,
            module_kind: ModuleKind::Esm,
            byte_len: 0,
            line_count: 0,
            imports: Vec::new(),
            exports: Vec::new(),
            symbol_facts: SymbolFileFacts {
                regions: vec![ExecutionRegionFact {
                    id: ExecutionRegionId::MODULE,
                    parent: None,
                    owner: None,
                    kind: ExecutionRegionKind::Module,
                    span: SourceSpan::new(0, 0),
                    eager: true,
                }],
                symbols: symbols
                    .iter()
                    .enumerate()
                    .map(|(index, (name, kind))| {
                        let offset = u32::try_from(index)
                            .expect("test fixture symbol count should fit in a u32");
                        let end = offset.saturating_add(1);
                        SymbolFact {
                            id: SemanticSymbolId(offset),
                            name: (*name).to_owned(),
                            kind: *kind,
                            namespace: SymbolNamespace::Runtime,
                            region: ExecutionRegionId::MODULE,
                            span: SourceSpan::new(offset, end),
                            declarations: vec![SourceSpan::new(offset, end)],
                            flags: SymbolFactFlags {
                                safe_removal_span: true,
                                ..SymbolFactFlags::default()
                            },
                        }
                    })
                    .collect(),
                ..SymbolFileFacts::default()
            },
            member_facts: Vec::new(),
            diagnostics: Vec::new(),
        }
    }

    fn reference(source: u32, target: u32, usage: UsageKind) -> SymbolReferenceFact {
        SymbolReferenceFact {
            owner: ReferenceOwner::Symbol(SemanticSymbolId(source)),
            region: ExecutionRegionId(source.saturating_add(1)),
            target: SemanticSymbolId(target),
            usage,
            read: true,
            write: false,
            call: true,
            escape: false,
            span: SourceSpan::new(target, target.saturating_add(1)),
        }
    }

    fn export(name: &str, local: u32, type_only: bool) -> ExportBindingFact {
        ExportBindingFact {
            exported: name.to_owned(),
            source: None,
            imported: None,
            local: Some(SemanticSymbolId(local)),
            kind: ExportBindingKind::Local,
            type_only,
            span: SourceSpan::new(local, local.saturating_add(1)),
        }
    }
}
