use std::{collections::HashMap, path::Path};

use oxc_allocator::Allocator;
use oxc_ast::AstKind;
use oxc_ast::ast::{
    AccessorProperty, Argument, AssignmentExpression, AssignmentOperator, CallExpression, Class,
    ClassElement, ExportAllDeclaration, ExportDeclaration, ExportDefaultDeclaration,
    ExportDefaultDeclarationKind, ExportFromDeclaration, ExportNamedDeclaration, Expression,
    ImportDeclaration, ImportDeclarationSpecifier, ImportExpression, MemberExpression,
    MethodDefinitionKind, ModuleExportName, NewExpression, PropertyDefinition, TSAccessibility,
    VariableDeclarator, WithStatement,
};
use oxc_ast_visit::{Visit, walk as visit};
use oxc_ecmascript::BoundNames;
use oxc_parser::Parser;
use oxc_semantic::{IsGlobalReference, Semantic, SemanticBuilder};
use oxc_span::{GetSpan, SourceType};

use crate::analysis::escape::{EscapeFact, UnknownScope};
use crate::domain::facts::{
    Activation, AnalysisDiagnostic, ClassMemberFact, ClassMemberKind, ClassMemberVisibility,
    DeclarationKind, DiagnosticSeverity, ExecutionRegionFact, ExecutionRegionId,
    ExecutionRegionKind, ExportBindingFact, ExportBindingKind, ExportFact, ExportKind, FileFacts,
    ImportBindingFact, ImportBindingKind, ImportFact, ImportKind, ModuleKind, ReferenceOwner,
    ResolutionMode, SemanticSymbolId, SourceKind, SourceSpan, SymbolFact, SymbolFactFlags,
    SymbolFileFacts, SymbolNamespace, SymbolReferenceFact, UnknownGuardFact, UnknownGuardKind,
    UsageKind,
};
use crate::limits::AnalysisLimits;

use super::constants::{
    DynamicLoadForm, StaticStringEvaluator, dynamic_call_candidate, dynamic_new_target,
};

#[must_use]
pub fn parse_file(display_path: &str, physical_path: &Path, source_text: &str) -> FileFacts {
    parse_file_with_limits(
        display_path,
        physical_path,
        source_text,
        AnalysisLimits::default(),
    )
}

#[must_use]
pub(crate) fn parse_file_with_limits(
    display_path: &str,
    physical_path: &Path,
    source_text: &str,
    limits: AnalysisLimits,
) -> FileFacts {
    let (source_kind, module_kind) = classify_source(physical_path);
    let byte_len = u64::try_from(source_text.len()).unwrap_or(u64::MAX);
    let line_count = count_lines(source_text);
    let source_type = match SourceType::from_path(physical_path) {
        Ok(source_type) => source_type,
        Err(error) => {
            let diagnostic = unsupported_source_type_diagnostic(display_path, error.to_string());
            return failed_file_facts(
                display_path,
                source_kind,
                module_kind,
                byte_len,
                line_count,
                vec![diagnostic],
            );
        }
    };

    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source_text, source_type).parse();
    let mut diagnostics = parsed
        .diagnostics
        .iter()
        .map(|diagnostic| oxc_diagnostic(display_path, "parse_failure", diagnostic))
        .collect::<Vec<_>>();

    if parsed.panicked && diagnostics.is_empty() {
        diagnostics.push(AnalysisDiagnostic {
            code: "parse_failure".to_owned(),
            path: display_path.to_owned(),
            severity: DiagnosticSeverity::Error,
            span: None,
            message: "The parser could not recover from this file".to_owned(),
            blocks_reachability: true,
        });
    }

    if !diagnostics.is_empty() {
        return failed_file_facts(
            display_path,
            source_kind,
            module_kind,
            byte_len,
            line_count,
            diagnostics,
        );
    }

    let semantic_return = SemanticBuilder::new_compiler()
        .with_build_nodes(true)
        .build(&parsed.program);
    diagnostics.extend(
        semantic_return
            .diagnostics
            .iter()
            .map(|diagnostic| oxc_diagnostic(display_path, "semantic_failure", diagnostic)),
    );

    if !diagnostics.is_empty() {
        return failed_file_facts(
            display_path,
            source_kind,
            module_kind,
            byte_len,
            line_count,
            diagnostics,
        );
    }

    let mut collector = FactCollector::new(
        display_path,
        source_text,
        source_kind,
        &semantic_return.semantic,
        limits,
    );
    collector.visit_program(&parsed.program);
    collector.finish_symbol_facts(source_text);
    collector.imports.sort_by(import_sort_key);
    collector.exports.sort_by(export_sort_key);
    collector.member_facts.sort_by_key(|member| {
        (
            member.span.start,
            member.span.end,
            member.declaring_class.clone(),
            member.name.clone(),
        )
    });
    sort_diagnostics(&mut collector.diagnostics);

    FileFacts {
        path: display_path.to_owned(),
        source_kind,
        module_kind,
        byte_len,
        line_count,
        imports: collector.imports,
        exports: collector.exports,
        symbol_facts: collector.symbol_facts,
        member_facts: collector.member_facts,
        diagnostics: collector.diagnostics,
    }
}

fn unsupported_source_type_diagnostic(path: &str, message: String) -> AnalysisDiagnostic {
    AnalysisDiagnostic {
        code: "unsupported_source_type".to_owned(),
        path: path.to_owned(),
        severity: DiagnosticSeverity::Error,
        span: None,
        message,
        blocks_reachability: true,
    }
}

fn failed_file_facts(
    display_path: &str,
    source_kind: SourceKind,
    module_kind: ModuleKind,
    byte_len: u64,
    line_count: u32,
    mut diagnostics: Vec<AnalysisDiagnostic>,
) -> FileFacts {
    sort_diagnostics(&mut diagnostics);
    FileFacts {
        path: display_path.to_owned(),
        source_kind,
        module_kind,
        byte_len,
        line_count,
        imports: Vec::new(),
        exports: Vec::new(),
        symbol_facts: SymbolFileFacts::default(),
        member_facts: Vec::new(),
        diagnostics,
    }
}

struct FactCollector<'s, 'a> {
    path: &'s str,
    source_text: &'s str,
    source_kind: SourceKind,
    semantic: &'s Semantic<'a>,
    imports: Vec<ImportFact>,
    exports: Vec<ExportFact>,
    symbol_facts: SymbolFileFacts,
    member_facts: Vec<ClassMemberFact>,
    diagnostics: Vec<AnalysisDiagnostic>,
    pending_regions: Vec<PendingRegion>,
    pending_guards: Vec<PendingGuard>,
    deferred_region_depth: usize,
    dynamic_scope_depth: usize,
    unknown_computed_member_access: bool,
    limits: AnalysisLimits,
}

#[derive(Debug, Clone, Copy)]
struct PendingRegion {
    kind: ExecutionRegionKind,
    span: SourceSpan,
    node_id: oxc_semantic::NodeId,
}

#[derive(Debug, Clone, Copy)]
struct PendingGuard {
    kind: UnknownGuardKind,
    span: SourceSpan,
    node_id: oxc_semantic::NodeId,
}

impl<'s, 'a> FactCollector<'s, 'a> {
    fn new(
        path: &'s str,
        source_text: &'s str,
        source_kind: SourceKind,
        semantic: &'s Semantic<'a>,
        limits: AnalysisLimits,
    ) -> Self {
        Self {
            path,
            source_text,
            source_kind,
            semantic,
            imports: Vec::new(),
            exports: Vec::new(),
            symbol_facts: SymbolFileFacts::default(),
            member_facts: Vec::new(),
            diagnostics: Vec::new(),
            pending_regions: Vec::new(),
            pending_guards: Vec::new(),
            deferred_region_depth: 0,
            dynamic_scope_depth: 0,
            unknown_computed_member_access: false,
            limits,
        }
    }

    fn add_module_load(
        &mut self,
        specifier: &str,
        kind: ImportKind,
        resolution_mode: ResolutionMode,
        type_only: bool,
        span: oxc_span::Span,
        deferred: bool,
    ) {
        let activation = if deferred {
            Activation::Deferred
        } else {
            Activation::Module
        };
        self.imports.push(ImportFact {
            specifier: specifier.to_owned(),
            kind,
            resolution_mode,
            activation,
            type_only,
            span: span.into(),
        });

        if deferred {
            self.diagnostics.push(AnalysisDiagnostic {
                code: "deferred_execution_region".to_owned(),
                path: self.path.to_owned(),
                severity: DiagnosticSeverity::Warning,
                span: Some(span.into()),
                message: format!(
                    "Cannot activate `{specifier}` until its execution region is modeled"
                ),
                blocks_reachability: true,
            });
        }
    }

    fn add_dynamic_diagnostic(&mut self, code: &str, message: &str, span: oxc_span::Span) {
        self.diagnostics.push(AnalysisDiagnostic {
            code: code.to_owned(),
            path: self.path.to_owned(),
            severity: DiagnosticSeverity::Warning,
            span: Some(span.into()),
            message: message.to_owned(),
            blocks_reachability: true,
        });
    }

    fn add_evaluated_load(
        &mut self,
        target: &Expression<'a>,
        form: DynamicLoadForm,
        span: oxc_span::Span,
        node_id: oxc_semantic::NodeId,
    ) {
        let evaluator = StaticStringEvaluator::with_limits(self.semantic, self.limits);
        match evaluator.evaluate_load_target(target) {
            Ok(Some(specifier)) => {
                let resolution_mode = if form == DynamicLoadForm::ChildProcessFork {
                    ResolutionMode::CommonJs
                } else {
                    ResolutionMode::Esm
                };
                self.add_module_load(
                    &specifier,
                    ImportKind::Dynamic,
                    resolution_mode,
                    false,
                    span,
                    self.is_deferred(node_id),
                );
            }
            Ok(None) => {
                let prefix = evaluator.leading_static_prefix(target).ok().flatten();
                let escape =
                    EscapeFact::unknown_module_specifier(prefix.as_deref(), SourceSpan::from(span));
                let scope = match escape.scope {
                    UnknownScope::RelativeDirectory(directory) => {
                        format!("the `{}` directory", directory.display())
                    }
                    UnknownScope::WorkspaceFileGraph => "the workspace file graph".to_owned(),
                };
                self.add_dynamic_diagnostic(
                    form.diagnostic_code(),
                    &format!(
                        "{} is not statically enumerable; uncertainty is limited to {scope}",
                        form.description()
                    ),
                    span,
                );
            }
            Err(error) => {
                self.add_dynamic_diagnostic(error.diagnostic_code(), &error.message(), span);
            }
        }
    }

    fn dynamic_form_is_authorized(&self, form: DynamicLoadForm, callee: &Expression<'a>) -> bool {
        if form == DynamicLoadForm::SharedWorker {
            return self.is_global_identifier(callee, "SharedWorker");
        }
        if form.required_node_binding().is_none() {
            return true;
        }
        if form.allows_global_binding()
            && matches!(
                form,
                DynamicLoadForm::Worker | DynamicLoadForm::SharedWorker
            )
            && self.is_global_identifier(callee, "Worker")
        {
            return true;
        }

        let (local, referenced_export) = match callee.get_inner_expression() {
            Expression::Identifier(identifier) => (
                self.resolved_expression_symbol(callee),
                identifier.name.as_str(),
            ),
            expression => {
                let Some(member) = expression.as_member_expression() else {
                    return false;
                };
                (
                    self.resolved_expression_symbol(member.object()),
                    member.static_property_name().unwrap_or(""),
                )
            }
        };
        let Some(local) = local else {
            return false;
        };
        self.symbol_facts.imports.iter().any(|binding| {
            if binding.local != local {
                return false;
            }
            let imported = binding.imported.as_deref().unwrap_or(referenced_export);
            form.matches_node_binding(&binding.source, imported)
        })
    }

    fn is_deferred(&self, node_id: oxc_semantic::NodeId) -> bool {
        if self.deferred_region_depth > 0 {
            return true;
        }
        let scoping = self.semantic.scoping();
        let scope_id = self.semantic.nodes().get_node(node_id).scope_id();
        scoping
            .scope_ancestors(scope_id)
            .any(|scope| scoping.scope_flags(scope).is_function())
    }

    fn is_global_identifier(&self, expression: &Expression<'a>, name: &str) -> bool {
        matches!(
            expression,
            Expression::Identifier(identifier)
                if identifier.name == name
                    && identifier.is_global_reference(self.semantic.scoping())
        )
    }

    fn is_require_syntax(expression: &Expression<'a>) -> bool {
        if matches!(
            expression,
            Expression::Identifier(identifier) if identifier.name == "require"
        ) {
            return true;
        }

        expression.as_member_expression().is_some_and(|member| {
            member.is_specific_member_access("require", "resolve")
                && matches!(
                    member.object(),
                    Expression::Identifier(identifier) if identifier.name == "require"
                )
        })
    }

    fn common_js_export(&self, member: &MemberExpression<'a>) -> Option<(String, ExportKind)> {
        if member.is_specific_member_access("module", "exports")
            && self.is_global_identifier(member.object(), "module")
        {
            return Some(("default".to_owned(), ExportKind::Default));
        }

        if self.is_global_identifier(member.object(), "exports") {
            return member
                .static_property_name()
                .map(|name| (name.to_owned(), ExportKind::Named));
        }

        let base = member.object().as_member_expression()?;
        if base.is_specific_member_access("module", "exports")
            && self.is_global_identifier(base.object(), "module")
        {
            return member
                .static_property_name()
                .map(|name| (name.to_owned(), ExportKind::Named));
        }

        None
    }

    fn is_common_js_export_property(&self, member: &MemberExpression<'a>) -> bool {
        if self.is_global_identifier(member.object(), "exports") {
            return true;
        }

        member.object().as_member_expression().is_some_and(|base| {
            base.is_specific_member_access("module", "exports")
                && self.is_global_identifier(base.object(), "module")
        })
    }

    fn is_common_js_export_object(&self, expression: &Expression<'a>) -> bool {
        self.is_global_identifier(expression, "exports")
            || expression.as_member_expression().is_some_and(|member| {
                member.is_specific_member_access("module", "exports")
                    && self.is_global_identifier(member.object(), "module")
            })
    }

    fn is_opaque_common_js_export_call(&self, expression: &CallExpression<'a>) -> bool {
        let Some(member) = expression.callee.as_member_expression() else {
            return false;
        };
        let Some(operation) = member.static_property_name() else {
            return false;
        };
        if !matches!(operation, "assign" | "defineProperties" | "defineProperty")
            || (!self.is_global_identifier(member.object(), "Object")
                && !self.is_global_identifier(member.object(), "Reflect"))
        {
            return false;
        }
        expression
            .arguments
            .first()
            .and_then(Argument::as_expression)
            .is_some_and(|target| self.is_common_js_export_object(target))
    }

    fn add_common_js_export_guard(
        &mut self,
        kind: UnknownGuardKind,
        node_id: oxc_semantic::NodeId,
        span: oxc_span::Span,
        message: &str,
    ) {
        self.pending_guards.push(PendingGuard {
            kind,
            span: span.into(),
            node_id,
        });
        self.diagnostics.push(AnalysisDiagnostic {
            code: "unsupported_common_js_export".to_owned(),
            path: self.path.to_owned(),
            severity: DiagnosticSeverity::Warning,
            span: Some(span.into()),
            message: message.to_owned(),
            blocks_reachability: false,
        });
    }

    fn visit_instance_initializer(&mut self, initializer: Option<&Expression<'a>>) {
        let Some(initializer) = initializer else {
            return;
        };

        self.deferred_region_depth += 1;
        self.visit_expression(initializer);
        self.deferred_region_depth -= 1;
    }

    fn resolved_export_symbol(&self, name: &ModuleExportName<'a>) -> Option<SemanticSymbolId> {
        let ModuleExportName::IdentifierReference(identifier) = name else {
            return None;
        };
        let reference = self
            .semantic
            .scoping()
            .get_reference(identifier.reference_id());
        reference.symbol_id().map(lower_symbol_id)
    }

    fn resolved_expression_symbol(&self, expression: &Expression<'a>) -> Option<SemanticSymbolId> {
        let Expression::Identifier(identifier) = expression else {
            return None;
        };
        let reference = self
            .semantic
            .scoping()
            .get_reference(identifier.reference_id());
        reference.symbol_id().map(lower_symbol_id)
    }

    #[allow(clippy::too_many_lines)]
    fn finish_symbol_facts(&mut self, source_text: &str) {
        let scoping = self.semantic.scoping();
        let nodes = self.semantic.nodes();
        let declaration_owners = scoping
            .symbol_ids()
            .map(|symbol_id| {
                (
                    scoping.symbol_declaration(symbol_id),
                    lower_symbol_id(symbol_id),
                )
            })
            .collect::<HashMap<_, _>>();

        let mut region_by_scope = HashMap::new();
        region_by_scope.insert(scoping.root_scope_id(), ExecutionRegionId::MODULE);
        let mut regions = vec![ExecutionRegionFact {
            id: ExecutionRegionId::MODULE,
            parent: None,
            owner: None,
            kind: ExecutionRegionKind::Module,
            span: SourceSpan::new(0, u32::try_from(source_text.len()).unwrap_or(u32::MAX)),
            eager: true,
        }];

        for scope_id in scoping.scope_descendants_from_root() {
            if scope_id == scoping.root_scope_id() {
                continue;
            }
            let flags = scoping.scope_flags(scope_id);
            if !flags.is_function() && !flags.is_class_static_block() {
                continue;
            }
            let node_id = scoping.get_node_id(scope_id);
            let parent = scoping
                .scope_ancestors(scope_id)
                .skip(1)
                .find_map(|ancestor| region_by_scope.get(&ancestor).copied())
                .unwrap_or(ExecutionRegionId::MODULE);
            let region_id = next_region_id(regions.len());
            let kind = if flags.is_class_static_block() {
                ExecutionRegionKind::ClassStaticBlock
            } else {
                ExecutionRegionKind::Function
            };
            regions.push(ExecutionRegionFact {
                id: region_id,
                parent: Some(parent),
                owner: owner_for_node(nodes, &declaration_owners, node_id),
                kind,
                span: nodes.kind(node_id).span().into(),
                eager: flags.is_class_static_block(),
            });
            region_by_scope.insert(scope_id, region_id);
        }

        self.pending_regions
            .sort_by_key(|region| (region.span.start, region.span.end, region.kind));
        for pending in &self.pending_regions {
            let scope_id = nodes.get_node(pending.node_id).scope_id();
            let parent = region_for_scope(scoping, &region_by_scope, scope_id);
            let region_id = next_region_id(regions.len());
            regions.push(ExecutionRegionFact {
                id: region_id,
                parent: Some(parent),
                owner: owner_for_node(nodes, &declaration_owners, pending.node_id),
                kind: pending.kind,
                span: pending.span,
                eager: false,
            });
        }

        let mut symbols = Vec::with_capacity(scoping.symbols_len());
        for symbol_id in scoping.symbol_ids() {
            let oxc_flags = scoping.symbol_flags(symbol_id);
            let declaration_node = scoping.symbol_declaration(symbol_id);
            let declaration_scope = nodes.get_node(declaration_node).scope_id();
            let kind = declaration_kind(oxc_flags);
            let namespace = symbol_namespace(oxc_flags);
            let mut declarations = scoping
                .symbol_declarations(symbol_id)
                .map(|node_id| SourceSpan::from(nodes.kind(node_id).span()))
                .collect::<Vec<_>>();
            declarations.sort_unstable();
            declarations.dedup();
            let initializer_effectful = declaration_is_effectful(kind, &declarations, source_text);
            let safe_removal_span =
                declaration_has_safe_removal_span(kind, initializer_effectful, declarations.len());
            symbols.push(SymbolFact {
                id: lower_symbol_id(symbol_id),
                name: scoping.symbol_name(symbol_id).to_owned(),
                kind,
                namespace,
                region: region_for_scope(scoping, &region_by_scope, declaration_scope),
                span: scoping.symbol_span(symbol_id).into(),
                declarations,
                flags: SymbolFactFlags {
                    mutated: scoping.symbol_is_mutated(symbol_id),
                    initializer_effectful,
                    ambient: oxc_flags.is_ambient(),
                    safe_removal_span,
                    ..SymbolFactFlags::default()
                },
            });
        }

        let mut references = Vec::with_capacity(scoping.references_len());
        for symbol_id in scoping.symbol_ids() {
            for reference in scoping.get_resolved_references(symbol_id) {
                let raw_span = self.semantic.reference_span(reference);
                let base_region = region_for_scope(scoping, &region_by_scope, reference.scope_id());
                let region = innermost_pending_region(&regions, base_region, raw_span.into());
                let region_fact = &regions[region.0 as usize];
                let parent = nodes.parent_kind(reference.node_id());
                if matches!(parent, AstKind::ExportSpecifier(_)) {
                    continue;
                }
                let call = parent.is_callee_with_span(raw_span);
                let escape = reference.is_read()
                    && (parent.has_argument_with_span(raw_span)
                        || matches!(
                            parent,
                            AstKind::AssignmentExpression(_)
                                | AstKind::ReturnStatement(_)
                                | AstKind::SpreadElement(_)
                                | AstKind::ThrowStatement(_)
                                | AstKind::YieldExpression(_)
                        ));
                references.push(SymbolReferenceFact {
                    owner: if reference.is_type() {
                        owner_for_node(nodes, &declaration_owners, reference.node_id())
                            .or(region_fact.owner)
                            .map_or(ReferenceOwner::Region(region), ReferenceOwner::Symbol)
                    } else {
                        region_fact
                            .owner
                            .map_or(ReferenceOwner::Region(region), ReferenceOwner::Symbol)
                    },
                    region,
                    target: lower_symbol_id(symbol_id),
                    usage: if reference.is_type() {
                        UsageKind::Type
                    } else {
                        UsageKind::Runtime
                    },
                    read: reference.is_read(),
                    write: reference.is_write(),
                    call,
                    escape,
                    span: raw_span.into(),
                });
            }
        }

        for scope_id in scoping.scope_descendants_from_root() {
            let flags = scoping.scope_flags(scope_id);
            let node_id = scoping.get_node_id(scope_id);
            let span = nodes.kind(node_id).span().into();
            let region = Some(region_for_scope(scoping, &region_by_scope, scope_id));
            if flags.contains_direct_eval() {
                self.symbol_facts.unknown_guards.push(UnknownGuardFact {
                    kind: UnknownGuardKind::DirectEval,
                    region,
                    span,
                });
            }
            if flags.is_with() {
                self.symbol_facts.unknown_guards.push(UnknownGuardFact {
                    kind: UnknownGuardKind::DynamicScope,
                    region,
                    span,
                });
            }
        }
        for pending in &self.pending_guards {
            let scope_id = nodes.get_node(pending.node_id).scope_id();
            self.symbol_facts.unknown_guards.push(UnknownGuardFact {
                kind: pending.kind,
                region: Some(region_for_scope(scoping, &region_by_scope, scope_id)),
                span: pending.span,
            });
        }

        let symbol_indexes = symbols
            .iter()
            .enumerate()
            .map(|(index, symbol)| (symbol.id, index))
            .collect::<HashMap<_, _>>();
        for import in &self.symbol_facts.imports {
            if let Some(index) = symbol_indexes.get(&import.local) {
                symbols[*index].flags.imported = true;
            }
        }
        for export in &self.symbol_facts.exports {
            if let Some(local) = export.local
                && let Some(index) = symbol_indexes.get(&local)
            {
                symbols[*index].flags.exported = true;
            }
        }
        for reference in &references {
            if reference.escape
                && let Some(index) = symbol_indexes.get(&reference.target)
            {
                symbols[*index].flags.escapes = true;
            }
        }

        for member in &mut self.member_facts {
            member.unknown_bracket_access |= self.unknown_computed_member_access;
            if member.declaring_class.starts_with("<anonymous@") {
                member.class_exported = true;
                member.class_escaped = true;
                continue;
            }
            if let Some(class_symbol) = symbols.iter().find(|symbol| {
                symbol.kind == DeclarationKind::Class && symbol.name == member.declaring_class
            }) {
                member.class_exported = class_symbol.flags.exported;
                member.class_escaped = class_symbol.flags.escapes;
            }
        }

        references.sort_by_key(|reference| {
            (
                reference.span.start,
                reference.span.end,
                reference.target,
                reference.usage,
                reference.owner,
            )
        });
        self.symbol_facts.imports.sort_by_key(|binding| {
            (
                binding.span.start,
                binding.span.end,
                binding.local,
                binding.kind,
            )
        });
        self.symbol_facts.exports.sort_by_key(|binding| {
            (
                binding.span.start,
                binding.span.end,
                binding.exported.clone(),
                binding.kind,
            )
        });
        self.symbol_facts.unknown_guards.sort_unstable();
        self.symbol_facts.unknown_guards.dedup();
        self.symbol_facts.regions = regions;
        self.symbol_facts.symbols = symbols;
        self.symbol_facts.references = references;
    }

    fn collect_class_members(&mut self, class: &Class<'a>) {
        let class_name = class.id.as_ref().map_or_else(
            || format!("<anonymous@{}>", class.span.start),
            |identifier| identifier.name.to_string(),
        );
        let participates_in_inheritance = class.heritage.is_some() || !class.implements.is_empty();
        let implements_external_contract = !class.implements.is_empty();
        let class_decorated = !class.decorators.is_empty();

        for element in &class.body.body {
            let Some(property_key) = element.property_key() else {
                continue;
            };
            let Some(raw_name) = property_key.name() else {
                continue;
            };
            let is_private = property_key.is_private_identifier();
            let name = if is_private {
                format!("#{raw_name}")
            } else {
                raw_name.into_owned()
            };
            let (kind, visibility, overridden, decorated, span) = match element {
                ClassElement::MethodDefinition(method) => {
                    let kind = match method.kind {
                        MethodDefinitionKind::Constructor => continue,
                        MethodDefinitionKind::Method => ClassMemberKind::Method,
                        MethodDefinitionKind::Get => ClassMemberKind::Getter,
                        MethodDefinitionKind::Set => ClassMemberKind::Setter,
                    };
                    (
                        kind,
                        member_visibility(is_private, method.accessibility),
                        method.r#override,
                        !method.decorators.is_empty(),
                        method.span,
                    )
                }
                ClassElement::PropertyDefinition(property) => (
                    ClassMemberKind::Field,
                    member_visibility(is_private, property.accessibility),
                    property.r#override,
                    !property.decorators.is_empty(),
                    property.span,
                ),
                ClassElement::AccessorProperty(property) => (
                    ClassMemberKind::Accessor,
                    member_visibility(is_private, property.accessibility),
                    property.r#override,
                    !property.decorators.is_empty(),
                    property.span,
                ),
                ClassElement::StaticBlock(_) | ClassElement::TSIndexSignature(_) => continue,
            };
            let decorated = decorated || class_decorated;
            let directly_referenced = member_token_occurrences(self.source_text, &name) > 1;
            let unknown_bracket_access = !is_private
                && (self.source_text.contains("[key]")
                    || self.source_text.contains("[name]")
                    || self.source_text.contains("[property]")
                    || self.source_text.contains("[member]"));
            self.member_facts.push(ClassMemberFact {
                declaring_class: class_name.clone(),
                name,
                kind,
                visibility,
                r#static: element.r#static(),
                span: span.into(),
                directly_referenced,
                decorated,
                emitted_decorator_metadata: decorated
                    && matches!(self.source_kind, SourceKind::TypeScript | SourceKind::Tsx),
                unknown_bracket_access,
                reflected_or_enumerated: contains_any(
                    self.source_text,
                    &[
                        "Object.keys(",
                        "Object.values(",
                        "Object.entries(",
                        "Object.getOwnProperty",
                        "Reflect.",
                    ],
                ),
                serialized: self.source_text.contains("JSON.stringify("),
                object_spread: self.source_text.contains("..."),
                proxied: self.source_text.contains("new Proxy("),
                passed_to_unknown_code: false,
                class_exported: false,
                class_escaped: false,
                participates_in_inheritance,
                relationships_complete: !participates_in_inheritance,
                overrides_live_base_member: overridden,
                has_live_override: false,
                implements_external_contract,
            });
        }
    }
}

impl<'a> Visit<'a> for FactCollector<'_, 'a> {
    fn visit_class(&mut self, class: &Class<'a>) {
        self.collect_class_members(class);
        visit::walk_class(self, class);
    }

    fn visit_member_expression(&mut self, expression: &MemberExpression<'a>) {
        if matches!(expression, MemberExpression::ComputedMemberExpression(_))
            && expression.static_property_name().is_none()
        {
            self.unknown_computed_member_access = true;
        }
        visit::walk_member_expression(self, expression);
    }

    fn visit_import_declaration(&mut self, declaration: &ImportDeclaration<'a>) {
        let is_side_effect = declaration
            .specifiers
            .as_ref()
            .is_none_or(|specifiers| specifiers.is_empty());
        let kind = if is_side_effect {
            ImportKind::SideEffect
        } else {
            ImportKind::Static
        };
        let all_specifiers_are_type_only =
            declaration.specifiers.as_ref().is_some_and(|specifiers| {
                !specifiers.is_empty()
                    && specifiers.iter().all(|specifier| {
                        matches!(
                            specifier,
                            ImportDeclarationSpecifier::ImportSpecifier(specifier)
                                if specifier.import_kind.is_type()
                        )
                    })
            });
        self.add_module_load(
            declaration.source.value.as_str(),
            kind,
            ResolutionMode::Esm,
            declaration.import_kind.is_type() || all_specifiers_are_type_only,
            declaration.span,
            false,
        );
        if let Some(specifiers) = &declaration.specifiers {
            for specifier in specifiers {
                let declaration_is_type = declaration.import_kind.is_type();
                let (local, imported, kind, specifier_is_type, span) = match specifier {
                    ImportDeclarationSpecifier::ImportSpecifier(specifier) => (
                        &specifier.local,
                        Some(module_export_name(&specifier.imported)),
                        ImportBindingKind::Named,
                        specifier.import_kind.is_type(),
                        specifier.span,
                    ),
                    ImportDeclarationSpecifier::ImportDefaultSpecifier(specifier) => (
                        &specifier.local,
                        Some("default".to_owned()),
                        ImportBindingKind::Default,
                        false,
                        specifier.span,
                    ),
                    ImportDeclarationSpecifier::ImportNamespaceSpecifier(specifier) => (
                        &specifier.local,
                        None,
                        ImportBindingKind::Namespace,
                        false,
                        specifier.span,
                    ),
                };
                self.symbol_facts.imports.push(ImportBindingFact {
                    source: declaration.source.value.to_string(),
                    imported,
                    local: lower_symbol_id(local.symbol_id()),
                    kind,
                    type_only: declaration_is_type || specifier_is_type,
                    span: span.into(),
                });
            }
        }
        visit::walk_import_declaration(self, declaration);
    }

    fn visit_export_named_declaration(&mut self, declaration: &ExportNamedDeclaration<'a>) {
        let declaration_is_type = declaration.export_kind.is_type();

        for specifier in &declaration.specifiers {
            let type_only = declaration_is_type || specifier.export_kind.is_type();
            self.exports.push(ExportFact {
                name: module_export_name(&specifier.exported),
                kind: ExportKind::Named,
                type_only,
                span: specifier.span.into(),
            });
            self.symbol_facts.exports.push(ExportBindingFact {
                exported: module_export_name(&specifier.exported),
                imported: None,
                local: self.resolved_export_symbol(&specifier.local),
                kind: ExportBindingKind::Local,
                source: None,
                type_only,
                span: specifier.span.into(),
            });
        }

        visit::walk_export_named_declaration(self, declaration);
    }

    fn visit_export_from_declaration(&mut self, declaration: &ExportFromDeclaration<'a>) {
        let declaration_is_type = declaration.export_kind.is_type();
        let all_specifiers_are_type_only = !declaration.specifiers.is_empty()
            && declaration
                .specifiers
                .iter()
                .all(|specifier| specifier.export_kind.is_type());
        self.add_module_load(
            declaration.source.value.as_str(),
            ImportKind::ReExport,
            ResolutionMode::Esm,
            declaration_is_type || all_specifiers_are_type_only,
            declaration.span,
            false,
        );

        for specifier in &declaration.specifiers {
            let type_only = declaration_is_type || specifier.export_kind.is_type();
            self.exports.push(ExportFact {
                name: module_export_name(&specifier.exported),
                kind: ExportKind::Named,
                type_only,
                span: specifier.span.into(),
            });
            self.symbol_facts.exports.push(ExportBindingFact {
                exported: module_export_name(&specifier.exported),
                imported: Some(module_export_name(&specifier.local)),
                local: None,
                kind: ExportBindingKind::ReExport,
                source: Some(declaration.source.value.to_string()),
                type_only,
                span: specifier.span.into(),
            });
        }

        visit::walk_export_from_declaration(self, declaration);
    }

    fn visit_export_declaration(&mut self, declaration: &ExportDeclaration<'a>) {
        let type_only = declaration.export_kind().is_type();
        declaration.declaration.bound_names(&mut |identifier| {
            self.exports.push(ExportFact {
                name: identifier.name.to_string(),
                kind: ExportKind::Named,
                type_only,
                span: identifier.span.into(),
            });
            self.symbol_facts.exports.push(ExportBindingFact {
                exported: identifier.name.to_string(),
                source: None,
                imported: None,
                local: Some(lower_symbol_id(identifier.symbol_id())),
                kind: ExportBindingKind::Local,
                type_only,
                span: identifier.span.into(),
            });
        });

        visit::walk_export_declaration(self, declaration);
    }

    fn visit_export_default_declaration(&mut self, declaration: &ExportDefaultDeclaration<'a>) {
        let type_only = matches!(
            &declaration.declaration,
            ExportDefaultDeclarationKind::TSInterfaceDeclaration(_)
        );
        self.exports.push(ExportFact {
            name: "default".to_owned(),
            kind: ExportKind::Default,
            type_only,
            span: declaration.span.into(),
        });
        let local = match &declaration.declaration {
            ExportDefaultDeclarationKind::FunctionDeclaration(function) => function
                .id
                .as_ref()
                .map(|id| lower_symbol_id(id.symbol_id())),
            ExportDefaultDeclarationKind::ClassDeclaration(class) => {
                class.id.as_ref().map(|id| lower_symbol_id(id.symbol_id()))
            }
            ExportDefaultDeclarationKind::TSInterfaceDeclaration(interface) => {
                Some(lower_symbol_id(interface.id.symbol_id()))
            }
            ExportDefaultDeclarationKind::Identifier(identifier) => self
                .semantic
                .scoping()
                .get_reference(identifier.reference_id())
                .symbol_id()
                .map(lower_symbol_id),
            _ => None,
        };
        self.symbol_facts.exports.push(ExportBindingFact {
            exported: "default".to_owned(),
            source: None,
            imported: None,
            local,
            kind: ExportBindingKind::Default,
            type_only,
            span: declaration.span.into(),
        });
        visit::walk_export_default_declaration(self, declaration);
    }

    fn visit_export_all_declaration(&mut self, declaration: &ExportAllDeclaration<'a>) {
        self.add_module_load(
            declaration.source.value.as_str(),
            ImportKind::ReExport,
            ResolutionMode::Esm,
            declaration.export_kind.is_type(),
            declaration.span,
            false,
        );
        let (name, kind) = declaration.exported.as_ref().map_or_else(
            || ("*".to_owned(), ExportKind::Star),
            |exported| (module_export_name(exported), ExportKind::Named),
        );
        self.exports.push(ExportFact {
            name,
            kind,
            type_only: declaration.export_kind.is_type(),
            span: declaration.span.into(),
        });
        self.symbol_facts.exports.push(ExportBindingFact {
            exported: declaration
                .exported
                .as_ref()
                .map_or_else(|| "*".to_owned(), module_export_name),
            source: Some(declaration.source.value.to_string()),
            imported: None,
            local: None,
            kind: if declaration.exported.is_some() {
                ExportBindingKind::ReExport
            } else {
                ExportBindingKind::Star
            },
            type_only: declaration.export_kind.is_type(),
            span: declaration.span.into(),
        });
        visit::walk_export_all_declaration(self, declaration);
    }

    fn visit_import_expression(&mut self, expression: &ImportExpression<'a>) {
        let evaluator = StaticStringEvaluator::with_limits(self.semantic, self.limits);
        match evaluator.evaluate(&expression.source) {
            Ok(Some(source)) => self.add_module_load(
                &source,
                ImportKind::Dynamic,
                ResolutionMode::Esm,
                false,
                expression.span,
                self.is_deferred(expression.node_id()),
            ),
            Ok(None) => {
                let prefix = evaluator
                    .leading_static_prefix(&expression.source)
                    .ok()
                    .flatten();
                let message = prefix.as_deref().map_or_else(
                    || "Dynamic import specifier is not statically enumerable".to_owned(),
                    |prefix| {
                        format!(
                            "Dynamic import specifier is not statically enumerable; uncertainty is limited to paths beginning with `{prefix}`"
                        )
                    },
                );
                self.add_dynamic_diagnostic(
                    "unsupported_dynamic_import",
                    &message,
                    expression.span,
                );
            }
            Err(error) => self.add_dynamic_diagnostic(
                error.diagnostic_code(),
                &error.message(),
                expression.span,
            ),
        }
        visit::walk_import_expression(self, expression);
    }

    fn visit_call_expression(&mut self, expression: &CallExpression<'a>) {
        let expression = self.alloc(expression);
        if self.is_opaque_common_js_export_call(expression) {
            self.add_common_js_export_guard(
                UnknownGuardKind::OpaqueCommonJsExports,
                expression.node_id(),
                expression.span,
                "CommonJS export mutation cannot be linked to a complete static export set",
            );
        }
        if self.dynamic_scope_depth > 0 && Self::is_require_syntax(&expression.callee) {
            self.add_dynamic_diagnostic(
                "unsupported_dynamic_scope_require",
                "Cannot determine whether `require` is global inside a `with` statement",
                expression.span,
            );
            visit::walk_call_expression(self, expression);
            return;
        }

        if let Some((form, target)) = dynamic_call_candidate(expression)
            && self.dynamic_form_is_authorized(form, &expression.callee)
        {
            self.add_evaluated_load(target, form, expression.span, expression.node_id());
        }

        let common_js_kind = if self.is_global_identifier(&expression.callee, "require") {
            Some(ImportKind::CommonJsRequire)
        } else if expression
            .callee
            .as_member_expression()
            .is_some_and(|member| {
                member.is_specific_member_access("require", "resolve")
                    && self.is_global_identifier(member.object(), "require")
            })
        {
            Some(ImportKind::CommonJsResolve)
        } else {
            None
        };

        if let Some(common_js_kind) = common_js_kind {
            if expression.arguments.len() == 1 {
                let Some(argument) = expression
                    .arguments
                    .first()
                    .and_then(Argument::as_expression)
                else {
                    self.add_dynamic_diagnostic(
                        "unsupported_dynamic_require",
                        "CommonJS require argument is a spread or unsupported expression",
                        expression.span,
                    );
                    visit::walk_call_expression(self, expression);
                    return;
                };
                let evaluator = StaticStringEvaluator::with_limits(self.semantic, self.limits);
                match evaluator.evaluate(argument) {
                    Ok(Some(source)) => self.add_module_load(
                        &source,
                        common_js_kind,
                        ResolutionMode::CommonJs,
                        false,
                        expression.span,
                        self.is_deferred(expression.node_id()),
                    ),
                    Ok(None) => self.add_dynamic_diagnostic(
                        "unsupported_dynamic_require",
                        "CommonJS require specifier is not statically enumerable",
                        expression.span,
                    ),
                    Err(error) => self.add_dynamic_diagnostic(
                        error.diagnostic_code(),
                        &error.message(),
                        expression.span,
                    ),
                }
            } else {
                self.add_dynamic_diagnostic(
                    "unsupported_dynamic_require",
                    "CommonJS require must have exactly one string-literal argument",
                    expression.span,
                );
            }
        }
        visit::walk_call_expression(self, expression);
    }

    fn visit_new_expression(&mut self, expression: &NewExpression<'a>) {
        let expression = self.alloc(expression);
        if let Some((form, target)) = dynamic_new_target(expression, self.semantic)
            && self.dynamic_form_is_authorized(form, &expression.callee)
        {
            self.add_evaluated_load(target, form, expression.span, expression.node_id());
        }
        visit::walk_new_expression(self, expression);
    }

    fn visit_variable_declarator(&mut self, declarator: &VariableDeclarator<'a>) {
        if let Some(Expression::CallExpression(call)) = &declarator.init
            && self.is_global_identifier(&call.callee, "require")
            && call.arguments.len() == 1
            && let Some(source) = call
                .arguments
                .first()
                .and_then(Argument::as_expression)
                .and_then(|argument| match argument {
                    Expression::StringLiteral(source) => Some(source),
                    _ => None,
                })
        {
            for local in declarator.id.get_binding_identifiers() {
                self.symbol_facts.imports.push(ImportBindingFact {
                    source: source.value.to_string(),
                    imported: None,
                    local: lower_symbol_id(local.symbol_id()),
                    kind: ImportBindingKind::CommonJs,
                    type_only: false,
                    span: declarator.span.into(),
                });
            }
        }
        visit::walk_variable_declarator(self, declarator);
    }

    fn visit_assignment_expression(&mut self, expression: &AssignmentExpression<'a>) {
        if let Some(member) = expression.left.as_member_expression()
            && expression.operator == AssignmentOperator::Assign
        {
            if let Some((name, kind)) = self.common_js_export(member) {
                let export_name = name.clone();
                self.exports.push(ExportFact {
                    name,
                    kind,
                    type_only: false,
                    span: expression.span.into(),
                });
                self.symbol_facts.exports.push(ExportBindingFact {
                    exported: export_name,
                    source: None,
                    imported: None,
                    local: self.resolved_expression_symbol(&expression.right),
                    kind: ExportBindingKind::CommonJs,
                    type_only: false,
                    span: expression.span.into(),
                });
                if kind == ExportKind::Default {
                    self.pending_guards.push(PendingGuard {
                        kind: UnknownGuardKind::OpaqueCommonJsExports,
                        span: expression.span.into(),
                        node_id: expression.node_id(),
                    });
                }
            } else if self.is_common_js_export_property(member) {
                self.add_common_js_export_guard(
                    UnknownGuardKind::ComputedCommonJsExport,
                    expression.node_id(),
                    expression.span,
                    "CommonJS export property name is not statically known",
                );
            }
        }
        visit::walk_assignment_expression(self, expression);
    }

    fn visit_property_definition(&mut self, property: &PropertyDefinition<'a>) {
        if property.r#static {
            visit::walk_property_definition(self, property);
            return;
        }

        self.visit_decorators(&property.decorators);
        self.visit_property_key(&property.key);
        if let Some(type_annotation) = &property.type_annotation {
            self.visit_ts_type_annotation(type_annotation);
        }
        if let Some(initializer) = property.value.as_ref() {
            self.pending_regions.push(PendingRegion {
                kind: ExecutionRegionKind::InstanceInitializer,
                span: initializer.span().into(),
                node_id: property.node_id(),
            });
        }
        self.visit_instance_initializer(property.value.as_ref());
    }

    fn visit_accessor_property(&mut self, property: &AccessorProperty<'a>) {
        if property.r#static {
            visit::walk_accessor_property(self, property);
            return;
        }

        self.visit_decorators(&property.decorators);
        self.visit_property_key(&property.key);
        if let Some(type_annotation) = &property.type_annotation {
            self.visit_ts_type_annotation(type_annotation);
        }
        if let Some(initializer) = property.value.as_ref() {
            self.pending_regions.push(PendingRegion {
                kind: ExecutionRegionKind::InstanceInitializer,
                span: initializer.span().into(),
                node_id: property.node_id(),
            });
        }
        self.visit_instance_initializer(property.value.as_ref());
    }

    fn visit_with_statement(&mut self, statement: &WithStatement<'a>) {
        self.visit_expression(&statement.object);
        self.dynamic_scope_depth += 1;
        self.visit_statement(&statement.body);
        self.dynamic_scope_depth -= 1;
    }
}

fn lower_symbol_id(symbol_id: oxc_semantic::SymbolId) -> SemanticSymbolId {
    SemanticSymbolId(u32::try_from(symbol_id.index()).unwrap_or(u32::MAX))
}

fn member_visibility(
    is_private_identifier: bool,
    accessibility: Option<TSAccessibility>,
) -> ClassMemberVisibility {
    if is_private_identifier {
        return ClassMemberVisibility::JavaScriptPrivate;
    }
    match accessibility {
        Some(TSAccessibility::Private) => ClassMemberVisibility::TypeScriptPrivate,
        Some(TSAccessibility::Protected) => ClassMemberVisibility::Protected,
        Some(TSAccessibility::Public) | None => ClassMemberVisibility::Public,
    }
}

fn member_token_occurrences(source: &str, member: &str) -> usize {
    if member.starts_with('#') {
        return source.match_indices(member).count();
    }
    source
        .match_indices(member)
        .filter(|(start, _)| {
            let before = source[..*start].chars().next_back();
            let end = *start + member.len();
            let after = source[end..].chars().next();
            !before.is_some_and(is_identifier_character)
                && !after.is_some_and(is_identifier_character)
        })
        .count()
}

fn is_identifier_character(character: char) -> bool {
    character == '_' || character == '$' || character.is_alphanumeric()
}

fn contains_any(source: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|pattern| source.contains(pattern))
}

fn next_region_id(region_count: usize) -> ExecutionRegionId {
    ExecutionRegionId(u32::try_from(region_count).unwrap_or(u32::MAX))
}

fn owner_for_node(
    nodes: &oxc_semantic::AstNodes<'_>,
    declaration_owners: &HashMap<oxc_semantic::NodeId, SemanticSymbolId>,
    node_id: oxc_semantic::NodeId,
) -> Option<SemanticSymbolId> {
    declaration_owners.get(&node_id).copied().or_else(|| {
        nodes
            .ancestor_ids(node_id)
            .find_map(|ancestor| declaration_owners.get(&ancestor).copied())
    })
}

fn region_for_scope(
    scoping: &oxc_semantic::Scoping,
    region_by_scope: &HashMap<oxc_semantic::ScopeId, ExecutionRegionId>,
    scope_id: oxc_semantic::ScopeId,
) -> ExecutionRegionId {
    scoping
        .scope_ancestors(scope_id)
        .find_map(|ancestor| region_by_scope.get(&ancestor).copied())
        .unwrap_or(ExecutionRegionId::MODULE)
}

fn innermost_pending_region(
    regions: &[ExecutionRegionFact],
    base_region: ExecutionRegionId,
    reference_span: SourceSpan,
) -> ExecutionRegionId {
    let base = &regions[base_region.0 as usize];
    regions
        .iter()
        .filter(|region| region.kind == ExecutionRegionKind::InstanceInitializer)
        .filter(|region| span_contains(region.span, reference_span))
        .filter(|region| {
            base.kind != ExecutionRegionKind::Function || !span_contains(region.span, base.span)
        })
        .min_by_key(|region| region.span.end.saturating_sub(region.span.start))
        .map_or(base_region, |region| region.id)
}

fn span_contains(outer: SourceSpan, inner: SourceSpan) -> bool {
    outer.start <= inner.start && outer.end >= inner.end
}

fn declaration_kind(flags: oxc_semantic::SymbolFlags) -> DeclarationKind {
    if flags.is_type_import() || flags.is_import() {
        DeclarationKind::Import
    } else if flags.is_type_alias() {
        DeclarationKind::TypeAlias
    } else if flags.is_interface() {
        DeclarationKind::Interface
    } else if flags.is_enum_member() {
        DeclarationKind::EnumMember
    } else if flags.is_enum() {
        DeclarationKind::Enum
    } else if flags.is_type_parameter() {
        DeclarationKind::TypeParameter
    } else if flags.is_catch_variable() {
        DeclarationKind::CatchBinding
    } else if flags.is_function() {
        DeclarationKind::Function
    } else if flags.is_class() {
        DeclarationKind::Class
    } else if flags.is_namespace_module() || flags.is_value_module() {
        DeclarationKind::Namespace
    } else if flags.is_variable() {
        DeclarationKind::Variable
    } else {
        DeclarationKind::Unknown
    }
}

fn symbol_namespace(flags: oxc_semantic::SymbolFlags) -> SymbolNamespace {
    match (flags.is_value(), flags.is_type()) {
        (true, true) => SymbolNamespace::RuntimeAndType,
        (false, true) => SymbolNamespace::Type,
        _ => SymbolNamespace::Runtime,
    }
}

fn declaration_is_effectful(
    kind: DeclarationKind,
    declarations: &[SourceSpan],
    source_text: &str,
) -> bool {
    match kind {
        DeclarationKind::Enum | DeclarationKind::Namespace => true,
        DeclarationKind::Variable => declarations.iter().any(|span| {
            source_slice(source_text, *span).is_some_and(|source| source.contains('='))
        }),
        DeclarationKind::Class => declarations.iter().any(|span| {
            source_slice(source_text, *span).is_some_and(|source| {
                source.contains("extends")
                    || source.contains("static")
                    || source.contains('@')
                    || source.contains('[')
            })
        }),
        _ => false,
    }
}

fn source_slice(source_text: &str, span: SourceSpan) -> Option<&str> {
    let start = usize::try_from(span.start).ok()?;
    let end = usize::try_from(span.end).ok()?;
    source_text.get(start..end)
}

fn declaration_has_safe_removal_span(
    kind: DeclarationKind,
    effectful: bool,
    declaration_count: usize,
) -> bool {
    !effectful
        && declaration_count == 1
        && matches!(
            kind,
            DeclarationKind::Function
                | DeclarationKind::Class
                | DeclarationKind::TypeAlias
                | DeclarationKind::Interface
        )
}

fn module_export_name(name: &ModuleExportName<'_>) -> String {
    match name {
        ModuleExportName::IdentifierName(identifier) => identifier.name.to_string(),
        ModuleExportName::IdentifierReference(identifier) => identifier.name.to_string(),
        ModuleExportName::StringLiteral(literal) => literal.value.to_string(),
    }
}

fn classify_source(path: &Path) -> (SourceKind, ModuleKind) {
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default();
    let source_kind = match extension {
        "ts" | "mts" | "cts" => SourceKind::TypeScript,
        "tsx" => SourceKind::Tsx,
        "jsx" => SourceKind::Jsx,
        _ => SourceKind::JavaScript,
    };
    let module_kind = match extension {
        "cjs" | "cts" => ModuleKind::CommonJs,
        _ => ModuleKind::Esm,
    };
    (source_kind, module_kind)
}

fn count_lines(source_text: &str) -> u32 {
    if source_text.is_empty() {
        return 0;
    }
    let newlines = source_text.bytes().filter(|byte| *byte == b'\n').count();
    let trailing_line = usize::from(!source_text.ends_with('\n'));
    u32::try_from(newlines.saturating_add(trailing_line)).unwrap_or(u32::MAX)
}

fn oxc_diagnostic(
    path: &str,
    code: &str,
    diagnostic: &oxc_diagnostics::OxcDiagnostic,
) -> AnalysisDiagnostic {
    let span = diagnostic.labels.first().map(|label| {
        let start = label.offset();
        let length = label.len();
        SourceSpan::new(start, start.saturating_add(length))
    });
    AnalysisDiagnostic {
        code: code.to_owned(),
        path: path.to_owned(),
        severity: DiagnosticSeverity::Error,
        span,
        message: diagnostic.to_string(),
        blocks_reachability: true,
    }
}

fn import_sort_key(left: &ImportFact, right: &ImportFact) -> std::cmp::Ordering {
    (left.span.start, left.span.end, &left.specifier, left.kind).cmp(&(
        right.span.start,
        right.span.end,
        &right.specifier,
        right.kind,
    ))
}

fn export_sort_key(left: &ExportFact, right: &ExportFact) -> std::cmp::Ordering {
    (left.span.start, left.span.end, &left.name, left.kind).cmp(&(
        right.span.start,
        right.span.end,
        &right.name,
        right.kind,
    ))
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

impl From<oxc_span::Span> for SourceSpan {
    fn from(span: oxc_span::Span) -> Self {
        Self::new(span.start, span.end)
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::parse_file;
    use crate::domain::facts::{
        Activation, ExecutionRegionKind, ExportBindingKind, ImportBindingKind, ImportKind,
        SymbolNamespace, UnknownGuardKind, UsageKind,
    };

    #[test]
    fn extracts_static_side_effect_and_dynamic_imports() {
        let facts = parse_file(
            "src/index.ts",
            Path::new("src/index.ts"),
            "import x from './x'; import './setup'; import('./lazy'); export { x };",
        );

        assert!(facts.diagnostics.is_empty());
        assert_eq!(facts.imports.len(), 3);
        assert_eq!(facts.imports[0].kind, ImportKind::Static);
        assert_eq!(facts.imports[1].kind, ImportKind::SideEffect);
        assert_eq!(facts.imports[2].kind, ImportKind::Dynamic);
        assert_eq!(facts.imports[2].activation, Activation::Module);
        assert_eq!(facts.exports[0].name, "x");
    }

    #[test]
    fn rejects_a_shadowed_require() {
        let facts = parse_file(
            "src/index.cjs",
            Path::new("src/index.cjs"),
            "function load(require) { return require('./shadowed'); }",
        );

        assert!(facts.imports.is_empty());
    }

    #[test]
    fn defers_a_require_inside_a_function() {
        let facts = parse_file(
            "src/index.cjs",
            Path::new("src/index.cjs"),
            "function load() { return require('./lazy.cjs'); }",
        );

        assert_eq!(facts.imports[0].activation, Activation::Deferred);
        assert_eq!(facts.diagnostics[0].code, "deferred_execution_region");
    }

    #[test]
    fn distinguishes_type_only_specifiers_and_runtime_imports() {
        let facts = parse_file(
            "src/index.ts",
            Path::new("src/index.ts"),
            "import { type Model } from './model'; import { type A, value } from './mixed'; export { type Model } from './public';",
        );

        assert!(facts.imports[0].type_only);
        assert!(!facts.imports[1].type_only);
        assert!(facts.imports[2].type_only);
    }

    #[test]
    fn extracts_require_resolve_and_common_js_exports() {
        let facts = parse_file(
            "src/index.cjs",
            Path::new("src/index.cjs"),
            "const path = require.resolve('./worker.cjs'); exports.named = 1; module.exports.other = 2; module.exports = 3;",
        );

        assert_eq!(facts.imports[0].kind, ImportKind::CommonJsResolve);
        assert_eq!(
            facts
                .exports
                .iter()
                .map(|export| export.name.as_str())
                .collect::<Vec<_>>(),
            vec!["named", "other", "default"]
        );
    }

    #[test]
    fn ignores_compound_common_js_export_assignments() {
        let facts = parse_file(
            "src/index.cjs",
            Path::new("src/index.cjs"),
            "module.exports += value;",
        );

        assert!(facts.exports.is_empty());
    }

    #[test]
    fn defers_instance_field_module_loads() {
        let facts = parse_file(
            "src/index.cjs",
            Path::new("src/index.cjs"),
            "class Worker { [require('./key.cjs')] = require('./worker.cjs'); }",
        );

        assert_eq!(facts.imports[0].activation, Activation::Module);
        assert_eq!(facts.imports[1].activation, Activation::Deferred);
        assert_eq!(facts.diagnostics[0].code, "deferred_execution_region");
    }

    #[test]
    fn defers_instance_accessor_initializers() {
        let facts = parse_file(
            "src/index.ts",
            Path::new("src/index.ts"),
            "class Worker { accessor implementation = require('./worker.cjs'); }",
        );

        assert_eq!(facts.imports[0].activation, Activation::Deferred);
        assert_eq!(facts.diagnostics[0].code, "deferred_execution_region");
    }

    #[test]
    fn diagnoses_computed_common_js_export_names() {
        let facts = parse_file(
            "src/index.cjs",
            Path::new("src/index.cjs"),
            "exports[exportName] = value;",
        );

        assert!(facts.exports.is_empty());
        assert_eq!(facts.diagnostics[0].code, "unsupported_common_js_export");
    }

    #[test]
    fn does_not_treat_require_as_global_inside_with() {
        let facts = parse_file(
            "src/index.cjs",
            Path::new("src/index.cjs"),
            "with (loader) { require('./maybe.cjs'); }",
        );

        assert!(facts.imports.is_empty());
        assert_eq!(
            facts.diagnostics[0].code,
            "unsupported_dynamic_scope_require"
        );
    }

    #[test]
    fn lowers_import_and_export_binding_forms_with_semantic_ids() {
        let facts = parse_file(
            "src/index.ts",
            Path::new("src/index.ts"),
            "import main, { type Model, value as local } from './dep'; import * as ns from './ns'; export { local as publicValue }; export { type Remote } from './remote'; export * from './star'; export default main;",
        );

        assert!(facts.diagnostics.is_empty());
        assert_eq!(facts.symbol_facts.imports.len(), 4);
        assert!(
            facts
                .symbol_facts
                .imports
                .iter()
                .any(|binding| binding.kind == ImportBindingKind::Default)
        );
        assert!(
            facts
                .symbol_facts
                .imports
                .iter()
                .any(|binding| binding.kind == ImportBindingKind::Namespace)
        );
        assert!(
            facts
                .symbol_facts
                .imports
                .iter()
                .any(|binding| { binding.kind == ImportBindingKind::Named && binding.type_only })
        );
        assert!(facts.symbol_facts.exports.iter().any(|binding| {
            binding.exported == "publicValue"
                && binding.kind == ExportBindingKind::Local
                && binding.local.is_some()
        }));
        assert!(facts.symbol_facts.exports.iter().any(|binding| {
            binding.exported == "Remote"
                && binding.kind == ExportBindingKind::ReExport
                && binding.type_only
        }));
        assert!(
            facts
                .symbol_facts
                .exports
                .iter()
                .any(|binding| binding.kind == ExportBindingKind::Star)
        );
    }

    #[test]
    fn semantic_references_distinguish_shadowed_bindings_and_regions() {
        let facts = parse_file(
            "src/index.ts",
            Path::new("src/index.ts"),
            "const value = 1; function read() { const value = 2; return value; } console.log(value);",
        );

        assert!(facts.diagnostics.is_empty());
        let values = facts
            .symbol_facts
            .symbols
            .iter()
            .filter(|symbol| symbol.name == "value")
            .collect::<Vec<_>>();
        assert_eq!(values.len(), 2);
        assert_ne!(values[0].id, values[1].id);
        assert!(
            facts
                .symbol_facts
                .regions
                .iter()
                .any(|region| { region.kind == ExecutionRegionKind::Function && !region.eager })
        );
        let referenced_values = facts
            .symbol_facts
            .references
            .iter()
            .filter(|reference| values.iter().any(|symbol| symbol.id == reference.target))
            .map(|reference| reference.target)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(referenced_values.len(), 2);
    }

    #[test]
    fn keeps_runtime_and_type_references_distinct() {
        let facts = parse_file(
            "src/index.ts",
            Path::new("src/index.ts"),
            "interface Model { value: string } const runtime = 1; type Alias = Model; console.log(runtime);",
        );

        let model = facts
            .symbol_facts
            .symbols
            .iter()
            .find(|symbol| symbol.name == "Model")
            .unwrap();
        assert_eq!(model.namespace, SymbolNamespace::Type);
        assert!(facts.symbol_facts.references.iter().any(|reference| {
            reference.target == model.id && reference.usage == UsageKind::Type
        }));
        assert!(facts.symbol_facts.references.iter().any(|reference| {
            reference.usage == UsageKind::Runtime
                && facts
                    .symbol_facts
                    .symbols
                    .iter()
                    .any(|symbol| symbol.id == reference.target && symbol.name == "runtime")
        }));
    }

    #[test]
    fn records_common_js_unknowns_as_export_scoped_guards() {
        let facts = parse_file(
            "src/index.cjs",
            Path::new("src/index.cjs"),
            "const implementation = require('./implementation'); exports[name] = implementation;",
        );

        assert!(facts.symbol_facts.imports.iter().any(|binding| {
            binding.kind == ImportBindingKind::CommonJs && binding.source == "./implementation"
        }));
        assert!(
            facts
                .symbol_facts
                .unknown_guards
                .iter()
                .any(|guard| { guard.kind == UnknownGuardKind::ComputedCommonJsExport })
        );
        assert!(!UnknownGuardKind::ComputedCommonJsExport.blocks_declaration_reachability());
    }

    #[test]
    fn direct_eval_and_with_are_declaration_reachability_guards() {
        let facts = parse_file(
            "src/index.cjs",
            Path::new("src/index.cjs"),
            "function run(source) { eval(source); } with (scope) { maybeUsed; }",
        );

        assert!(facts.symbol_facts.unknown_guards.iter().any(|guard| {
            guard.kind == UnknownGuardKind::DirectEval
                && guard.kind.blocks_declaration_reachability()
        }));
        assert!(facts.symbol_facts.unknown_guards.iter().any(|guard| {
            guard.kind == UnknownGuardKind::DynamicScope
                && guard.kind.blocks_declaration_reachability()
        }));
    }
}
