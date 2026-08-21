use oxc_ast::{
    AstKind,
    ast::{
        BinaryOperator, CallExpression, Expression, MemberExpression, NewExpression,
        TemplateLiteral,
    },
};
use oxc_semantic::{IsGlobalReference, Semantic, SymbolFlags, SymbolId};

use crate::limits::AnalysisLimits;

pub(crate) type EvaluationResult<T> = Result<Option<T>, ConstantEvaluationLimit>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConstantEvaluationLimitKind {
    Depth,
    StringBytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConstantEvaluationLimit {
    pub kind: ConstantEvaluationLimitKind,
    pub limit: usize,
}

impl ConstantEvaluationLimit {
    pub(crate) const fn diagnostic_code(self) -> &'static str {
        match self.kind {
            ConstantEvaluationLimitKind::Depth => "constant_evaluation_depth_limit_exceeded",
            ConstantEvaluationLimitKind::StringBytes => "static_string_limit_exceeded",
        }
    }

    pub(crate) fn message(self) -> String {
        match self.kind {
            ConstantEvaluationLimitKind::Depth => format!(
                "Static string evaluation exceeded the configured recursion limit of {}",
                self.limit
            ),
            ConstantEvaluationLimitKind::StringBytes => format!(
                "Static string evaluation exceeded the configured output limit of {} bytes",
                self.limit
            ),
        }
    }
}

/// A statically recognized JavaScript form that can introduce a file edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DynamicLoadForm {
    ImportMetaResolve,
    ImportMetaUrl,
    Worker,
    SharedWorker,
    ChildProcessFork,
    ModuleRegister,
    ModuleRegisterHooks,
}

impl DynamicLoadForm {
    pub(crate) const fn diagnostic_code(self) -> &'static str {
        match self {
            Self::ImportMetaResolve => "unsupported_import_meta_resolve",
            Self::ImportMetaUrl => "unsupported_import_meta_url",
            Self::Worker | Self::SharedWorker => "unsupported_dynamic_worker",
            Self::ChildProcessFork => "unsupported_dynamic_child_process",
            Self::ModuleRegister | Self::ModuleRegisterHooks => "unsupported_dynamic_loader",
        }
    }

    pub(crate) const fn description(self) -> &'static str {
        match self {
            Self::ImportMetaResolve => "import.meta.resolve specifier",
            Self::ImportMetaUrl => "URL relative to import.meta.url",
            Self::Worker => "Worker entry",
            Self::SharedWorker => "SharedWorker entry",
            Self::ChildProcessFork => "child-process fork entry",
            Self::ModuleRegister => "module.register loader",
            Self::ModuleRegisterHooks => "module.registerHooks loader",
        }
    }

    /// Node built-in calls are only syntactic candidates here. The parser must
    /// verify the callee binding came from this module and export before adding
    /// a fact.
    pub(crate) const fn required_node_binding(self) -> Option<(&'static str, &'static str)> {
        match self {
            Self::Worker => Some(("node:worker_threads", "Worker")),
            Self::ChildProcessFork => Some(("node:child_process", "fork")),
            Self::ModuleRegister => Some(("node:module", "register")),
            Self::ModuleRegisterHooks => Some(("node:module", "registerHooks")),
            Self::ImportMetaResolve | Self::ImportMetaUrl | Self::SharedWorker => None,
        }
    }

    /// Browser worker constructors may be globals. `Worker` may alternatively
    /// be a proven import from `node:worker_threads`.
    pub(crate) const fn allows_global_binding(self) -> bool {
        matches!(self, Self::Worker | Self::SharedWorker)
    }

    /// Accepts both canonical `node:` names and their Node legacy spelling.
    pub(crate) fn matches_node_binding(self, source: &str, export: &str) -> bool {
        let Some((required_source, required_export)) = self.required_node_binding() else {
            return false;
        };
        source.strip_prefix("node:").unwrap_or(source)
            == required_source
                .strip_prefix("node:")
                .unwrap_or(required_source)
            && export == required_export
    }
}

/// Evaluates only the deliberately small, exact string subset used by module
/// loading forms. It never executes project code or invokes JavaScript coercion.
pub(crate) struct StaticStringEvaluator<'s, 'a> {
    semantic: &'s Semantic<'a>,
    limits: AnalysisLimits,
}

impl<'s, 'a> StaticStringEvaluator<'s, 'a> {
    #[cfg(test)]
    pub(crate) fn new(semantic: &'s Semantic<'a>) -> Self {
        Self::with_limits(semantic, AnalysisLimits::default())
    }

    pub(crate) const fn with_limits(semantic: &'s Semantic<'a>, limits: AnalysisLimits) -> Self {
        Self { semantic, limits }
    }

    /// Returns an exact string for literals, cooked template literals, string
    /// addition, and direct local `const` bindings composed from those forms.
    pub(crate) fn evaluate(&self, expression: &Expression<'a>) -> EvaluationResult<String> {
        self.evaluate_inner(expression, 0, &mut Vec::new())
    }

    /// Evaluates a module target, unwrapping the exact
    /// `new URL(target, import.meta.url)` form used by workers and assets.
    pub(crate) fn evaluate_load_target(
        &self,
        expression: &Expression<'a>,
    ) -> EvaluationResult<String> {
        if let Expression::NewExpression(new_expression) = expression.get_inner_expression()
            && let Some((DynamicLoadForm::ImportMetaUrl, target)) =
                dynamic_new_target(new_expression, self.semantic)
        {
            return self.evaluate(target);
        }
        self.evaluate(expression)
    }

    /// Returns the known leading portion of an otherwise dynamic string. This
    /// is used only to localize an unknown path; it is never treated as an
    /// exact file edge.
    pub(crate) fn leading_static_prefix(
        &self,
        expression: &Expression<'a>,
    ) -> EvaluationResult<String> {
        if let Some(value) = self.evaluate(expression)? {
            return Ok(Some(value));
        }
        let prefix = self.prefix_inner(expression, 0, &mut Vec::new())?;
        Ok(prefix.filter(|prefix| !prefix.is_empty()))
    }

    fn evaluate_inner(
        &self,
        expression: &Expression<'a>,
        depth: usize,
        active_symbols: &mut Vec<SymbolId>,
    ) -> EvaluationResult<String> {
        if depth >= self.limits.max_constant_evaluation_depth {
            return Err(self.depth_limit());
        }

        match expression.get_inner_expression() {
            Expression::StringLiteral(literal) => {
                self.bounded_string(literal.value.as_str()).map(Some)
            }
            Expression::TemplateLiteral(template) => {
                self.evaluate_template(template, depth, active_symbols)
            }
            Expression::BinaryExpression(binary) if binary.operator == BinaryOperator::Addition => {
                let Some(left) = self.evaluate_inner(&binary.left, depth + 1, active_symbols)?
                else {
                    return Ok(None);
                };
                let Some(right) = self.evaluate_inner(&binary.right, depth + 1, active_symbols)?
                else {
                    return Ok(None);
                };
                self.join_bounded(&left, &right).map(Some)
            }
            Expression::Identifier(identifier) => {
                let Some(reference_id) = identifier.reference_id.get() else {
                    return Ok(None);
                };
                let Some(symbol_id) = self
                    .semantic
                    .scoping()
                    .get_reference(reference_id)
                    .symbol_id()
                else {
                    return Ok(None);
                };
                if active_symbols.contains(&symbol_id)
                    || !self
                        .semantic
                        .scoping()
                        .symbol_flags(symbol_id)
                        .contains(SymbolFlags::ConstVariable)
                {
                    return Ok(None);
                }

                let declaration = self.semantic.symbol_declaration(symbol_id);
                let AstKind::VariableDeclarator(declarator) = declaration.kind() else {
                    return Ok(None);
                };
                let AstKind::VariableDeclaration(variable_declaration) =
                    self.semantic.nodes().parent_kind(declaration.id())
                else {
                    return Ok(None);
                };
                if !variable_declaration.kind.is_const() || !declarator.id.is_binding_identifier() {
                    return Ok(None);
                }
                let Some(binding) = declarator.id.get_binding_identifier() else {
                    return Ok(None);
                };
                if binding.symbol_id.get() != Some(symbol_id) {
                    return Ok(None);
                }

                active_symbols.push(symbol_id);
                let value = declarator.init.as_ref().map_or(Ok(None), |initializer| {
                    self.evaluate_inner(initializer, depth + 1, active_symbols)
                });
                active_symbols.pop();
                value
            }
            _ => Ok(None),
        }
    }

    fn evaluate_template(
        &self,
        template: &TemplateLiteral<'a>,
        depth: usize,
        active_symbols: &mut Vec<SymbolId>,
    ) -> EvaluationResult<String> {
        if template.quasis.len() != template.expressions.len().saturating_add(1) {
            return Ok(None);
        }

        let mut output = String::new();
        for (index, quasi) in template.quasis.iter().enumerate() {
            let Some(cooked) = quasi.value.cooked.as_ref() else {
                return Ok(None);
            };
            self.push_bounded(&mut output, cooked.as_str())?;
            if let Some(expression) = template.expressions.get(index) {
                let Some(value) = self.evaluate_inner(expression, depth + 1, active_symbols)?
                else {
                    return Ok(None);
                };
                self.push_bounded(&mut output, &value)?;
            }
        }
        Ok(Some(output))
    }

    fn prefix_inner(
        &self,
        expression: &Expression<'a>,
        depth: usize,
        active_symbols: &mut Vec<SymbolId>,
    ) -> EvaluationResult<String> {
        if depth >= self.limits.max_constant_evaluation_depth {
            return Err(self.depth_limit());
        }

        match expression.get_inner_expression() {
            Expression::TemplateLiteral(template) => {
                let Some(first) = template
                    .quasis
                    .first()
                    .and_then(|quasi| quasi.value.cooked.as_ref())
                else {
                    return Ok(None);
                };
                let mut output = self.bounded_string(first.as_str())?;
                for (index, expression) in template.expressions.iter().enumerate() {
                    let Some(value) = self.evaluate_inner(expression, depth + 1, active_symbols)?
                    else {
                        break;
                    };
                    self.push_bounded(&mut output, &value)?;
                    let Some(next) = template
                        .quasis
                        .get(index + 1)
                        .and_then(|quasi| quasi.value.cooked.as_ref())
                    else {
                        return Ok(None);
                    };
                    self.push_bounded(&mut output, next.as_str())?;
                }
                Ok(Some(output))
            }
            Expression::BinaryExpression(binary) if binary.operator == BinaryOperator::Addition => {
                if let Some(left) = self.evaluate_inner(&binary.left, depth + 1, active_symbols)? {
                    let right = self
                        .prefix_inner(&binary.right, depth + 1, active_symbols)?
                        .unwrap_or_default();
                    self.join_bounded(&left, &right).map(Some)
                } else {
                    self.prefix_inner(&binary.left, depth + 1, active_symbols)
                }
            }
            Expression::Identifier(identifier) => {
                let Some(reference_id) = identifier.reference_id.get() else {
                    return Ok(None);
                };
                let Some(symbol_id) = self
                    .semantic
                    .scoping()
                    .get_reference(reference_id)
                    .symbol_id()
                else {
                    return Ok(None);
                };
                if active_symbols.contains(&symbol_id)
                    || !self
                        .semantic
                        .scoping()
                        .symbol_flags(symbol_id)
                        .contains(SymbolFlags::ConstVariable)
                {
                    return Ok(None);
                }
                let declaration = self.semantic.symbol_declaration(symbol_id);
                let AstKind::VariableDeclarator(declarator) = declaration.kind() else {
                    return Ok(None);
                };
                let AstKind::VariableDeclaration(variable_declaration) =
                    self.semantic.nodes().parent_kind(declaration.id())
                else {
                    return Ok(None);
                };
                if !variable_declaration.kind.is_const() || !declarator.id.is_binding_identifier() {
                    return Ok(None);
                }
                let Some(binding) = declarator.id.get_binding_identifier() else {
                    return Ok(None);
                };
                if binding.symbol_id.get() != Some(symbol_id) {
                    return Ok(None);
                }
                active_symbols.push(symbol_id);
                let prefix = declarator.init.as_ref().map_or(Ok(None), |initializer| {
                    self.prefix_inner(initializer, depth + 1, active_symbols)
                });
                active_symbols.pop();
                prefix
            }
            _ => Ok(None),
        }
    }

    fn bounded_string(&self, value: &str) -> Result<String, ConstantEvaluationLimit> {
        if value.len() > self.limits.max_static_string_bytes {
            return Err(self.string_limit());
        }
        Ok(value.to_owned())
    }

    fn join_bounded(&self, left: &str, right: &str) -> Result<String, ConstantEvaluationLimit> {
        let Some(capacity) = left.len().checked_add(right.len()) else {
            return Err(self.string_limit());
        };
        let mut output = String::with_capacity(capacity);
        self.push_bounded(&mut output, left)?;
        self.push_bounded(&mut output, right)?;
        Ok(output)
    }

    fn push_bounded(
        &self,
        output: &mut String,
        value: &str,
    ) -> Result<(), ConstantEvaluationLimit> {
        let Some(combined_length) = output.len().checked_add(value.len()) else {
            return Err(self.string_limit());
        };
        if combined_length > self.limits.max_static_string_bytes {
            return Err(self.string_limit());
        }
        output.push_str(value);
        Ok(())
    }

    const fn depth_limit(&self) -> ConstantEvaluationLimit {
        ConstantEvaluationLimit {
            kind: ConstantEvaluationLimitKind::Depth,
            limit: self.limits.max_constant_evaluation_depth,
        }
    }

    const fn string_limit(&self) -> ConstantEvaluationLimit {
        ConstantEvaluationLimit {
            kind: ConstantEvaluationLimitKind::StringBytes,
            limit: self.limits.max_static_string_bytes,
        }
    }
}

/// Recognizes call shapes. Node built-in forms are candidates only: callers
/// must validate [`DynamicLoadForm::required_node_binding`] against semantic
/// import/require facts before retaining the target.
pub(crate) fn dynamic_call_candidate<'a>(
    expression: &'a CallExpression<'a>,
) -> Option<(DynamicLoadForm, &'a Expression<'a>)> {
    let first_argument = expression.arguments.first()?.as_expression()?;
    if expression
        .callee
        .as_member_expression()
        .is_some_and(|member| {
            member.static_property_name() == Some("resolve")
                && matches!(
                    member.object().get_inner_expression(),
                    Expression::ImportMeta(_)
                )
        })
    {
        return Some((DynamicLoadForm::ImportMetaResolve, first_argument));
    }

    let callee_name = match expression.callee.get_inner_expression() {
        Expression::Identifier(identifier) => identifier.name.as_str(),
        callee => callee
            .as_member_expression()
            .and_then(MemberExpression::static_property_name)?,
    };
    let form = match callee_name {
        "fork" => DynamicLoadForm::ChildProcessFork,
        "register" => DynamicLoadForm::ModuleRegister,
        "registerHooks" => DynamicLoadForm::ModuleRegisterHooks,
        _ => return None,
    };
    Some((form, first_argument))
}

/// Recognizes constructor shapes whose first argument introduces a file edge.
/// Worker candidates still require global-or-Node-import provenance validation.
pub(crate) fn dynamic_new_target<'a>(
    expression: &'a NewExpression<'a>,
    semantic: &Semantic<'a>,
) -> Option<(DynamicLoadForm, &'a Expression<'a>)> {
    let constructor_name = match expression.callee.get_inner_expression() {
        Expression::Identifier(identifier) => Some(identifier.name.as_str()),
        callee => callee
            .as_member_expression()
            .and_then(MemberExpression::static_property_name),
    };
    if constructor_name == Some("Worker") {
        return first_new_argument(expression).map(|target| (DynamicLoadForm::Worker, target));
    }
    if constructor_name == Some("SharedWorker") {
        return first_new_argument(expression)
            .map(|target| (DynamicLoadForm::SharedWorker, target));
    }
    if !is_global_identifier(&expression.callee, "URL", semantic) || expression.arguments.len() != 2
    {
        return None;
    }
    let target = first_new_argument(expression)?;
    let base = expression.arguments.get(1)?.as_expression()?;
    is_import_meta_url(base).then_some((DynamicLoadForm::ImportMetaUrl, target))
}

fn first_new_argument<'a>(expression: &'a NewExpression<'a>) -> Option<&'a Expression<'a>> {
    expression.arguments.first()?.as_expression()
}

fn is_global_identifier(expression: &Expression<'_>, name: &str, semantic: &Semantic<'_>) -> bool {
    matches!(
        expression.get_inner_expression(),
        Expression::Identifier(identifier)
            if identifier.name == name
                && identifier.is_global_reference(semantic.scoping())
    )
}

fn is_import_meta_url(expression: &Expression<'_>) -> bool {
    expression
        .get_inner_expression()
        .as_member_expression()
        .is_some_and(|member| {
            member.static_property_name() == Some("url")
                && matches!(
                    member.object().get_inner_expression(),
                    Expression::ImportMeta(_)
                )
        })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use oxc_allocator::Allocator;
    use oxc_ast::ast::{CallExpression, ImportExpression, NewExpression};
    use oxc_ast_visit::{Visit, walk};
    use oxc_parser::Parser;
    use oxc_semantic::{Semantic, SemanticBuilder};
    use oxc_span::SourceType;

    use super::{
        ConstantEvaluationLimitKind, DynamicLoadForm, StaticStringEvaluator,
        dynamic_call_candidate, dynamic_new_target,
    };
    use crate::limits::AnalysisLimits;

    #[test]
    fn evaluates_literals_templates_and_local_const_concatenation() {
        let values = exact_evaluated_imports(
            "const directory = './workers/'; const name = 'task'; import(directory + `${name}.js`); import(`./plain.js`);",
            AnalysisLimits::default(),
        );

        assert_eq!(
            values,
            [
                Some("./workers/task.js".to_owned()),
                Some("./plain.js".to_owned())
            ]
        );
    }

    #[test]
    fn rejects_mutable_side_effecting_and_non_string_expressions() {
        let values = exact_evaluated_imports(
            "let mutable = './mutable.js'; const called = build(); const number = 1; import(mutable); import(called); import(number + '.js');",
            AnalysisLimits::default(),
        );

        assert_eq!(values, [None, None, None]);
    }

    #[test]
    fn rejects_cycles_without_guessing_a_value() {
        let values = exact_evaluated_imports(
            "const a = b; const b = a; import(a);",
            AnalysisLimits::default(),
        );

        assert_eq!(values, [None]);
    }

    #[test]
    fn reports_values_over_the_configured_bound() {
        let limits = AnalysisLimits {
            max_static_string_bytes: 8,
            ..AnalysisLimits::default()
        };
        let results = evaluated_imports("import('./longer-than-eight.js');", limits);

        let error = results
            .into_iter()
            .next()
            .expect("one import")
            .expect_err("report the explicit string bound");
        assert_eq!(error.kind, ConstantEvaluationLimitKind::StringBytes);
        assert_eq!(error.limit, 8);
        assert_eq!(error.diagnostic_code(), "static_string_limit_exceeded");
        assert!(error.message().contains("8 bytes"));
    }

    #[test]
    fn reports_constant_evaluation_depth_exhaustion() {
        let limits = AnalysisLimits {
            max_constant_evaluation_depth: 1,
            ..AnalysisLimits::default()
        };
        let results = evaluated_imports("const target = './worker.js'; import(target);", limits);

        let error = results
            .into_iter()
            .next()
            .expect("one import")
            .expect_err("report the explicit recursion bound");
        assert_eq!(error.kind, ConstantEvaluationLimitKind::Depth);
        assert_eq!(error.limit, 1);
        assert_eq!(
            error.diagnostic_code(),
            "constant_evaluation_depth_limit_exceeded"
        );
    }

    #[test]
    fn exposes_only_the_leading_exact_prefix_of_a_dynamic_template() {
        let allocator = Allocator::default();
        let parsed = Parser::new(
            &allocator,
            "const root = './routes/'; import(`${root}${route}.js`);",
            SourceType::from_path(Path::new("index.js")).expect("source type"),
        )
        .parse();
        assert!(parsed.diagnostics.is_empty());
        let semantic = SemanticBuilder::new_compiler()
            .with_build_nodes(true)
            .build(&parsed.program)
            .semantic;
        let evaluator = StaticStringEvaluator::new(&semantic);
        let mut collector = PrefixCollector {
            evaluator,
            prefixes: Vec::new(),
        };
        collector.visit_program(&parsed.program);

        assert_eq!(collector.prefixes, [Ok(Some("./routes/".to_owned()))]);
    }

    #[test]
    fn recognizes_runtime_entry_forms_and_unwraps_url_targets() {
        let allocator = Allocator::default();
        let parsed = Parser::new(
            &allocator,
            "import { fork } from 'node:child_process'; import { register } from 'node:module'; import { Worker } from 'node:worker_threads'; import.meta.resolve('./resolved.js'); new Worker(new URL('./worker.js', import.meta.url)); fork(new URL('./child.js', import.meta.url)); register('./loader.mjs', import.meta.url);",
            SourceType::from_path(Path::new("index.mjs")).expect("source type"),
        )
        .parse();
        assert!(parsed.diagnostics.is_empty());
        let semantic = SemanticBuilder::new_compiler()
            .with_build_nodes(true)
            .build(&parsed.program)
            .semantic;
        let mut collector = DynamicCandidateCollector {
            evaluator: StaticStringEvaluator::new(&semantic),
            semantic: &semantic,
            candidates: Vec::new(),
        };
        collector.visit_program(&parsed.program);

        for expected in [
            (DynamicLoadForm::ImportMetaResolve, "./resolved.js"),
            (DynamicLoadForm::Worker, "./worker.js"),
            (DynamicLoadForm::ImportMetaUrl, "./worker.js"),
            (DynamicLoadForm::ChildProcessFork, "./child.js"),
            (DynamicLoadForm::ImportMetaUrl, "./child.js"),
            (DynamicLoadForm::ModuleRegister, "./loader.mjs"),
        ] {
            assert!(
                collector
                    .candidates
                    .contains(&(expected.0, expected.1.to_owned())),
                "missing {expected:?} from {:?}",
                collector.candidates
            );
        }
    }

    #[test]
    fn node_binding_requirements_accept_canonical_and_legacy_specifiers() {
        assert!(
            DynamicLoadForm::ChildProcessFork.matches_node_binding("node:child_process", "fork")
        );
        assert!(DynamicLoadForm::ChildProcessFork.matches_node_binding("child_process", "fork"));
        assert!(DynamicLoadForm::Worker.matches_node_binding("node:worker_threads", "Worker"));
        assert!(!DynamicLoadForm::Worker.matches_node_binding("node:worker_threads", "worker"));
        assert!(DynamicLoadForm::Worker.allows_global_binding());
        assert!(!DynamicLoadForm::ChildProcessFork.allows_global_binding());
    }

    fn exact_evaluated_imports(source: &str, limits: AnalysisLimits) -> Vec<Option<String>> {
        evaluated_imports(source, limits)
            .into_iter()
            .map(|result| result.expect("constant evaluation stays within configured bounds"))
            .collect()
    }

    fn evaluated_imports(
        source: &str,
        limits: AnalysisLimits,
    ) -> Vec<super::EvaluationResult<String>> {
        let allocator = Allocator::default();
        let parsed = Parser::new(
            &allocator,
            source,
            SourceType::from_path(Path::new("index.js")).expect("source type"),
        )
        .parse();
        assert!(parsed.diagnostics.is_empty());
        let semantic = SemanticBuilder::new_compiler()
            .with_build_nodes(true)
            .build(&parsed.program)
            .semantic;
        let evaluator = StaticStringEvaluator::with_limits(&semantic, limits);
        let mut collector = ValueCollector {
            evaluator,
            values: Vec::new(),
        };
        collector.visit_program(&parsed.program);
        collector.values
    }

    struct ValueCollector<'s, 'a> {
        evaluator: StaticStringEvaluator<'s, 'a>,
        values: Vec<super::EvaluationResult<String>>,
    }

    impl<'a> Visit<'a> for ValueCollector<'_, 'a> {
        fn visit_import_expression(&mut self, expression: &ImportExpression<'a>) {
            self.values
                .push(self.evaluator.evaluate(&expression.source));
            walk::walk_import_expression(self, expression);
        }
    }

    struct PrefixCollector<'s, 'a> {
        evaluator: StaticStringEvaluator<'s, 'a>,
        prefixes: Vec<super::EvaluationResult<String>>,
    }

    impl<'a> Visit<'a> for PrefixCollector<'_, 'a> {
        fn visit_import_expression(&mut self, expression: &ImportExpression<'a>) {
            self.prefixes
                .push(self.evaluator.leading_static_prefix(&expression.source));
            walk::walk_import_expression(self, expression);
        }
    }

    struct DynamicCandidateCollector<'s, 'a> {
        evaluator: StaticStringEvaluator<'s, 'a>,
        semantic: &'s Semantic<'a>,
        candidates: Vec<(DynamicLoadForm, String)>,
    }

    impl<'a> Visit<'a> for DynamicCandidateCollector<'_, 'a> {
        fn visit_call_expression(&mut self, expression: &CallExpression<'a>) {
            if let Some((form, target)) = dynamic_call_candidate(expression)
                && let Some(value) = self
                    .evaluator
                    .evaluate_load_target(target)
                    .expect("candidate stays within configured bounds")
            {
                self.candidates.push((form, value));
            }
            walk::walk_call_expression(self, expression);
        }

        fn visit_new_expression(&mut self, expression: &NewExpression<'a>) {
            if let Some((form, target)) = dynamic_new_target(expression, self.semantic)
                && let Some(value) = self
                    .evaluator
                    .evaluate_load_target(target)
                    .expect("candidate stays within configured bounds")
            {
                self.candidates.push((form, value));
            }
            walk::walk_new_expression(self, expression);
        }
    }
}
