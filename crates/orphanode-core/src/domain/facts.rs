use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    JavaScript,
    Jsx,
    TypeScript,
    Tsx,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleKind {
    Esm,
    CommonJs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportKind {
    Static,
    SideEffect,
    ReExport,
    Dynamic,
    CommonJsRequire,
    CommonJsResolve,
    Plugin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionMode {
    Esm,
    CommonJs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Activation {
    Module,
    Deferred,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportKind {
    Named,
    Default,
    Star,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    Error,
    Warning,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceSpan {
    pub start: u32,
    pub end: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ImportFact {
    pub specifier: String,
    pub kind: ImportKind,
    pub resolution_mode: ResolutionMode,
    pub activation: Activation,
    pub type_only: bool,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportFact {
    pub name: String,
    pub kind: ExportKind,
    pub type_only: bool,
    pub span: SourceSpan,
}

/// Stable, file-local identity assigned from Oxc's semantic `SymbolId`.
///
/// The numeric value is only meaningful together with the owning [`FileFacts`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(transparent)]
pub struct SemanticSymbolId(pub u32);

/// Stable, file-local execution-region identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(transparent)]
pub struct ExecutionRegionId(pub u32);

impl ExecutionRegionId {
    pub const MODULE: Self = Self(0);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolNamespace {
    Runtime,
    Type,
    RuntimeAndType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeclarationKind {
    Variable,
    Function,
    Class,
    Import,
    TypeAlias,
    Interface,
    Enum,
    EnumMember,
    TypeParameter,
    Namespace,
    CatchBinding,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionRegionKind {
    Module,
    Function,
    ClassStaticBlock,
    InstanceInitializer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageKind {
    Runtime,
    Type,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportBindingKind {
    Default,
    Named,
    Namespace,
    CommonJs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportBindingKind {
    Local,
    Default,
    ReExport,
    Star,
    CommonJs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownGuardKind {
    DirectEval,
    DynamicScope,
    ComputedCommonJsExport,
    OpaqueCommonJsExports,
}

impl UnknownGuardKind {
    /// Whether this guard can hide references to arbitrary lexical bindings.
    #[must_use]
    pub const fn blocks_declaration_reachability(self) -> bool {
        matches!(self, Self::DirectEval | Self::DynamicScope)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)]
pub struct SymbolFactFlags {
    pub imported: bool,
    pub exported: bool,
    pub mutated: bool,
    pub initializer_effectful: bool,
    pub escapes: bool,
    pub ambient: bool,
    pub safe_removal_span: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SymbolFact {
    pub id: SemanticSymbolId,
    pub name: String,
    pub kind: DeclarationKind,
    pub namespace: SymbolNamespace,
    pub region: ExecutionRegionId,
    pub span: SourceSpan,
    pub declarations: Vec<SourceSpan>,
    pub flags: SymbolFactFlags,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "id")]
pub enum ReferenceOwner {
    Region(ExecutionRegionId),
    Symbol(SemanticSymbolId),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)]
pub struct SymbolReferenceFact {
    pub owner: ReferenceOwner,
    pub region: ExecutionRegionId,
    pub target: SemanticSymbolId,
    pub usage: UsageKind,
    pub read: bool,
    pub write: bool,
    pub call: bool,
    pub escape: bool,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionRegionFact {
    pub id: ExecutionRegionId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<ExecutionRegionId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<SemanticSymbolId>,
    pub kind: ExecutionRegionKind,
    pub span: SourceSpan,
    /// Eager regions activate with their parent; callable regions activate when
    /// their owner becomes live or escapes.
    pub eager: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportBindingFact {
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imported: Option<String>,
    pub local: SemanticSymbolId,
    pub kind: ImportBindingKind,
    pub type_only: bool,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportBindingFact {
    pub exported: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imported: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local: Option<SemanticSymbolId>,
    pub kind: ExportBindingKind,
    pub type_only: bool,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnknownGuardFact {
    pub kind: UnknownGuardKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<ExecutionRegionId>,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SymbolFileFacts {
    pub regions: Vec<ExecutionRegionFact>,
    pub symbols: Vec<SymbolFact>,
    pub references: Vec<SymbolReferenceFact>,
    pub imports: Vec<ImportBindingFact>,
    pub exports: Vec<ExportBindingFact>,
    pub unknown_guards: Vec<UnknownGuardFact>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassMemberKind {
    Method,
    Field,
    Getter,
    Setter,
    Accessor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassMemberVisibility {
    JavaScriptPrivate,
    TypeScriptPrivate,
    Protected,
    Public,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)]
pub struct ClassMemberFact {
    pub declaring_class: String,
    pub name: String,
    pub kind: ClassMemberKind,
    pub visibility: ClassMemberVisibility,
    pub r#static: bool,
    pub span: SourceSpan,
    pub directly_referenced: bool,
    pub decorated: bool,
    pub emitted_decorator_metadata: bool,
    pub unknown_bracket_access: bool,
    pub reflected_or_enumerated: bool,
    pub serialized: bool,
    pub object_spread: bool,
    pub proxied: bool,
    pub passed_to_unknown_code: bool,
    pub class_exported: bool,
    pub class_escaped: bool,
    pub participates_in_inheritance: bool,
    pub relationships_complete: bool,
    pub overrides_live_base_member: bool,
    pub has_live_override: bool,
    pub implements_external_contract: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisDiagnostic {
    pub code: String,
    pub path: String,
    pub severity: DiagnosticSeverity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span: Option<SourceSpan>,
    pub message: String,
    pub blocks_reachability: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct FileFacts {
    pub path: String,
    pub source_kind: SourceKind,
    pub module_kind: ModuleKind,
    pub byte_len: u64,
    pub line_count: u32,
    pub imports: Vec<ImportFact>,
    pub exports: Vec<ExportFact>,
    pub symbol_facts: SymbolFileFacts,
    pub member_facts: Vec<ClassMemberFact>,
    pub diagnostics: Vec<AnalysisDiagnostic>,
}

impl SourceSpan {
    #[must_use]
    pub const fn new(start: u32, end: u32) -> Self {
        Self { start, end }
    }
}
