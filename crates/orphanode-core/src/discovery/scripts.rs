use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// A byte span in the original package-script value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ScriptSpan {
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptToken {
    pub value: String,
    pub span: ScriptSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptSegment {
    pub tokens: Vec<ScriptToken>,
    pub span: ScriptSpan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum UnmodeledScriptKind {
    DanglingEscape,
    GlobExpansion,
    InlineCode,
    Redirection,
    ShellExpansion,
    UnsupportedShellSyntax,
    UnsupportedShellWrapper,
    UnterminatedDoubleQuote,
    UnterminatedSingleQuote,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct UnmodeledScriptSpan {
    pub script: String,
    pub span: ScriptSpan,
    pub kind: UnmodeledScriptKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenizedScript {
    pub segments: Vec<ScriptSegment>,
    pub unmodeled: Vec<(ScriptSpan, UnmodeledScriptKind)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ScriptReferenceKind {
    Binary,
    File,
    Package,
}

/// Static evidence contributed by a reachable package script.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ScriptReference {
    pub script: String,
    pub kind: ScriptReferenceKind,
    pub value: String,
    pub span: ScriptSpan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ScriptCallKind {
    Explicit,
    Lifecycle,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ScriptCall {
    pub caller: String,
    pub callee: String,
    pub kind: ScriptCallKind,
    pub span: Option<ScriptSpan>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct MissingScriptReference {
    pub caller: String,
    pub callee: String,
    pub span: Option<ScriptSpan>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptAnalysis {
    pub reachable_scripts: Vec<String>,
    pub calls: Vec<ScriptCall>,
    pub references: Vec<ScriptReference>,
    pub missing_scripts: Vec<MissingScriptReference>,
    pub unmodeled: Vec<UnmodeledScriptSpan>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Quote {
    Unquoted,
    Single,
    Double,
}

struct ScriptTokenizer<'a> {
    source: &'a str,
    segments: Vec<ScriptSegment>,
    segment_tokens: Vec<ScriptToken>,
    unmodeled: Vec<(ScriptSpan, UnmodeledScriptKind)>,
    word: String,
    word_start: Option<usize>,
    segment_start: usize,
    quote: Quote,
    quote_start: usize,
    index: usize,
}

/// Splits a package script into static shell segments without invoking a shell.
///
/// Quotes and escapes are decoded, while byte spans continue to point at the
/// original string. Dynamic expansion, redirection, and malformed quoting are
/// retained as explicit unmodeled spans instead of being guessed through.
#[must_use]
pub fn tokenize_script(source: &str) -> TokenizedScript {
    ScriptTokenizer::new(source).tokenize()
}

impl<'a> ScriptTokenizer<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            segments: Vec::new(),
            segment_tokens: Vec::new(),
            unmodeled: Vec::new(),
            word: String::new(),
            word_start: None,
            segment_start: 0,
            quote: Quote::Unquoted,
            quote_start: 0,
            index: 0,
        }
    }

    fn tokenize(mut self) -> TokenizedScript {
        while self.index < self.source.len() {
            let character = next_character(self.source, self.index);
            match self.quote {
                Quote::Single => self.consume_single_quoted(character),
                Quote::Double => self.consume_double_quoted(character),
                Quote::Unquoted => self.consume_unquoted(character),
            }
        }
        self.finish()
    }

    fn consume_single_quoted(&mut self, character: char) {
        if character == '\'' {
            self.quote = Quote::Unquoted;
        } else {
            self.word.push(character);
        }
        self.index += character.len_utf8();
    }

    fn consume_double_quoted(&mut self, character: char) {
        match character {
            '"' => {
                self.quote = Quote::Unquoted;
                self.index += character.len_utf8();
            }
            '\\' => self.consume_escape(),
            '$' | '`' => self.consume_expansion(character),
            _ => {
                self.word.push(character);
                self.index += character.len_utf8();
            }
        }
    }

    fn consume_unquoted(&mut self, character: char) {
        match character {
            '\'' => self.begin_quote(Quote::Single),
            '"' => self.begin_quote(Quote::Double),
            '\\' => {
                self.word_start.get_or_insert(self.index);
                self.consume_escape();
            }
            '$' | '`' => {
                self.word_start.get_or_insert(self.index);
                self.consume_expansion(character);
            }
            '*' | '?' | '[' => self.consume_unmodeled_character(
                character,
                UnmodeledScriptKind::GlobExpansion,
                true,
            ),
            '>' | '<' => {
                self.finish_word();
                self.consume_unmodeled_character(
                    character,
                    UnmodeledScriptKind::Redirection,
                    false,
                );
            }
            '(' | ')' | '{' | '}' => self.consume_unmodeled_character(
                character,
                UnmodeledScriptKind::UnsupportedShellSyntax,
                true,
            ),
            ';' | '|' | '&' | '\n' => self.consume_operator(character),
            '#' if self.word_start.is_none() => self.consume_comment(),
            character if character.is_whitespace() => {
                self.finish_word();
                self.index += character.len_utf8();
            }
            _ => {
                self.word_start.get_or_insert(self.index);
                self.word.push(character);
                self.index += character.len_utf8();
            }
        }
    }

    fn begin_quote(&mut self, quote: Quote) {
        self.word_start.get_or_insert(self.index);
        self.quote = quote;
        self.quote_start = self.index;
        self.index += 1;
    }

    fn consume_escape(&mut self) {
        let escaped_index = self.index + 1;
        if escaped_index >= self.source.len() {
            self.unmodeled.push((
                ScriptSpan {
                    start: self.index,
                    end: self.source.len(),
                },
                UnmodeledScriptKind::DanglingEscape,
            ));
            self.index = self.source.len();
            return;
        }
        let escaped = next_character(self.source, escaped_index);
        self.word.push(escaped);
        self.index = escaped_index + escaped.len_utf8();
    }

    fn consume_expansion(&mut self, marker: char) {
        let end = shell_expansion_end(self.source, self.index, marker);
        self.unmodeled.push((
            ScriptSpan {
                start: self.index,
                end,
            },
            UnmodeledScriptKind::ShellExpansion,
        ));
        self.index = end;
    }

    fn consume_unmodeled_character(
        &mut self,
        character: char,
        kind: UnmodeledScriptKind,
        retain: bool,
    ) {
        if retain {
            self.word_start.get_or_insert(self.index);
            self.word.push(character);
        }
        self.unmodeled.push((
            ScriptSpan {
                start: self.index,
                end: self.index + character.len_utf8(),
            },
            kind,
        ));
        self.index += character.len_utf8();
    }

    fn consume_operator(&mut self, character: char) {
        self.finish_word();
        self.finish_segment(self.index);
        self.index += character.len_utf8();
        if self.index < self.source.len() && next_character(self.source, self.index) == character {
            self.index += character.len_utf8();
        }
        self.segment_start = self.index;
    }

    fn consume_comment(&mut self) {
        self.finish_segment(self.index);
        if let Some(relative_newline) = self.source[self.index..].find('\n') {
            self.index += relative_newline + 1;
            self.segment_start = self.index;
        } else {
            self.index = self.source.len();
        }
    }

    fn finish_word(&mut self) {
        finish_word(
            &mut self.segment_tokens,
            &mut self.word,
            &mut self.word_start,
            self.index,
        );
    }

    fn finish_segment(&mut self, end: usize) {
        finish_segment(
            &mut self.segments,
            &mut self.segment_tokens,
            self.segment_start,
            end,
        );
    }

    fn finish(mut self) -> TokenizedScript {
        let unterminated = match self.quote {
            Quote::Unquoted => None,
            Quote::Single => Some(UnmodeledScriptKind::UnterminatedSingleQuote),
            Quote::Double => Some(UnmodeledScriptKind::UnterminatedDoubleQuote),
        };
        if let Some(kind) = unterminated {
            self.unmodeled.push((
                ScriptSpan {
                    start: self.quote_start,
                    end: self.source.len(),
                },
                kind,
            ));
        }
        self.index = self.source.len();
        self.finish_word();
        self.finish_segment(self.source.len());
        self.unmodeled.sort_unstable();
        self.unmodeled.dedup();
        TokenizedScript {
            segments: self.segments,
            unmodeled: self.unmodeled,
        }
    }
}

/// Analyzes package scripts from selected roots.
///
/// An empty `root_scripts` slice means every declared script is manually
/// invocable and therefore reachable. Explicit roots additionally retain their
/// `pre<name>` and `post<name>` lifecycle hooks and nested package-manager runs.
#[must_use]
pub fn analyze_scripts(
    scripts: &BTreeMap<String, String>,
    root_scripts: &[String],
) -> ScriptAnalysis {
    let mut queue = VecDeque::new();
    let mut missing_scripts = BTreeSet::new();

    if root_scripts.is_empty() {
        queue.extend(scripts.keys().cloned());
    } else {
        let roots = root_scripts.iter().cloned().collect::<BTreeSet<_>>();
        for root in roots {
            if scripts.contains_key(&root) {
                queue.push_back(root);
            } else {
                missing_scripts.insert(MissingScriptReference {
                    caller: "<root>".to_owned(),
                    callee: root,
                    span: None,
                });
            }
        }
    }

    let mut reachable = BTreeSet::new();
    let mut calls = BTreeSet::new();
    let mut references = BTreeSet::new();
    let mut unmodeled = BTreeSet::new();

    while let Some(script_name) = queue.pop_front() {
        if !reachable.insert(script_name.clone()) {
            continue;
        }

        schedule_lifecycle_script(scripts, &script_name, "pre", &mut queue, &mut calls);
        schedule_lifecycle_script(scripts, &script_name, "post", &mut queue, &mut calls);

        let Some(source) = scripts.get(&script_name) else {
            continue;
        };
        let tokenized = tokenize_script(source);
        for (span, kind) in &tokenized.unmodeled {
            unmodeled.insert(UnmodeledScriptSpan {
                script: script_name.clone(),
                span: *span,
                kind: *kind,
            });
        }

        for segment in &tokenized.segments {
            if tokenized
                .unmodeled
                .iter()
                .any(|(span, _)| spans_overlap(*span, segment.span))
            {
                continue;
            }

            let mut contribution = SegmentContribution::default();
            analyze_segment(&script_name, segment, 0, &mut contribution);
            references.extend(contribution.references);
            for (span, kind) in contribution.unmodeled {
                unmodeled.insert(UnmodeledScriptSpan {
                    script: script_name.clone(),
                    span,
                    kind,
                });
            }
            for (callee, span) in contribution.nested_scripts {
                calls.insert(ScriptCall {
                    caller: script_name.clone(),
                    callee: callee.clone(),
                    kind: ScriptCallKind::Explicit,
                    span: Some(span),
                });
                if scripts.contains_key(&callee) {
                    queue.push_back(callee);
                } else {
                    missing_scripts.insert(MissingScriptReference {
                        caller: script_name.clone(),
                        callee,
                        span: Some(span),
                    });
                }
            }
        }
    }

    ScriptAnalysis {
        reachable_scripts: reachable.into_iter().collect(),
        calls: calls.into_iter().collect(),
        references: references.into_iter().collect(),
        missing_scripts: missing_scripts.into_iter().collect(),
        unmodeled: unmodeled.into_iter().collect(),
    }
}

#[derive(Default)]
struct SegmentContribution {
    nested_scripts: BTreeSet<(String, ScriptSpan)>,
    references: BTreeSet<ScriptReference>,
    unmodeled: BTreeSet<(ScriptSpan, UnmodeledScriptKind)>,
}

fn analyze_segment(
    script_name: &str,
    segment: &ScriptSegment,
    recursion_depth: usize,
    contribution: &mut SegmentContribution,
) {
    let Some(command_index) = find_command_index(script_name, &segment.tokens, contribution) else {
        return;
    };
    let command = &segment.tokens[command_index];
    let command_name = binary_name(&command.value);
    let arguments = &segment.tokens[command_index + 1..];

    if matches!(
        command_name.as_str(),
        "cross-env-shell" | "sh" | "bash" | "cmd" | "powershell" | "pwsh"
    ) {
        analyze_static_shell_wrapper(
            script_name,
            &command_name,
            arguments,
            recursion_depth,
            segment.span,
            contribution,
        );
        return;
    }

    if command_name == "concurrently" {
        add_reference(
            contribution,
            script_name,
            ScriptReferenceKind::Binary,
            &command_name,
            command.span,
        );
        contribution
            .unmodeled
            .insert((segment.span, UnmodeledScriptKind::UnsupportedShellWrapper));
        return;
    }

    match command_name.as_str() {
        "node" => analyze_node_command(script_name, arguments, contribution),
        "npm" | "pnpm" | "yarn" | "bun" => {
            analyze_package_manager(script_name, &command_name, arguments, contribution);
        }
        "npx" | "bunx" => analyze_exec_command(script_name, arguments, contribution),
        "npm-run-all" | "run-s" | "run-p" => analyze_script_list(arguments, contribution),
        _ if looks_like_file(&command.value) => add_reference(
            contribution,
            script_name,
            ScriptReferenceKind::File,
            &command.value,
            command.span,
        ),
        _ if !is_system_command(&command_name) => {
            add_reference(
                contribution,
                script_name,
                ScriptReferenceKind::Binary,
                &command_name,
                command.span,
            );
            if is_supported_file_tool(&command_name) {
                analyze_tool_files(script_name, arguments, contribution);
            }
        }
        _ => {}
    }
}

fn find_command_index(
    script_name: &str,
    tokens: &[ScriptToken],
    contribution: &mut SegmentContribution,
) -> Option<usize> {
    let mut index = consume_environment_assignments(script_name, tokens, 0, contribution);
    loop {
        let command = tokens.get(index)?;
        match binary_name(&command.value).as_str() {
            "env" => {
                index += 1;
                index = skip_env_options(tokens, index);
                index = consume_environment_assignments(script_name, tokens, index, contribution);
            }
            "cross-env" => {
                index += 1;
                while tokens
                    .get(index)
                    .is_some_and(|token| token.value.starts_with('-'))
                {
                    index += 1;
                }
                index = consume_environment_assignments(script_name, tokens, index, contribution);
            }
            "command" | "exec" => {
                index += 1;
                while tokens
                    .get(index)
                    .is_some_and(|token| token.value.starts_with('-'))
                {
                    index += 1;
                }
            }
            _ => return Some(index),
        }
    }
}

fn skip_env_options(tokens: &[ScriptToken], mut index: usize) -> usize {
    while let Some(token) = tokens.get(index) {
        if matches!(token.value.as_str(), "-u" | "--unset" | "-C" | "--chdir") {
            index += 2;
        } else if token.value.starts_with('-') {
            index += 1;
        } else {
            break;
        }
    }
    index
}

fn consume_environment_assignments(
    script_name: &str,
    tokens: &[ScriptToken],
    mut index: usize,
    contribution: &mut SegmentContribution,
) -> usize {
    while let Some(token) = tokens.get(index) {
        let Some((name, value)) = environment_assignment(&token.value) else {
            break;
        };
        if name == "NODE_OPTIONS" {
            analyze_node_options(script_name, value, token.span, contribution);
        }
        index += 1;
    }
    index
}

fn analyze_static_shell_wrapper(
    script_name: &str,
    wrapper: &str,
    arguments: &[ScriptToken],
    recursion_depth: usize,
    segment_span: ScriptSpan,
    contribution: &mut SegmentContribution,
) {
    if recursion_depth >= 4 {
        contribution
            .unmodeled
            .insert((segment_span, UnmodeledScriptKind::UnsupportedShellWrapper));
        return;
    }

    let command_token = if wrapper == "cross-env-shell" {
        arguments
            .iter()
            .find(|token| environment_assignment(&token.value).is_none())
    } else if wrapper == "cmd" {
        arguments
            .windows(2)
            .find(|pair| pair[0].value.eq_ignore_ascii_case("/c"))
            .map(|pair| &pair[1])
    } else if matches!(wrapper, "powershell" | "pwsh") {
        arguments
            .windows(2)
            .find(|pair| {
                matches!(
                    pair[0].value.to_ascii_lowercase().as_str(),
                    "-command" | "-c"
                )
            })
            .map(|pair| &pair[1])
    } else {
        arguments
            .windows(2)
            .find(|pair| pair[0].value == "-c")
            .map(|pair| &pair[1])
    };
    let Some(command_token) = command_token else {
        contribution
            .unmodeled
            .insert((segment_span, UnmodeledScriptKind::UnsupportedShellWrapper));
        return;
    };

    let nested = tokenize_script(&command_token.value);
    if !nested.unmodeled.is_empty() {
        contribution.unmodeled.insert((
            command_token.span,
            UnmodeledScriptKind::UnsupportedShellWrapper,
        ));
        return;
    }
    let mut nested_contribution = SegmentContribution::default();
    for nested_segment in &nested.segments {
        analyze_segment(
            script_name,
            nested_segment,
            recursion_depth + 1,
            &mut nested_contribution,
        );
    }
    contribution.nested_scripts.extend(
        nested_contribution
            .nested_scripts
            .into_iter()
            .map(|(script, _)| (script, command_token.span)),
    );
    contribution
        .references
        .extend(
            nested_contribution
                .references
                .into_iter()
                .map(|mut reference| {
                    reference.span = command_token.span;
                    reference
                }),
        );
    contribution.unmodeled.extend(
        nested_contribution
            .unmodeled
            .into_iter()
            .map(|(_, kind)| (command_token.span, kind)),
    );
}

fn analyze_package_manager(
    script_name: &str,
    manager: &str,
    arguments: &[ScriptToken],
    contribution: &mut SegmentContribution,
) {
    let action_index = package_manager_action_index(arguments);
    let Some(first) = arguments.get(action_index) else {
        return;
    };
    let remaining = &arguments[action_index + 1..];

    if matches!(first.value.as_str(), "run" | "run-script") {
        if let Some(callee) = remaining.iter().find(|token| !token.value.starts_with('-')) {
            contribution
                .nested_scripts
                .insert((callee.value.clone(), callee.span));
        }
        return;
    }
    if manager == "npm" && matches!(first.value.as_str(), "start" | "stop" | "restart" | "test") {
        contribution
            .nested_scripts
            .insert((first.value.clone(), first.span));
        return;
    }
    if matches!(first.value.as_str(), "exec" | "dlx" | "x") {
        analyze_exec_command(script_name, remaining, contribution);
        return;
    }
    if matches!(manager, "yarn" | "pnpm" | "bun")
        && !first.value.starts_with('-')
        && !PACKAGE_MANAGER_COMMANDS.contains(&first.value.as_str())
    {
        // `pnpm up` is a CLI action, not an implicit `pnpm run up`. Only
        // non-builtin verbs can name a package script.
        contribution
            .nested_scripts
            .insert((first.value.clone(), first.span));
    }
}

/// Verbs that every supported package manager handles itself. An implicit
/// `run` never applies to them, so they are never package-script calls.
const PACKAGE_MANAGER_COMMANDS: [&str; 32] = [
    "add",
    "audit",
    "bin",
    "ci",
    "config",
    "dedupe",
    "deploy",
    "import",
    "init",
    "install",
    "i",
    "link",
    "ln",
    "list",
    "login",
    "logout",
    "outdated",
    "pack",
    "patch",
    "pm",
    "prune",
    "publish",
    "rebuild",
    "remove",
    "rm",
    "store",
    "unlink",
    "uninstall",
    "up",
    "update",
    "upgrade",
    "why",
];

fn package_manager_action_index(arguments: &[ScriptToken]) -> usize {
    let mut index = 0;
    while let Some(token) = arguments.get(index) {
        if matches!(
            token.value.as_str(),
            "--filter" | "-F" | "--workspace" | "--prefix" | "--cwd" | "--dir" | "-C"
        ) {
            index += 2;
        } else if token.value.starts_with('-') {
            index += 1;
        } else {
            break;
        }
    }
    index
}

fn analyze_exec_command(
    script_name: &str,
    arguments: &[ScriptToken],
    contribution: &mut SegmentContribution,
) {
    let mut index = 0;
    while index < arguments.len() {
        let token = &arguments[index];
        if matches!(token.value.as_str(), "--package" | "-p") {
            if let Some(package) = arguments.get(index + 1) {
                add_reference(
                    contribution,
                    script_name,
                    ScriptReferenceKind::Package,
                    &package.value,
                    package.span,
                );
            }
            index += 2;
        } else if let Some(package) = token.value.strip_prefix("--package=") {
            add_reference(
                contribution,
                script_name,
                ScriptReferenceKind::Package,
                package,
                token.span,
            );
            index += 1;
        } else if token.value.starts_with('-') {
            index += 1;
        } else {
            add_reference(
                contribution,
                script_name,
                ScriptReferenceKind::Binary,
                &binary_name(&token.value),
                token.span,
            );
            break;
        }
    }
}

fn analyze_script_list(arguments: &[ScriptToken], contribution: &mut SegmentContribution) {
    for token in arguments {
        if !token.value.starts_with('-') {
            contribution
                .nested_scripts
                .insert((token.value.clone(), token.span));
        }
    }
}

fn analyze_node_command(
    script_name: &str,
    arguments: &[ScriptToken],
    contribution: &mut SegmentContribution,
) {
    let mut index = 0;
    let mut test_mode = false;
    while index < arguments.len() {
        let token = &arguments[index];
        if let Some(value) = inline_node_loader_value(&token.value) {
            add_node_loader_reference(script_name, value, token.span, contribution);
            index += 1;
        } else if is_node_loader_flag(&token.value) {
            if let Some(value) = arguments.get(index + 1) {
                add_node_loader_reference(script_name, &value.value, value.span, contribution);
            }
            index += 2;
        } else if matches!(token.value.as_str(), "-e" | "--eval" | "-p" | "--print") {
            let end = arguments
                .get(index + 1)
                .map_or(token.span.end, |value| value.span.end);
            contribution.unmodeled.insert((
                ScriptSpan {
                    start: token.span.start,
                    end,
                },
                UnmodeledScriptKind::InlineCode,
            ));
            return;
        } else if token.value == "--test" || token.value.starts_with("--test=") {
            test_mode = true;
            index += 1;
        } else if token.value.starts_with('-') {
            index += usize::from(node_flag_takes_value(&token.value)) + 1;
        } else {
            if looks_like_file(&token.value) {
                add_reference(
                    contribution,
                    script_name,
                    ScriptReferenceKind::File,
                    &token.value,
                    token.span,
                );
            }
            index += 1;
            if !test_mode {
                break;
            }
        }
    }
}

fn analyze_node_options(
    script_name: &str,
    options: &str,
    outer_span: ScriptSpan,
    contribution: &mut SegmentContribution,
) {
    let tokenized = tokenize_script(options);
    if !tokenized.unmodeled.is_empty() || tokenized.segments.len() != 1 {
        contribution
            .unmodeled
            .insert((outer_span, UnmodeledScriptKind::ShellExpansion));
        return;
    }
    let Some(segment) = tokenized.segments.first() else {
        return;
    };
    let mut index = 0;
    while index < segment.tokens.len() {
        let token = &segment.tokens[index];
        if let Some(value) = inline_node_loader_value(&token.value) {
            add_node_loader_reference(script_name, value, outer_span, contribution);
            index += 1;
        } else if is_node_loader_flag(&token.value) {
            if let Some(value) = segment.tokens.get(index + 1) {
                add_node_loader_reference(script_name, &value.value, outer_span, contribution);
            }
            index += 2;
        } else {
            index += 1;
        }
    }
}

fn analyze_tool_files(
    script_name: &str,
    arguments: &[ScriptToken],
    contribution: &mut SegmentContribution,
) {
    let mut previous_wants_path = false;
    for token in arguments {
        if previous_wants_path || (!token.value.starts_with('-') && looks_like_file(&token.value)) {
            if looks_like_file(&token.value) {
                add_reference(
                    contribution,
                    script_name,
                    ScriptReferenceKind::File,
                    &token.value,
                    token.span,
                );
            }
            previous_wants_path = false;
        } else {
            previous_wants_path = matches!(
                token.value.as_str(),
                "--config" | "--project" | "--require" | "-c" | "-p" | "-r"
            );
        }
    }
}

fn add_node_loader_reference(
    script_name: &str,
    value: &str,
    span: ScriptSpan,
    contribution: &mut SegmentContribution,
) {
    let kind = if looks_like_file(value) {
        ScriptReferenceKind::File
    } else {
        ScriptReferenceKind::Package
    };
    add_reference(contribution, script_name, kind, value, span);
}

fn add_reference(
    contribution: &mut SegmentContribution,
    script_name: &str,
    kind: ScriptReferenceKind,
    value: &str,
    span: ScriptSpan,
) {
    if value.is_empty() {
        return;
    }
    contribution.references.insert(ScriptReference {
        script: script_name.to_owned(),
        kind,
        value: value.to_owned(),
        span,
    });
}

fn schedule_lifecycle_script(
    scripts: &BTreeMap<String, String>,
    script_name: &str,
    prefix: &str,
    queue: &mut VecDeque<String>,
    calls: &mut BTreeSet<ScriptCall>,
) {
    let lifecycle_name = format!("{prefix}{script_name}");
    if lifecycle_name == script_name || !scripts.contains_key(&lifecycle_name) {
        return;
    }
    calls.insert(ScriptCall {
        caller: script_name.to_owned(),
        callee: lifecycle_name.clone(),
        kind: ScriptCallKind::Lifecycle,
        span: None,
    });
    queue.push_back(lifecycle_name);
}

fn finish_word(
    tokens: &mut Vec<ScriptToken>,
    word: &mut String,
    word_start: &mut Option<usize>,
    end: usize,
) {
    let Some(start) = word_start.take() else {
        return;
    };
    tokens.push(ScriptToken {
        value: std::mem::take(word),
        span: ScriptSpan { start, end },
    });
}

fn finish_segment(
    segments: &mut Vec<ScriptSegment>,
    tokens: &mut Vec<ScriptToken>,
    start: usize,
    end: usize,
) {
    if tokens.is_empty() {
        return;
    }
    segments.push(ScriptSegment {
        tokens: std::mem::take(tokens),
        span: ScriptSpan { start, end },
    });
}

fn shell_expansion_end(source: &str, start: usize, marker: char) -> usize {
    let marker_end = start + marker.len_utf8();
    if marker == '`' {
        return source[marker_end..]
            .find('`')
            .map_or(source.len(), |offset| marker_end + offset + 1);
    }
    if source[marker_end..].starts_with('(') {
        return source[marker_end + 1..]
            .find(')')
            .map_or(source.len(), |offset| marker_end + offset + 2);
    }
    marker_end
}

fn next_character(source: &str, index: usize) -> char {
    source[index..]
        .chars()
        .next()
        .expect("index is inside the source")
}

fn spans_overlap(left: ScriptSpan, right: ScriptSpan) -> bool {
    left.start < right.end && right.start < left.end
}

fn environment_assignment(token: &str) -> Option<(&str, &str)> {
    let (name, value) = token.split_once('=')?;
    let mut characters = name.chars();
    let first = characters.next()?;
    if !(first == '_' || first.is_ascii_alphabetic())
        || !characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
    {
        return None;
    }
    Some((name, value))
}

fn binary_name(command: &str) -> String {
    command
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(command)
        .strip_suffix(".cmd")
        .or_else(|| {
            command
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or(command)
                .strip_suffix(".exe")
        })
        .unwrap_or_else(|| command.rsplit(['/', '\\']).next().unwrap_or(command))
        .to_owned()
}

fn looks_like_file(value: &str) -> bool {
    if value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with('/')
        || value.starts_with(".\\")
        || value.starts_with("..\\")
    {
        return true;
    }
    let extension = value
        .rsplit_once('.')
        .map(|(_, extension)| extension)
        .unwrap_or_default();
    matches!(
        extension,
        "js" | "jsx"
            | "mjs"
            | "cjs"
            | "ts"
            | "tsx"
            | "mts"
            | "cts"
            | "json"
            | "jsonc"
            | "yaml"
            | "yml"
            | "css"
            | "scss"
            | "html"
    )
}

fn inline_node_loader_value(flag: &str) -> Option<&str> {
    [
        "--require=",
        "--import=",
        "--loader=",
        "--experimental-loader=",
    ]
    .into_iter()
    .find_map(|prefix| flag.strip_prefix(prefix))
    .or_else(|| flag.strip_prefix("-r").filter(|value| !value.is_empty()))
}

fn is_node_loader_flag(flag: &str) -> bool {
    matches!(
        flag,
        "-r" | "--require" | "--import" | "--loader" | "--experimental-loader"
    )
}

fn node_flag_takes_value(flag: &str) -> bool {
    matches!(
        flag,
        "--conditions"
            | "--diagnostic-dir"
            | "--dns-result-order"
            | "--inspect-port"
            | "--max-http-header-size"
            | "--redirect-warnings"
            | "--title"
            | "--trace-event-categories"
            | "--trace-event-file-pattern"
    )
}

fn is_supported_file_tool(command: &str) -> bool {
    matches!(
        command,
        "ava"
            | "babel"
            | "eslint"
            | "jest"
            | "mocha"
            | "prettier"
            | "rollup"
            | "ts-node"
            | "tsc"
            | "tsx"
            | "vite"
            | "vitest"
            | "webpack"
    )
}

fn is_system_command(command: &str) -> bool {
    matches!(
        command,
        "bun"
            | "cd"
            | "cp"
            | "echo"
            | "export"
            | "false"
            | "git"
            | "mkdir"
            | "mv"
            | "node"
            | "npm"
            | "npx"
            | "pnpm"
            | "printf"
            | "rm"
            | "set"
            | "sleep"
            | "test"
            | "true"
            | "yarn"
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        ScriptCallKind, ScriptReferenceKind, UnmodeledScriptKind, analyze_scripts, tokenize_script,
    };

    #[test]
    fn tokenization_preserves_quotes_and_static_segments() {
        let tokenized = tokenize_script("eslint 'src/one file.ts' && node \"src/run.js\"");

        assert!(tokenized.unmodeled.is_empty());
        assert_eq!(tokenized.segments.len(), 2);
        assert_eq!(tokenized.segments[0].tokens[1].value, "src/one file.ts");
        assert_eq!(tokenized.segments[1].tokens[1].value, "src/run.js");
    }

    #[test]
    fn nested_runs_and_lifecycle_hooks_are_reachable_and_sorted() {
        let scripts = BTreeMap::from([
            ("build".to_owned(), "npm run compile".to_owned()),
            ("compile".to_owned(), "tsx scripts/build.ts".to_owned()),
            ("postbuild".to_owned(), "eslint src/index.ts".to_owned()),
            (
                "prebuild".to_owned(),
                "node --require ts-node/register setup.js".to_owned(),
            ),
            ("unused".to_owned(), "echo unused".to_owned()),
        ]);

        let analysis = analyze_scripts(&scripts, &["build".to_owned()]);

        assert_eq!(
            analysis.reachable_scripts,
            ["build", "compile", "postbuild", "prebuild"].map(str::to_owned)
        );
        assert!(analysis.calls.iter().any(|call| {
            call.caller == "build"
                && call.callee == "prebuild"
                && call.kind == ScriptCallKind::Lifecycle
        }));
        assert!(analysis.calls.iter().any(|call| {
            call.caller == "build"
                && call.callee == "compile"
                && call.kind == ScriptCallKind::Explicit
        }));
    }

    #[test]
    fn package_manager_cli_actions_are_not_implicit_script_calls() {
        let scripts = BTreeMap::from([
            (
                "upgrade-latest".to_owned(),
                "pnpm up --latest --interactive".to_owned(),
            ),
            ("fresh".to_owned(), "yarn install && bun add zod".to_owned()),
        ]);

        let analysis = analyze_scripts(&scripts, &[]);

        assert!(analysis.missing_scripts.is_empty());
        assert!(
            !analysis.calls.iter().any(|call| call.callee == "up"
                || call.callee == "add"
                || call.callee == "install")
        );
    }

    #[test]
    fn implicit_pnpm_runs_of_real_scripts_stay_reachable() {
        let scripts = BTreeMap::from([
            ("dist".to_owned(), "pnpm build".to_owned()),
            ("build".to_owned(), "tsc -p tsconfig.json".to_owned()),
        ]);

        let analysis = analyze_scripts(&scripts, &["dist".to_owned()]);

        assert_eq!(
            analysis.reachable_scripts,
            ["build", "dist"].map(str::to_owned)
        );
    }

    #[test]
    fn node_options_loaders_files_and_direct_binaries_become_evidence() {
        let scripts = BTreeMap::from([(
            "test".to_owned(),
            "NODE_OPTIONS='--require ts-node/register --loader ./loader.mjs' node --test tests/a.test.ts && npx --package eslint eslint src/a.ts".to_owned(),
        )]);

        let analysis = analyze_scripts(&scripts, &[]);

        assert!(analysis.references.iter().any(|reference| {
            reference.kind == ScriptReferenceKind::Package && reference.value == "ts-node/register"
        }));
        assert!(analysis.references.iter().any(|reference| {
            reference.kind == ScriptReferenceKind::File && reference.value == "./loader.mjs"
        }));
        assert!(analysis.references.iter().any(|reference| {
            reference.kind == ScriptReferenceKind::File && reference.value == "tests/a.test.ts"
        }));
        assert!(analysis.references.iter().any(|reference| {
            reference.kind == ScriptReferenceKind::Package && reference.value == "eslint"
        }));
        assert!(analysis.references.iter().any(|reference| {
            reference.kind == ScriptReferenceKind::Binary && reference.value == "eslint"
        }));
    }

    #[test]
    fn dynamic_shell_segments_are_visible_and_do_not_create_guessed_evidence() {
        let scripts = BTreeMap::from([(
            "dynamic".to_owned(),
            "node $ENTRY && eslint src/static.ts".to_owned(),
        )]);

        let analysis = analyze_scripts(&scripts, &[]);

        assert!(analysis.unmodeled.iter().any(|span| {
            span.script == "dynamic" && span.kind == UnmodeledScriptKind::ShellExpansion
        }));
        assert!(!analysis.references.iter().any(|reference| {
            reference.kind == ScriptReferenceKind::File && reference.value == "$ENTRY"
        }));
        assert!(analysis.references.iter().any(|reference| {
            reference.kind == ScriptReferenceKind::File && reference.value == "src/static.ts"
        }));
    }

    #[test]
    fn absent_nested_scripts_are_reported_without_becoming_reachable() {
        let scripts = BTreeMap::from([("build".to_owned(), "pnpm run missing".to_owned())]);

        let analysis = analyze_scripts(&scripts, &["build".to_owned()]);

        assert_eq!(analysis.reachable_scripts, ["build".to_owned()]);
        assert_eq!(analysis.missing_scripts.len(), 1);
        assert_eq!(analysis.missing_scripts[0].callee, "missing");
    }

    #[test]
    fn package_manager_and_env_options_do_not_hide_the_invoked_command() {
        let scripts = BTreeMap::from([
            (
                "build".to_owned(),
                "pnpm --filter app run compile".to_owned(),
            ),
            (
                "compile".to_owned(),
                "env -u NODE_OPTIONS node -rts-node/register src/index.ts".to_owned(),
            ),
        ]);

        let analysis = analyze_scripts(&scripts, &["build".to_owned()]);

        assert_eq!(
            analysis.reachable_scripts,
            ["build", "compile"].map(str::to_owned)
        );
        assert!(analysis.references.iter().any(|reference| {
            reference.kind == ScriptReferenceKind::Package && reference.value == "ts-node/register"
        }));
    }
}
