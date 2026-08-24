use std::path::{Component, Path, PathBuf};

use crate::domain::facts::SourceSpan;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EscapeReason {
    DynamicModuleSpecifier,
}

/// The smallest graph surface that an unresolved behavior can invalidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UnknownScope {
    RelativeDirectory(PathBuf),
    WorkspaceFileGraph,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EscapeFact {
    pub reason: EscapeReason,
    pub scope: UnknownScope,
    pub span: SourceSpan,
}

impl EscapeFact {
    pub(crate) fn unknown_module_specifier(
        leading_static_prefix: Option<&str>,
        span: SourceSpan,
    ) -> Self {
        Self {
            reason: EscapeReason::DynamicModuleSpecifier,
            scope: unknown_module_scope(leading_static_prefix),
            span,
        }
    }
}

pub(crate) fn unknown_module_scope(leading_static_prefix: Option<&str>) -> UnknownScope {
    leading_static_prefix
        .and_then(relative_directory_from_prefix)
        .map_or(
            UnknownScope::WorkspaceFileGraph,
            UnknownScope::RelativeDirectory,
        )
}

fn relative_directory_from_prefix(prefix: &str) -> Option<PathBuf> {
    if !prefix.starts_with("./") {
        return None;
    }

    let relative_prefix = prefix.strip_prefix("./")?;
    let candidate = Path::new(relative_prefix);
    let directory = if prefix.ends_with('/') || prefix.ends_with('\\') {
        candidate
    } else {
        candidate.parent().unwrap_or_else(|| Path::new(""))
    };
    let mut normalized = PathBuf::new();
    for component in directory.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(name) => normalized.push(name),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    if normalized.as_os_str().is_empty() {
        normalized.push(".");
    }
    Some(normalized)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{UnknownScope, unknown_module_scope};

    #[test]
    fn localizes_relative_dynamic_paths_to_their_containing_directory() {
        assert_eq!(
            unknown_module_scope(Some("./routes/admin/route-")),
            UnknownScope::RelativeDirectory(PathBuf::from("routes/admin"))
        );
        assert_eq!(
            unknown_module_scope(Some("./workers/")),
            UnknownScope::RelativeDirectory(PathBuf::from("workers"))
        );
        assert_eq!(
            unknown_module_scope(Some("./entry-")),
            UnknownScope::RelativeDirectory(PathBuf::from("."))
        );
    }

    #[test]
    fn widens_bare_parent_and_unknown_prefixes_to_the_workspace_file_graph() {
        for prefix in [None, Some(""), Some("package/"), Some("../outside/")] {
            assert_eq!(
                unknown_module_scope(prefix),
                UnknownScope::WorkspaceFileGraph
            );
        }
    }
}
