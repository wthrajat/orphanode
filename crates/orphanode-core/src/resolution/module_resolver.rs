use std::path::{Path, PathBuf};

use oxc_resolver::{ResolveError, ResolveOptions, Resolver, TsconfigDiscovery};
use thiserror::Error;

use crate::domain::facts::ResolutionMode;

pub trait ModuleResolver {
    /// Resolves `specifier` from `containing_file` using the requested module mode.
    ///
    /// # Errors
    ///
    /// Returns a [`ResolutionFailure`] when the resolver cannot map the specifier
    /// to a file and the specifier is not a recognized built-in module.
    fn resolve(
        &self,
        containing_file: &Path,
        specifier: &str,
        mode: ResolutionMode,
    ) -> Result<ModuleResolution, ResolutionFailure>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleResolution {
    File(PathBuf),
    External,
}

pub struct OxcModuleResolver {
    esm: Resolver,
    common_js: Resolver,
}

#[derive(Debug, Error)]
#[error("{message}")]
pub struct ResolutionFailure {
    message: String,
}

impl OxcModuleResolver {
    #[must_use]
    pub fn new() -> Self {
        Self::for_profiles(&["node".to_owned()])
    }

    #[must_use]
    pub fn for_profiles(profiles: &[String]) -> Self {
        Self::build(profiles, false, None)
    }

    /// Creates a resolver whose Yarn Plug'n'Play manifest lookup is anchored
    /// to the scanned workspace instead of the host process directory.
    #[must_use]
    pub fn for_profiles_with_yarn_pnp(profiles: &[String], workspace_root: &Path) -> Self {
        Self::build(profiles, true, Some(workspace_root))
    }

    fn build(profiles: &[String], yarn_pnp: bool, workspace_root: Option<&Path>) -> Self {
        let mut shared_conditions = profiles
            .iter()
            .map(|profile| profile.trim())
            .filter(|profile| !profile.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if shared_conditions.is_empty() {
            shared_conditions.push("node".to_owned());
        }
        shared_conditions.sort();
        shared_conditions.dedup();
        let mut esm_conditions = shared_conditions.clone();
        esm_conditions.retain(|condition| condition != "require");
        esm_conditions.extend(["import".to_owned(), "default".to_owned()]);
        esm_conditions.sort();
        esm_conditions.dedup();
        let mut common_js_conditions = shared_conditions;
        common_js_conditions.retain(|condition| condition != "import");
        common_js_conditions.extend(["require".to_owned(), "default".to_owned()]);
        common_js_conditions.sort();
        common_js_conditions.dedup();
        Self {
            esm: Resolver::new(options_for(&esm_conditions, yarn_pnp, workspace_root)),
            common_js: Resolver::new(options_for(&common_js_conditions, yarn_pnp, workspace_root)),
        }
    }
}

impl Default for OxcModuleResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleResolver for OxcModuleResolver {
    fn resolve(
        &self,
        containing_file: &Path,
        specifier: &str,
        mode: ResolutionMode,
    ) -> Result<ModuleResolution, ResolutionFailure> {
        let resolver = match mode {
            ResolutionMode::Esm => &self.esm,
            ResolutionMode::CommonJs => &self.common_js,
        };
        match resolver.resolve_file(containing_file, specifier) {
            Ok(resolution) => Ok(ModuleResolution::File(resolution.into_path_buf())),
            Err(ResolveError::Builtin { .. }) => Ok(ModuleResolution::External),
            Err(error) => Err(ResolutionFailure {
                message: error.to_string(),
            }),
        }
    }
}

#[must_use]
pub fn is_relative(specifier: &str) -> bool {
    specifier == "."
        || specifier == ".."
        || specifier.starts_with("./")
        || specifier.starts_with("../")
        || specifier.starts_with(".\\")
        || specifier.starts_with("..\\")
}

fn options_for(
    conditions: &[String],
    yarn_pnp: bool,
    workspace_root: Option<&Path>,
) -> ResolveOptions {
    ResolveOptions {
        cwd: if yarn_pnp {
            workspace_root.map(Path::to_path_buf)
        } else {
            None
        },
        condition_names: conditions.to_vec(),
        extensions: [
            ".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs", ".json", ".node",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        extension_alias: vec![
            (
                ".js".to_owned(),
                vec![".ts".to_owned(), ".tsx".to_owned(), ".js".to_owned()],
            ),
            (
                ".mjs".to_owned(),
                vec![".mts".to_owned(), ".mjs".to_owned()],
            ),
            (
                ".cjs".to_owned(),
                vec![".cts".to_owned(), ".cjs".to_owned()],
            ),
        ],
        builtin_modules: true,
        symlinks: true,
        tsconfig: Some(TsconfigDiscovery::Auto),
        yarn_pnp,
        ..ResolveOptions::default()
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{OxcModuleResolver, is_relative, options_for};

    #[test]
    fn classifies_only_relative_specifiers() {
        assert!(is_relative("./file.js"));
        assert!(is_relative("../file.js"));
        assert!(!is_relative("@/file.js"));
        assert!(!is_relative("package/subpath"));
        assert!(!is_relative("node:fs"));
    }

    #[test]
    fn yarn_pnp_is_enabled_only_for_detected_projects() {
        assert!(options_for(&["node".to_owned()], true, None).yarn_pnp);
        assert!(!options_for(&["node".to_owned()], false, None).yarn_pnp);
    }

    #[test]
    fn yarn_pnp_manifest_lookup_is_rooted_at_the_scanned_workspace() {
        let process_directory = std::env::current_dir().expect("current directory");
        let workspace_root = process_directory.join("different-scanned-workspace");
        assert_ne!(workspace_root, process_directory);
        let resolver =
            OxcModuleResolver::for_profiles_with_yarn_pnp(&["node".to_owned()], &workspace_root);

        assert_eq!(
            resolver.esm.options().cwd.as_deref(),
            Some(workspace_root.as_path())
        );
        assert_eq!(
            resolver.common_js.options().cwd.as_deref(),
            Some(workspace_root.as_path())
        );
    }

    #[test]
    fn ordinary_resolution_does_not_override_the_process_directory() {
        let options = options_for(
            &["node".to_owned()],
            false,
            Some(Path::new("/workspace/project")),
        );

        assert_eq!(options.cwd, None);
    }
}
