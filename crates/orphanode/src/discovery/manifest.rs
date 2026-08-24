use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use thiserror::Error;

/// Normalized workspace patterns from the package manifest formats understood by
/// npm, Yarn, and Bun.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceDeclaration {
    pub patterns: Vec<String>,
}

impl<'de> Deserialize<'de> for WorkspaceDeclaration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let patterns = match value {
            Value::Array(values) => {
                deserialize_string_array(values).map_err(serde::de::Error::custom)?
            }
            Value::Object(mut object) => {
                let packages = object.remove("packages").ok_or_else(|| {
                    serde::de::Error::custom("workspace object must contain a `packages` array")
                })?;
                let Value::Array(values) = packages else {
                    return Err(serde::de::Error::custom(
                        "workspace object `packages` must be an array",
                    ));
                };
                deserialize_string_array(values).map_err(serde::de::Error::custom)?
            }
            _ => {
                return Err(serde::de::Error::custom(
                    "`workspaces` must be an array or an object containing `packages`",
                ));
            }
        };

        Ok(Self { patterns })
    }
}

fn deserialize_string_array(values: Vec<Value>) -> Result<Vec<String>, &'static str> {
    values
        .into_iter()
        .map(|value| match value {
            Value::String(value) => Ok(value),
            _ => Err("workspace patterns must be strings"),
        })
        .collect()
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum BinaryDeclaration {
    #[default]
    Absent,
    Single(String),
    Named(BTreeMap<String, String>),
}

/// Static package metadata used by discovery and later package-evidence stages.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageManifest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub private: bool,
    #[serde(default)]
    pub package_manager: Option<String>,
    #[serde(default)]
    pub r#type: Option<String>,
    #[serde(default)]
    pub main: Option<String>,
    #[serde(default)]
    pub module: Option<String>,
    #[serde(default)]
    pub browser: Option<Value>,
    #[serde(default)]
    pub bin: BinaryDeclaration,
    #[serde(default)]
    pub exports: Option<Value>,
    #[serde(default)]
    pub imports: Option<Value>,
    #[serde(default)]
    pub types: Option<String>,
    #[serde(default)]
    pub typings: Option<String>,
    #[serde(default)]
    pub files: Vec<String>,
    #[serde(default)]
    pub workspaces: WorkspaceDeclaration,
    #[serde(default)]
    pub scripts: BTreeMap<String, String>,
    #[serde(default)]
    pub dependencies: BTreeMap<String, String>,
    #[serde(default)]
    pub dev_dependencies: BTreeMap<String, String>,
    #[serde(default)]
    pub peer_dependencies: BTreeMap<String, String>,
    #[serde(default)]
    pub optional_dependencies: BTreeMap<String, String>,
    #[serde(default, alias = "bundleDependencies")]
    pub bundled_dependencies: BTreeSet<String>,
    #[serde(default)]
    pub orphanode: Option<Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryTargetProfile {
    NodeImport,
    NodeRequire,
    Bundler,
    Browser,
    Types,
    CommandLine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageEntryField {
    Exports,
    Main,
    Module,
    Browser,
    Bin,
    Types,
    Typings,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageEntryRoot {
    pub path: PathBuf,
    pub field: PackageEntryField,
}

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("cannot read package manifest `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("invalid package manifest `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("package field `{field}` contains unsafe entry path `{target}`")]
    UnsafeEntry { field: &'static str, target: String },
}

/// Reads a package manifest as data. No package script or configuration code is
/// evaluated.
///
/// # Errors
///
/// Returns an error when the file cannot be read or contains invalid static
/// package metadata.
pub fn read_package_manifest(path: &Path) -> Result<PackageManifest, ManifestError> {
    let source = fs::read_to_string(path).map_err(|source| ManifestError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_str(&source).map_err(|source| ManifestError::Parse {
        path: path.to_path_buf(),
        source,
    })
}

/// Selects package entry candidates for exactly one target profile.
///
/// Conditional export arrays are retained conservatively because more than one
/// fallback can be valid depending on file availability. Publication `files` and
/// package `imports` are intentionally not treated as runtime roots.
///
/// # Errors
///
/// Returns an error when a selected entry is absolute or escapes the package.
pub fn package_entry_roots(
    manifest: &PackageManifest,
    profile: EntryTargetProfile,
) -> Result<Vec<PackageEntryRoot>, ManifestError> {
    let mut roots = Vec::new();

    match profile {
        EntryTargetProfile::CommandLine => add_binary_roots(manifest, &mut roots)?,
        EntryTargetProfile::Types => {
            add_export_roots(manifest, &["types"], &mut roots)?;
            if roots.is_empty() {
                if let Some(types) = &manifest.types {
                    add_root(&mut roots, types, PackageEntryField::Types, "types")?;
                } else if let Some(typings) = &manifest.typings {
                    add_root(&mut roots, typings, PackageEntryField::Typings, "typings")?;
                }
            }
        }
        EntryTargetProfile::NodeImport => {
            add_export_roots(manifest, &["node", "import"], &mut roots)?;
            if roots.is_empty() {
                add_optional_root(
                    &mut roots,
                    manifest.main.as_deref(),
                    PackageEntryField::Main,
                )?;
            }
        }
        EntryTargetProfile::NodeRequire => {
            add_export_roots(manifest, &["node", "require"], &mut roots)?;
            if roots.is_empty() {
                add_optional_root(
                    &mut roots,
                    manifest.main.as_deref(),
                    PackageEntryField::Main,
                )?;
            }
        }
        EntryTargetProfile::Bundler => {
            add_export_roots(manifest, &["import", "module"], &mut roots)?;
            if roots.is_empty() {
                add_optional_root(
                    &mut roots,
                    manifest.module.as_deref(),
                    PackageEntryField::Module,
                )?;
                if roots.is_empty() {
                    add_optional_root(
                        &mut roots,
                        manifest.main.as_deref(),
                        PackageEntryField::Main,
                    )?;
                }
            }
        }
        EntryTargetProfile::Browser => {
            add_export_roots(manifest, &["browser", "import"], &mut roots)?;
            if roots.is_empty() {
                let browser = manifest.browser.as_ref().and_then(Value::as_str);
                add_optional_root(&mut roots, browser, PackageEntryField::Browser)?;
                if roots.is_empty() {
                    add_optional_root(
                        &mut roots,
                        manifest.module.as_deref(),
                        PackageEntryField::Module,
                    )?;
                }
                if roots.is_empty() {
                    add_optional_root(
                        &mut roots,
                        manifest.main.as_deref(),
                        PackageEntryField::Main,
                    )?;
                }
            }
        }
    }

    Ok(roots)
}

fn add_binary_roots(
    manifest: &PackageManifest,
    roots: &mut Vec<PackageEntryRoot>,
) -> Result<(), ManifestError> {
    match &manifest.bin {
        BinaryDeclaration::Absent => Ok(()),
        BinaryDeclaration::Single(target) => add_root(roots, target, PackageEntryField::Bin, "bin"),
        BinaryDeclaration::Named(binaries) => {
            for target in binaries.values() {
                add_root(roots, target, PackageEntryField::Bin, "bin")?;
            }
            Ok(())
        }
    }
}

fn add_export_roots(
    manifest: &PackageManifest,
    active_conditions: &[&str],
    roots: &mut Vec<PackageEntryRoot>,
) -> Result<(), ManifestError> {
    let Some(exports) = manifest.exports.as_ref().and_then(root_export_value) else {
        return Ok(());
    };
    let mut targets = Vec::new();
    collect_export_targets(exports, active_conditions, &mut targets);
    for target in targets {
        add_root(roots, target, PackageEntryField::Exports, "exports")?;
    }
    Ok(())
}

fn root_export_value(exports: &Value) -> Option<&Value> {
    let Value::Object(map) = exports else {
        return Some(exports);
    };
    if map.keys().any(|key| key.starts_with('.')) {
        map.get(".")
    } else {
        Some(exports)
    }
}

fn collect_export_targets<'a>(
    value: &'a Value,
    condition_priority: &[&str],
    targets: &mut Vec<&'a str>,
) {
    match value {
        Value::String(target) => {
            if !targets.contains(&target.as_str()) {
                targets.push(target);
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_export_targets(value, condition_priority, targets);
            }
        }
        Value::Object(conditions) => {
            let selected = condition_priority
                .iter()
                .find_map(|condition| conditions.get(*condition))
                .or_else(|| conditions.get("default"));
            if let Some(target) = selected {
                collect_export_targets(target, condition_priority, targets);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn add_optional_root(
    roots: &mut Vec<PackageEntryRoot>,
    target: Option<&str>,
    field: PackageEntryField,
) -> Result<(), ManifestError> {
    let Some(target) = target else {
        return Ok(());
    };
    let field_name = match field {
        PackageEntryField::Main => "main",
        PackageEntryField::Module => "module",
        PackageEntryField::Browser => "browser",
        PackageEntryField::Types => "types",
        PackageEntryField::Typings => "typings",
        PackageEntryField::Exports | PackageEntryField::Bin => unreachable!(),
    };
    add_root(roots, target, field, field_name)
}

fn add_root(
    roots: &mut Vec<PackageEntryRoot>,
    target: &str,
    field: PackageEntryField,
    field_name: &'static str,
) -> Result<(), ManifestError> {
    let normalized = target.strip_prefix("./").unwrap_or(target);
    let path = Path::new(normalized);
    if normalized.is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(ManifestError::UnsafeEntry {
            field: field_name,
            target: target.to_owned(),
        });
    }
    let root = PackageEntryRoot {
        path: path.to_path_buf(),
        field,
    };
    if !roots.contains(&root) {
        roots.push(root);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        EntryTargetProfile, PackageEntryField, PackageManifest, WorkspaceDeclaration,
        package_entry_roots,
    };

    #[test]
    fn accepts_npm_yarn_bun_and_legacy_workspace_shapes() {
        let array: PackageManifest =
            serde_json::from_str(r#"{"workspaces":["packages/*","!packages/fixtures/**"]}"#)
                .expect("array workspaces");
        let object: PackageManifest = serde_json::from_str(
            r#"{"workspaces":{"packages":["apps/*"],"catalog":{"react":"19"}}}"#,
        )
        .expect("object workspaces");

        assert_eq!(
            array.workspaces,
            WorkspaceDeclaration {
                patterns: vec!["packages/*".to_owned(), "!packages/fixtures/**".to_owned()]
            }
        );
        assert_eq!(object.workspaces.patterns, ["apps/*"]);
    }

    #[test]
    fn entry_fields_are_selected_per_target_profile() {
        let manifest: PackageManifest = serde_json::from_str(
            r#"{
                "main":"./dist/index.cjs",
                "module":"./dist/index.mjs",
                "browser":"./dist/browser.js",
                "types":"./dist/index.d.ts",
                "exports": {
                    ".": {
                        "types":"./dist/exported.d.ts",
                        "browser":"./dist/exported.browser.js",
                        "import":"./dist/exported.mjs",
                        "require":"./dist/exported.cjs"
                    }
                },
                "files":["src/**"]
            }"#,
        )
        .expect("manifest");

        let import =
            package_entry_roots(&manifest, EntryTargetProfile::NodeImport).expect("import roots");
        let require =
            package_entry_roots(&manifest, EntryTargetProfile::NodeRequire).expect("require roots");
        let browser =
            package_entry_roots(&manifest, EntryTargetProfile::Browser).expect("browser roots");
        let types = package_entry_roots(&manifest, EntryTargetProfile::Types).expect("type roots");

        assert_eq!(import[0].path.to_string_lossy(), "dist/exported.mjs");
        assert_eq!(require[0].path.to_string_lossy(), "dist/exported.cjs");
        assert_eq!(
            browser[0].path.to_string_lossy(),
            "dist/exported.browser.js"
        );
        assert_eq!(types[0].path.to_string_lossy(), "dist/exported.d.ts");
        assert!(
            import
                .iter()
                .all(|root| root.field == PackageEntryField::Exports)
        );
    }

    #[test]
    fn publication_files_are_not_entry_roots_and_unsafe_paths_fail() {
        let publication_only: PackageManifest =
            serde_json::from_str(r#"{"files":["src/**"]}"#).expect("manifest");
        assert!(
            package_entry_roots(&publication_only, EntryTargetProfile::NodeImport)
                .expect("entry roots")
                .is_empty()
        );

        let unsafe_manifest: PackageManifest =
            serde_json::from_str(r#"{"main":"../outside.js"}"#).expect("manifest");
        assert!(package_entry_roots(&unsafe_manifest, EntryTargetProfile::NodeImport).is_err());
    }

    #[test]
    fn conditional_export_arrays_preserve_declared_fallback_order() {
        let manifest: PackageManifest = serde_json::from_str(
            r#"{"exports":{".":["./dist/z.js","./dist/a.js","./dist/z.js"]}}"#,
        )
        .expect("manifest with fallback array");

        let roots = package_entry_roots(&manifest, EntryTargetProfile::NodeImport)
            .expect("ordered fallback roots");
        assert_eq!(
            roots
                .iter()
                .map(|root| root.path.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            ["dist/z.js", "dist/a.js"]
        );
    }
}
