use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::contract::{
    DECLARATIVE_PLUGIN_API_VERSION, DeclarativePlugin, DetectionRules, PatternContribution,
    PluginCapability, PluginContributions, PluginValidationError, ReferenceContribution,
    ReferenceKind, UnsupportedCase, validate_reference_name, validate_workspace_pattern,
};

const BUILTIN_PLUGIN_VERSION: &str = "1.0.0";

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BuiltinDetectionInput {
    pub package_names: BTreeSet<String>,
    pub config_files: BTreeSet<String>,
}

impl BuiltinDetectionInput {
    fn validate(&self) -> Result<(), PluginValidationError> {
        for package in &self.package_names {
            validate_reference_name("detectionInput.packageNames", package)?;
        }
        for config_file in &self.config_files {
            validate_workspace_pattern(config_file)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionEvidenceKind {
    Package,
    ConfigFile,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DetectionEvidence {
    pub kind: DetectionEvidenceKind,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedBuiltinPlugin {
    pub plugin: DeclarativePlugin,
    pub evidence: Vec<DetectionEvidence>,
}

#[must_use]
pub fn builtin_plugins() -> Vec<DeclarativePlugin> {
    let mut plugins = vec![
        build_plugin(astro()),
        build_plugin(babel()),
        build_plugin(eslint()),
        build_plugin(jest()),
        build_plugin(next()),
        build_plugin(nuxt()),
        build_plugin(postcss()),
        build_plugin(storybook()),
        build_plugin(sveltekit()),
        build_plugin(typescript_config()),
        build_plugin(vite()),
        build_plugin(vitest()),
    ];
    plugins.sort_by(|left, right| left.id.cmp(&right.id));
    plugins
}

/// Detects built-in plugins from already-normalized package and config facts.
///
/// # Errors
///
/// Returns an error when an input path/package or a built-in contract fails
/// validation. Detection never executes configuration or reads package code.
pub fn detect_builtin_plugins(
    input: &BuiltinDetectionInput,
) -> Result<Vec<DetectedBuiltinPlugin>, PluginValidationError> {
    input.validate()?;
    let mut detected = Vec::new();
    for mut plugin in builtin_plugins() {
        plugin.validate()?;
        let mut evidence = detection_evidence(&plugin.detection, input);
        if !evidence.is_empty() {
            evidence.sort();
            evidence.dedup();
            add_detected_package_references(&mut plugin, &evidence);
            plugin.canonicalize();
            plugin.validate()?;
            detected.push(DetectedBuiltinPlugin { plugin, evidence });
        }
    }
    Ok(detected)
}

fn add_detected_package_references(plugin: &mut DeclarativePlugin, evidence: &[DetectionEvidence]) {
    let reason = format!("Detected {} package", plugin.display_name);
    plugin.contributions.references.extend(
        evidence
            .iter()
            .filter(|item| item.kind == DetectionEvidenceKind::Package)
            .map(|item| ReferenceContribution {
                name: item.value.clone(),
                kind: ReferenceKind::Package,
                reason: reason.clone(),
            }),
    );
    if !plugin.contributions.references.is_empty() {
        plugin.capabilities.push(PluginCapability::References);
    }
}

fn detection_evidence(
    rules: &DetectionRules,
    input: &BuiltinDetectionInput,
) -> Vec<DetectionEvidence> {
    let package_evidence = input.package_names.iter().filter(|package| {
        rules.package_names.binary_search(package).is_ok()
            || rules
                .package_prefixes
                .iter()
                .any(|prefix| package.starts_with(prefix))
    });
    let config_evidence = input.config_files.iter().filter(|path| {
        rules
            .config_files
            .iter()
            .any(|pattern| wildcard_matches(pattern, path))
    });

    package_evidence
        .map(|package| DetectionEvidence {
            kind: DetectionEvidenceKind::Package,
            value: package.clone(),
        })
        .chain(config_evidence.map(|path| DetectionEvidence {
            kind: DetectionEvidenceKind::ConfigFile,
            value: path.clone(),
        }))
        .collect()
}

fn wildcard_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.chars().collect::<Vec<_>>();
    let value = value.chars().collect::<Vec<_>>();
    let mut previous = vec![false; value.len() + 1];
    previous[0] = true;

    for token in pattern {
        let mut current = vec![false; value.len() + 1];
        if token == '*' {
            current[0] = previous[0];
        }
        for (index, character) in value.iter().enumerate() {
            current[index + 1] = match token {
                '*' => previous[index + 1] || current[index],
                '?' => previous[index],
                literal => literal == *character && previous[index],
            };
        }
        previous = current;
    }
    previous[value.len()]
}

#[derive(Clone, Copy)]
struct BuiltinSpec {
    id: &'static str,
    display_name: &'static str,
    packages: &'static [&'static str],
    package_prefixes: &'static [&'static str],
    configs: &'static [&'static str],
    entries: &'static [&'static str],
    project_files: &'static [&'static str],
    target_conditions: &'static [&'static str],
    unsupported_code: &'static str,
    unsupported_summary: &'static str,
}

fn build_plugin(spec: BuiltinSpec) -> DeclarativePlugin {
    let reason = format!("{} static convention", spec.display_name);
    let mut plugin = DeclarativePlugin {
        schema: None,
        api_version: DECLARATIVE_PLUGIN_API_VERSION.to_owned(),
        id: spec.id.to_owned(),
        version: BUILTIN_PLUGIN_VERSION.to_owned(),
        display_name: spec.display_name.to_owned(),
        capabilities: Vec::new(),
        detection: DetectionRules {
            package_names: owned(spec.packages),
            package_prefixes: owned(spec.package_prefixes),
            config_files: owned(spec.configs),
        },
        contributions: PluginContributions {
            entry_patterns: contributions(spec.entries, &reason),
            project_file_patterns: contributions(spec.project_files, &reason),
            config_file_patterns: contributions(spec.configs, &reason),
            target_conditions: owned(spec.target_conditions),
            ..PluginContributions::default()
        },
        unsupported_cases: vec![UnsupportedCase {
            code: spec.unsupported_code.to_owned(),
            summary: spec.unsupported_summary.to_owned(),
            blocks_reachability: true,
        }],
    };
    plugin.capabilities = capabilities_for(&plugin.contributions);
    plugin.canonicalize();
    debug_assert!(plugin.validate().is_ok());
    plugin
}

fn capabilities_for(contributions: &PluginContributions) -> Vec<PluginCapability> {
    let mut capabilities = vec![PluginCapability::Diagnostics];
    if !contributions.entry_patterns.is_empty() {
        capabilities.push(PluginCapability::Entries);
    }
    if !contributions.project_file_patterns.is_empty() {
        capabilities.push(PluginCapability::ProjectFiles);
    }
    if !contributions.config_file_patterns.is_empty() {
        capabilities.push(PluginCapability::ConfigFiles);
    }
    if !contributions.references.is_empty() {
        capabilities.push(PluginCapability::References);
    }
    if !contributions.target_conditions.is_empty() {
        capabilities.push(PluginCapability::TargetConditions);
    }
    capabilities
}

fn contributions(patterns: &[&str], reason: &str) -> Vec<PatternContribution> {
    patterns
        .iter()
        .map(|pattern| PatternContribution {
            pattern: (*pattern).to_owned(),
            reason: reason.to_owned(),
        })
        .collect()
}

fn owned(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn astro() -> BuiltinSpec {
    BuiltinSpec {
        id: "astro",
        display_name: "Astro",
        packages: &["astro"],
        package_prefixes: &[],
        configs: &[
            "astro.config.cjs",
            "astro.config.cts",
            "astro.config.js",
            "astro.config.mjs",
            "astro.config.mts",
            "astro.config.ts",
        ],
        entries: &["src/middleware.*", "src/pages/**/*.*"],
        project_files: &["src/content.config.*", "src/content/**/*.*"],
        target_conditions: &["browser", "node"],
        unsupported_code: "plugin_astro_embedded_code",
        unsupported_summary: "Astro component scripts and dynamic integrations require embedded-code extraction",
    }
}

fn babel() -> BuiltinSpec {
    BuiltinSpec {
        id: "babel",
        display_name: "Babel",
        packages: &["@babel/core"],
        package_prefixes: &[],
        configs: &[
            ".babelrc",
            ".babelrc.cjs",
            ".babelrc.js",
            ".babelrc.json",
            "babel.config.cjs",
            "babel.config.cts",
            "babel.config.js",
            "babel.config.mjs",
            "babel.config.mts",
            "babel.config.ts",
        ],
        entries: &[],
        project_files: &[],
        target_conditions: &[],
        unsupported_code: "plugin_babel_dynamic_config",
        unsupported_summary: "Executable Babel configuration and computed plugin names are not evaluated",
    }
}

fn eslint() -> BuiltinSpec {
    BuiltinSpec {
        id: "eslint",
        display_name: "ESLint",
        packages: &["eslint"],
        package_prefixes: &[],
        configs: &[
            ".eslintrc",
            ".eslintrc.cjs",
            ".eslintrc.js",
            ".eslintrc.json",
            ".eslintrc.yaml",
            ".eslintrc.yml",
            "eslint.config.cjs",
            "eslint.config.cts",
            "eslint.config.js",
            "eslint.config.mjs",
            "eslint.config.mts",
            "eslint.config.ts",
        ],
        entries: &[],
        project_files: &[],
        target_conditions: &["node"],
        unsupported_code: "plugin_eslint_dynamic_config",
        unsupported_summary: "Executable ESLint configuration and computed plugin references are not evaluated",
    }
}

fn jest() -> BuiltinSpec {
    BuiltinSpec {
        id: "jest",
        display_name: "Jest",
        packages: &["@jest/core", "jest"],
        package_prefixes: &[],
        configs: &[
            "jest.config.cjs",
            "jest.config.cts",
            "jest.config.js",
            "jest.config.json",
            "jest.config.mjs",
            "jest.config.mts",
            "jest.config.ts",
        ],
        entries: &[
            "**/*.spec.*",
            "**/*.test.*",
            "**/__tests__/**/*.*",
            "test/**/*.*",
            "tests/**/*.*",
        ],
        project_files: &[],
        target_conditions: &["node", "test"],
        unsupported_code: "plugin_jest_dynamic_config",
        unsupported_summary: "Executable Jest configuration and custom resolver behavior are not evaluated",
    }
}

fn next() -> BuiltinSpec {
    BuiltinSpec {
        id: "next",
        display_name: "Next.js",
        packages: &["next"],
        package_prefixes: &[],
        configs: &[
            "next.config.cjs",
            "next.config.js",
            "next.config.mjs",
            "next.config.ts",
        ],
        entries: &[
            "app/**/default.*",
            "app/**/error.*",
            "app/**/global-error.*",
            "app/**/layout.*",
            "app/**/loading.*",
            "app/**/not-found.*",
            "app/**/page.*",
            "app/**/route.*",
            "app/**/template.*",
            "instrumentation.*",
            "middleware.*",
            "pages/**/*.*",
        ],
        project_files: &["next-env.d.ts"],
        target_conditions: &["browser", "node", "react-server"],
        unsupported_code: "plugin_next_dynamic_config",
        unsupported_summary: "Dynamic Next.js configuration and generated route manifests are not evaluated",
    }
}

fn nuxt() -> BuiltinSpec {
    BuiltinSpec {
        id: "nuxt",
        display_name: "Nuxt",
        packages: &["nuxt"],
        package_prefixes: &[],
        configs: &["nuxt.config.js", "nuxt.config.mjs", "nuxt.config.ts"],
        entries: &[
            "app.vue",
            "error.vue",
            "layouts/**/*.vue",
            "middleware/**/*.*",
            "modules/**/*.*",
            "pages/**/*.vue",
            "plugins/**/*.*",
            "server/api/**/*.*",
            "server/middleware/**/*.*",
            "server/plugins/**/*.*",
            "server/routes/**/*.*",
        ],
        project_files: &["app.config.*"],
        target_conditions: &["browser", "node"],
        unsupported_code: "plugin_nuxt_embedded_code",
        unsupported_summary: "Vue embedded scripts, dynamic modules, and generated Nuxt manifests require deeper modeling",
    }
}

fn postcss() -> BuiltinSpec {
    BuiltinSpec {
        id: "postcss",
        display_name: "PostCSS",
        packages: &["postcss"],
        package_prefixes: &[],
        configs: &[
            ".postcssrc",
            ".postcssrc.cjs",
            ".postcssrc.js",
            ".postcssrc.json",
            ".postcssrc.yaml",
            ".postcssrc.yml",
            "postcss.config.cjs",
            "postcss.config.cts",
            "postcss.config.js",
            "postcss.config.mjs",
            "postcss.config.mts",
            "postcss.config.ts",
        ],
        entries: &[],
        project_files: &[],
        target_conditions: &[],
        unsupported_code: "plugin_postcss_dynamic_config",
        unsupported_summary: "Executable PostCSS configuration and computed plugin names are not evaluated",
    }
}

fn storybook() -> BuiltinSpec {
    BuiltinSpec {
        id: "storybook",
        display_name: "Storybook",
        packages: &["storybook"],
        package_prefixes: &["@storybook/"],
        configs: &[
            ".storybook/main.cjs",
            ".storybook/main.js",
            ".storybook/main.mjs",
            ".storybook/main.ts",
        ],
        entries: &[
            ".storybook/manager.*",
            ".storybook/preview.*",
            ".storybook/test-runner.*",
            "**/*.stories.*",
        ],
        project_files: &["**/*.mdx"],
        target_conditions: &["browser", "development"],
        unsupported_code: "plugin_storybook_dynamic_stories",
        unsupported_summary: "Computed story globs, framework presets, and MDX imports require deeper modeling",
    }
}

fn sveltekit() -> BuiltinSpec {
    BuiltinSpec {
        id: "sveltekit",
        display_name: "SvelteKit",
        packages: &["@sveltejs/kit"],
        package_prefixes: &[],
        configs: &["svelte.config.cjs", "svelte.config.js", "svelte.config.mjs"],
        entries: &[
            "src/hooks.*",
            "src/params/**/*.*",
            "src/routes/**/+error.*",
            "src/routes/**/+layout.*",
            "src/routes/**/+page.*",
            "src/routes/**/+server.*",
            "src/service-worker.*",
        ],
        project_files: &["src/app.d.ts", "src/app.html"],
        target_conditions: &["browser", "node"],
        unsupported_code: "plugin_sveltekit_embedded_code",
        unsupported_summary: "Svelte embedded scripts and generated route nodes require deeper modeling",
    }
}

fn typescript_config() -> BuiltinSpec {
    BuiltinSpec {
        id: "typescript-config",
        display_name: "TypeScript project configuration",
        packages: &["typescript"],
        package_prefixes: &[],
        configs: &[
            "jsconfig.*.json",
            "jsconfig.json",
            "tsconfig.*.json",
            "tsconfig.json",
        ],
        entries: &[],
        project_files: &[],
        target_conditions: &[],
        unsupported_code: "plugin_typescript_dynamic_extends",
        unsupported_summary: "Package-based extends, project references, and include expansion require config graph modeling",
    }
}

fn vite() -> BuiltinSpec {
    BuiltinSpec {
        id: "vite",
        display_name: "Vite",
        packages: &["vite"],
        package_prefixes: &[],
        configs: &[
            "vite.config.cjs",
            "vite.config.cts",
            "vite.config.js",
            "vite.config.mjs",
            "vite.config.mts",
            "vite.config.ts",
        ],
        entries: &[],
        project_files: &["index.html"],
        target_conditions: &["browser", "development", "module"],
        unsupported_code: "plugin_vite_html_entries",
        unsupported_summary: "HTML module-script roots and executable Vite configuration require static config extraction",
    }
}

fn vitest() -> BuiltinSpec {
    BuiltinSpec {
        id: "vitest",
        display_name: "Vitest",
        packages: &["vitest"],
        package_prefixes: &[],
        configs: &[
            "vitest.config.cjs",
            "vitest.config.cts",
            "vitest.config.js",
            "vitest.config.mjs",
            "vitest.config.mts",
            "vitest.config.ts",
            "vitest.workspace.js",
            "vitest.workspace.ts",
        ],
        entries: &["**/*.spec.*", "**/*.test.*", "test/**/*.*", "tests/**/*.*"],
        project_files: &[],
        target_conditions: &["development", "node", "test"],
        unsupported_code: "plugin_vitest_dynamic_config",
        unsupported_summary: "Executable Vitest workspace/config callbacks and custom pools are not evaluated",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{BuiltinDetectionInput, builtin_plugins, detect_builtin_plugins, wildcard_matches};

    #[test]
    fn registry_contains_every_initial_builtin_in_stable_order() {
        let plugins = builtin_plugins();
        let ids = plugins
            .iter()
            .map(|plugin| plugin.id.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            ids,
            [
                "astro",
                "babel",
                "eslint",
                "jest",
                "next",
                "nuxt",
                "postcss",
                "storybook",
                "sveltekit",
                "typescript-config",
                "vite",
                "vitest",
            ]
        );
        assert!(plugins.iter().all(|plugin| plugin.validate().is_ok()));
        assert!(plugins.iter().all(|plugin| {
            plugin
                .unsupported_cases
                .iter()
                .all(|unsupported| unsupported.blocks_reachability)
        }));
    }

    #[test]
    fn every_builtin_has_versioned_positive_negative_and_gap_coverage() {
        for plugin in builtin_plugins() {
            assert_eq!(plugin.version, "1.0.0", "{} version", plugin.id);
            assert!(
                !plugin.unsupported_cases.is_empty(),
                "{} must document a conservative gap",
                plugin.id
            );

            let package = plugin
                .detection
                .package_names
                .first()
                .expect("every initial built-in has package evidence")
                .clone();
            let package_detection = detect_builtin_plugins(&BuiltinDetectionInput {
                package_names: BTreeSet::from([package]),
                config_files: BTreeSet::new(),
            })
            .expect("detect built-in from package evidence");
            assert!(
                package_detection
                    .iter()
                    .any(|detected| detected.plugin.id == plugin.id),
                "{} package evidence must activate it",
                plugin.id
            );

            let config_pattern = plugin
                .detection
                .config_files
                .first()
                .expect("every initial built-in has config evidence");
            let config_file = config_pattern.replace('*', "build").replace('?', "x");
            let config_detection = detect_builtin_plugins(&BuiltinDetectionInput {
                package_names: BTreeSet::new(),
                config_files: BTreeSet::from([config_file]),
            })
            .expect("detect built-in from config evidence");
            assert!(
                config_detection
                    .iter()
                    .any(|detected| detected.plugin.id == plugin.id),
                "{} config evidence must activate it",
                plugin.id
            );
        }

        let unrelated = detect_builtin_plugins(&BuiltinDetectionInput {
            package_names: BTreeSet::from(["not-a-supported-plugin".to_owned()]),
            config_files: BTreeSet::from(["unrelated.config.js".to_owned()]),
        })
        .expect("validate negative built-in evidence");
        assert!(unrelated.is_empty());
    }

    #[test]
    fn detection_uses_package_config_and_package_prefix_evidence() {
        let input = BuiltinDetectionInput {
            package_names: BTreeSet::from(["@storybook/react-vite".to_owned(), "next".to_owned()]),
            config_files: BTreeSet::from([
                "eslint.config.mjs".to_owned(),
                "tsconfig.build.json".to_owned(),
            ]),
        };

        let detected = detect_builtin_plugins(&input).expect("detect builtins");
        let ids = detected
            .iter()
            .map(|item| item.plugin.id.as_str())
            .collect::<Vec<_>>();

        assert_eq!(ids, ["eslint", "next", "storybook", "typescript-config"]);
        assert!(detected.iter().all(|item| !item.evidence.is_empty()));
        let storybook = detected
            .iter()
            .find(|item| item.plugin.id == "storybook")
            .expect("storybook detection");
        assert_eq!(
            storybook
                .plugin
                .contributions
                .references
                .iter()
                .map(|reference| reference.name.as_str())
                .collect::<Vec<_>>(),
            ["@storybook/react-vite"]
        );
    }

    #[test]
    fn unrelated_packages_do_not_activate_a_plugin() {
        let input = BuiltinDetectionInput {
            package_names: BTreeSet::from(["react".to_owned()]),
            config_files: BTreeSet::new(),
        };

        assert!(
            detect_builtin_plugins(&input)
                .expect("valid input")
                .is_empty()
        );
    }

    #[test]
    fn config_detection_supports_bounded_star_and_question_wildcards() {
        assert!(wildcard_matches("tsconfig.*.json", "tsconfig.build.json"));
        assert!(wildcard_matches("config.??", "config.ts"));
        assert!(!wildcard_matches("tsconfig.*.json", "tsconfig.json"));
    }
}
