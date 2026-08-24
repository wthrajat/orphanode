use serde::Serialize;

use crate::cache::ContentDigest;

use super::ProjectPath;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageManager {
    Npm,
    Pnpm,
    Yarn,
    Bun,
}

impl PackageManager {
    #[must_use]
    pub const fn executable(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Pnpm => "pnpm",
            Self::Yarn => "yarn",
            Self::Bun => "bun",
        }
    }

    #[must_use]
    pub const fn remove_subcommand(self) -> &'static str {
        match self {
            Self::Npm => "uninstall",
            Self::Pnpm | Self::Yarn | Self::Bun => "remove",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyKind {
    Production,
    Development,
    Optional,
    Peer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectDependency {
    pub name: String,
    pub kind: DependencyKind,
}

impl DirectDependency {
    /// Creates a direct dependency selected for removal.
    ///
    /// # Errors
    ///
    /// Returns an error when the name could be interpreted as an option or invalid package name.
    pub fn new(name: impl Into<String>, kind: DependencyKind) -> Result<Self, &'static str> {
        let name = name.into();
        if !valid_package_name(&name) {
            return Err("dependency name is not a safe npm package name");
        }
        Ok(Self { name, kind })
    }

    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if valid_package_name(&self.name) {
            Ok(())
        } else {
            Err("dependency name is not a safe npm package name")
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DependencyRemoval {
    pub dependency: DirectDependency,
    pub reason: String,
}

impl DependencyRemoval {
    /// Describes one dependency change and the evidence-backed reason shown in previews.
    ///
    /// # Errors
    ///
    /// Returns an error when the reason is empty, unbounded, or unsafe to display.
    pub fn new(
        dependency: DirectDependency,
        reason: impl Into<String>,
    ) -> Result<Self, &'static str> {
        let removal = Self {
            dependency,
            reason: reason.into(),
        };
        removal.validate()?;
        Ok(removal)
    }

    fn validate(&self) -> Result<(), &'static str> {
        self.dependency.validate()?;
        validate_reason(&self.reason)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageManagerCommand {
    pub manager: PackageManager,
    pub working_directory: ProjectPath,
    pub manifest_path: ProjectPath,
    pub analyzed_manifest_content: ContentDigest,
    pub removals: Vec<DependencyRemoval>,
    pub program: String,
    pub arguments: Vec<String>,
}

impl PackageManagerCommand {
    /// Builds one package-manager invocation for all selected removals in a workspace.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty or duplicate removal set.
    pub fn remove_direct_dependencies(
        manager: PackageManager,
        working_directory: ProjectPath,
        analyzed_manifest_content: ContentDigest,
        mut removals: Vec<DependencyRemoval>,
    ) -> Result<Self, &'static str> {
        removals.sort_by(|left, right| left.dependency.name.cmp(&right.dependency.name));
        if removals.is_empty() {
            return Err("package-manager removal must contain at least one dependency");
        }
        if removals
            .windows(2)
            .any(|pair| pair[0].dependency.name == pair[1].dependency.name)
        {
            return Err("package-manager removal contains a duplicate dependency");
        }
        let manifest_path = workspace_manifest_path(&working_directory);
        let mut arguments = Vec::with_capacity(removals.len() + 1);
        arguments.push(manager.remove_subcommand().to_owned());
        arguments.extend(
            removals
                .iter()
                .map(|removal| removal.dependency.name.clone()),
        );
        let command = Self {
            manager,
            working_directory,
            manifest_path,
            analyzed_manifest_content,
            removals,
            program: manager.executable().to_owned(),
            arguments,
        };
        command.validate()?;
        Ok(command)
    }

    /// Builds a package-manager invocation for one selected dependency.
    ///
    /// # Errors
    ///
    /// Returns an error when the reason is invalid.
    pub fn remove_direct_dependency(
        manager: PackageManager,
        working_directory: ProjectPath,
        analyzed_manifest_content: ContentDigest,
        dependency: DirectDependency,
        reason: impl Into<String>,
    ) -> Result<Self, &'static str> {
        Self::remove_direct_dependencies(
            manager,
            working_directory,
            analyzed_manifest_content,
            vec![DependencyRemoval::new(dependency, reason)?],
        )
    }

    #[must_use]
    pub fn display_command(&self) -> String {
        let mut command = self.program.clone();
        for argument in &self.arguments {
            command.push(' ');
            command.push_str(argument);
        }
        command
    }

    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if self.removals.is_empty() {
            return Err("package-manager removal must contain at least one dependency");
        }
        for removal in &self.removals {
            removal.validate()?;
        }
        if self
            .removals
            .windows(2)
            .any(|pair| pair[0].dependency.name >= pair[1].dependency.name)
        {
            return Err("package-manager dependencies must be unique and sorted");
        }
        if self.manifest_path != workspace_manifest_path(&self.working_directory) {
            return Err("package-manager command does not target its exact workspace manifest");
        }
        let expected_arguments = std::iter::once(self.manager.remove_subcommand()).chain(
            self.removals
                .iter()
                .map(|removal| removal.dependency.name.as_str()),
        );
        if self.program != self.manager.executable()
            || self
                .arguments
                .iter()
                .map(String::as_str)
                .ne(expected_arguments)
        {
            return Err("package-manager command does not match its typed removal operation");
        }
        Ok(())
    }
}

fn workspace_manifest_path(working_directory: &ProjectPath) -> ProjectPath {
    let path = if working_directory.as_str() == "." {
        "package.json".to_owned()
    } else {
        format!("{}/package.json", working_directory.as_str())
    };
    ProjectPath::new(path).expect("a package manifest below a validated workspace is safe")
}

fn validate_reason(reason: &str) -> Result<(), &'static str> {
    if reason.trim().is_empty() || reason.len() > 4096 || reason.chars().any(char::is_control) {
        Err("fix reason must be nonempty, bounded, and safe to display")
    } else {
        Ok(())
    }
}

fn valid_package_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 214
        && !name.starts_with('-')
        && !name.contains("..")
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'@' | b'/' | b'-' | b'_' | b'.')
        })
}

#[cfg(test)]
mod tests {
    use super::{
        DependencyKind, DependencyRemoval, DirectDependency, PackageManager, PackageManagerCommand,
    };
    use crate::{cache::ContentDigest, fixes::ProjectPath};

    #[test]
    fn plans_a_package_manager_removal_in_the_exact_workspace() {
        let command = PackageManagerCommand::remove_direct_dependency(
            PackageManager::Pnpm,
            ProjectPath::new("packages/app").unwrap(),
            ContentDigest::of_bytes(b"{\"name\":\"app\"}"),
            DirectDependency::new("@scope/unused", DependencyKind::Development).unwrap(),
            "No reachable runtime or tool reference retains this dependency",
        )
        .unwrap();

        assert_eq!(command.working_directory.as_str(), "packages/app");
        assert_eq!(command.manifest_path.as_str(), "packages/app/package.json");
        assert_eq!(command.display_command(), "pnpm remove @scope/unused");
        assert_eq!(
            command.removals[0].reason,
            "No reachable runtime or tool reference retains this dependency"
        );
    }

    #[test]
    fn rejects_option_injection_as_a_package_name() {
        assert!(DirectDependency::new("--filter", DependencyKind::Production).is_err());
    }

    #[test]
    fn groups_workspace_removals_into_one_deterministic_command() {
        let command = PackageManagerCommand::remove_direct_dependencies(
            PackageManager::Npm,
            ProjectPath::root(),
            ContentDigest::of_bytes(b"{}"),
            vec![
                DependencyRemoval::new(
                    DirectDependency::new("zeta", DependencyKind::Production).unwrap(),
                    "zeta is unused",
                )
                .unwrap(),
                DependencyRemoval::new(
                    DirectDependency::new("alpha", DependencyKind::Development).unwrap(),
                    "alpha is unused",
                )
                .unwrap(),
            ],
        )
        .unwrap();

        assert_eq!(command.display_command(), "npm uninstall alpha zeta");
        assert_eq!(command.removals[0].reason, "alpha is unused");
        assert_eq!(command.removals[1].reason, "zeta is unused");
    }
}
