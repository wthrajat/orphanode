use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorldMode {
    Open,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetProfile {
    pub name: String,
    pub conditions: BTreeSet<String>,
    pub world: WorldMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetProfileDefinition {
    pub extends: Option<String>,
    pub conditions: BTreeSet<String>,
    pub world: Option<WorldMode>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TargetProfileError {
    #[error("target profile `{0}` extends an unknown profile")]
    UnknownParent(String),
    #[error("target profile inheritance contains a cycle through `{0}`")]
    Cycle(String),
}

/// Resolves target inheritance into deterministic, fully populated profiles.
///
/// # Errors
///
/// Returns [`TargetProfileError::UnknownParent`] when a profile extends an
/// undefined profile, or [`TargetProfileError::Cycle`] when inheritance is
/// cyclic.
pub fn resolve_target_profiles(
    definitions: &BTreeMap<String, TargetProfileDefinition>,
    default_world: WorldMode,
) -> Result<Vec<TargetProfile>, TargetProfileError> {
    let mut resolved = BTreeMap::new();
    for name in definitions.keys() {
        resolve_profile(
            name,
            definitions,
            default_world,
            &mut BTreeSet::new(),
            &mut resolved,
        )?;
    }
    Ok(resolved.into_values().collect())
}

fn resolve_profile(
    name: &str,
    definitions: &BTreeMap<String, TargetProfileDefinition>,
    default_world: WorldMode,
    visiting: &mut BTreeSet<String>,
    resolved: &mut BTreeMap<String, TargetProfile>,
) -> Result<TargetProfile, TargetProfileError> {
    if let Some(profile) = resolved.get(name) {
        return Ok(profile.clone());
    }
    if !visiting.insert(name.to_owned()) {
        return Err(TargetProfileError::Cycle(name.to_owned()));
    }
    let definition = definitions
        .get(name)
        .ok_or_else(|| TargetProfileError::UnknownParent(name.to_owned()))?;
    let mut conditions = BTreeSet::new();
    let mut world = default_world;
    if let Some(parent_name) = &definition.extends {
        if !definitions.contains_key(parent_name) {
            return Err(TargetProfileError::UnknownParent(parent_name.clone()));
        }
        let parent = resolve_profile(parent_name, definitions, default_world, visiting, resolved)?;
        conditions = parent.conditions;
        world = parent.world;
    }
    conditions.extend(definition.conditions.iter().cloned());
    world = definition.world.unwrap_or(world);
    visiting.remove(name);

    let profile = TargetProfile {
        name: name.to_owned(),
        conditions,
        world,
    };
    resolved.insert(name.to_owned(), profile.clone());
    Ok(profile)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::{TargetProfileDefinition, TargetProfileError, WorldMode, resolve_target_profiles};

    #[test]
    fn profiles_inherit_conditions_and_can_override_world_mode() {
        let definitions = BTreeMap::from([
            (
                "node".to_owned(),
                TargetProfileDefinition {
                    extends: None,
                    conditions: BTreeSet::from(["node".to_owned(), "import".to_owned()]),
                    world: None,
                },
            ),
            (
                "test".to_owned(),
                TargetProfileDefinition {
                    extends: Some("node".to_owned()),
                    conditions: BTreeSet::from(["development".to_owned()]),
                    world: Some(WorldMode::Closed),
                },
            ),
        ]);

        let profiles =
            resolve_target_profiles(&definitions, WorldMode::Open).expect("resolve profiles");
        let test = profiles
            .iter()
            .find(|profile| profile.name == "test")
            .expect("test profile");
        assert_eq!(
            test.conditions,
            BTreeSet::from([
                "development".to_owned(),
                "import".to_owned(),
                "node".to_owned()
            ])
        );
        assert_eq!(test.world, WorldMode::Closed);
    }

    #[test]
    fn profile_cycles_are_visible() {
        let definitions = BTreeMap::from([
            (
                "a".to_owned(),
                TargetProfileDefinition {
                    extends: Some("b".to_owned()),
                    conditions: BTreeSet::new(),
                    world: None,
                },
            ),
            (
                "b".to_owned(),
                TargetProfileDefinition {
                    extends: Some("a".to_owned()),
                    conditions: BTreeSet::new(),
                    world: None,
                },
            ),
        ]);

        assert!(matches!(
            resolve_target_profiles(&definitions, WorldMode::Closed),
            Err(TargetProfileError::Cycle(_))
        ));
    }
}
