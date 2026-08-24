use std::collections::BTreeMap;

use serde::Serialize;

macro_rules! dense_id {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(pub u32);

        impl $name {
            #[must_use]
            pub const fn index(self) -> usize {
                self.0 as usize
            }
        }
    };
}

dense_id!(WorkspaceId);
dense_id!(ModuleId);
dense_id!(ExecutionRegionId);
dense_id!(SymbolId);
dense_id!(MemberId);
dense_id!(PackageId);
dense_id!(ManifestDeclarationId);
dense_id!(TargetProfileId);
dense_id!(EvidenceId);
dense_id!(InternedStringId);

/// Deterministic shared storage for repeated paths, specifiers, and names.
#[derive(Debug, Default, Clone)]
pub struct StringInterner {
    values: Vec<String>,
    ids_by_value: BTreeMap<String, InternedStringId>,
}

impl StringInterner {
    /// Interns a string and returns its stable identifier.
    ///
    /// # Panics
    ///
    /// Panics if the interner contains more strings than can be represented by
    /// an [`InternedStringId`].
    #[must_use]
    pub fn intern(&mut self, value: impl Into<String>) -> InternedStringId {
        let value = value.into();
        if let Some(id) = self.ids_by_value.get(&value) {
            return *id;
        }

        let id = InternedStringId(
            u32::try_from(self.values.len()).expect("string interner exceeded u32 capacity"),
        );
        self.values.push(value.clone());
        self.ids_by_value.insert(value, id);
        id
    }

    #[must_use]
    pub fn get(&self, id: InternedStringId) -> Option<&str> {
        self.values.get(id.index()).map(String::as_str)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::StringInterner;

    #[test]
    fn interning_is_stable_and_deduplicated() {
        let mut interner = StringInterner::default();
        let first = interner.intern("src/index.ts");
        let second = interner.intern("chalk");
        let duplicate = interner.intern("src/index.ts");

        assert_eq!(first, duplicate);
        assert_ne!(first, second);
        assert_eq!(interner.get(first), Some("src/index.ts"));
        assert_eq!(interner.len(), 2);
    }
}
