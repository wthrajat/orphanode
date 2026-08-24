use std::path::{Component, Path};

use serde::{Deserialize, Serialize};

use super::Digest;

macro_rules! digest_key {
    ($name:ident) => {
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub Digest);

        impl $name {
            #[must_use]
            pub fn of_bytes(bytes: &[u8]) -> Self {
                Self(Digest::of_bytes(bytes))
            }
        }
    };
}

digest_key!(ContentDigest);
digest_key!(ConfigDigest);
digest_key!(ProfileDigest);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CanonicalFileIdentity(String);

impl CanonicalFileIdentity {
    /// Creates a bounded canonical identity without parent traversal.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, oversized, NUL-containing, or traversing identities.
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        if value.is_empty() || value.len() > 16 * 1024 || value.contains('\0') {
            return Err("canonical file identity must contain between 1 and 16384 safe bytes");
        }
        if Path::new(&value)
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        {
            return Err("canonical file identity must not contain a parent traversal");
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self) -> Result<(), &'static str> {
        Self::new(self.0.clone()).map(|_| ())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContextDigest {
    pub kind: String,
    pub identity: String,
    pub digest: Digest,
}

impl ContextDigest {
    /// Creates a digest for a relevant manifest, TypeScript config, or other context.
    ///
    /// # Errors
    ///
    /// Returns an error when the context kind or identity is empty or exceeds its limit.
    pub fn new(
        kind: impl Into<String>,
        identity: impl Into<String>,
        bytes: &[u8],
    ) -> Result<Self, &'static str> {
        let value = Self {
            kind: kind.into(),
            identity: identity.into(),
            digest: Digest::of_bytes(bytes),
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), &'static str> {
        if self.kind.is_empty() || self.kind.len() > 128 || self.kind.contains('\0') {
            return Err("context kind must contain between 1 and 128 bytes");
        }
        if self.identity.is_empty()
            || self.identity.len() > 16 * 1024
            || self.identity.contains('\0')
        {
            return Err("context identity must contain between 1 and 16384 bytes");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CacheKey {
    pub config: ConfigDigest,
    pub profile: ProfileDigest,
    pub file: CanonicalFileIdentity,
    pub content: ContentDigest,
    pub contexts: Vec<ContextDigest>,
}

impl CacheKey {
    #[must_use]
    pub fn new(
        config: ConfigDigest,
        profile: ProfileDigest,
        file: CanonicalFileIdentity,
        content: ContentDigest,
        mut contexts: Vec<ContextDigest>,
    ) -> Self {
        contexts.sort();
        contexts.dedup();
        Self {
            config,
            profile,
            file,
            content,
            contexts,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        self.file.validate()?;
        if self.contexts.len() > 64 {
            return Err("cache key contains more than 64 context digests");
        }
        for context in &self.contexts {
            context.validate()?;
        }
        if !self.contexts.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err("cache-key contexts must be sorted and unique");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{CacheKey, CanonicalFileIdentity, ConfigDigest, ContentDigest, ProfileDigest};

    #[test]
    fn all_semantic_inputs_participate_in_the_key() {
        let base = CacheKey::new(
            ConfigDigest::of_bytes(b"config-a"),
            ProfileDigest::of_bytes(b"node"),
            CanonicalFileIdentity::new("src/index.ts").unwrap(),
            ContentDigest::of_bytes(b"source-a"),
            Vec::new(),
        );
        let changed_content = CacheKey::new(
            base.config,
            base.profile,
            base.file.clone(),
            ContentDigest::of_bytes(b"source-b"),
            Vec::new(),
        );
        let changed_config = CacheKey::new(
            ConfigDigest::of_bytes(b"config-b"),
            base.profile,
            base.file.clone(),
            base.content,
            Vec::new(),
        );
        let changed_profile = CacheKey::new(
            base.config,
            ProfileDigest::of_bytes(b"browser"),
            base.file.clone(),
            base.content,
            Vec::new(),
        );

        assert_ne!(base, changed_content);
        assert_ne!(base, changed_config);
        assert_ne!(base, changed_profile);
    }
}
