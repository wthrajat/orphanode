use serde::{Deserialize, Serialize};

pub const CACHE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CacheSchema {
    pub schema_version: u32,
    pub tool_version: String,
    pub parser_compatibility_version: String,
}

impl CacheSchema {
    #[must_use]
    pub fn current(
        tool_version: impl Into<String>,
        parser_compatibility_version: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: CACHE_SCHEMA_VERSION,
            tool_version: tool_version.into(),
            parser_compatibility_version: parser_compatibility_version.into(),
        }
    }

    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != CACHE_SCHEMA_VERSION {
            return Err("cache schema version is incompatible");
        }
        if self.tool_version.is_empty() || self.tool_version.len() > 128 {
            return Err("tool version must contain between 1 and 128 bytes");
        }
        if self.parser_compatibility_version.is_empty()
            || self.parser_compatibility_version.len() > 128
        {
            return Err("parser compatibility version must contain between 1 and 128 bytes");
        }
        Ok(())
    }
}
