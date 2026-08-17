pub const DEFAULT_MAX_SOURCE_FILE_BYTES: u64 = 2 * 1024 * 1024;
pub const DEFAULT_MAX_DISCOVERED_FILES: usize = 100_000;
pub const DEFAULT_MAX_DIAGNOSTICS: usize = 1_000;
pub const DEFAULT_MAX_CONSTANT_EVALUATION_DEPTH: usize = 32;
pub const DEFAULT_MAX_STATIC_STRING_BYTES: usize = 16 * 1024;
pub const DEFAULT_MAX_PATTERN_EXPANSIONS: usize = 256;
pub const DEFAULT_MAX_PROTOCOL_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

/// Hard input and expansion limits used by one analysis request.
///
/// Limits are explicit request configuration rather than silent truncation
/// points. A stage that reaches one of these limits must emit a blocking
/// diagnostic or return an error before omitting reachability-relevant facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnalysisLimits {
    pub max_source_file_bytes: u64,
    pub max_discovered_files: usize,
    pub max_diagnostics: usize,
    pub max_constant_evaluation_depth: usize,
    pub max_static_string_bytes: usize,
    pub max_pattern_expansions: usize,
    pub max_protocol_message_bytes: usize,
}

impl Default for AnalysisLimits {
    fn default() -> Self {
        Self {
            max_source_file_bytes: DEFAULT_MAX_SOURCE_FILE_BYTES,
            max_discovered_files: DEFAULT_MAX_DISCOVERED_FILES,
            max_diagnostics: DEFAULT_MAX_DIAGNOSTICS,
            max_constant_evaluation_depth: DEFAULT_MAX_CONSTANT_EVALUATION_DEPTH,
            max_static_string_bytes: DEFAULT_MAX_STATIC_STRING_BYTES,
            max_pattern_expansions: DEFAULT_MAX_PATTERN_EXPANSIONS,
            max_protocol_message_bytes: DEFAULT_MAX_PROTOCOL_MESSAGE_BYTES,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AnalysisLimits, DEFAULT_MAX_CONSTANT_EVALUATION_DEPTH, DEFAULT_MAX_DIAGNOSTICS,
        DEFAULT_MAX_DISCOVERED_FILES, DEFAULT_MAX_PATTERN_EXPANSIONS,
        DEFAULT_MAX_PROTOCOL_MESSAGE_BYTES, DEFAULT_MAX_SOURCE_FILE_BYTES,
        DEFAULT_MAX_STATIC_STRING_BYTES,
    };

    #[test]
    fn default_limits_are_named_and_nonzero() {
        let limits = AnalysisLimits::default();

        assert_eq!(limits.max_source_file_bytes, DEFAULT_MAX_SOURCE_FILE_BYTES);
        assert_eq!(limits.max_discovered_files, DEFAULT_MAX_DISCOVERED_FILES);
        assert_eq!(limits.max_diagnostics, DEFAULT_MAX_DIAGNOSTICS);
        assert_eq!(
            limits.max_constant_evaluation_depth,
            DEFAULT_MAX_CONSTANT_EVALUATION_DEPTH
        );
        assert_eq!(
            limits.max_static_string_bytes,
            DEFAULT_MAX_STATIC_STRING_BYTES
        );
        assert_eq!(
            limits.max_pattern_expansions,
            DEFAULT_MAX_PATTERN_EXPANSIONS
        );
        assert_eq!(
            limits.max_protocol_message_bytes,
            DEFAULT_MAX_PROTOCOL_MESSAGE_BYTES
        );
        assert!(limits.max_source_file_bytes > 0);
        assert!(limits.max_diagnostics > 0);
    }
}
