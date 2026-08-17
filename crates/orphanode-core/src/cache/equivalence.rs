use serde::Serialize;

use super::Digest;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EquivalenceReport {
    pub byte_identical: bool,
    pub clean_digest: Digest,
    pub cached_digest: Digest,
    pub first_difference: Option<usize>,
}

#[must_use]
pub fn compare_bytes(clean: &[u8], cached: &[u8]) -> EquivalenceReport {
    let first_difference = clean
        .iter()
        .zip(cached)
        .position(|(clean_byte, cached_byte)| clean_byte != cached_byte)
        .or_else(|| (clean.len() != cached.len()).then(|| clean.len().min(cached.len())));

    EquivalenceReport {
        byte_identical: first_difference.is_none(),
        clean_digest: Digest::of_bytes(clean),
        cached_digest: Digest::of_bytes(cached),
        first_difference,
    }
}

/// Serializes two results with the same deterministic serializer and compares them.
///
/// # Errors
///
/// Returns a JSON serialization error when either value cannot be serialized.
pub fn compare_serialized<T: Serialize>(
    clean: &T,
    cached: &T,
) -> Result<EquivalenceReport, serde_json::Error> {
    let clean_bytes = serde_json::to_vec(clean)?;
    let cached_bytes = serde_json::to_vec(cached)?;
    Ok(compare_bytes(&clean_bytes, &cached_bytes))
}

/// Runs clean and cached scan hooks and compares their canonical output bytes.
///
/// # Errors
///
/// Returns the first error produced by either scan hook.
pub fn run_equivalence_probe<E>(
    clean_scan: impl FnOnce() -> Result<Vec<u8>, E>,
    cached_scan: impl FnOnce() -> Result<Vec<u8>, E>,
) -> Result<EquivalenceReport, E> {
    let clean = clean_scan()?;
    let cached = cached_scan()?;
    Ok(compare_bytes(&clean, &cached))
}

#[cfg(test)]
mod tests {
    use super::{compare_bytes, run_equivalence_probe};

    #[test]
    fn reports_byte_identical_runs() {
        let report = run_equivalence_probe::<std::convert::Infallible>(
            || Ok(br#"{"status":"complete"}"#.to_vec()),
            || Ok(br#"{"status":"complete"}"#.to_vec()),
        )
        .unwrap();

        assert!(report.byte_identical);
        assert_eq!(report.clean_digest, report.cached_digest);
    }

    #[test]
    fn identifies_the_first_difference() {
        let report = compare_bytes(b"abcdef", b"abcxef");

        assert!(!report.byte_identical);
        assert_eq!(report.first_difference, Some(3));
    }
}
