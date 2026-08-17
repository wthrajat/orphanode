//! Versioned, corruption-tolerant storage for compact analysis facts.

mod digest;
mod equivalence;
mod key;
mod schema;
mod store;

pub use digest::Digest;
pub use equivalence::{
    EquivalenceReport, compare_bytes, compare_serialized, run_equivalence_probe,
};
pub use key::{
    CacheKey, CanonicalFileIdentity, ConfigDigest, ContentDigest, ContextDigest, ProfileDigest,
};
pub use schema::{CACHE_SCHEMA_VERSION, CacheSchema};
pub use store::{
    CacheCommit, CacheEntry, CacheError, CacheLimits, CacheLoadStatus, CacheSnapshot,
    PersistentCache,
};
