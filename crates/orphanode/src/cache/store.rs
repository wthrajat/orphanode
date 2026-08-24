use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{CacheKey, CacheSchema, Digest};

const GENERATIONS_DIRECTORY: &str = "generations";
const ACTIVE_DIRECTORY: &str = "active";
const GENERATION_PREFIX: &str = "generation-";
const GENERATION_SUFFIX: &str = ".json";
const ACTIVE_PREFIX: &str = "active-";
const ACTIVE_SUFFIX: &str = ".txt";

static NAME_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheLimits {
    pub max_entries: usize,
    pub max_entry_bytes: usize,
    pub max_generation_bytes: u64,
    pub max_total_bytes: u64,
    pub retained_generations: usize,
    pub max_generation_files_to_scan: usize,
}

impl Default for CacheLimits {
    fn default() -> Self {
        Self {
            max_entries: 100_000,
            max_entry_bytes: 8 * 1024 * 1024,
            max_generation_bytes: 128 * 1024 * 1024,
            max_total_bytes: 256 * 1024 * 1024,
            retained_generations: 3,
            max_generation_files_to_scan: 64,
        }
    }
}

impl CacheLimits {
    fn validate(self) -> Result<(), CacheError> {
        if self.max_entries == 0
            || self.max_entry_bytes == 0
            || self.max_generation_bytes == 0
            || self.max_total_bytes < self.max_generation_bytes
            || self.retained_generations == 0
            || self.max_generation_files_to_scan == 0
        {
            return Err(CacheError::InvalidLimits);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CacheEntry {
    pub key: CacheKey,
    pub payload: Vec<u8>,
}

impl CacheEntry {
    #[must_use]
    pub fn new(key: CacheKey, payload: Vec<u8>) -> Self {
        Self { key, payload }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheLoadStatus {
    Empty,
    Active {
        generation: String,
    },
    Recovered {
        generation: String,
        ignored_issues: Vec<String>,
    },
    Reset {
        ignored_issues: Vec<String>,
    },
}

#[derive(Debug, Clone)]
pub struct CacheSnapshot {
    generation: Option<String>,
    entries: BTreeMap<CacheKey, Vec<u8>>,
    pub status: CacheLoadStatus,
}

impl CacheSnapshot {
    #[must_use]
    pub fn generation(&self) -> Option<&str> {
        self.generation.as_deref()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub fn get(&self, key: &CacheKey) -> Option<&[u8]> {
        self.entries.get(key).map(Vec::as_slice)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&CacheKey, &[u8])> {
        self.entries
            .iter()
            .map(|(key, payload)| (key, payload.as_slice()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheCommit {
    pub generation: String,
    pub entries: usize,
    pub serialized_bytes: usize,
    pub maintenance_warnings: Vec<String>,
}

#[derive(Debug, Error)]
pub enum CacheError {
    #[error("cache limits are internally inconsistent")]
    InvalidLimits,
    #[error("cache entry exceeds configured size limit: {actual} > {limit} bytes")]
    EntryTooLarge { actual: usize, limit: usize },
    #[error("cache generation exceeds configured entry limit: {actual} > {limit}")]
    TooManyEntries { actual: usize, limit: usize },
    #[error("cache generation exceeds configured size limit: {actual} > {limit} bytes")]
    GenerationTooLarge { actual: usize, limit: u64 },
    #[error("cache generation contains duplicate keys")]
    DuplicateKey,
    #[error("invalid cache key: {0}")]
    InvalidKey(&'static str),
    #[error("invalid cache schema: {0}")]
    InvalidSchema(&'static str),
    #[error("failed to encode cache generation: {0}")]
    Encode(#[from] serde_json::Error),
    #[error("cache I/O failed for {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, Clone)]
pub struct PersistentCache {
    root: PathBuf,
    schema: CacheSchema,
    limits: CacheLimits,
}

impl PersistentCache {
    /// Creates a cache handle without touching the filesystem.
    ///
    /// # Errors
    ///
    /// Returns an error when schema metadata or configured limits are invalid.
    pub fn new(
        root: impl Into<PathBuf>,
        schema: CacheSchema,
        limits: CacheLimits,
    ) -> Result<Self, CacheError> {
        limits.validate()?;
        schema.validate().map_err(CacheError::InvalidSchema)?;
        Ok(Self {
            root: root.into(),
            schema,
            limits,
        })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Loads the newest usable generation, recovering around corrupt generations.
    ///
    /// # Errors
    ///
    /// Returns an error when the cache root itself cannot be enumerated.
    pub fn load(&self) -> Result<CacheSnapshot, CacheError> {
        if !self.root.exists() {
            return Ok(empty_snapshot(CacheLoadStatus::Empty));
        }

        let generation_paths = self.generation_paths()?;
        let marker_targets = self.marker_targets()?;
        let mut candidates = marker_targets.clone();
        let marked: BTreeSet<_> = marker_targets.iter().cloned().collect();
        candidates.extend(
            generation_paths
                .iter()
                .filter_map(|path| file_name(path))
                .filter(|name| !marked.contains(name)),
        );
        candidates.truncate(self.limits.max_generation_files_to_scan);

        if candidates.is_empty() {
            return Ok(empty_snapshot(CacheLoadStatus::Empty));
        }

        let preferred = candidates.first().cloned();
        let mut issues = Vec::new();
        for generation in candidates {
            match self.read_generation(&generation) {
                Ok(entries) => {
                    let status = if Some(&generation) == preferred.as_ref() && issues.is_empty() {
                        CacheLoadStatus::Active {
                            generation: generation.clone(),
                        }
                    } else {
                        CacheLoadStatus::Recovered {
                            generation: generation.clone(),
                            ignored_issues: issues,
                        }
                    };
                    return Ok(CacheSnapshot {
                        generation: Some(generation),
                        entries,
                        status,
                    });
                }
                Err(issue) => issues.push(format!("{generation}: {issue}")),
            }
        }

        Ok(empty_snapshot(CacheLoadStatus::Reset {
            ignored_issues: issues,
        }))
    }

    /// Validates and atomically activates a new immutable generation.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid or oversized entries, encoding failure, or I/O failure.
    pub fn commit<I>(&self, entries: I) -> Result<CacheCommit, CacheError>
    where
        I: IntoIterator<Item = CacheEntry>,
    {
        let generation = next_generation_name();
        let body = self.build_body(generation.clone(), entries)?;
        let body_bytes = serde_json::to_vec(&body)?;
        let envelope = CacheEnvelope {
            body_checksum: Digest::of_bytes(&body_bytes),
            body,
        };
        let encoded = serde_json::to_vec(&envelope)?;
        if encoded.len() as u64 > self.limits.max_generation_bytes {
            return Err(CacheError::GenerationTooLarge {
                actual: encoded.len(),
                limit: self.limits.max_generation_bytes,
            });
        }

        self.create_directories()?;
        let generation_path = self.generations_directory().join(&generation);
        Self::atomic_create(&generation_path, &encoded)?;

        let marker_name = generation
            .strip_prefix(GENERATION_PREFIX)
            .and_then(|value| value.strip_suffix(GENERATION_SUFFIX))
            .map_or_else(unique_token, ToOwned::to_owned);
        let marker_path = self
            .active_directory()
            .join(format!("{ACTIVE_PREFIX}{marker_name}{ACTIVE_SUFFIX}"));
        Self::atomic_create(&marker_path, format!("{generation}\n").as_bytes())?;

        let maintenance_warnings = self.prune(&generation);
        Ok(CacheCommit {
            generation,
            entries: envelope.body.entries.len(),
            serialized_bytes: encoded.len(),
            maintenance_warnings,
        })
    }

    fn build_body<I>(&self, generation: String, entries: I) -> Result<CacheBody, CacheError>
    where
        I: IntoIterator<Item = CacheEntry>,
    {
        let entries: Vec<_> = entries.into_iter().collect();
        if entries.len() > self.limits.max_entries {
            return Err(CacheError::TooManyEntries {
                actual: entries.len(),
                limit: self.limits.max_entries,
            });
        }

        let mut keys = BTreeSet::new();
        for entry in &entries {
            entry.key.validate().map_err(CacheError::InvalidKey)?;
            if entry.payload.len() > self.limits.max_entry_bytes {
                return Err(CacheError::EntryTooLarge {
                    actual: entry.payload.len(),
                    limit: self.limits.max_entry_bytes,
                });
            }
            if !keys.insert(&entry.key) {
                return Err(CacheError::DuplicateKey);
            }
        }

        Ok(CacheBody {
            schema: self.schema.clone(),
            generation,
            entries,
        })
    }

    fn read_generation(&self, generation: &str) -> Result<BTreeMap<CacheKey, Vec<u8>>, String> {
        if !valid_generation_name(generation) {
            return Err("invalid generation name".to_owned());
        }
        let path = self.generations_directory().join(generation);
        let mut file = File::open(&path).map_err(|error| error.to_string())?;
        let mut encoded = Vec::new();
        Read::by_ref(&mut file)
            .take(self.limits.max_generation_bytes + 1)
            .read_to_end(&mut encoded)
            .map_err(|error| error.to_string())?;
        if encoded.len() as u64 > self.limits.max_generation_bytes {
            return Err("generation exceeds configured byte limit".to_owned());
        }

        let envelope: CacheEnvelope =
            serde_json::from_slice(&encoded).map_err(|error| error.to_string())?;
        if envelope.body.schema != self.schema {
            return Err("generation uses an incompatible schema or tool version".to_owned());
        }
        if envelope.body.generation != generation {
            return Err("generation identity does not match its file name".to_owned());
        }
        if envelope.body.entries.len() > self.limits.max_entries {
            return Err("generation exceeds configured entry limit".to_owned());
        }

        let body_bytes = serde_json::to_vec(&envelope.body).map_err(|error| error.to_string())?;
        if Digest::of_bytes(&body_bytes) != envelope.body_checksum {
            return Err("generation checksum does not match its contents".to_owned());
        }

        let mut entries = BTreeMap::new();
        for entry in envelope.body.entries {
            entry.key.validate().map_err(str::to_owned)?;
            if entry.payload.len() > self.limits.max_entry_bytes {
                return Err("entry exceeds configured byte limit".to_owned());
            }
            if entries.insert(entry.key, entry.payload).is_some() {
                return Err("generation contains duplicate cache keys".to_owned());
            }
        }
        Ok(entries)
    }

    fn create_directories(&self) -> Result<(), CacheError> {
        for path in [
            self.root.clone(),
            self.generations_directory(),
            self.active_directory(),
        ] {
            fs::create_dir_all(&path).map_err(|source| CacheError::Io { path, source })?;
        }
        Ok(())
    }

    fn atomic_create(destination: &Path, contents: &[u8]) -> Result<(), CacheError> {
        let parent = destination.parent().ok_or_else(|| CacheError::Io {
            path: destination.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "cache destination has no parent",
            ),
        })?;
        let temporary = parent.join(format!(".tmp-{}", unique_token()));
        let result = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)
                .map_err(|source| CacheError::Io {
                    path: temporary.clone(),
                    source,
                })?;
            file.write_all(contents).map_err(|source| CacheError::Io {
                path: temporary.clone(),
                source,
            })?;
            file.sync_all().map_err(|source| CacheError::Io {
                path: temporary.clone(),
                source,
            })?;
            fs::rename(&temporary, destination).map_err(|source| CacheError::Io {
                path: destination.to_path_buf(),
                source,
            })?;
            sync_directory(parent);
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    fn generation_paths(&self) -> Result<Vec<PathBuf>, CacheError> {
        list_files(&self.generations_directory(), |name| {
            valid_generation_name(name)
        })
    }

    fn marker_targets(&self) -> Result<Vec<String>, CacheError> {
        let marker_paths = list_files(&self.active_directory(), valid_marker_name)?;
        let mut targets = Vec::new();
        for path in marker_paths {
            let Ok(metadata) = fs::metadata(&path) else {
                continue;
            };
            if metadata.len() > 512 {
                continue;
            }
            let Ok(contents) = fs::read_to_string(&path) else {
                continue;
            };
            let target = contents.trim();
            if valid_generation_name(target) && !targets.iter().any(|value| value == target) {
                targets.push(target.to_owned());
            }
        }
        Ok(targets)
    }

    fn prune(&self, active_generation: &str) -> Vec<String> {
        let mut warnings = Vec::new();
        let Ok(paths) = self.generation_paths() else {
            return vec!["could not enumerate old cache generations".to_owned()];
        };
        let mut total_bytes = paths
            .iter()
            .filter_map(|path| fs::metadata(path).ok().map(|metadata| metadata.len()))
            .sum::<u64>();
        let mut retained = paths.len();

        for path in paths.iter().rev() {
            let Some(name) = file_name(path) else {
                continue;
            };
            if name == active_generation {
                continue;
            }
            let should_remove = retained > self.limits.retained_generations
                || total_bytes > self.limits.max_total_bytes;
            if !should_remove {
                continue;
            }
            let size = fs::metadata(path).map_or(0, |metadata| metadata.len());
            match fs::remove_file(path) {
                Ok(()) => {
                    retained = retained.saturating_sub(1);
                    total_bytes = total_bytes.saturating_sub(size);
                }
                Err(error) => warnings.push(format!("could not prune {}: {error}", path.display())),
            }
        }

        if let Ok(marker_paths) = list_files(&self.active_directory(), valid_marker_name) {
            for path in marker_paths
                .into_iter()
                .skip(self.limits.retained_generations)
            {
                if let Err(error) = fs::remove_file(&path) {
                    warnings.push(format!("could not prune {}: {error}", path.display()));
                }
            }
        }
        warnings
    }

    fn generations_directory(&self) -> PathBuf {
        self.root.join(GENERATIONS_DIRECTORY)
    }

    fn active_directory(&self) -> PathBuf {
        self.root.join(ACTIVE_DIRECTORY)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CacheEnvelope {
    body_checksum: Digest,
    body: CacheBody,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CacheBody {
    schema: CacheSchema,
    generation: String,
    entries: Vec<CacheEntry>,
}

fn empty_snapshot(status: CacheLoadStatus) -> CacheSnapshot {
    CacheSnapshot {
        generation: None,
        entries: BTreeMap::new(),
        status,
    }
}

fn list_files(
    directory: &Path,
    include: impl Fn(&str) -> bool,
) -> Result<Vec<PathBuf>, CacheError> {
    if !directory.exists() {
        return Ok(Vec::new());
    }
    let entries = fs::read_dir(directory).map_err(|source| CacheError::Io {
        path: directory.to_path_buf(),
        source,
    })?;
    let mut paths = Vec::new();
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_file() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if include(name) {
            paths.push(entry.path());
        }
    }
    paths.sort_by(|left, right| right.file_name().cmp(&left.file_name()));
    Ok(paths)
}

fn valid_generation_name(name: &str) -> bool {
    name.starts_with(GENERATION_PREFIX)
        && name.ends_with(GENERATION_SUFFIX)
        && name
            .strip_prefix(GENERATION_PREFIX)
            .and_then(|value| value.strip_suffix(GENERATION_SUFFIX))
            .is_some_and(|value| {
                !value.is_empty()
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || byte == b'-')
            })
}

fn valid_marker_name(name: &str) -> bool {
    name.starts_with(ACTIVE_PREFIX)
        && name.ends_with(ACTIVE_SUFFIX)
        && name
            .strip_prefix(ACTIVE_PREFIX)
            .and_then(|value| value.strip_suffix(ACTIVE_SUFFIX))
            .is_some_and(|value| {
                !value.is_empty()
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || byte == b'-')
            })
}

fn next_generation_name() -> String {
    format!("{GENERATION_PREFIX}{}{GENERATION_SUFFIX}", unique_token())
}

fn unique_token() -> String {
    let nanoseconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let process = std::process::id();
    let counter = NAME_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{nanoseconds:039}-{process:010}-{counter:020}")
}

fn file_name(path: &Path) -> Option<String> {
    path.file_name()?.to_str().map(ToOwned::to_owned)
}

#[cfg(unix)]
fn sync_directory(directory: &Path) {
    if let Ok(file) = File::open(directory) {
        let _ = file.sync_all();
    }
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) {}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use super::{CacheEntry, CacheLimits, CacheLoadStatus, PersistentCache};
    use crate::cache::{
        CacheKey, CacheSchema, CanonicalFileIdentity, ConfigDigest, ContentDigest, ProfileDigest,
    };

    #[test]
    fn commits_and_loads_the_active_generation() {
        let directory = TestDirectory::new("round-trip");
        let cache = test_cache(&directory, CacheLimits::default());
        let key = test_key(b"one");

        let commit = cache
            .commit([CacheEntry::new(key.clone(), b"facts".to_vec())])
            .unwrap();
        let loaded = cache.load().unwrap();

        assert_eq!(loaded.generation(), Some(commit.generation.as_str()));
        assert_eq!(loaded.get(&key), Some(b"facts".as_slice()));
        assert!(matches!(loaded.status, CacheLoadStatus::Active { .. }));
    }

    #[test]
    fn recovers_the_previous_generation_after_corruption() {
        let directory = TestDirectory::new("recovery");
        let cache = test_cache(&directory, CacheLimits::default());
        let first_key = test_key(b"first");
        let first = cache
            .commit([CacheEntry::new(first_key.clone(), b"old facts".to_vec())])
            .unwrap();
        let second = cache
            .commit([CacheEntry::new(test_key(b"second"), b"new facts".to_vec())])
            .unwrap();
        let corrupt_path = directory.path().join("generations").join(second.generation);
        fs::write(corrupt_path, b"not json").unwrap();

        let loaded = cache.load().unwrap();

        assert_eq!(loaded.generation(), Some(first.generation.as_str()));
        assert_eq!(loaded.get(&first_key), Some(b"old facts".as_slice()));
        assert!(matches!(loaded.status, CacheLoadStatus::Recovered { .. }));
    }

    #[test]
    fn incompatible_generations_reset_to_an_empty_cache() {
        let directory = TestDirectory::new("schema-change");
        let old_cache = test_cache(&directory, CacheLimits::default());
        old_cache
            .commit([CacheEntry::new(test_key(b"one"), b"facts".to_vec())])
            .unwrap();
        let new_cache = PersistentCache::new(
            directory.path(),
            CacheSchema::current("0.2.0", "oxc-2"),
            CacheLimits::default(),
        )
        .unwrap();

        let loaded = new_cache.load().unwrap();

        assert!(loaded.is_empty());
        assert!(matches!(loaded.status, CacheLoadStatus::Reset { .. }));
    }

    #[test]
    fn enforces_entry_size_before_writing() {
        let directory = TestDirectory::new("entry-limit");
        let limits = CacheLimits {
            max_entry_bytes: 3,
            ..CacheLimits::default()
        };
        let cache = test_cache(&directory, limits);

        let error = cache
            .commit([CacheEntry::new(test_key(b"one"), vec![0; 4])])
            .unwrap_err();

        assert!(error.to_string().contains("entry exceeds"));
        assert!(!directory.path().join("generations").exists());
    }

    fn test_cache(directory: &TestDirectory, limits: CacheLimits) -> PersistentCache {
        PersistentCache::new(
            directory.path(),
            CacheSchema::current("0.1.0", "oxc-1"),
            limits,
        )
        .unwrap()
    }

    fn test_key(source: &[u8]) -> CacheKey {
        CacheKey::new(
            ConfigDigest::of_bytes(b"config"),
            ProfileDigest::of_bytes(b"node"),
            CanonicalFileIdentity::new("src/index.ts").unwrap(),
            ContentDigest::of_bytes(source),
            Vec::new(),
        )
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "orphanode-cache-{label}-{}-{}",
                std::process::id(),
                super::unique_token()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
