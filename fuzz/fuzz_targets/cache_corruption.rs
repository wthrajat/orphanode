#![no_main]

use std::{
    env, fs,
    path::{Path, PathBuf},
    process,
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};

use libfuzzer_sys::fuzz_target;
use orphanode_core::cache::{CacheEntry, CacheLimits, CacheSchema, PersistentCache};

const MAX_INPUT_BYTES: usize = 64 * 1024;

struct CacheState {
    cache: PersistentCache,
    generation_path: PathBuf,
    generation_baseline: Vec<u8>,
    marker_path: PathBuf,
    marker_baseline: Vec<u8>,
}

static CACHE_STATE: OnceLock<CacheState> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    let state = CACHE_STATE.get_or_init(initialize_cache);
    if fs::write(&state.generation_path, &state.generation_baseline).is_err()
        || fs::write(&state.marker_path, &state.marker_baseline).is_err()
    {
        return;
    }

    let (selector, payload) = match data.split_first() {
        Some((selector, payload)) => (*selector, payload),
        None => (0, &[][..]),
    };
    let destination = if selector % 2 == 0 {
        &state.generation_path
    } else {
        &state.marker_path
    };
    if fs::write(destination, payload).is_ok() {
        let _ = state.cache.load();
    }
});

fn initialize_cache() -> CacheState {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let root = env::temp_dir().join(format!(
        "orphanode-cache-fuzz-{}-{timestamp}",
        process::id()
    ));
    let limits = CacheLimits {
        max_entries: 16,
        max_entry_bytes: 4 * 1024,
        max_generation_bytes: MAX_INPUT_BYTES as u64,
        max_total_bytes: (MAX_INPUT_BYTES * 2) as u64,
        retained_generations: 1,
        max_generation_files_to_scan: 4,
    };
    let cache = PersistentCache::new(&root, CacheSchema::current("fuzz", "fuzz"), limits)
        .expect("bounded fuzz cache must be valid");
    let commit = cache
        .commit(std::iter::empty::<CacheEntry>())
        .expect("fuzz cache initialization must succeed");
    let generation_path = root.join("generations").join(commit.generation);
    let marker_path = only_file(&root.join("active"));
    let generation_baseline = fs::read(&generation_path).expect("read generation baseline");
    let marker_baseline = fs::read(&marker_path).expect("read marker baseline");
    CacheState {
        cache,
        generation_path,
        generation_baseline,
        marker_path,
        marker_baseline,
    }
}

fn only_file(directory: &Path) -> PathBuf {
    let mut paths = fs::read_dir(directory)
        .expect("read cache directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file());
    let path = paths.next().expect("cache directory must contain a file");
    assert!(
        paths.next().is_none(),
        "cache directory must contain one file"
    );
    path
}
