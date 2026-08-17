#![no_main]

use std::{
    env, fs,
    path::{Path, PathBuf},
    process,
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};

use libfuzzer_sys::fuzz_target;
use orphanode_core::discovery::{
    configuration::load_orphanode_configuration,
    manifest::{EntryTargetProfile, PackageManifest, package_entry_roots},
};

const MAX_INPUT_BYTES: usize = 32 * 1024;
const PROFILES: [EntryTargetProfile; 6] = [
    EntryTargetProfile::NodeImport,
    EntryTargetProfile::NodeRequire,
    EntryTargetProfile::Bundler,
    EntryTargetProfile::Browser,
    EntryTargetProfile::Types,
    EntryTargetProfile::CommandLine,
];
const EMPTY_PACKAGE_MANIFEST: &[u8] = b"{}\n";

static CONFIGURATION_ROOT: OnceLock<PathBuf> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    if let Ok(manifest) = serde_json::from_slice::<PackageManifest>(data) {
        for profile in PROFILES {
            let _ = package_entry_roots(&manifest, profile);
        }
    }

    let configuration_root = CONFIGURATION_ROOT.get_or_init(initialize_configuration_root);
    if restore_configuration_project(configuration_root, data) {
        let _ = load_orphanode_configuration(configuration_root);
    }
});

fn initialize_configuration_root() -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let root = env::temp_dir().join(format!(
        "orphanode-config-fuzz-{}-{timestamp}",
        process::id()
    ));
    fs::create_dir_all(&root).expect("create bounded fuzz configuration root");
    root
}

fn restore_configuration_project(root: &Path, jsonc: &[u8]) -> bool {
    fs::write(root.join("package.json"), EMPTY_PACKAGE_MANIFEST).is_ok()
        && fs::write(root.join("orphanode.jsonc"), jsonc).is_ok()
}
