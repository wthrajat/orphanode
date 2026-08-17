#![no_main]

use std::{cell::OnceCell, path::PathBuf, str};

use libfuzzer_sys::fuzz_target;
use orphanode_core::{
    domain::facts::ResolutionMode,
    resolution::{ModuleResolver, OxcModuleResolver, is_relative},
};

const MAX_INPUT_BYTES: usize = 4 * 1024;

thread_local! {
    static RESOLVER: OnceCell<OxcModuleResolver> = const { OnceCell::new() };
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    let Some((&selector, specifier_bytes)) = data.split_first() else {
        return;
    };
    let Ok(specifier) = str::from_utf8(specifier_bytes) else {
        return;
    };
    let (containing_file, mode) = containing_file_and_mode(selector);
    let _ = is_relative(specifier);
    RESOLVER.with(|slot| {
        let resolver = slot.get_or_init(OxcModuleResolver::new);
        let _ = resolver.resolve(&containing_file, specifier, mode);
    });
});

fn containing_file_and_mode(selector: u8) -> (PathBuf, ResolutionMode) {
    let repository_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    match selector % 3 {
        0 => (
            repository_root.join("fixtures/esm/src/index.js"),
            ResolutionMode::Esm,
        ),
        1 => (
            repository_root.join("fixtures/commonjs/src/index.cjs"),
            ResolutionMode::CommonJs,
        ),
        _ => (
            repository_root.join("fixtures/ts-path-alias/src/index.ts"),
            ResolutionMode::Esm,
        ),
    }
}
