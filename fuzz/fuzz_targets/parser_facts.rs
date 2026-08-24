#![no_main]

use std::{path::Path, str};

use libfuzzer_sys::fuzz_target;
use orphanode::javascript::parse_file;

const MAX_INPUT_BYTES: usize = 64 * 1024;
const SOURCE_PATHS: [&str; 8] = [
    "input.js",
    "input.jsx",
    "input.ts",
    "input.tsx",
    "input.mjs",
    "input.cjs",
    "input.mts",
    "input.cts",
];

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    let Some((&selector, source_bytes)) = data.split_first() else {
        return;
    };
    let Ok(source) = str::from_utf8(source_bytes) else {
        return;
    };
    let display_path = SOURCE_PATHS[usize::from(selector) % SOURCE_PATHS.len()];
    let _ = parse_file(display_path, Path::new(display_path), source);
});
