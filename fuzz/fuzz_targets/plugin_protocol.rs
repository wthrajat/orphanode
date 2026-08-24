#![no_main]

use std::path::Path;

use libfuzzer_sys::fuzz_target;
use orphanode::plugins::{
    DeclarativePlugin, HostRequest, HostResponse, validate_host_request, validate_host_response,
};

const MAX_INPUT_BYTES: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    if let Ok(mut plugin) = serde_json::from_slice::<DeclarativePlugin>(data) {
        let _ = plugin.validate();
        plugin.canonicalize();
        let _ = plugin.validate();
    }

    if let Ok(request) = serde_json::from_slice::<HostRequest>(data) {
        let _ = validate_host_request(&request);
    }

    if let Ok(mut response) = serde_json::from_slice::<HostResponse>(data) {
        let _ = response.contributions.validate();
        response.contributions.canonicalize();
        let _ = response.contributions.validate();
    }

    if let Ok((request, response)) = serde_json::from_slice::<(HostRequest, HostResponse)>(data) {
        let _ = validate_host_response(Path::new("."), &request, &response);
    }
});
