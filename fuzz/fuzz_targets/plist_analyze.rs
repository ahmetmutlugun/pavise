#![no_main]
//! Info.plist, privacy manifest and provisioning profile parsing.

use libfuzzer_sys::fuzz_target;
use pavise::manifest::{info_plist, privacy, provisioning};

fuzz_target!(|data: &[u8]| {
    let _ = info_plist::analyze(data, None);
    let _ = privacy::analyze(Some(data), &[]);
    let _ = provisioning::parse(data);
    let _ = pavise::patterns::engine::plist_key_values(data);
});
