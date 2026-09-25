#![no_main]
//! Mach-O parsing, section extraction and code-signature entitlements.

use libfuzzer_sys::fuzz_target;
use pavise::binary::macho;
use pavise::manifest::entitlements;

fuzz_target!(|data: &[u8]| {
    let _ = macho::analyze(data, "fuzz");
    let _ = macho::ustrings(data);
    let _ = macho::objc_class_names(data);
    if let Some(ent) = entitlements::extract_from_binary(data) {
        let _ = entitlements::analyze(&ent);
    }
});
