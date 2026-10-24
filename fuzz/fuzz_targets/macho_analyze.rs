#![no_main]
//! Mach-O parsing, section extraction, code-signature entitlements and
//! call-site attribution (debug map, stubs, indirect symbols).

use libfuzzer_sys::fuzz_target;
use pavise::binary::{callsites, macho};
use pavise::manifest::entitlements;

fuzz_target!(|data: &[u8]| {
    let _ = macho::analyze(data, "fuzz");
    let _ = macho::ustrings(data);
    let _ = macho::objc_class_names(data);
    let _ = callsites::callers(data, &["_strcpy", "_rand", "_NSLog"]);
    if let Some(ent) = entitlements::extract_from_binary(data) {
        let _ = entitlements::analyze(&ent);
    }
});
