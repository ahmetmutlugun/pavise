#![no_main]
//! Secret regexes, URL and email extraction over arbitrary file contents.

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use pavise::patterns::engine::{extract_printable_strings, PatternEngine};
use pavise::patterns::{emails, urls};

static ENGINE: OnceLock<PatternEngine> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let engine = ENGINE.get_or_init(|| PatternEngine::load(None).expect("embedded rules"));
    let text = extract_printable_strings(data, 6);
    let _ = engine.scan(&text, "Payload/Fuzz.app/config.json");
    let _ = urls::extract(&text, "fuzz");
    let _ = emails::extract_emails(&text, "fuzz");
});
