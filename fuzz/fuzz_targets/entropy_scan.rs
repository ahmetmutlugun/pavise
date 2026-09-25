#![no_main]
//! High-entropy token detection over arbitrary UTF-8 lines.

use libfuzzer_sys::fuzz_target;
use pavise::patterns::entropy;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let lines: Vec<&str> = text.lines().collect();
    let _ = entropy::scan_for_high_entropy(&lines, "Payload/Fuzz.app/config.json");
    let _ = entropy::is_lottie_json(data);
});
