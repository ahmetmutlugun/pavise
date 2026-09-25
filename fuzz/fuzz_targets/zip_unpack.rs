#![no_main]
//! Arbitrary bytes as an IPA: the unpacker must fail cleanly, never panic or
//! blow past the extraction cap.

use std::io::Write;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut file = tempfile::NamedTempFile::new().expect("temp file");
    file.write_all(data).expect("write input");
    let _ = pavise::unpacker::ipa::unpack_with_limit(file.path(), 16 * 1024 * 1024);
});
