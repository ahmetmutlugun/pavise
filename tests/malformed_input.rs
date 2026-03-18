//! Test Plan §1: Malformed Input Tests
//! Validates that the unpacker and binary analyzer handle corrupt/adversarial input gracefully.

mod common;

use pavise::types::Severity;
use pavise::{scan_ipa, ScanOptions};
use std::io::Write;
use tempfile::NamedTempFile;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

fn default_opts() -> ScanOptions {
    ScanOptions {
        rules_dir: common::rules_dir(),
        min_severity: Severity::Info,
        network: false,
        show_progress: false,
    }
}

// ------------------------------------------------------------------ //
// ZIP/IPA Handling
// ------------------------------------------------------------------ //

#[test]
fn test_truncated_zip() {
    let mut tmp = NamedTempFile::new().unwrap();
    // Write bytes that start like a ZIP but are truncated
    tmp.write_all(b"PK\x03\x04truncated garbage here")
        .unwrap();
    tmp.flush().unwrap();

    let result = scan_ipa(tmp.path(), &default_opts());
    assert!(result.is_err(), "Truncated ZIP should fail gracefully");
}

#[test]
fn test_zip_with_zero_entries() {
    let mut buf = Vec::new();
    {
        let cursor = std::io::Cursor::new(&mut buf);
        let zip = ZipWriter::new(cursor);
        zip.finish().unwrap();
    }

    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(&buf).unwrap();
    tmp.flush().unwrap();

    let result = scan_ipa(tmp.path(), &default_opts());
    assert!(
        result.is_err(),
        "ZIP with zero entries should fail (no Info.plist)"
    );
}

#[test]
fn test_zip_path_traversal_ignored() {
    // Create a ZIP with an entry containing ".." — should be silently skipped
    let ipa = common::IpaBuilder::new("TestApp")
        .add_file("../../etc/passwd", b"root:x:0:0")
        .build();

    let report = scan_ipa(ipa.path(), &default_opts()).expect("scan should succeed");
    // The traversal file should not appear in any findings' evidence
    let has_passwd = report
        .findings
        .iter()
        .any(|f| f.evidence.iter().any(|e| e.contains("etc/passwd")));
    assert!(
        !has_passwd,
        "Path traversal entries should be silently skipped"
    );
}

#[test]
fn test_zip_absolute_path_ignored() {
    let ipa = common::IpaBuilder::new("TestApp")
        .add_file("/etc/shadow", b"shadow data")
        .build();

    // Should succeed — absolute path entries are skipped
    let report = scan_ipa(ipa.path(), &default_opts()).expect("scan should succeed");
    assert_eq!(report.app_info.name, "TestApp");
}

#[test]
fn test_non_zip_with_ipa_extension() {
    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(b"This is not a ZIP file at all").unwrap();
    tmp.flush().unwrap();

    let result = scan_ipa(tmp.path(), &default_opts());
    assert!(result.is_err(), "Non-ZIP file should fail gracefully");
}

#[test]
fn test_valid_zip_missing_payload_dir() {
    // Valid ZIP but no Payload/ directory structure
    let mut buf = Vec::new();
    {
        let cursor = std::io::Cursor::new(&mut buf);
        let mut zip = ZipWriter::new(cursor);
        let options = SimpleFileOptions::default();
        zip.start_file("SomeOtherDir/file.txt", options).unwrap();
        zip.write_all(b"hello").unwrap();
        zip.finish().unwrap();
    }

    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(&buf).unwrap();
    tmp.flush().unwrap();

    let result = scan_ipa(tmp.path(), &default_opts());
    assert!(
        result.is_err(),
        "ZIP without Payload/ should fail (no Info.plist)"
    );
}

#[test]
fn test_zip_extremely_long_entry_name() {
    // Entry with a very long name (> 4096 chars) — should not panic
    let long_name = format!("Payload/TestApp.app/{}", "a".repeat(5000));
    let ipa = common::IpaBuilder::new("TestApp")
        .add_file(&long_name, b"data")
        .build();

    let result = scan_ipa(ipa.path(), &default_opts());
    // Should either succeed or fail gracefully — must not panic
    let _ = result;
}

// ------------------------------------------------------------------ //
// Mach-O Parsing
// ------------------------------------------------------------------ //

#[test]
fn test_truncated_macho_header() {
    // Feed only 2 bytes instead of a valid Mach-O
    let result = pavise::binary::macho::analyze(&[0xFE, 0xED], "test_binary");
    assert!(result.is_err(), "Truncated Mach-O should fail gracefully");
}

#[test]
fn test_invalid_magic_number() {
    // 16 bytes of zeros — not a valid Mach-O magic
    let result = pavise::binary::macho::analyze(&[0u8; 16], "test_binary");
    assert!(result.is_err(), "Invalid magic number should fail gracefully");
}

#[test]
fn test_empty_macho_data() {
    let result = pavise::binary::macho::analyze(&[], "test_binary");
    assert!(result.is_err(), "Empty data should fail gracefully");
}

#[test]
fn test_macho_random_garbage() {
    // Random-ish data that starts with valid Mach-O magic but is otherwise garbage
    let mut data = vec![0xCF, 0xFA, 0xED, 0xFE]; // MH_MAGIC_64
    data.extend_from_slice(&[0u8; 100]);
    let result = pavise::binary::macho::analyze(&data, "test_binary");
    // Should either parse what it can or fail — must not panic
    let _ = result;
}

// ------------------------------------------------------------------ //
// IPA with multiple Info.plist at different depths
// ------------------------------------------------------------------ //

#[test]
fn test_multiple_info_plists() {
    let framework_plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
    <key>CFBundleName</key><string>Framework</string>
    <key>CFBundleIdentifier</key><string>com.test.framework</string>
    <key>CFBundleExecutable</key><string>Framework</string>
    <key>CFBundleShortVersionString</key><string>1.0</string>
    <key>CFBundleVersion</key><string>1</string>
</dict></plist>"#;

    let ipa = common::IpaBuilder::new("TestApp")
        .add_bundle_file(
            "Frameworks/MyLib.framework/Info.plist",
            framework_plist.as_bytes(),
        )
        .build();

    let report = scan_ipa(ipa.path(), &default_opts()).expect("scan should succeed");
    // The app-level Info.plist should be used, not the framework's
    assert_eq!(report.app_info.name, "TestApp");
}

// ------------------------------------------------------------------ //
// ZIP Bomb Detection
// ------------------------------------------------------------------ //

#[test]
fn test_zip_bomb_high_compression_ratio() {
    // Create a ZIP entry with very high compression ratio (lots of zeros compress well)
    let mut buf = Vec::new();
    {
        let cursor = std::io::Cursor::new(&mut buf);
        let mut zip = ZipWriter::new(cursor);
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

        // Write a file with 10MB of zeros (compresses to almost nothing)
        let plist_path = "Payload/BombApp.app/Info.plist";
        zip.start_file(plist_path, SimpleFileOptions::default())
            .unwrap();
        zip.write_all(
            common::minimal_info_plist("BombApp").as_bytes(),
        )
        .unwrap();

        // This entry has extremely high compression ratio
        zip.start_file("Payload/BombApp.app/bigfile.bin", options)
            .unwrap();
        let zeros = vec![0u8; 10 * 1024 * 1024]; // 10 MB of zeros
        zip.write_all(&zeros).unwrap();

        zip.finish().unwrap();
    }

    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(&buf).unwrap();
    tmp.flush().unwrap();

    // Should either succeed (skipping the bomb entry) or fail gracefully — must not panic or OOM
    let _ = scan_ipa(tmp.path(), &default_opts());
}

#[test]
fn test_zip_entry_mismatched_declared_vs_actual_size() {
    // We can't easily create a ZIP with mismatched sizes using the zip crate
    // (it validates internally), but we can create a valid ZIP and ensure
    // the scanner handles post-read size validation. Just verify no panic.
    let ipa = common::IpaBuilder::new("MismatchApp").build();
    let result = scan_ipa(ipa.path(), &default_opts());
    // Should succeed — no mismatched sizes in a properly created ZIP
    assert!(result.is_ok());
}

// ------------------------------------------------------------------ //
// Fat Mach-O Edge Cases
// ------------------------------------------------------------------ //

#[test]
fn test_fat_binary_zero_architectures() {
    // FAT_MAGIC = 0xCAFEBABE, nfat_arch = 0
    let data: Vec<u8> = vec![
        0xCA, 0xFE, 0xBA, 0xBE, // FAT_MAGIC (big-endian)
        0x00, 0x00, 0x00, 0x00, // nfat_arch = 0
    ];
    let result = pavise::binary::macho::analyze(&data, "test_fat_zero");
    // Should fail gracefully — no architectures to analyze
    assert!(
        result.is_err(),
        "Fat binary with zero architectures should fail gracefully"
    );
}

#[test]
fn test_fat_binary_invalid_architecture_offsets() {
    // FAT_MAGIC with 1 arch but offset points past EOF
    let mut data: Vec<u8> = vec![
        0xCA, 0xFE, 0xBA, 0xBE, // FAT_MAGIC
        0x00, 0x00, 0x00, 0x01, // nfat_arch = 1
    ];
    // fat_arch struct: cputype(4) + cpusubtype(4) + offset(4) + size(4) + align(4) = 20 bytes
    data.extend_from_slice(&[0x00, 0x00, 0x00, 0x0C]); // cputype = ARM (12)
    data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // cpusubtype = 0
    data.extend_from_slice(&[0x00, 0x0F, 0xFF, 0xFF]); // offset = way past EOF
    data.extend_from_slice(&[0x00, 0x00, 0x10, 0x00]); // size = 4096
    data.extend_from_slice(&[0x00, 0x00, 0x00, 0x0E]); // align = 14

    let result = pavise::binary::macho::analyze(&data, "test_fat_invalid_offsets");
    // Should fail gracefully — offset points past EOF
    assert!(
        result.is_err(),
        "Fat binary with invalid offsets should fail gracefully"
    );
}

// ------------------------------------------------------------------ //
// Mach-O with invalid symbol table offsets
// ------------------------------------------------------------------ //

#[test]
fn test_macho_invalid_symtab_offsets() {
    // Build a minimal Mach-O 64-bit header with a corrupt LC_SYMTAB pointing past EOF
    let mut data = Vec::new();
    // MH_MAGIC_64
    data.extend_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]);
    // cputype = ARM64 (0x0100000C)
    data.extend_from_slice(&[0x0C, 0x00, 0x00, 0x01]);
    // cpusubtype = 0
    data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    // filetype = MH_EXECUTE (2)
    data.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]);
    // ncmds = 1
    data.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
    // sizeofcmds = 24 (LC_SYMTAB is 24 bytes)
    data.extend_from_slice(&[0x18, 0x00, 0x00, 0x00]);
    // flags = MH_PIE
    data.extend_from_slice(&[0x00, 0x00, 0x20, 0x00]);
    // reserved (Mach-O 64 has 4 extra bytes)
    data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    // LC_SYMTAB (cmd=2, cmdsize=24)
    data.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // cmd = LC_SYMTAB
    data.extend_from_slice(&[0x18, 0x00, 0x00, 0x00]); // cmdsize = 24
    data.extend_from_slice(&[0xFF, 0xFF, 0x00, 0x00]); // symoff = past EOF
    data.extend_from_slice(&[0xFF, 0x00, 0x00, 0x00]); // nsyms = 255
    data.extend_from_slice(&[0xFF, 0xFF, 0x00, 0x00]); // stroff = past EOF
    data.extend_from_slice(&[0xFF, 0x00, 0x00, 0x00]); // strsize = 255

    let result = pavise::binary::macho::analyze(&data, "test_invalid_symtab");
    // Should either parse what it can or fail — must not panic
    let _ = result;
}

#[test]
fn test_macho_corrupt_code_signature() {
    // Minimal MH_MAGIC_64 header with a bogus LC_CODE_SIGNATURE load command
    let mut data = Vec::new();
    // MH_MAGIC_64
    data.extend_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]);
    // cputype = ARM64
    data.extend_from_slice(&[0x0C, 0x00, 0x00, 0x01]);
    // cpusubtype
    data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    // filetype = MH_EXECUTE
    data.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]);
    // ncmds = 1
    data.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
    // sizeofcmds = 16
    data.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]);
    // flags
    data.extend_from_slice(&[0x00, 0x00, 0x20, 0x00]);
    // reserved
    data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    // LC_CODE_SIGNATURE (cmd = 0x1D, cmdsize = 16)
    data.extend_from_slice(&[0x1D, 0x00, 0x00, 0x00]); // cmd = LC_CODE_SIGNATURE
    data.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // cmdsize = 16
    data.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]); // dataoff = bogus
    data.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]); // datasize = bogus

    let result = pavise::binary::macho::analyze(&data, "test_corrupt_codesig");
    // Should not panic — goblin may parse the header even with bad offsets
    let _ = result;
}

#[test]
fn test_macho_overlapping_segments() {
    // Minimal 64-bit header with two LC_SEGMENT_64 commands that overlap
    let mut data = Vec::new();
    // MH_MAGIC_64
    data.extend_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]);
    // cputype = ARM64
    data.extend_from_slice(&[0x0C, 0x00, 0x00, 0x01]);
    // cpusubtype
    data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    // filetype = MH_EXECUTE
    data.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]);
    // ncmds = 2
    data.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]);
    // sizeofcmds = 144 (72 * 2 = minimal LC_SEGMENT_64)
    data.extend_from_slice(&[0x90, 0x00, 0x00, 0x00]);
    // flags
    data.extend_from_slice(&[0x00, 0x00, 0x20, 0x00]);
    // reserved
    data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    // LC_SEGMENT_64 #1 (cmd=0x19, cmdsize=72, no sections)
    let mut seg1 = vec![0x19, 0x00, 0x00, 0x00]; // cmd
    seg1.extend_from_slice(&[0x48, 0x00, 0x00, 0x00]); // cmdsize = 72
    seg1.extend_from_slice(&[0u8; 16]); // segname (16 bytes)
    seg1.extend_from_slice(&[0x00; 8]); // vmaddr
    seg1.extend_from_slice(&[0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // vmsize = 0x1000
    seg1.extend_from_slice(&[0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // fileoff = 0x1000
    seg1.extend_from_slice(&[0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // filesize = 0x1000
    seg1.extend_from_slice(&[0x07, 0x00, 0x00, 0x00]); // maxprot
    seg1.extend_from_slice(&[0x05, 0x00, 0x00, 0x00]); // initprot
    seg1.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // nsects = 0
    seg1.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // flags
    data.extend_from_slice(&seg1);

    // LC_SEGMENT_64 #2 — overlapping with #1 (same fileoff)
    let mut seg2 = vec![0x19, 0x00, 0x00, 0x00];
    seg2.extend_from_slice(&[0x48, 0x00, 0x00, 0x00]);
    seg2.extend_from_slice(&[0u8; 16]); // segname
    seg2.extend_from_slice(&[0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // vmaddr overlaps
    seg2.extend_from_slice(&[0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // vmsize
    seg2.extend_from_slice(&[0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // fileoff = same
    seg2.extend_from_slice(&[0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // filesize
    seg2.extend_from_slice(&[0x07, 0x00, 0x00, 0x00]);
    seg2.extend_from_slice(&[0x05, 0x00, 0x00, 0x00]);
    seg2.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    seg2.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    data.extend_from_slice(&seg2);

    let result = pavise::binary::macho::analyze(&data, "test_overlapping_segments");
    // Should not panic
    let _ = result;
}

#[test]
fn test_32bit_armv7_macho() {
    // MH_MAGIC (32-bit, little-endian) = 0xFEEDFACE
    let mut data = Vec::new();
    data.extend_from_slice(&[0xCE, 0xFA, 0xED, 0xFE]); // MH_MAGIC (LE)
    data.extend_from_slice(&[0x0C, 0x00, 0x00, 0x00]); // cputype = ARM (12)
    data.extend_from_slice(&[0x09, 0x00, 0x00, 0x00]); // cpusubtype = ARMv7 (9)
    data.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // filetype = MH_EXECUTE
    data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ncmds = 0
    data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // sizeofcmds = 0
    data.extend_from_slice(&[0x00, 0x00, 0x20, 0x00]); // flags = MH_PIE

    let result = pavise::binary::macho::analyze(&data, "test_armv7");
    match result {
        Ok(r) => {
            assert_eq!(r.binary_info.bits, 32, "ARMv7 should be 32-bit");
            assert!(
                r.binary_info.arch.contains("ARM"),
                "Arch should contain ARM, got: {}",
                r.binary_info.arch
            );
        }
        Err(_) => {
            // Also acceptable — 32-bit parsing may not be fully supported
        }
    }
}

// ------------------------------------------------------------------ //
// IPA missing CFBundleExecutable
// ------------------------------------------------------------------ //

#[test]
fn test_plist_missing_bundle_executable() {
    // Build an IPA whose Info.plist lacks CFBundleExecutable
    let plist_no_exec = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>NoExec</string>
    <key>CFBundleIdentifier</key><string>com.test.noexec</string>
    <key>CFBundleShortVersionString</key><string>1.0</string>
    <key>CFBundleVersion</key><string>1</string>
    <key>MinimumOSVersion</key><string>14.0</string>
    <key>CFBundleSupportedPlatforms</key><array><string>iPhoneOS</string></array>
</dict>
</plist>"#;

    let mut buf = Vec::new();
    {
        let cursor = std::io::Cursor::new(&mut buf);
        let mut zip = ZipWriter::new(cursor);
        let options = SimpleFileOptions::default();

        zip.start_file("Payload/NoExec.app/Info.plist", options)
            .unwrap();
        zip.write_all(plist_no_exec.as_bytes()).unwrap();
        zip.finish().unwrap();
    }

    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(&buf).unwrap();
    tmp.flush().unwrap();

    let report = scan_ipa(tmp.path(), &default_opts()).expect("scan should succeed");
    // With no CFBundleExecutable, main_binary should be None
    assert!(
        report.main_binary.is_none(),
        "Missing CFBundleExecutable should result in no main binary"
    );
    assert_eq!(report.app_info.name, "NoExec");
}
