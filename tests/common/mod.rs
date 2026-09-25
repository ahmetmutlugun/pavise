#![allow(dead_code)]

use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

pub struct IpaBuilder {
    app_name: String,
    main_binary: Vec<u8>,
    extra_files: Vec<(String, Vec<u8>)>,
}

impl IpaBuilder {
    pub fn new(app_name: &str) -> Self {
        IpaBuilder {
            app_name: app_name.to_string(),
            main_binary: minimal_macho(),
            extra_files: Vec::new(),
        }
    }

    /// Replace the main executable bytes (default: `minimal_macho()`).
    pub fn main_binary(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.main_binary = data.into();
        self
    }

    pub fn add_file(mut self, path: &str, content: impl Into<Vec<u8>>) -> Self {
        self.extra_files.push((path.to_string(), content.into()));
        self
    }

    /// Add a file inside `Payload/<app_name>.app/` automatically.
    pub fn add_bundle_file(self, rel_path: &str, content: impl Into<Vec<u8>>) -> Self {
        let full_path = format!("Payload/{}.app/{}", self.app_name, rel_path);
        self.add_file(&full_path, content)
    }

    /// Write the IPA (ZIP) to a NamedTempFile and return it.
    ///
    /// IMPORTANT: Keep the returned `NamedTempFile` alive for the entire test
    /// body or the file will be deleted before `scan_ipa` can read it.
    pub fn build(self) -> NamedTempFile {
        let mut buf = Vec::new();
        {
            let cursor = std::io::Cursor::new(&mut buf);
            let mut zip = ZipWriter::new(cursor);
            let options = SimpleFileOptions::default();

            // Mandatory: Info.plist at Payload/<App>.app/Info.plist
            let plist_path = format!("Payload/{}.app/Info.plist", self.app_name);
            zip.start_file(&plist_path, options).unwrap();
            zip.write_all(minimal_info_plist(&self.app_name).as_bytes())
                .unwrap();

            // Mandatory: main executable (scan_ipa fails if it can't be parsed)
            let bin_path = format!("Payload/{}.app/{}", self.app_name, self.app_name);
            zip.start_file(&bin_path, options).unwrap();
            zip.write_all(&self.main_binary).unwrap();

            // Extra caller-supplied files
            for (path, content) in &self.extra_files {
                zip.start_file(path.as_str(), options).unwrap();
                zip.write_all(content).unwrap();
            }

            zip.finish().unwrap();
        }

        let mut tmp = NamedTempFile::new().expect("create temp file");
        tmp.write_all(&buf).expect("write IPA bytes");
        tmp.flush().expect("flush IPA bytes");
        tmp
    }
}

/// Header-only arm64 MH_EXECUTE Mach-O with MH_PIE and no load commands.
pub fn minimal_macho() -> Vec<u8> {
    let mut b = Vec::with_capacity(32);
    for word in [
        0xFEED_FACFu32, // MH_MAGIC_64
        0x0100_000C,    // CPU_TYPE_ARM64
        0,              // cpusubtype
        2,              // MH_EXECUTE
        0,              // ncmds
        0,              // sizeofcmds
        0x0020_0000,    // MH_PIE
        0,              // reserved
    ] {
        b.extend_from_slice(&word.to_le_bytes());
    }
    b
}

/// Minimal XML Info.plist sufficient to pass `info_plist::analyze`.
pub fn minimal_info_plist(app_name: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>{app_name}</string>
    <key>CFBundleIdentifier</key>
    <string>com.test.{app_name}</string>
    <key>CFBundleExecutable</key>
    <string>{app_name}</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>MinimumOSVersion</key>
    <string>14.0</string>
    <key>CFBundleSupportedPlatforms</key>
    <array>
        <string>iPhoneOS</string>
    </array>
</dict>
</plist>
"#
    )
}

/// Returns the `rules/` directory at the project root (compile-time, CWD-independent).
pub fn rules_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("rules")
}
