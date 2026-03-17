use anyhow::{Context, Result};
use digest::Digest;
use md5::Md5;
use sha1::Sha1;
use sha2::Sha256;
use std::io::{Read, Seek};
use std::path::Path;
use tracing::debug;
use zip::ZipArchive;

use super::{ExtractedFile, UnpackedArchive};
use crate::types::FileHashes;

/// Maximum single file size to load into RAM (512 MB).
/// Modern app binaries (especially large Swift/ObjC apps) can exceed 200 MB.
/// The total extracted size cap (MAX_TOTAL_EXTRACTED) provides zip bomb protection.
const MAX_IN_MEMORY: usize = 512 * 1024 * 1024;

/// Maximum total decompressed size across all extracted files (2 GB).
/// Prevents zip bombs from exhausting memory.
const MAX_TOTAL_EXTRACTED: usize = 2 * 1024 * 1024 * 1024;

/// Maximum number of entries to extract. Prevents attacks using
/// millions of tiny files to exhaust memory via per-entry overhead.
const MAX_ENTRY_COUNT: usize = 50_000;

/// Maximum compression ratio. A 1 KB compressed entry decompressing
/// to 50 MB is a strong zip-bomb signal.
const MAX_COMPRESSION_RATIO: u64 = 200;

pub struct IpaUnpackResult {
    pub archive: UnpackedArchive,
    pub hashes: FileHashes,
    /// Relative path to the main binary inside the archive
    pub main_binary_path: Option<String>,
    /// Bundle prefix, e.g. "Payload/MyApp.app"
    pub bundle_prefix: Option<String>,
    /// Paths of all framework binaries
    pub framework_binary_paths: Vec<String>,
}

pub fn unpack(path: &Path) -> Result<IpaUnpackResult> {
    // --- 1. Hash the file while reading it ---
    let file_data =
        std::fs::read(path).with_context(|| format!("Failed to read IPA: {}", path.display()))?;
    let size_bytes = file_data.len() as u64;

    let md5_hash = hex::encode(Md5::digest(&file_data));
    let sha1_hash = hex::encode(Sha1::digest(&file_data));
    let sha256_hash = hex::encode(Sha256::digest(&file_data));

    let hashes = FileHashes {
        md5: md5_hash,
        sha1: sha1_hash,
        sha256: sha256_hash,
        size_bytes,
    };

    // --- 2. Open as ZIP ---
    let cursor = std::io::Cursor::new(&file_data);
    let mut zip = ZipArchive::new(cursor).context("Failed to open IPA as ZIP archive")?;

    debug!("IPA contains {} entries", zip.len());

    // --- 3. Find the bundle prefix (Payload/<App>.app) ---
    let bundle_prefix = find_bundle_prefix(&zip);
    debug!("Bundle prefix: {:?}", bundle_prefix);

    // --- 4. Extract all relevant files ---
    let mut files: Vec<ExtractedFile> = Vec::new();
    let mut total_extracted: usize = 0;

    let entry_count = zip.len();
    if entry_count > MAX_ENTRY_COUNT {
        anyhow::bail!(
            "ZIP contains {} entries (limit: {}). Possible zip bomb.",
            entry_count,
            MAX_ENTRY_COUNT
        );
    }

    for i in 0..entry_count {
        let mut entry = zip.by_index(i).context("Failed to read ZIP entry")?;
        let name = entry.name().to_string();

        // Skip directory entries
        if name.ends_with('/') {
            continue;
        }

        // Defense-in-depth: reject path traversal attempts (ZIP slip)
        if name.contains("..") || name.starts_with('/') {
            debug!("Skipping suspicious ZIP entry (path traversal): {}", name);
            continue;
        }

        let uncompressed = entry.size();
        let compressed = entry.compressed_size();

        // Check compression ratio for bomb detection
        if compressed > 0 && uncompressed / compressed > MAX_COMPRESSION_RATIO {
            debug!(
                "Skipping suspicious entry (ratio {}:1): {}",
                uncompressed / compressed,
                name
            );
            continue;
        }

        let size = uncompressed as usize;

        // Only fully extract files under the per-file size limit
        if size > MAX_IN_MEMORY {
            debug!("Skipping large file ({}MB): {}", size / 1024 / 1024, name);
            continue;
        }

        // Check total extracted size limit
        if total_extracted + size > MAX_TOTAL_EXTRACTED {
            anyhow::bail!(
                "Total decompressed size exceeds {} MB limit. Possible zip bomb.",
                MAX_TOTAL_EXTRACTED / (1024 * 1024)
            );
        }

        let mut data = Vec::with_capacity(size.min(1024 * 1024));
        entry.read_to_end(&mut data)?;

        // Verify actual size matches claimed size (defense against lying headers)
        if data.len() > MAX_IN_MEMORY {
            debug!(
                "Entry actual size ({}MB) exceeds limit, discarding: {}",
                data.len() / 1024 / 1024,
                name
            );
            continue;
        }

        total_extracted += data.len();
        files.push(ExtractedFile { path: name, data });
    }

    // --- 5. Determine main binary path from Info.plist ---
    let main_binary_path = resolve_main_binary_path(&files, &bundle_prefix);
    debug!("Main binary path: {:?}", main_binary_path);

    // --- 6. Find framework binary paths ---
    let framework_binary_paths = find_framework_binaries(&files, &bundle_prefix);
    debug!("Framework binaries: {:?}", framework_binary_paths);

    Ok(IpaUnpackResult {
        archive: UnpackedArchive { files },
        hashes,
        main_binary_path,
        bundle_prefix,
        framework_binary_paths,
    })
}

fn find_bundle_prefix<R: Read + Seek>(zip: &ZipArchive<R>) -> Option<String> {
    // Look for Payload/<App>.app/Info.plist using file_names() (immutable iterator)
    for name in zip.file_names() {
        if name.starts_with("Payload/") && name.ends_with("/Info.plist") {
            // e.g., "Payload/MyApp.app/Info.plist" → "Payload/MyApp.app"
            if let Some(prefix) = name.strip_suffix("/Info.plist") {
                // Ensure it's directly inside Payload/ (depth 2)
                let parts: Vec<&str> = prefix.split('/').collect();
                if parts.len() == 2 {
                    return Some(prefix.to_string());
                }
            }
        }
    }
    None
}

fn resolve_main_binary_path(
    files: &[ExtractedFile],
    bundle_prefix: &Option<String>,
) -> Option<String> {
    let prefix = bundle_prefix.as_deref()?;
    let plist_path = format!("{}/Info.plist", prefix);

    let plist_file = files.iter().find(|f| f.path == plist_path)?;

    // Try to parse as binary plist
    let value: plist::Value = if plist_file.data.starts_with(b"bplist") {
        plist::from_bytes(&plist_file.data).ok()?
    } else {
        // Try XML plist
        plist::from_bytes(&plist_file.data).ok()?
    };

    let dict = value.as_dictionary()?;
    let exec_name = dict.get("CFBundleExecutable")?.as_string()?;

    Some(format!("{}/{}", prefix, exec_name))
}

fn find_framework_binaries(files: &[ExtractedFile], bundle_prefix: &Option<String>) -> Vec<String> {
    let Some(prefix) = bundle_prefix else {
        return Vec::new();
    };

    let frameworks_prefix = format!("{}/Frameworks/", prefix);
    let mut result = Vec::new();

    for file in files {
        if !file.path.starts_with(&frameworks_prefix) {
            continue;
        }

        // Framework structure: Frameworks/<Name>.framework/<Name>
        // Identify the binary: it's a file directly inside a .framework directory
        // and has no extension (Mach-O binaries don't have .dylib for framework binaries)
        let relative = &file.path[frameworks_prefix.len()..];
        let parts: Vec<&str> = relative.split('/').collect();

        // parts[0] = "Name.framework", parts[1] = "Name" (the binary)
        if parts.len() == 2 {
            let framework_dir = parts[0];
            let binary_name = parts[1];

            if framework_dir.ends_with(".framework") {
                let expected_binary = framework_dir.trim_end_matches(".framework");
                if binary_name == expected_binary {
                    result.push(file.path.clone());
                }
            }
        }

        // Also catch .dylib files in Frameworks/
        if parts.len() == 1 && (relative.ends_with(".dylib") || relative.ends_with(".so")) {
            result.push(file.path.clone());
        }
    }

    result
}
