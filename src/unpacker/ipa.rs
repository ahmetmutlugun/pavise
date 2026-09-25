use anyhow::{Context, Result};
use digest::Digest;
use md5::Md5;
use rayon::prelude::*;
use sha1::Sha1;
use sha2::Sha256;
use std::io::Read;
use std::path::Path;
use tracing::debug;
use zip::ZipArchive;

use super::{decompress, ExtractedFile, SharedFile, UnpackedArchive};
use crate::types::FileHashes;

/// Maximum single file size to scan (512 MB).
/// Modern app binaries (especially large Swift/ObjC apps) can exceed 200 MB.
/// The total extracted size cap (MAX_TOTAL_EXTRACTED) provides zip bomb protection.
const MAX_IN_MEMORY: u64 = 512 * 1024 * 1024;

/// Default cap on total decompressed size across all files (4 GB), summed
/// over declared sizes; `UnpackedArchive::read` rejects entries that inflate
/// past theirs. Large legitimate apps (e.g. emulator bundles) can exceed
/// 2 GB decompressed. The server passes a lower cap.
pub const MAX_TOTAL_EXTRACTED: u64 = 4 * 1024 * 1024 * 1024;

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
    /// Executables of app extensions (`PlugIns/*.appex`, `Extensions/*.appex`)
    pub extension_binary_paths: Vec<String>,
}

pub fn unpack(path: &Path) -> Result<IpaUnpackResult> {
    unpack_with_limit(path, MAX_TOTAL_EXTRACTED)
}

/// Unpack with a cap on total decompressed bytes (by declared size).
///
/// Only the ZIP directory is read up front; small lookup files and the main
/// binary are inflated here, everything else lazily via `UnpackedArchive::read`.
pub fn unpack_with_limit(path: &Path, max_total: u64) -> Result<IpaUnpackResult> {
    let open = || {
        std::fs::File::open(path).with_context(|| format!("Failed to read IPA: {}", path.display()))
    };
    // Hash by streaming (the IPA itself is never held in RAM), overlapped with
    // reading the ZIP directory.
    let (hashes, unpacked) = rayon::join(
        || hash_file(open()?).with_context(|| format!("Failed to read IPA: {}", path.display())),
        || unpack_entries(open()?, max_total),
    );
    let (archive, bundle_prefix, main_binary_path) = unpacked?;
    let hashes = hashes?;
    debug!("Bundle prefix: {:?}", bundle_prefix);
    debug!("Main binary path: {:?}", main_binary_path);

    let framework_binary_paths = find_framework_binaries(&archive.files, &bundle_prefix);
    debug!("Framework binaries: {:?}", framework_binary_paths);

    let extension_binary_paths = find_extension_binaries(&archive.files, &bundle_prefix);
    debug!("Extension binaries: {:?}", extension_binary_paths);

    Ok(IpaUnpackResult {
        archive,
        hashes,
        main_binary_path,
        bundle_prefix,
        framework_binary_paths,
        extension_binary_paths,
    })
}

/// Files kept in memory after unpacking: small, and read by several checks.
fn is_retained(path: &str) -> bool {
    const SUFFIXES: &[&str] = &[
        ".plist",
        ".xcprivacy",
        ".mobileprovision",
        "/Podfile.lock",
        "/Package.resolved",
    ];
    SUFFIXES.iter().any(|s| path.ends_with(s))
}

type Entries = (UnpackedArchive, Option<String>, Option<String>);

fn unpack_entries(file: std::fs::File, max_total: u64) -> Result<Entries> {
    let reader = SharedFile::new(file).context("Failed to read IPA")?;
    let mut zip = ZipArchive::new(reader).context("Failed to open IPA as ZIP archive")?;

    let entry_count = zip.len();
    debug!("IPA contains {} entries", entry_count);
    if entry_count > MAX_ENTRY_COUNT {
        anyhow::bail!(
            "ZIP contains {} entries (limit: {}). Possible zip bomb.",
            entry_count,
            MAX_ENTRY_COUNT
        );
    }

    // --- 1. Directory pass: names and sizes only, nothing is inflated ---
    let mut names = Vec::with_capacity(entry_count);
    let mut files: Vec<ExtractedFile> = Vec::new();
    let mut total_declared: u64 = 0;

    for index in 0..entry_count {
        // by_index_raw skips decompression — only metadata is needed.
        let entry = zip
            .by_index_raw(index)
            .context("Failed to read ZIP entry")?;
        let name = entry_name(&entry);
        let (size, compressed) = (entry.size(), entry.compressed_size());
        drop(entry);
        names.push(name.clone());

        // Skip directory entries
        if name.ends_with('/') {
            continue;
        }

        // Defense-in-depth: reject path traversal attempts (ZIP slip)
        if name.contains("..") || name.starts_with('/') {
            debug!("Skipping suspicious ZIP entry (path traversal): {}", name);
            continue;
        }

        // Check compression ratio for bomb detection
        if compressed > 0 && size / compressed > MAX_COMPRESSION_RATIO {
            debug!(
                "Skipping suspicious entry (ratio {}:1): {}",
                size / compressed,
                name
            );
            continue;
        }

        if size > MAX_IN_MEMORY {
            debug!("Skipping large file ({}MB): {}", size / 1024 / 1024, name);
            continue;
        }

        total_declared += size;
        if total_declared > max_total {
            anyhow::bail!(
                "Total decompressed size exceeds {} MB limit. Possible zip bomb.",
                max_total / (1024 * 1024)
            );
        }

        files.push(ExtractedFile {
            path: name,
            size,
            index,
            data: None,
        });
    }

    let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let bundle_prefix = find_bundle_prefix_in_names(&name_refs);

    // --- 2. Inflate the lookup files, then the executable Info.plist names ---
    load(&zip, &mut files, |f| is_retained(&f.path))?;
    let main_binary_path = resolve_main_binary_path(&files, &bundle_prefix);
    if let Some(main) = &main_binary_path {
        load(&zip, &mut files, |f| &f.path == main)?;
    }

    Ok((
        UnpackedArchive { files, zip },
        bundle_prefix,
        main_binary_path,
    ))
}

/// Inflate the selected entries in parallel and keep them in memory.
fn load(
    zip: &ZipArchive<SharedFile>,
    files: &mut [ExtractedFile],
    select: impl Fn(&ExtractedFile) -> bool + Sync,
) -> Result<()> {
    files
        .par_iter_mut()
        .filter(|f| f.data.is_none() && select(f))
        .try_for_each(|f| {
            f.data = Some(decompress(&mut zip.clone(), f)?);
            Ok(())
        })
}

fn hash_file(mut file: std::fs::File) -> std::io::Result<FileHashes> {
    let (mut md5, mut sha1, mut sha256) = (Md5::new(), Sha1::new(), Sha256::new());
    let mut buf = vec![0u8; 1024 * 1024];
    let mut size_bytes = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        md5.update(&buf[..n]);
        sha1.update(&buf[..n]);
        sha256.update(&buf[..n]);
        size_bytes += n as u64;
    }
    Ok(FileHashes {
        md5: hex::encode(md5.finalize()),
        sha1: hex::encode(sha1.finalize()),
        sha256: hex::encode(sha256.finalize()),
        size_bytes,
    })
}

/// Entry name, preferring the raw bytes when they are valid UTF-8. Entries
/// without the ZIP UTF-8 flag are decoded as CP437 by `name()`, which mangles
/// non-ASCII bundle names (e.g. Hebrew) so the executable named in Info.plist
/// is never found.
fn entry_name(entry: &zip::read::ZipFile<'_>) -> String {
    match std::str::from_utf8(entry.name_raw()) {
        Ok(s) => s.to_string(),
        Err(_) => entry.name().to_string(),
    }
}

fn find_bundle_prefix_in_names(names: &[&str]) -> Option<String> {
    // Standard layout: Payload/<App>.app/Info.plist
    for &name in names {
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
    // Unsigned/sideload layout: <App>.app/Info.plist at the archive root
    // (no Payload/ wrapper). Require the .app suffix so nested resource
    // bundles like Foo.bundle/Info.plist don't match.
    for &name in names {
        if let Some(prefix) = name.strip_suffix("/Info.plist") {
            if prefix.ends_with(".app") && !prefix.contains('/') {
                return Some(prefix.to_string());
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

    let exec_name = bundle_executable(plist_file.data.as_deref()?)?;
    Some(format!("{}/{}", prefix, exec_name))
}

/// `CFBundleExecutable` from an Info.plist (binary or XML).
fn bundle_executable(plist_data: &[u8]) -> Option<String> {
    let value: plist::Value = plist::from_bytes(plist_data).ok()?;
    let exec = value
        .as_dictionary()?
        .get("CFBundleExecutable")?
        .as_string()?;
    // A name with a path separator would point outside the bundle.
    (!exec.is_empty() && !exec.contains('/')).then(|| exec.to_string())
}

/// Executables of app extensions directly under the main bundle:
/// `PlugIns/<X>.appex` (NSExtension) and `Extensions/<X>.appex` (ExtensionKit).
fn find_extension_binaries(files: &[ExtractedFile], bundle_prefix: &Option<String>) -> Vec<String> {
    let Some(prefix) = bundle_prefix else {
        return Vec::new();
    };
    let mut result = Vec::new();
    for dir in ["PlugIns", "Extensions"] {
        let base = format!("{}/{}/", prefix, dir);
        for f in files {
            let Some(rel) = f.path.strip_prefix(&base) else {
                continue;
            };
            let Some(appex) = rel.strip_suffix("/Info.plist") else {
                continue;
            };
            if !appex.ends_with(".appex") || appex.contains('/') {
                continue;
            }
            let Some(exec) = f.data.as_deref().and_then(bundle_executable) else {
                continue;
            };
            let bin_path = format!("{}{}/{}", base, appex, exec);
            if files.iter().any(|b| b.path == bin_path) {
                result.push(bin_path);
            }
        }
    }
    result.sort();
    result
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_prefix_standard_payload_layout() {
        let names = [
            "Payload/MyApp.app/Info.plist",
            "Payload/MyApp.app/Frameworks/Foo.framework/Info.plist",
        ];
        assert_eq!(
            find_bundle_prefix_in_names(&names),
            Some("Payload/MyApp.app".to_string())
        );
    }

    #[test]
    fn bundle_prefix_root_app_layout() {
        // Unsigned IPAs (e.g. Mattermost) put <App>.app at the archive root.
        let names = [
            "Mattermost.app/SwiftyJSON.bundle/Info.plist",
            "Mattermost.app/Info.plist",
        ];
        assert_eq!(
            find_bundle_prefix_in_names(&names),
            Some("Mattermost.app".to_string())
        );
    }

    #[test]
    fn bundle_prefix_payload_wins_over_root() {
        let names = ["Stray.app/Info.plist", "Payload/Real.app/Info.plist"];
        assert_eq!(
            find_bundle_prefix_in_names(&names),
            Some("Payload/Real.app".to_string())
        );
    }

    #[test]
    fn bundle_prefix_ignores_root_resource_bundles() {
        let names = ["Foo.bundle/Info.plist", "docs/readme.txt"];
        assert_eq!(find_bundle_prefix_in_names(&names), None);
    }
}
