//! Drop Chromium's files from the page cache after a PDF render.
//!
//! Starting Chrome reads ~250 MB of binary and shared libraries. The kernel
//! charges that cache to the container's cgroup and keeps it until memory runs
//! short, which, under a large limit, is never. Railway's usage-billed memory
//! counts it, so one PDF render would otherwise add ~250 MB for the life of the
//! container. `POSIX_FADV_DONTNEED` needs no privileges and skips pages that
//! are still mapped, so libraries this server uses stay cached. The next render
//! reads the files from disk again.

use std::path::Path;

/// Debian's `chromium-headless-shell` package and the libraries and fonts it loads.
const DIRS: &[&str] = &[
    "/usr/lib/chromium",
    "/usr/lib/x86_64-linux-gnu",
    "/usr/lib/aarch64-linux-gnu",
    "/usr/share/fonts",
];

/// Directory depth to descend; the trees above are shallow.
const MAX_DEPTH: usize = 6;

/// Evict every regular file under `DIRS` from the page cache. Best effort:
/// missing directories and unreadable files are skipped.
pub fn evict_chromium() {
    let started = std::time::Instant::now();
    let mut files = 0usize;
    for dir in DIRS {
        walk(Path::new(dir), MAX_DEPTH, &mut |path| {
            evict(path);
            files += 1;
        });
    }
    tracing::debug!(
        files,
        elapsed_ms = started.elapsed().as_millis() as u64,
        "Evicted Chromium page cache"
    );
}

/// Call `f` for each regular file under `dir`, without following symlinks.
fn walk(dir: &Path, depth: usize, f: &mut impl FnMut(&Path)) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_file() {
            f(&entry.path());
        } else if kind.is_dir() && depth > 0 {
            walk(&entry.path(), depth - 1, f);
        }
    }
}

#[cfg(target_os = "linux")]
fn evict(path: &Path) {
    if let Ok(file) = std::fs::File::open(path) {
        // Offset 0 with no length covers the whole file.
        let _ = rustix::fs::fadvise(&file, 0, None, rustix::fs::Advice::DontNeed);
    }
}

#[cfg(not(target_os = "linux"))]
fn evict(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walk_visits_regular_files_only_within_depth() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("a.so"), b"x").unwrap();
        std::fs::create_dir_all(root.join("d1/d2")).unwrap();
        std::fs::write(root.join("d1/b.so"), b"x").unwrap();
        std::fs::write(root.join("d1/d2/c.so"), b"x").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(root.join("d1"), root.join("link")).unwrap();

        let mut seen = Vec::new();
        walk(root, 1, &mut |p| {
            seen.push(p.strip_prefix(root).unwrap().to_path_buf())
        });
        seen.sort();
        assert_eq!(seen, [Path::new("a.so"), Path::new("d1/b.so")]);
    }

    #[test]
    fn evict_tolerates_missing_paths() {
        evict(Path::new("/nonexistent/pavise-page-cache-test"));
        walk(Path::new("/nonexistent/pavise"), MAX_DEPTH, &mut |_| {});
    }
}
