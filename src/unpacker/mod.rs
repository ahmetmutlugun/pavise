pub mod ipa;

use anyhow::{Context, Result};
use std::borrow::Cow;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::sync::Arc;
use zip::ZipArchive;

/// One file in the archive.
///
/// Contents are kept in memory only for files several checks look up
/// (plists, provisioning profile, lock files, the main binary). Everything
/// else is decompressed on demand by [`UnpackedArchive::read`], so a scan never
/// holds the whole decompressed IPA at once.
#[derive(Debug)]
pub struct ExtractedFile {
    /// Path within the archive (e.g., "Payload/App.app/Info.plist")
    pub path: String,
    /// Declared uncompressed size
    pub size: u64,
    index: usize,
    data: Option<Vec<u8>>,
}

/// Result of unpacking an archive
pub struct UnpackedArchive {
    /// Every file entry that passed the zip-bomb checks
    pub files: Vec<ExtractedFile>,
    zip: ZipArchive<SharedFile>,
}

impl UnpackedArchive {
    /// Contents of `file`: borrowed if kept at unpack time, otherwise
    /// decompressed now. Fails if the entry inflates past its declared size.
    pub fn read<'a>(&'a self, file: &'a ExtractedFile) -> Result<Cow<'a, [u8]>> {
        match &file.data {
            Some(data) => Ok(Cow::Borrowed(data)),
            None => decompress(&mut self.zip.clone(), file).map(Cow::Owned),
        }
    }

    pub fn find(&self, path_suffix: &str) -> Option<&ExtractedFile> {
        self.files.iter().find(|f| f.path.ends_with(path_suffix))
    }

    pub fn find_all<'a>(&'a self, path_suffix: &'a str) -> impl Iterator<Item = &'a ExtractedFile> {
        self.files
            .iter()
            .filter(move |f| f.path.ends_with(path_suffix))
    }

    pub fn filter_prefix<'a>(&'a self, prefix: &'a str) -> impl Iterator<Item = &'a ExtractedFile> {
        self.files
            .iter()
            .filter(move |f| f.path.starts_with(prefix))
    }
}

/// Inflate one entry. The declared size is attacker-controlled: read at most
/// one byte past it, so a lying header can't decompress more than it claimed.
fn decompress(zip: &mut ZipArchive<SharedFile>, file: &ExtractedFile) -> Result<Vec<u8>> {
    let entry = zip
        .by_index(file.index)
        .with_context(|| format!("Failed to read ZIP entry '{}'", file.path))?;
    // Exact capacity: growing by doubling would briefly need up to 2x the file.
    let mut data = Vec::with_capacity(file.size as usize);
    entry
        .take(file.size + 1)
        .read_to_end(&mut data)
        .with_context(|| format!("Failed to decompress ZIP entry '{}'", file.path))?;
    if data.len() as u64 > file.size {
        anyhow::bail!(
            "ZIP entry '{}' decompresses past its declared size ({} bytes). Possible zip bomb.",
            file.path,
            file.size
        );
    }
    Ok(data)
}

/// `Read + Seek` over a shared file handle using positional reads, so clones
/// (one per thread) decompress different entries concurrently.
#[derive(Clone)]
struct SharedFile {
    file: Arc<File>,
    len: u64,
    pos: u64,
}

impl SharedFile {
    fn new(file: File) -> io::Result<Self> {
        let len = file.metadata()?.len();
        Ok(SharedFile {
            file: Arc::new(file),
            len,
            pos: 0,
        })
    }
}

impl Read for SharedFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        #[cfg(unix)]
        let n = std::os::unix::fs::FileExt::read_at(&*self.file, buf, self.pos)?;
        #[cfg(windows)]
        let n = std::os::windows::fs::FileExt::seek_read(&*self.file, buf, self.pos)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for SharedFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let target = match pos {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::End(off) => self.len.checked_add_signed(off),
            SeekFrom::Current(off) => self.pos.checked_add_signed(off),
        };
        self.pos = target.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "seek before start of file")
        })?;
        Ok(self.pos)
    }
}

/// Caps the bytes of inflated files a scan holds at once. Parallel workers
/// acquire a file's size before reading it and block while the budget is
/// spent; a file larger than the whole budget runs alone.
pub struct ByteBudget {
    cap: u64,
    available: std::sync::Mutex<u64>,
    freed: std::sync::Condvar,
}

impl ByteBudget {
    pub fn new(cap: u64) -> Self {
        ByteBudget {
            cap,
            available: std::sync::Mutex::new(cap),
            freed: std::sync::Condvar::new(),
        }
    }

    /// Block until `bytes` (clamped to the cap) are free and take them. The
    /// holder must not wait on other budget holders (e.g. nested rayon work).
    pub fn acquire(&self, bytes: u64) -> BudgetPermit<'_> {
        let bytes = bytes.min(self.cap);
        let mut available = self.available.lock().unwrap_or_else(|e| e.into_inner());
        while *available < bytes {
            available = self
                .freed
                .wait(available)
                .unwrap_or_else(|e| e.into_inner());
        }
        *available -= bytes;
        BudgetPermit {
            budget: self,
            bytes,
        }
    }
}

/// Returns its bytes to the [`ByteBudget`] on drop.
pub struct BudgetPermit<'a> {
    budget: &'a ByteBudget,
    bytes: u64,
}

impl Drop for BudgetPermit<'_> {
    fn drop(&mut self) {
        let mut available = self
            .budget
            .available
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *available += self.bytes;
        self.budget.freed.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_blocks_until_bytes_are_returned() {
        let budget = std::sync::Arc::new(ByteBudget::new(100));
        let first = budget.acquire(80);
        let (tx, rx) = std::sync::mpsc::channel();
        let b = std::sync::Arc::clone(&budget);
        let waiter = std::thread::spawn(move || {
            let _p = b.acquire(50);
            tx.send(()).unwrap();
        });
        assert!(rx
            .recv_timeout(std::time::Duration::from_millis(100))
            .is_err());
        drop(first);
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .expect("waiter proceeds once bytes are freed");
        waiter.join().unwrap();
        // Oversized requests are clamped so they can still run alone.
        drop(budget.acquire(1_000));
    }
}
