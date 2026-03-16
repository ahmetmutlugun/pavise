pub mod ipa;
pub mod apk;

/// Represents a file extracted from the archive, held in memory.
#[derive(Debug)]
pub struct ExtractedFile {
    /// Path within the archive (e.g., "Payload/App.app/Info.plist")
    pub path: String,
    /// Raw file contents
    pub data: Vec<u8>,
}

/// Result of unpacking an archive
pub struct UnpackedArchive {
    /// All files extracted in memory (small files only; large ones memory-mapped)
    pub files: Vec<ExtractedFile>,
}

impl UnpackedArchive {
    pub fn find(&self, path_suffix: &str) -> Option<&ExtractedFile> {
        self.files.iter().find(|f| f.path.ends_with(path_suffix))
    }

    pub fn find_all<'a>(&'a self, path_suffix: &'a str) -> impl Iterator<Item = &'a ExtractedFile> {
        self.files.iter().filter(move |f| f.path.ends_with(path_suffix))
    }

    pub fn filter_prefix<'a>(&'a self, prefix: &'a str) -> impl Iterator<Item = &'a ExtractedFile> {
        self.files.iter().filter(move |f| f.path.starts_with(prefix))
    }
}
