//! PDF report generation using Typst as a library.
//!
//! The Typst template is embedded at compile time. JSON is written to a temp
//! directory so the Typst `json()` function can load it during compilation.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use typst::diag::{eco_format, FileError, FileResult, PackageError, PackageResult};
use typst::foundations::{Bytes, Datetime};
use typst::syntax::package::PackageSpec;
use typst::syntax::{FileId, Source};
use typst::text::{Font, FontBook};
use typst::utils::LazyHash;
use typst::Library;
use typst_kit::fonts::{FontSearcher, FontSlot};

use crate::types::ScanReport;

const TEMPLATE: &str = include_str!("../../templates/report.typ");

/// Compile a ScanReport to a PDF and return the raw bytes.
pub fn to_bytes(report: &ScanReport) -> Result<Vec<u8>> {
    let json_str = serde_json::to_string_pretty(report)
        .context("Failed to serialize report to JSON")?;

    // Write the JSON to a temp dir so Typst's json() function can read it.
    let tmp = tempfile::tempdir().context("Failed to create temp directory")?;
    std::fs::write(tmp.path().join("scan_report.json"), &json_str)
        .context("Failed to write scan_report.json to temp directory")?;

    let world = TypstWrapperWorld::new(
        tmp.path().to_string_lossy().into_owned(),
        TEMPLATE.to_string(),
    );

    let result = typst::compile(&world);

    for w in &result.warnings {
        tracing::debug!("typst warning: {}", w.message);
    }

    let document = result.output.map_err(|errors| {
        let msgs: Vec<String> = errors.iter().map(|e| e.message.to_string()).collect();
        anyhow::anyhow!("Typst compilation failed:\n{}", msgs.join("\n"))
    })?;

    let pdf_bytes = typst_pdf::pdf(&document, &typst_pdf::PdfOptions::default())
        .map_err(|e| anyhow::anyhow!("PDF export failed: {:?}", e))?;

    Ok(pdf_bytes)
}

// ─── TypstWrapperWorld ────────────────────────────────────────────────────────

struct TypstWrapperWorld {
    root: PathBuf,
    source: Source,
    library: LazyHash<Library>,
    book: LazyHash<FontBook>,
    fonts: Vec<FontSlot>,
    files: Arc<Mutex<HashMap<FileId, FileEntry>>>,
    cache_directory: PathBuf,
    http: ureq::Agent,
    time: time::OffsetDateTime,
}

impl TypstWrapperWorld {
    fn new(root: String, source: String) -> Self {
        let root = PathBuf::from(root);
        let fonts = FontSearcher::new().include_system_fonts(true).search();
        Self {
            library: LazyHash::new(Library::default()),
            book: LazyHash::new(fonts.book),
            root,
            fonts: fonts.fonts,
            source: Source::detached(source),
            time: time::OffsetDateTime::now_utc(),
            cache_directory: std::env::var_os("CACHE_DIRECTORY")
                .map(|p| p.into())
                .unwrap_or_else(std::env::temp_dir),
            http: ureq::Agent::new(),
            files: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn load_file(&self, id: FileId) -> FileResult<FileEntry> {
        let mut files = self.files.lock().map_err(|_| FileError::AccessDenied)?;
        if let Some(entry) = files.get(&id) {
            return Ok(entry.clone());
        }
        let path = if let Some(package) = id.package() {
            let pkg_dir = self.download_package(package)?;
            id.vpath().resolve(&pkg_dir)
        } else {
            id.vpath().resolve(&self.root)
        }
        .ok_or(FileError::AccessDenied)?;

        let content =
            std::fs::read(&path).map_err(|e| FileError::from_io(e, &path))?;
        Ok(files
            .entry(id)
            .or_insert(FileEntry::new(content, None))
            .clone())
    }

    fn download_package(&self, package: &PackageSpec) -> PackageResult<PathBuf> {
        let subdir =
            format!("{}/{}/{}", package.namespace, package.name, package.version);
        let path = self.cache_directory.join(subdir);
        if path.exists() {
            return Ok(path);
        }

        let url = format!(
            "https://packages.typst.org/{}/{}-{}.tar.gz",
            package.namespace, package.name, package.version,
        );

        let response = retry(|| {
            let resp = self
                .http
                .get(&url)
                .call()
                .map_err(|e| eco_format!("{e}"))?;
            if resp.status() / 100 != 2 {
                return Err(eco_format!("HTTP {}", resp.status()));
            }
            Ok(resp)
        })
        .map_err(|e| PackageError::NetworkFailed(Some(e)))?;

        let mut compressed = Vec::new();
        response
            .into_reader()
            .read_to_end(&mut compressed)
            .map_err(|e| PackageError::NetworkFailed(Some(eco_format!("{e}"))))?;

        let raw = zune_inflate::DeflateDecoder::new(&compressed)
            .decode_gzip()
            .map_err(|e| PackageError::MalformedArchive(Some(eco_format!("{e}"))))?;

        let mut archive = tar::Archive::new(raw.as_slice());
        archive.unpack(&path).map_err(|e| {
            let _ = std::fs::remove_dir_all(&path);
            PackageError::MalformedArchive(Some(eco_format!("{e}")))
        })?;

        Ok(path)
    }
}

// ─── typst::World impl ───────────────────────────────────────────────────────

impl typst::World for TypstWrapperWorld {
    fn library(&self) -> &LazyHash<Library> {
        &self.library
    }
    fn book(&self) -> &LazyHash<FontBook> {
        &self.book
    }
    fn main(&self) -> FileId {
        self.source.id()
    }
    fn source(&self, id: FileId) -> FileResult<Source> {
        if id == self.source.id() {
            Ok(self.source.clone())
        } else {
            self.load_file(id)?.source(id)
        }
    }
    fn file(&self, id: FileId) -> FileResult<Bytes> {
        self.load_file(id).map(|f| f.bytes.clone())
    }
    fn font(&self, id: usize) -> Option<Font> {
        self.fonts[id].get()
    }
    fn today(&self, offset: Option<i64>) -> Option<Datetime> {
        let off = offset.unwrap_or(0);
        let utc = time::UtcOffset::from_hms(off.try_into().ok()?, 0, 0).ok()?;
        let dt = self.time.checked_to_offset(utc)?;
        Some(Datetime::Date(dt.date()))
    }
}

// ─── FileEntry ────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct FileEntry {
    bytes: Bytes,
    source: Option<Source>,
}

impl FileEntry {
    fn new(bytes: Vec<u8>, source: Option<Source>) -> Self {
        Self { bytes: bytes.into(), source }
    }

    fn source(&mut self, id: FileId) -> FileResult<Source> {
        let source = if let Some(s) = &self.source {
            s
        } else {
            let text = std::str::from_utf8(&self.bytes)
                .map_err(|_| FileError::InvalidUtf8)?;
            let text = text.trim_start_matches('\u{feff}');
            let s = Source::new(id, text.into());
            self.source.insert(s)
        };
        Ok(source.clone())
    }
}

// ─── helpers ─────────────────────────────────────────────────────────────────

fn retry<T, E>(mut f: impl FnMut() -> Result<T, E>) -> Result<T, E> {
    match f() {
        Ok(v) => Ok(v),
        Err(_) => f(),
    }
}
