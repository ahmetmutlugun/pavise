//! PDF report generation.
//!
//! The PDF is a brief, human-oriented summary — not a dump of the scan. It has
//! its own template (`templates/report.pdf.tera`) in the Pavise design system
//! (cream / navy / mint, Bricolage Grotesque, DM Sans, JetBrains Mono — fonts
//! embedded from `assets/fonts/`, so rendering never touches the network).
//!
//! Everything the template shows is pre-shaped by `report::view` (with
//! `PDF_LIMITS`): findings are grouped by rule, evidence is capped, and every
//! untrusted string is cleaned and length-bounded so long names/paths cannot
//! break the layout. Headless Chrome then prints the HTML to A4. It needs a
//! Chrome/Chromium binary on the host (`$CHROME` overrides auto-detection).

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use base64::Engine;
use headless_chrome::types::PrintToPdfOptions;
use headless_chrome::{Browser, LaunchOptions};
use tera::{Context as TeraContext, Tera};

use super::view::{self, clip, version_label, PDF_LIMITS};
use crate::types::ScanReport;

const TEMPLATE: &str = include_str!("../../templates/report.pdf.tera");
const FONT_DISPLAY: &[u8] = include_bytes!("../../assets/fonts/bricolage-grotesque.woff2");
const FONT_BODY: &[u8] = include_bytes!("../../assets/fonts/dm-sans.woff2");
const FONT_MONO: &[u8] = include_bytes!("../../assets/fonts/jetbrains-mono.woff2");

// A4 in inches — a fallback only; the template's `@page` rule wins.
const A4_WIDTH_IN: f64 = 8.27;
const A4_HEIGHT_IN: f64 = 11.69;

/// Default render budget for `to_bytes`.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

/// Compile a `ScanReport` to a PDF and return the raw bytes.
pub fn to_bytes(report: &ScanReport) -> Result<Vec<u8>> {
    to_bytes_with_timeout(report, DEFAULT_TIMEOUT)
}

/// Like `to_bytes`, but every Chrome call is bounded by what is left of
/// `timeout`, so the function itself returns — and Chrome is killed when the
/// `Browser` drops — within roughly that budget. A caller-side timeout alone
/// would abandon the thread and leave Chrome running.
pub fn to_bytes_with_timeout(report: &ScanReport, timeout: Duration) -> Result<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    let remaining = || {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .context("PDF generation timed out")
    };

    let html = render_html(report)?;

    // Chrome loads the document from disk via a file:// URL. A temp dir keeps
    // the file isolated and auto-removed when it drops.
    let tmp = tempfile::tempdir().context("Failed to create temp directory")?;
    let html_path = tmp.path().join("report.html");
    std::fs::write(&html_path, html.as_bytes()).context("Failed to write temp HTML for PDF")?;
    let url = format!("file://{}", html_path.display());

    let options = LaunchOptions::default_builder()
        .headless(true)
        // Disable the sandbox so generation also works as root / in containers
        // (common on servers); the page is our own template with escaped data.
        .sandbox(false)
        .idle_browser_timeout(timeout)
        .build()
        .context("Failed to build Chrome launch options")?;

    let browser = Browser::new(options).context(
        "Failed to launch headless Chrome for PDF generation. \
         A Chrome or Chromium binary must be installed on the host.",
    )?;

    let tab = browser.new_tab().context("Failed to open a browser tab")?;
    tab.set_default_timeout(remaining()?);
    tab.navigate_to(&url)
        .context("Failed to load the report into the browser")?;
    tab.set_default_timeout(remaining()?);
    tab.wait_until_navigated()
        .context("Report page did not finish loading")?;
    // Embedded fonts decode asynchronously; printing before they are ready
    // would fall back to system fonts.
    tab.set_default_timeout(remaining()?);
    tab.evaluate("document.fonts.ready.then(() => true)", true)
        .context("Report fonts did not finish loading")?;

    tab.set_default_timeout(remaining()?);
    let pdf = tab
        .print_to_pdf(Some(pdf_options()))
        .context("Chrome failed to print the report to PDF")?;

    Ok(pdf)
}

/// Render the print-ready HTML that Chrome turns into the PDF.
pub fn render_html(report: &ScanReport) -> Result<String> {
    let mut tera = Tera::default();
    // The `.html` suffix turns on Tera's autoescaping — every value in the
    // view model comes from the scanned app and must be treated as untrusted.
    tera.add_raw_template("report.pdf.html", TEMPLATE)
        .context("Failed to load PDF report template")?;

    let mut ctx = TeraContext::new();
    ctx.insert("r", &view::build(report, &PDF_LIMITS));
    ctx.insert("fonts_css", fonts_css());
    ctx.insert("footer_css", &footer_css(report));
    tera.render("report.pdf.html", &ctx)
        .context("Failed to render PDF report template")
}

fn fonts_css() -> &'static str {
    static CSS: OnceLock<String> = OnceLock::new();
    CSS.get_or_init(|| {
        let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        [
            ("Bricolage Grotesque", "600 800", FONT_DISPLAY),
            ("DM Sans", "400 700", FONT_BODY),
            ("JetBrains Mono", "400 600", FONT_MONO),
        ]
        .iter()
        .map(|(family, weight, data)| {
            format!(
                "@font-face{{font-family:'{family}';font-weight:{weight};font-style:normal;\
                 src:url(data:font/woff2;base64,{}) format('woff2')}}",
                b64(data)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
    })
}

// ─── Chrome print settings ───────────────────────────────────────────────────

fn pdf_options() -> PrintToPdfOptions {
    // Page size, margins, background and the running footer all come from the
    // template's `@page` rules (margin boxes), so the page reads as full-bleed
    // cream and the footer uses the embedded fonts.
    PrintToPdfOptions {
        landscape: Some(false),
        display_header_footer: Some(false),
        print_background: Some(true),
        scale: Some(1.0),
        paper_width: Some(A4_WIDTH_IN),
        paper_height: Some(A4_HEIGHT_IN),
        margin_top: Some(0.0),
        margin_bottom: Some(0.0),
        margin_left: Some(0.0),
        margin_right: Some(0.0),
        prefer_css_page_size: Some(true),
        ..Default::default()
    }
}

/// The running footer's left text, as a CSS string literal.
fn footer_css(r: &ScanReport) -> String {
    let name = match clip(&r.app_info.name, 48) {
        n if n.is_empty() => "Unnamed app".to_string(),
        n => n,
    };
    let mut text = format!("Pavise  /  {name}");
    let ver = version_label(&r.app_info.version);
    if !ver.is_empty() {
        text.push_str(&format!(" v{ver}"));
    }
    text.push_str(&format!("  /  Grade {}", clip(&r.grade, 2)));
    css_string(&text)
}

/// Quote an untrusted string as a CSS string literal for the `@page` footer.
/// Everything outside a small safe set is hex-escaped, so it can neither end
/// the string nor the enclosing `<style>` element.
fn css_string(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '-' | '_' | ',' | '(' | ')') {
            out.push(c);
        } else {
            out.push_str(&format!("\\{:x} ", c as u32));
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn css_string_cannot_escape_style() {
        let q = css_string("a\"</style><script>x'\\");
        assert!(q.starts_with('"') && q.ends_with('"'));
        let inner = &q[1..q.len() - 1];
        assert!(!inner.contains(['"', '<', '>', '\'']));
    }
}
