//! The scan page's result fragment (`GET /api/scan/:id`, and the body the
//! upload endpoints return to the browser).
//!
//! It renders the same view model as the PDF (`report::view`), with
//! `WEB_LIMITS`: every finding group is listed (collapsed), so the page and
//! the PDF always agree on counts, grouping, verdict and OWASP mapping.

use std::sync::OnceLock;

use anyhow::{Context, Result};
use tera::{Context as TeraContext, Tera};

use super::view::{self, WEB_LIMITS};
use crate::types::ScanReport;

const TEMPLATE: &str = include_str!("../../templates/scan_result.html.tera");

fn tera() -> &'static Tera {
    static TERA: OnceLock<Tera> = OnceLock::new();
    TERA.get_or_init(|| {
        let mut tera = Tera::default();
        // `.html` turns on autoescaping: the view model holds untrusted strings.
        tera.add_raw_template("scan_result.html", TEMPLATE)
            .expect("scan_result template is valid");
        tera
    })
}

/// Render the result fragment for a stored scan.
///
/// `id` is the server-issued scan id used for the download links; `cached`
/// marks a result reused from an identical earlier upload.
pub fn fragment(id: &str, report: &ScanReport, cached: bool) -> Result<String> {
    let mut ctx = TeraContext::new();
    ctx.insert("r", &view::build(report, &WEB_LIMITS));
    ctx.insert("id", id);
    ctx.insert("cached", &cached);
    tera()
        .render("scan_result.html", &ctx)
        .context("Failed to render scan result fragment")
}
