//! Render a PDF (or its HTML with `--html`) from a saved JSON report.
//! Handy for iterating on `templates/report.pdf.tera` without rescanning:
//!
//!     cargo run --example pdf_from_json -- report.json out.pdf [--html]
use anyhow::{Context, Result};
use pavise::{report::pdf, types::ScanReport};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [input, output, rest @ ..] = args.as_slice() else {
        anyhow::bail!("usage: pdf_from_json <report.json> <out.pdf> [--html]");
    };
    let json = std::fs::read_to_string(input).with_context(|| format!("read {input}"))?;
    let report: ScanReport = serde_json::from_str(&json).context("parse report JSON")?;
    if rest.iter().any(|a| a == "--html") {
        std::fs::write(output, pdf::render_html(&report)?)?;
    } else {
        std::fs::write(output, pdf::to_bytes(&report)?)?;
    }
    Ok(())
}
