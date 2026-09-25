# PDF report

`src/report/pdf.rs` + `templates/report.pdf.tera`. A brief, human summary.
JSON, SARIF and HTML stay the full-data formats.

## Pipeline

1. `report::view::build(report, &PDF_LIMITS)` turns `ScanReport` into a small
   view model (shared with the scan page, see [scan page](scan-page.md)): findings are
   grouped by rule and severity (`×N`), and evidence, detail cards and info rows
   are capped (`PDF_LIMITS`). Every untrusted string goes through `clip`,
   `clip_middle` (for paths) or `mask` (for secrets).
2. Tera renders the template under a `.html` name, so autoescape is on.
3. Headless Chrome loads it from a temp `file://` URL, waits for
   `document.fonts.ready`, and prints it (`to_bytes_with_timeout` bounds every call).

## Layout

- Page 1 always has the masthead (app name, bundle id, grade), severity counts,
  a one-line verdict, **Fix first** (top 8 High/Warning groups, one line each),
  binary hardening and the OWASP Mobile Top 10 grid. Titles and previews are
  single-line with ellipsis, and the name and bundle ID are clamped to two lines,
  so page 1 can't overflow.
- After that: finding cards (at most 25), an informational table (at most 20),
  trackers, and scan details.
- Left out on purpose: domain and email lists, the scan log, framework lists,
  and full evidence.

## Design system

The tokens mirror `web/src/styles/scan.css` (cream `#f4f0e5` page, navy
masthead, mint accents, sev-high/warn/info hues). The fonts are Bricolage
Grotesque, DM Sans and JetBrains Mono. They are embedded from `assets/fonts/`
(latin subsets, OFL, licences alongside) as base64 `@font-face`, so rendering
never hits the network.

## Gotchas

- **Don't use Chrome's `headerTemplate`/`footerTemplate`.** Their boxes span the
  whole page and paint over the content. The footer is an `@page`
  `@bottom-left/right` margin box instead (Chrome 131+). Page size, margins
  and the cream margin background also come from `@page`
  (`prefer_css_page_size: true`, all API margins 0).
- The footer text is dynamic CSS inside `<style>`. HTML escaping means nothing
  there, so it goes through `css_string()` (hex-escapes everything outside a
  safe set).
- `clean()` strips control and bidi-override characters, so a hostile app name
  can't reorder text.

## Iterating

```sh
pavise app.ipa -o r.json
cargo run --release --example pdf_from_json -- r.json out.pdf   # --html for the page
pdftoppm -r 80 -png out.pdf page                                 # eyeball it
```
