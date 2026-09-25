# Scan page (`/scan`)

`web/scan.html` + `web/src/scripts/scan.ts` + `web/src/styles/scan.css`, built by
Vite into `web/dist/`. The result area is a server-rendered fragment.

## Result fragment

`report::web::fragment()` renders `templates/scan_result.html.tera` from the
**same view model as the PDF** (`src/report/view.rs`, `WEB_LIMITS` vs
`PDF_LIMITS`). Counts, grouping (`×N`), verdict, OWASP grid and secret masking
therefore always match the PDF. Change grouping or wording in `view.rs`, not in
a template.

- Served by `POST /api/upload/:id/scan`, `POST /api/scan` (browser UA) and
  `GET /api/scan/:id` (history).
- All groups are listed as collapsed `<details>` cards. Filters (To fix / Info /
  All) toggle `data-filter` on `.rs-list`. CSS hides the rest, so the fragment
  still reads fine without JS.
- `scan.ts` reads `data-scan-id|name|grade|score` off `.rs` for history. Don't
  scrape text nodes.
- The client still runs `sanitizeHtml` over every fragment (defence in depth).

## Status indicators must reflect reality

| Step | Source of truth |
|---|---|
| Upload | XHR `upload.onprogress` byte counts per 50 MB chunk (fetch can't report request-body progress) |
| Analyse | Indeterminate bar + elapsed time. The server has no progress events |
| Busy | `503` + `Retry-After`: client retries up to 20×, showing a countdown. The upload session is kept |
| Failed | HTTP status of the error fragment (`422` bad IPA, `404` expired, `500`) |
| Cancelled | `AbortController` aborts the XHR/fetch |

Don't reintroduce timer-driven "phases": they claimed steps were done while
the upload was still running.

Other facts shown on the page come from the server:
- The upload limit comes from `<meta name="pavise-max-upload-bytes">`, which
  `serve_html` fills from `PAVISE_MAX_UPLOAD_BYTES`. The fallback of 512 MiB
  applies under `vite dev`.
- History entries older than `RESULT_TTL` (1 h), or that returned 404, are
  shown as expired.
- PDF/JSON downloads are fetched as blobs, so render time ("Rendering PDF…")
  and errors show inline. Otherwise a 503 would save as a broken `.pdf`.

## Layout

With a result on screen (`.page.has-results`), the hero hides and the drop zone
becomes a one-line strip. The previous result is dimmed (`#results.is-stale`)
while a new scan runs.

`.page` needs `grid-template-columns: minmax(0, 1fr)`. Without it, nowrap
evidence previews widen the implicit column and phones scroll sideways.

## Gotchas

- `tsconfig.json` has `noEmit`. `tsc` used to emit `.js` next to the `.ts`
  files, and Vite resolves `./scripts/scan` to `.js` first, so stale compiled
  files shadowed the source.
- In `.tera` templates, compute booleans with `{% set %}` before passing them to
  a macro.

## Checking it

```sh
cd web && npm run build && cd .. && cargo run --release --bin pavise-server
# /scan in a browser. Throttle the network in devtools to watch real upload progress.
```
