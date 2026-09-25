# Web server (`pavise-server`)

`src/serve.rs` only sets up tracing, reads config and binds the listener. Routing,
handlers and middleware live in `src/server/` (`build_router`), so
`tests/server_integration.rs` drives the same router production runs.

## Configuration (env, parsed once in `server/config.rs`)

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | 3000 | Listen port |
| `PAVISE_MAX_SCANS` | 4 | Concurrent scans (semaphore) |
| `PAVISE_MAX_UPLOAD_BYTES` | 512 MiB | Max IPA size |
| `PAVISE_MAX_EXTRACTED_BYTES` | 1.5 GiB | Zip-bomb cap on a scan's total declared decompressed size |
| `PAVISE_MAX_IN_FLIGHT_BYTES` | 512 MiB | Inflated file bytes one scan holds at once (peak-memory bound) |
| `PAVISE_MAX_PDF` | 2 | Concurrent headless-Chrome renders |
| `PAVISE_MAX_UPLOAD_SESSIONS` | 16 | Open chunked uploads (2 per IP) |
| `PAVISE_BODY_TIMEOUT_SECS` | 300 | Time to receive one request body |
| `PAVISE_CACHE_MAX_ENTRIES` | 256 | Cap on result store and hash cache (oldest evicted) |
| `PAVISE_CACHE_TTL_HOURS` | 24 | Hash-cache TTL (results: 1 h) |
| `PAVISE_RATE_LIMIT` | 20 | Requests / IP / minute |
| `PAVISE_TRUSTED_PROXY` | unset | Proxy IPs/CIDRs whose forwarding headers are believed |
| `PAVISE_UPLOAD_DIR`, `PAVISE_DIST_DIR`, `PAVISE_LOG_DIR` | | Paths |

Memory budget per scan: main binary + ~1.4 × `PAVISE_MAX_IN_FLIGHT_BYTES` (the
file bytes plus text extracted from them), times `PAVISE_MAX_SCANS`, plus
~250 MB per PDF render. Sizing and measurements: [Railway deploy](deploy-railway.md).

## Client IP / proxies

`CF-Connecting-IP` and `X-Forwarded-For` are only read when the TCP peer matches
`PAVISE_TRUSTED_PROXY` (comma-separated, e.g. `127.0.0.1,172.16.0.0/12`; the
legacy `1`/`true` means loopback + private ranges). From XFF the **rightmost**
hop is used; the leftmost is client-supplied. Unset = headers ignored, so rate
limiting keys on the peer address. Behind a same-host proxy, set it or every
visitor shares the proxy's rate-limit bucket.

## Invariants (tested)

- The scan permit is taken after the upload is fully received and after the
  cache check, and is moved into the blocking task, so disconnects don't free
  a slot while a scan still runs.
- Uploads are `TempPath`s: deleted on success, failure and panic. A busy
  `/api/upload/:id/scan` keeps the session so the client can retry.
- PDF renders hold a `PAVISE_MAX_PDF` permit until Chrome exits;
  `pdf::to_bytes_with_timeout` bounds every Chrome call by the remaining budget.
- ZIP entries are inflated lazily and read through `take(declared + 1)`;
  exceeding the declared size or `max_extracted_bytes` (summed declared sizes)
  fails the scan. The IPA is hashed by streaming.
- TTLs are checked on read, not only by the 10-minute `evict_expired` sweep.
  An oversized direct upload returns 413 even when axum's body limit trips first.

Not handled in-process: slow request *headers* (axum 0.7 `serve` has no header
timeout). Rely on the fronting proxy (Cloudflare) for that.
