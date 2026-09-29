# Deploying on Railway

`railway.json` builds the root `Dockerfile` and health-checks `/healthz`.
`deploy.limitOverride` caps the container at 1 vCPU and 1 GiB. At that size, set
`PAVISE_MAX_SCANS=1`: a single large IPA peaks at ~850 MB (below).
Railway injects `PORT`; the server reads it. The Dockerfile `HEALTHCHECK` is
ignored there (docker-compose still uses it). Logs go to stderr only;
`PAVISE_LOG_DIR` is set by `docker-compose.yml`, not the image.

Builds: BuildKit cache mounts keep Cargo's registry, `target/` and the npm
cache between builds (ids embed the Railway service id; update the Dockerfile
if the service is recreated). Locally, rebuilds after a source edit or a
dependency change take ~20 s instead of ~100 s; cold builds ~65 s.
`watchPatterns` in `railway.json` skips deploys for docs/benchmarks-only
commits. On a 4 GB build host, pass `CARGO_BUILD_JOBS=2` to avoid OOM.

## Suggested variables

| Variable | Small instance (≤ 2 GB) | Notes |
|---|---|---|
| `PAVISE_MAX_SCANS` | 2 | each scan peaks at ~150–850 MB (below) |
| `PAVISE_MAX_IN_FLIGHT_BYTES` | 268435456 | 256 MiB; trades a little wall time for memory |
| `PAVISE_MAX_PDF` | 1 | one headless-shell render peaks at 125–205 MB |
| `PAVISE_CACHE_MAX_ENTRIES` | 64 | reports are 0.1–0.7 MB each |
| `PAVISE_TRUSTED_PROXY` | Railway's proxy range | otherwise every visitor shares one rate-limit bucket |
| `RAYON_NUM_THREADS` | vCPU count | only if the container sees host cores |

The image sets `MALLOC_ARENA_MAX=2`, `MALLOC_MMAP_THRESHOLD_=131072`,
`MALLOC_TRIM_THRESHOLD_=131072`. Keep them: glibc otherwise holds freed scan
buffers, and usage-billed memory never drops after the first big scan.

A PDF render leaves ~350 MB of Chromium binary and libraries in page cache.
It was measured with `/sys/fs/cgroup/memory.stat` as `anon` 18 MB, `file`
374 MB. Railway's graph (and its bill) counts that cache, and under an 8 GB limit it is never freed.
After each render, the server evicts it with `posix_fadvise(DONTNEED)`
(`src/server/page_cache.rs`): the graph fell from 396 MB to 47 MB. By hand:
`find /usr/lib/chromium -type f -exec dd if={} iflag=nocache count=0 \;`.
The image runs `tini` as PID 1; without it every render left zombie Chrome
helpers behind.

## Measurements (2026-09-25, Linux container, 8 CPUs)

CLI, peak RSS, committed HEAD vs current tree:

| App (IPA size) | Before | After |
|---|---|---|
| Provenance (1 GB) | 3101 MB, failed at 2 GB cap | 831 MB |
| UTM (130 MB) | 953 MB | 320 MB |
| osu! (221 MB) | 636 MB | 327 MB |
| FunkiniOS (174 MB) | 438 MB | 210 MB |
| SwissCovid (106 MB) | 341 MB | 175 MB |
| Telegram (82 MB) | 278 MB | 137 MB |

Server RSS (`pavise-server`, 4 sequential + 4 concurrent scans):

| | glibc default | tuned malloc env |
|---|---|---|
| idle at start | 9 MB | 9 MB |
| after scans | 214–280 MB | 21–24 MB |
| peak, 4 concurrent | 681 MB | 399 MB |

mimalloc was also tried: higher peaks (873 MB) and slower release. Chrome
flags (`--no-zygote`, `--renderer-process-limit=1`, `--in-process-gpu`) did
not reduce a render below ~240 MB, so none are added. The image uses Debian's
`chromium-headless-shell` instead of `chromium`. Measured in the container (3 renders each):
peak memory 332–371 → 124–205 MB, cache left behind 351 → 248 MB, render time 730 → 470 ms.
The PDFs were pixel-identical at 60 dpi (macOS, Chrome for Testing 154).

Wall time vs the pre-change working tree (macOS, 10 cores): Provenance 35 s →
7 s, Telegram 2.1 s → 0.7 s, Mattermost 2.4 s → 0.3 s.

## Performance pitfalls

- **RegexSet + non-ASCII text.** `PatternEngine` used a `RegexSet` pre-pass.
  Once `__ustring` (UTF-16) text is appended, the Unicode `.{0,20}` / `(?i)`
  rules thrash the combined lazy DFA and it falls back to the PikeVM:
  22 s instead of 0.2 s on a 357 MB binary. Plain per-rule `Regex`es keep
  their literal prefilters and are fast either way.
- **Eager unpacking.** Holding every inflated file cost ~2–3× the IPA size.
  `UnpackedArchive` keeps only plists, provisioning profiles, lockfiles and
  the main binary; other files are inflated once in the parallel per-file
  pass, bounded by a `ByteBudget` (`PAVISE_MAX_IN_FLIGHT_BYTES`).
- A file larger than the budget runs alone; a waiting rayon worker blocks, so
  the per-file closure must never wait on other rayon jobs (deadlock).
