# End-of-life library detection

QS-SCA-001 (Warning, Dependencies score class) flags bundled libraries whose release line
has ended. The code is in `src/resources/eol.rs` and the data in `data/eol/`.

## Data

- `data/eol/<slug>.json` holds endoflife.date snapshots (`/api/v1/products/<slug>`), trimmed
  to `name`, `isEol`, `eolFrom`, `isEoes`, `eoesFrom`. They are compiled in through
  `SNAPSHOTS`, so scans stay offline and reproducible.
- `scripts/update-eol.sh` refreshes every file. `scripts/update-eol.sh <slug>…` adds new
  products. The script needs `curl` and `jq`.
- `.github/workflows/eol-refresh.yml` runs every Monday and opens a PR (`chore/eol-refresh`)
  only when a support status or date changed. Patch releases and fetch times aren't stored.
  PRs opened with `GITHUB_TOKEN` don't start CI, so push to the branch to run it.
- A result changes only when a snapshot PR is merged, never because the scan date moved.

## Semantics

- A version maps to the longest numeric-prefix release line: `1.1.1k` → `1.1.1`,
  `8.0.1` → `8`, `2021.3.16` → `2021.3`.
- The line counts as ended when `isEol` is true. Paid extended support (`isEoes: false`,
  e.g. OpenSSL premium, Qt ESR) doesn't count. The finding mentions it instead.
- An untracked version between two ended lines (GStreamer 1.19, a dev release) counts as
  ended. So does a version older than every tracked line when the oldest one has ended.
- Some old lines have no `eolFrom`. For those, the text leaves out the date.

## Detected libraries (`DETECTORS`)

| Product | Scope | Signal |
|---|---|---|
| openssl | Mach-O | `OpenSSL 1.1.1k  25 Mar 2021` |
| lua | Mach-O | `$LuaVersion: Lua 5.4.6` |
| qt | Mach-O | `Qt 6.5.0 (arm64-little_endian…` (QLibraryInfo::build) |
| godot | Mach-O | `Godot Engine v4.2.1.stable` |
| unity | UnityFramework | `2021.3.16f1` |
| gstreamer | `gstreamer*` binary | bare `1.19.1` next to `GStreamer source release` |
| ffmpeg | Mach-O | `Lavf60.3.100` → release via `ffmpeg_release` table |
| dotnet | `System.Private.CoreLib.dll` | `8.0.1+<sha>` |
| python | archive paths | `…/lib/python3.11/` |
| react-native | `.jsbundle` | `major:0,minor:71,patch:4,prerelease` |
| jquery, jquery-ui, bootstrap, vue, angularjs, ionic (v1), font-awesome | JS/CSS/HTML | license banners |

A bundled framework whose plist version is a placeholder takes the detected version.
Other hits become their own component (`… (statically linked)` for Mach-O).

## Why not every endoflife.date product

The site tracks about 480 products. Most are servers, OSes, databases and cloud services
that never ship inside an IPA. A product can only be added if the app bundle carries a
reliable version string. Known gaps:

- Angular and React: production builds strip the banners.
- React Native with Hermes: the version is bytecode, not a string.
- Flutter: not tracked by endoflife.date.
- SQLite: has only a single support line. Apple's system copy isn't bundled anyway.
- FFmpeg 8+: add `ffmpeg_release` rows from `libavformat/version.h` at each release tag.

## Adding a library

1. Run `scripts/update-eol.sh <slug>`. Add the file to `SNAPSHOTS`.
2. Add a `Detector`. Use a distinctive `needle` (a literal prefilter, keeps scans fast), a
   regex capturing the version, and a `file_hint` when the version string is generic.
3. Add a case to the `native_banners` or `web_banners` test. `every_detector_has_a_snapshot`
   checks that the data file exists.
