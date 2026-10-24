# Releasing

Pushing a `v*` tag runs `.github/workflows/release.yml`. It builds `pavise` with `--locked`
for macOS (arm64, x86_64) and Linux (arm64, x86_64) and attaches
`pavise-<tag>-<target>.tar.gz` plus `.sha256` files to a GitHub release.

## Steps

1. Bump `version` in `Cargo.toml`. Run `cargo test --release --all-targets`,
   `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check` and `cargo audit`.
   CI runs the same checks and must be green.
2. `git tag vX.Y.Z && git push origin vX.Y.Z`, then wait for the release workflow.
3. Homebrew: in a checkout of `ahmetmutlugun/homebrew-tap`, run
   `../pavise/scripts/brew-formula.sh vX.Y.Z > Formula/pavise.rb`, then commit and push.
   Check with `brew install ahmetmutlugun/tap/pavise && pavise --version`.
4. crates.io: `cargo publish --locked` from the tag. Publishing is manual for now; the
   `CARGO_REGISTRY_TOKEN` repo secret exists for automating it later.
5. Update the `@vX.Y.Z` pin in the README's GitHub Action example.

## Names

- The crates.io package is **`pavise-cli`**, because `pavise` there is an unrelated 2021
  placeholder. The binary, library and report `scanner.name` stay `pavise`.
- The GitHub Action (`.github/actions/pavise`) downloads release tarballs by the names above.
  Renaming an asset breaks every pinned Action user and `install.sh`.

## Gotchas

- `fuzz/` is its own workspace and its lockfile is gitignored. The fuzz workflow copies the
  root `Cargo.lock` so it builds the same dependency versions that ship. Without that copy,
  an unrelated semver break (zip 2.6, Oct 2026) failed the nightly fuzz job for a week.
- Minimum supported Rust is 1.88, set by zip 9 and `time`. Keep `rust-version` in sync when a
  dependency raises it.
