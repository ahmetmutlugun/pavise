# Releasing

Pushing a `v*` tag runs `.github/workflows/release.yml`:

1. `check-version`: the tag must equal `Cargo.toml`'s version, or nothing is built.
2. `build` + `release`: `pavise` built with `--locked` for macOS (arm64, x86_64) and Linux
   (arm64, x86_64), attached to a GitHub release as `pavise-<tag>-<target>.tar.gz` + `.sha256`.
3. `publish-crate`: `cargo publish --locked` with the `CARGO_REGISTRY_TOKEN` secret. It is
   skipped if that version is already on crates.io, so a re-run is safe.
4. `update-homebrew`: writes `Formula/pavise.rb` in `ahmetmutlugun/homebrew-tap` with
   `scripts/brew-formula.sh`. It needs the `HOMEBREW_TAP_TOKEN` secret (a fine-grained token
   with Contents write on that repo); without it the job warns and you run the script by hand.
5. `smoke-test`: dispatches `action-smoke.yml` on the tag (the Action, SARIF, `fail-on` and
   `install.sh` on Linux x86_64/arm64 and macOS). Check its result under Actions.

## Steps

1. Bump `version` in `Cargo.toml` and the `@vX.Y.Z` pin in the README's Action example.
   Run `cargo test --release --all-targets`, `cargo clippy --all-targets -- -D warnings` and
   `cargo fmt --check`, then push and wait for CI to pass.
2. `git tag -a vX.Y.Z -m "Pavise vX.Y.Z" && git push origin vX.Y.Z`, then watch the release
   and smoke-test runs.

## Names

- The crates.io package is **`pavise-cli`**, because `pavise` there is an unrelated 2021
  placeholder. The binary, library and report `scanner.name` stay `pavise`.
- The GitHub Action (`.github/actions/pavise`) downloads release tarballs by the names above.
  Renaming an asset breaks every pinned Action user and `install.sh`.

## Gotchas

- `fuzz/` is its own workspace and its lockfile is gitignored. The fuzz workflow copies the
  root `Cargo.lock` so it builds the same dependency versions that ship. Without that copy,
  an unrelated semver break (zip 2.6, Oct 2026) failed the nightly fuzz job for a week.
- CI uses the latest stable Rust, so a new release can add clippy lints that fail CI on
  unchanged code (1.99, Oct 2026). A local toolchain that is behind won't show them.
- Minimum supported Rust is 1.88, set by zip 9 and `time`. Keep `rust-version` in sync when a
  dependency raises it.
