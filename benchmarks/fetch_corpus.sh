#!/usr/bin/env bash
# fetch_corpus.sh — discover and fetch prebuilt IPAs from open-source iOS apps.
#
# Source list: https://github.com/dkhamsing/open-source-ios-apps (README)
# Phases:
#   discover  — query GitHub Releases API for every repo, log any .ipa/.ipa.zip
#               assets to manifest.tsv. Fast, network-light. Safe to re-run.
#   fetch     — download every asset in manifest.tsv not already on disk;
#               record sha256 in sha256.txt.
#   verify    — re-hash downloaded files against sha256.txt.
#
# Requires: gh (authenticated), jq, curl, sha256sum (or shasum).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORPUS="$ROOT/corpus"
CACHE="$CORPUS/_cache"
MANIFEST="$CORPUS/manifest.tsv"
SHAFILE="$CORPUS/sha256.txt"
README_RAW="https://raw.githubusercontent.com/dkhamsing/open-source-ios-apps/master/README.md"

mkdir -p "$CORPUS" "$CACHE"

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'
  fi
}

discover() {
  local readme="$CACHE/source-readme.md"
  curl -sSL "$README_RAW" -o "$readme"

  # Extract unique owner/repo pairs.
  local repos
  repos=$(grep -oE 'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+' "$readme" \
    | sed 's|https://github.com/||' \
    | grep -v '^dkhamsing/open-source-ios-apps$' \
    | sort -u)

  local total
  total=$(echo "$repos" | wc -l | tr -d ' ')
  echo "discover: $total repos to query" >&2

  # Header (overwrite on each discover run).
  printf "owner_repo\ttag\tasset_name\tsize_bytes\tdownload_url\n" > "$MANIFEST"

  local i=0 hits=0
  while IFS= read -r repo; do
    i=$((i+1))
    # latest release only — keeps API calls bounded
    local json
    json=$(gh api -H "Accept: application/vnd.github+json" \
      "/repos/$repo/releases/latest" 2>/dev/null || true)
    if [ -z "$json" ] || echo "$json" | jq -e '.message' >/dev/null 2>&1; then
      printf "  [%4d/%d] %-60s -- no release\n" "$i" "$total" "$repo" >&2
      continue
    fi
    local tag
    tag=$(echo "$json" | jq -r '.tag_name // empty')
    # Match *.ipa or *.ipa.zip (case-insensitive).
    local matches
    matches=$(echo "$json" | jq -r '
      .assets[]?
      | select(.name | test("\\.ipa(\\.zip)?$"; "i"))
      | [.name, (.size|tostring), .browser_download_url] | @tsv')
    if [ -n "$matches" ]; then
      while IFS=$'\t' read -r name size url; do
        printf "%s\t%s\t%s\t%s\t%s\n" "$repo" "$tag" "$name" "$size" "$url" >> "$MANIFEST"
        hits=$((hits+1))
        printf "  [%4d/%d] %-60s ++ %s (%s)\n" "$i" "$total" "$repo" "$name" "$size" >&2
      done <<< "$matches"
    else
      printf "  [%4d/%d] %-60s    (no ipa)\n" "$i" "$total" "$repo" >&2
    fi
  done <<< "$repos"

  echo "discover: $hits IPA assets across all latest releases" >&2
  echo "manifest written to: $MANIFEST" >&2
}

fetch() {
  if [ ! -s "$MANIFEST" ]; then
    echo "fetch: $MANIFEST missing or empty — run \`$0 discover\` first" >&2
    exit 1
  fi
  : > "$SHAFILE.tmp"
  # Skip header.
  tail -n +2 "$MANIFEST" | while IFS=$'\t' read -r repo tag name size url; do
    # Sanitize both repo and tag — either may contain '/' (e.g. tag "builds/494").
    local safe_repo="${repo//\//__}"
    local safe_tag="${tag//\//__}"
    local safe="${safe_repo}__${safe_tag}__${name}"
    local out="$CORPUS/$safe"
    if [ -f "$out" ]; then
      echo "  exists: $safe" >&2
    else
      echo "  fetch:  $safe ($size bytes)" >&2
      if ! curl -fL --retry 3 --retry-delay 2 -o "$out.part" "$url"; then
        echo "  ERROR: download failed for $safe — skipping sha256" >&2
        rm -f "$out.part"
        continue
      fi
      mv "$out.part" "$out"
    fi
    printf "%s  %s\n" "$(sha256 "$out")" "$safe" >> "$SHAFILE.tmp"
  done
  mv "$SHAFILE.tmp" "$SHAFILE"
  echo "fetch: sha256 manifest at $SHAFILE" >&2
}

verify() {
  if [ ! -s "$SHAFILE" ]; then
    echo "verify: $SHAFILE missing — run \`$0 fetch\` first" >&2
    exit 1
  fi
  ( cd "$CORPUS" && \
    if command -v sha256sum >/dev/null 2>&1; then sha256sum -c "$SHAFILE"
    else shasum -a 256 -c "$SHAFILE"
    fi )
}

case "${1:-}" in
  discover) discover ;;
  fetch)    fetch ;;
  verify)   verify ;;
  *)        echo "usage: $0 {discover|fetch|verify}" >&2; exit 2 ;;
esac
