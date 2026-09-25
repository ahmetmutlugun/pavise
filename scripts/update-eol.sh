#!/bin/sh
# Refresh end-of-life snapshots in data/eol/ from endoflife.date.
#
#   scripts/update-eol.sh            # refresh every existing data/eol/<product>.json
#   scripts/update-eol.sh qt lua     # also add (or refresh) these products
#
# Only EOL fields are kept (no "latest" patch release, no fetch timestamp), so a
# refresh changes files only when a release line's support status or dates change.
# Product slugs: https://endoflife.date/api/v1/products
set -eu

DIR="$(cd "$(dirname "$0")/.." && pwd)/data/eol"
mkdir -p "$DIR"

products="$(ls "$DIR" 2>/dev/null | sed -n 's/\.json$//p') $*"
products="$(printf '%s\n' $products | sort -u)"

for p in $products; do
    tmp="$(mktemp)"
    if ! curl -fsSL --retry 3 "https://endoflife.date/api/v1/products/$p" -o "$tmp"; then
        echo "error: could not fetch '$p' (unknown slug or network failure)" >&2
        rm -f "$tmp"
        exit 1
    fi
    jq '{
        product: .result.name,
        label: .result.label,
        releases: [.result.releases[] | {name, isEol, eolFrom, isEoes, eoesFrom}]
    }' "$tmp" > "$DIR/$p.json"
    rm -f "$tmp"
    echo "updated $p"
done
