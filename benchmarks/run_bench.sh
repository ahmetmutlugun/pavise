#!/usr/bin/env bash
# run_bench.sh — scan every IPA in corpus/ with Pavise and MobSF, save outputs.
#
# Layout:
#   runs/pavise/<safe>.json          Pavise JSON report
#   runs/pavise/<safe>.stderr.log    Pavise stderr (verbose timing)
#   runs/mobsf/<safe>.upload.json    MobSF upload response (hash, file_name)
#   runs/mobsf/<safe>.scan.json      MobSF scan response (raw)
#   runs/mobsf/<safe>.report.json    MobSF /report_json output
#   runs/_timings.tsv                file, pavise_sec, mobsf_sec, pv_high, pv_warn, mobsf_high, mobsf_warn, mobsf_score
#   runs/_run.log                    line-per-IPA progress log
#
# Re-runnable: skips an IPA's tool entirely if its primary output JSON already exists.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORPUS="$ROOT/corpus"
RUNS="$ROOT/runs"
PV_DIR="$RUNS/pavise"
MS_DIR="$RUNS/mobsf"
TIMINGS="$RUNS/_timings.tsv"
LOG="$RUNS/_run.log"

PAVISE_BIN="${PAVISE_BIN:-$ROOT/../target/release/pavise}"
MOBSF_URL="${MOBSF_URL:-http://localhost:8000}"
MOBSF_API="${MOBSF_API:?set MOBSF_API to the REST API key}"

mkdir -p "$PV_DIR" "$MS_DIR"
[ -f "$TIMINGS" ] || printf "file\tpavise_sec\tmobsf_sec\tpv_high\tpv_warn\tmobsf_high\tmobsf_warn\tmobsf_score\n" > "$TIMINGS"

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$LOG" >&2; }

# Resolve a scan target. Files ending in .ipa.zip are unzipped to a sibling .ipa.
resolve_ipa() {
  local f="$1"
  case "$f" in
    *.ipa.zip)
      local extracted="${f%.zip}"
      if [ ! -f "$extracted" ]; then
        log "  unzipping $(basename "$f") -> $(basename "$extracted")"
        # The .ipa.zip wrappers used by Bitwarden contain a single .ipa.
        local tmpdir; tmpdir=$(mktemp -d)
        unzip -q "$f" -d "$tmpdir"
        # -type f: some archives (e.g. Bitwarden) wrap the real IPA in a
        # directory whose name also ends in .ipa — we want the file.
        local inner
        inner=$(find "$tmpdir" -type f -name '*.ipa' | head -1)
        [ -n "$inner" ] || { log "  ERROR: no .ipa file inside $f"; rm -rf "$tmpdir"; return 1; }
        mv "$inner" "$extracted"
        rm -rf "$tmpdir"
      fi
      echo "$extracted"
      ;;
    *.ipa) echo "$f" ;;
    *) return 1 ;;
  esac
}

run_pavise() {
  local ipa="$1" safe="$2"
  local out="$PV_DIR/$safe.json"
  local err="$PV_DIR/$safe.stderr.log"
  if [ -f "$out" ]; then echo "skip"; return 0; fi
  local t0 t1
  t0=$(perl -MTime::HiRes=time -e 'printf "%.3f\n", time')
  # Pavise uses exit 1 to signal "completed, high findings present", and exit 2
  # for actual errors. Accept 0 or 1 as success; only 2+ is a real failure.
  "$PAVISE_BIN" --network --verbose -f json -o "$out" "$ipa" 2> "$err"
  local rc=$?
  t1=$(perl -MTime::HiRes=time -e 'printf "%.3f\n", time')
  if [ "$rc" -le 1 ] && [ -f "$out" ]; then
    awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.3f\n", b-a}'
  else
    echo "FAIL(rc=$rc)"
    return 1
  fi
}

run_mobsf() {
  local ipa="$1" safe="$2"
  local up="$MS_DIR/$safe.upload.json"
  local sc="$MS_DIR/$safe.scan.json"
  local rp="$MS_DIR/$safe.report.json"
  if [ -f "$rp" ]; then echo "skip"; return 0; fi
  local t0 t1
  t0=$(perl -MTime::HiRes=time -e 'printf "%.3f\n", time')
  # 1) upload
  if ! curl -sf -F "file=@$ipa" -H "Authorization: $MOBSF_API" \
        "$MOBSF_URL/api/v1/upload" -o "$up"; then
    echo "UPLOAD_FAIL"; return 1
  fi
  local hash
  hash=$(jq -r '.hash // empty' "$up")
  [ -n "$hash" ] || { echo "NO_HASH"; return 1; }
  # 2) scan (this can take a while for big IPAs)
  if ! curl -sf -X POST -H "Authorization: $MOBSF_API" \
        --max-time 1800 \
        -d "hash=$hash" -d "re_scan=0" \
        "$MOBSF_URL/api/v1/scan" -o "$sc"; then
    echo "SCAN_FAIL"; return 1
  fi
  # 3) full report
  if ! curl -sf -X POST -H "Authorization: $MOBSF_API" \
        --max-time 600 \
        -d "hash=$hash" \
        "$MOBSF_URL/api/v1/report_json" -o "$rp"; then
    echo "REPORT_FAIL"; return 1
  fi
  t1=$(perl -MTime::HiRes=time -e 'printf "%.3f\n", time')
  awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.3f\n", b-a}'
}

extract_pv_counts() {
  jq -r '
    [.findings[] | select(.severity=="high")] as $h
    | [.findings[] | select(.severity=="warning")] as $w
    | "\($h|length)\t\($w|length)"
  ' "$1" 2>/dev/null || echo $'?\t?'
}

extract_mobsf_counts() {
  jq -r '
    "\((.appsec.high // []) | length)\t\((.appsec.warning // []) | length)\t\(.appsec.security_score // "null")"
  ' "$1" 2>/dev/null || echo $'?\t?\t?'
}

# --- main loop ---

log "bench start — corpus=$CORPUS"
[ -x "$PAVISE_BIN" ] || { log "FATAL: pavise binary not found at $PAVISE_BIN"; exit 2; }

# Sort files alphabetically; iterate over .ipa and .ipa.zip.
mapfile -t FILES < <(find "$CORPUS" -maxdepth 1 \( -name '*.ipa' -o -name '*.ipa.zip' \) | sort)
total=${#FILES[@]}
log "found $total IPA(s) to scan"

i=0
for f in "${FILES[@]}"; do
  i=$((i+1))
  base=$(basename "$f")
  safe="${base%.ipa.zip}"; safe="${safe%.ipa}"
  log "[$i/$total] $base"

  ipa=$(resolve_ipa "$f") || { log "  resolve failed"; continue; }

  pv_t=$(run_pavise "$ipa" "$safe")
  log "  pavise: ${pv_t}s"

  ms_t=$(run_mobsf "$ipa" "$safe")
  log "  mobsf:  ${ms_t}s"

  pv_counts=$'?\t?'
  [ -f "$PV_DIR/$safe.json" ] && pv_counts=$(extract_pv_counts "$PV_DIR/$safe.json")
  ms_counts=$'?\t?\t?'
  [ -f "$MS_DIR/$safe.report.json" ] && ms_counts=$(extract_mobsf_counts "$MS_DIR/$safe.report.json")

  printf "%s\t%s\t%s\t%s\t%s\n" "$base" "$pv_t" "$ms_t" "$pv_counts" "$ms_counts" >> "$TIMINGS"
done

log "bench done."
