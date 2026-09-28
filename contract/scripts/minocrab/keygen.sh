#!/usr/bin/env bash
# keygen.sh — proving and verifying keys for the MinoCrab-emitted circuits (AA project 00040, P2.1).
#
#   contract/scripts/minocrab/keygen.sh <zkir-dir> <out-dir>
#
# <zkir-dir> holds the ported circuits' `.zkir` files (`contract/minocrab/scripts/gate.sh emit`).
# <out-dir> receives, per circuit, `<c>.zkir`, `<c>.bzkir`, `<c>.prover` and `<c>.verifier`, plus a
# `keygen.log`. It must not exist yet: a previous result is never overwritten.
#
# THE TOOL is compactc 0.34.0's own bundled `zkir-v3 compile-many`, the same binary compactc runs to
# key every circuit it compiles, so the MinoCrab keys and the compactc keys come out of one keygen.
# It runs from an image built from the SHA-256-pinned release archive (`compactc.Dockerfile` next to
# this script), and the script refuses to run unless the image's `compactc --version`,
# `--language-version` and the `zkir-v3` binary hash are the pinned ones.
#
# THE SRS is Midnight's `bls_midnight_2p<k>` for each circuit's k, read from MIDNIGHT_PP
# (default ~/.cache/midnight/zk-params) and checked against the digests effectstream/binaries
# 0.3.120 publishes. The container runs with `--network none`, so it cannot fetch anything: a
# missing or different SRS is a hard failure, never a silent download.
#
# KEYS ARE NEVER COMMITTED. The repository keeps only their SHA-256s:
# `contract/minocrab/keys/SHA256SUMS` and `contract/minocrab/keys/manifest.json`.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <zkir-dir> <out-dir>" >&2
  exit 64
fi
ZKIR_DIR="$(cd "$1" && pwd)"
OUT="$2"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARAMS="${MIDNIGHT_PP:-$HOME/.cache/midnight/zk-params}"
IMAGE="${COMPACTC_IMAGE:-aa-compactc:0.34.0}"
NAME="aa00040-p2-keygen-$$"

# The pins. The archive SHA-256 is in compactc.Dockerfile (the pin of record); these are the
# binaries inside it (aarch64-unknown-linux-musl, the host architecture of every number recorded).
COMPACTC_VERSION=0.34.0
LANGUAGE_VERSION=0.26.0
ZKIR_V3_SHA256=6a91308419d24bc0633210897d10c7c1b2193444e8bde09ce763e9556cb8f93a
# (bash 3.2 compatible: no associative arrays)
srs_sha256() {
  case "$1" in
    bls_midnight_2p17) echo 4a9ef6c7c0619aab74eede44b13e753e3ba54508a02dd3b7106a949aabb73b74 ;;
    bls_midnight_2p18) echo e8436dc5d8b598f169c127c745135d889744007e6d384ff126df8d1332522f86 ;;
    *) echo unknown ;;
  esac
}

sha() { shasum -a 256 "$1" | cut -d ' ' -f 1; }

[ -e "$OUT" ] && { echo "REFUSING: $OUT exists; a previous keygen result stands" >&2; exit 97; }
ls "$ZKIR_DIR"/*.zkir >/dev/null 2>&1 || { echo "no .zkir files in $ZKIR_DIR" >&2; exit 66; }

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  docker build -q -t "$IMAGE" -f "$HERE/compactc.Dockerfile" "$HERE" >/dev/null
fi
ver="$(docker run --rm --network none "$IMAGE" compactc --version | tr -d '[:space:]')"
lang="$(docker run --rm --network none "$IMAGE" compactc --language-version | tr -d '[:space:]')"
zsha="$(docker run --rm --network none "$IMAGE" sha256sum /opt/compactc/zkir-v3 | cut -d ' ' -f 1)"
[ "$ver" = "$COMPACTC_VERSION" ] || { echo "compactc $ver, expected $COMPACTC_VERSION" >&2; exit 70; }
[ "$lang" = "$LANGUAGE_VERSION" ] || { echo "language $lang, expected $LANGUAGE_VERSION" >&2; exit 70; }
[ "$zsha" = "$ZKIR_V3_SHA256" ] || { echo "zkir-v3 $zsha, expected $ZKIR_V3_SHA256" >&2; exit 70; }

# Stage the IR: compile-many writes each `.bzkir` next to its input, and the input must stay
# untouched, so the container sees a writable copy (re-hashed below).
mkdir -p "$OUT"
chmod 700 "$OUT"
STAGE="$OUT/ir"
mkdir -p "$STAGE" "$OUT/keys"
cp "$ZKIR_DIR"/*.zkir "$STAGE/"
LOG="$OUT/keygen.log"
{
  echo "KEYGEN_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "IMAGE=$IMAGE COMPACTC=$ver LANGUAGE=$lang ZKIR_V3_SHA256=$zsha"
  echo "PARAMS=$PARAMS (mounted read-only; container --network none)"
  for f in bls_midnight_2p17 bls_midnight_2p18; do
    [ -f "$PARAMS/$f" ] || { echo "SRS $f missing from $PARAMS" >&2; exit 70; }
    got="$(sha "$PARAMS/$f")"
    echo "SRS $f $(wc -c < "$PARAMS/$f" | tr -d ' ') $got"
    [ "$got" = "$(srs_sha256 "$f")" ] || { echo "SRS $f hash $got, expected $(srs_sha256 "$f")" >&2; exit 70; }
  done
  for z in "$STAGE"/*.zkir; do echo "ZKIR $(basename "$z") $(sha "$z")"; done
} | tee "$LOG"

# Peak memory, sampled every 5 s (keygen at k18 needs about 4 GiB).
(
  while sleep 5; do
    docker stats --no-stream --format 'MEM {{.MemUsage}}' "$NAME" 2>/dev/null || break
  done
) >> "$LOG" 2>&1 &
sampler=$!
trap 'kill $sampler 2>/dev/null || true; docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT

t0=$(date +%s)
docker run --rm --name "$NAME" --network none --cpus 4 --memory 8g --memory-swap 8g \
  -v "$PARAMS:/params:ro" -e MIDNIGHT_PP=/params \
  -v "$STAGE:/ir" -v "$OUT/keys:/keys" \
  "$IMAGE" /opt/compactc/zkir-v3 compile-many /ir /keys 2>&1 | tee -a "$LOG"
t1=$(date +%s)
kill $sampler 2>/dev/null || true

# Flatten: <c>.zkir, <c>.bzkir, <c>.prover, <c>.verifier side by side.
for z in "$STAGE"/*.zkir; do
  c="$(basename "$z" .zkir)"
  cp "$z" "$OUT/$c.zkir"
  if [ -f "$STAGE/$c.bzkir" ]; then mv "$STAGE/$c.bzkir" "$OUT/$c.bzkir"; fi
  if [ -f "$OUT/keys/$c.bzkir" ]; then mv "$OUT/keys/$c.bzkir" "$OUT/$c.bzkir"; fi
  mv "$OUT/keys/$c.prover" "$OUT/$c.prover"
  mv "$OUT/keys/$c.verifier" "$OUT/$c.verifier"
  [ -f "$OUT/$c.bzkir" ] || { echo "no .bzkir for $c" >&2; exit 1; }
done
rm -rf "$STAGE" "$OUT/keys"
chmod 600 "$OUT"/*.prover "$OUT"/*.verifier
{
  echo "KEYGEN_SECONDS=$((t1 - t0))"
  echo "KEYGEN_END=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  for f in "$OUT"/*.zkir "$OUT"/*.bzkir "$OUT"/*.prover "$OUT"/*.verifier; do
    echo "OUT $(basename "$f") $(wc -c < "$f" | tr -d ' ') $(sha "$f")"
  done
  echo "PEAK_MEM $(grep '^MEM ' "$LOG" | awk '{print $2}' | sort -h | tail -1)"
} | tee -a "$LOG"
