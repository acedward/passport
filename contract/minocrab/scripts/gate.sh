#!/usr/bin/env bash
# One-command Docker entry point for the MinoCrab port (AA project 00040).
#
#   scripts/gate.sh test            cargo test (no baseline needed)
#   scripts/gate.sh gate            the differential gate (needs COMPACTC_BASELINE_DIR; writes its JSON
#                                   reports to GATE_OUT_DIR when that is set)
#   scripts/gate.sh emit OUT_DIR    write the ported circuits' .zkir files to OUT_DIR
#   scripts/gate.sh cargo ARGS...   any cargo command in the pinned container
#
# COMPACTC_BASELINE_DIR is the compactc 0.34.0 `managed/account/zkir` directory of account.compact
# sha256 44cff904…; the gate checks every baseline hash it reads against the pinned list before use.
#
# Runs in Docker with a unique `aa00040-` name, capped CPU and memory, and removes the container on
# exit. Cargo's home and target directory are the named volumes aa00040-cargo and aa00040-target
# (delete them with `docker volume rm aa00040-cargo aa00040-target` when done).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${AA00040_IMAGE:-aa00040-rust:1.95}"
CPUS="${AA00040_CPUS:-6}"
MEM="${AA00040_MEM:-12g}"
tag="$(( 10001 + RANDOM % 55000 ))"   # a run marker only; nothing listens on it
name="aa00040-${1:-test}-${tag}"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  docker build -q -t "$IMAGE" -f "$HERE/docker/Dockerfile" "$HERE/docker" >/dev/null
fi

mounts=(-v "$HERE:/src" -v aa00040-cargo:/cargo -v aa00040-target:/target)
envs=()
if [[ -n "${COMPACTC_BASELINE_DIR:-}" ]]; then
  mounts+=(-v "$COMPACTC_BASELINE_DIR:/baseline:ro")
  envs+=(-e COMPACTC_BASELINE_DIR=/baseline)
fi
if [[ -n "${GATE_OUT_DIR:-}" ]]; then
  mkdir -p "$GATE_OUT_DIR"
  mounts+=(-v "$(cd "$GATE_OUT_DIR" && pwd):/gate-out")
  envs+=(-e GATE_OUT_DIR=/gate-out)
fi

run() {
  docker run --rm --name "$name" --cpus "$CPUS" --memory "$MEM" "${mounts[@]}" ${envs[@]+"${envs[@]}"} "$IMAGE" "$@"
}

cmd="${1:-test}"; shift || true
case "$cmd" in
  test) run cargo test --locked -p passport-account-minocrab "$@" ;;
  gate)
    [[ -n "${COMPACTC_BASELINE_DIR:-}" ]] || { echo "gate: set COMPACTC_BASELINE_DIR" >&2; exit 64; }
    run cargo test --locked -p passport-account-minocrab --features compactc-baseline --test gate -- --nocapture --test-threads 1 "$@" ;;
  emit)
    out="${1:?emit OUT_DIR}"; mkdir -p "$out"; out="$(cd "$out" && pwd)"
    mounts+=(-v "$out:/out")
    run cargo run --locked -q -p passport-account-minocrab --bin emit-zkir -- /out ;;
  cargo) run cargo "$@" ;;
  *) echo "usage: $0 {test|gate|emit OUT|cargo ARGS}" >&2; exit 64 ;;
esac
