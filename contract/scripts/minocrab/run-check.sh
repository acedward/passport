#!/usr/bin/env bash
# run-check.sh — run one command of the stagenet check (stagenet-check.ts, AA project 00040 P3) in
# Docker, with the owner's secrets mounted READ-ONLY and never on a command line.
#
#   contract/scripts/minocrab/run-check.sh preflight          # read-only
#   contract/scripts/minocrab/run-check.sh run                # every live step not yet done
#   contract/scripts/minocrab/run-check.sh deploy|deposit|swap|append|withdraw
#   contract/scripts/minocrab/run-check.sh vk-check           # read-only
#   contract/scripts/minocrab/run-check.sh status [--wallet]
#   P4 (the five lane circuits, then the authority retirement; CHECK_NAME_PREFIX=aa00040-p4):
#   contract/scripts/minocrab/run-check.sh preflight4        # opens the wallet, spends nothing
#   contract/scripts/minocrab/run-check.sh run4              # swap4 .. retire, one wallet session
#   contract/scripts/minocrab/run-check.sh swap4|rotate|add-device|remove-device|unshielded|to-contract|retire
#   contract/scripts/minocrab/run-check.sh status4 [--wallet]
#
# Steps that open the funding wallet:
#   * take the SHARED funding-wallet lock (~/.stagenet-offer-ladders/funding.lock, the Offer Files
#     protocol: one process per seed; exclusive create, released on exit), waiting up to 30 minutes;
#   * wait for >= 10 GB of Docker memory headroom, then start the pinned proof server (9.0.0-rc.6, by
#     digest) on a random free 127.0.0.1 port >= 10000; the check joins its network namespace;
#   * mount the mnemonic file and the EVM device key read-only.
# Every container (${CHECK_NAME_PREFIX:-aa00040-p3}-*) is removed on exit and the lock is released, whatever happens.
#
# Environment: CHECK_EVIDENCE_DIR_HOST (required: public evidence), STAGENET_WALLET_FILE_HOST
# (required for wallet steps), EVM_DEVICE_KEY_FILE_HOST (default: the 00039 test EOA),
# CHECK_STATE_DIR_HOST (default ~/.config/aa-00040, mode 700), CHECK_KEYSETS (default
# ~/.cache/aa-00040/keysets), PS_PARAMS (a WRITABLE proof-server parameter cache).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTRACT="$(cd "$HERE/../.." && pwd)"
CMD="${1:?usage: run-check.sh <command>}"
shift || true

KEYSETS="${CHECK_KEYSETS:-$HOME/.cache/aa-00040/keysets}"
STATE="${CHECK_STATE_DIR_HOST:-$HOME/.config/aa-00040}"
DEVICE_KEY="${EVM_DEVICE_KEY_FILE_HOST:-$HOME/.config/aa-00039/gate-bridge-device.key}"
PARAMS="${PS_PARAMS:-$HOME/.cache/aa-00040/ps-params}"
IMAGE="${CHECK_IMAGE:-midnight-2-offers/aa-contracts:demo-infra-14580}"
PROOF_IMAGE="midnightntwrk/proof-server:9.0.0-rc.6@sha256:38a819eacde273f725551fdf90ca7c31ebf3c0ff145f3ed58ee35f92fb7ce95b"
LOCK="$HOME/.stagenet-offer-ladders/funding.lock"
TAG="$$"
PFX="${CHECK_NAME_PREFIX:-aa00040-p3}"
PROOF_NAME="$PFX-proof-$TAG"
RUN_NAME="$PFX-run-$CMD-$TAG"
: "${CHECK_EVIDENCE_DIR_HOST:?set CHECK_EVIDENCE_DIR_HOST (public evidence)}"

say() { printf '== %s\n' "$*" >&2; }

case "$CMD" in
  run|deploy|deposit|swap|append|withdraw) NEEDS_WALLET=1 ;;
  preflight4|run4|swap4|rotate|add-device|remove-device|unshielded|to-contract|retire|diagnose-add) NEEDS_WALLET=1 ;;
  status|status4) if [ "${1:-}" = --wallet ]; then NEEDS_WALLET=1; else NEEDS_WALLET=0; fi ;;
  preflight|vk-check|inspect|selftest) NEEDS_WALLET=0 ;;
  *) echo "unknown command $CMD" >&2; exit 2 ;;
esac

mkdir -p "$STATE/work" "$STATE/logs" "$CHECK_EVIDENCE_DIR_HOST"
chmod 700 "$STATE" "$STATE/work" "$STATE/logs"

cleanup() {
  docker rm -f "$RUN_NAME" >/dev/null 2>&1 || true
  docker rm -f "$PROOF_NAME" >/dev/null 2>&1 || true
  if [ "${LOCK_TAKEN:-0}" = 1 ]; then rm -f "$LOCK"; say "funding lock released"; fi
}
trap cleanup EXIT INT TERM

wallet_in_use() {
  local ids
  ids="$(docker ps -q)"
  [ -n "$ids" ] && docker inspect --format '{{.Name}} {{range .Mounts}}{{.Source}} {{end}}' $ids 2>/dev/null |
    grep -F "/Offer Files/.stagenet" >/dev/null
}

NET_ARGS=(--network bridge)
SECRET_ARGS=()
if [ "$NEEDS_WALLET" = 1 ]; then
  : "${STAGENET_WALLET_FILE_HOST:?set STAGENET_WALLET_FILE_HOST}"
  [ -f "$STAGENET_WALLET_FILE_HOST" ] || { echo "no mnemonic file at the configured path" >&2; exit 2; }
  [ -f "$DEVICE_KEY" ] || { echo "no EVM device key at the configured path" >&2; exit 2; }
  mkdir -p "$(dirname "$LOCK")"
  for i in $(seq 1 16); do
    if ! wallet_in_use && ( set -o noclobber
      printf '{"purpose":"aa-00040 stagenet check %s","pid":%s,"host":"%s","at":"%s"}' \
        "$CMD" "$$" "$(hostname)" "$(date -u +%FT%TZ)" > "$LOCK" ) 2>/dev/null; then
      LOCK_TAKEN=1; break
    fi
    [ "$i" = 16 ] && { echo "the funding wallet is still busy after 30 min: $(cat "$LOCK" 2>/dev/null)" >&2; exit 75; }
    say "the funding wallet is busy ($(cat "$LOCK" 2>/dev/null || echo 'a container has it mounted')); waiting 120 s ($i/15)"
    sleep 120
  done
  say "funding lock taken at $(date -u +%FT%TZ)"

  for i in $(seq 1 31); do
    HEADROOM="$(docker stats --no-stream --format '{{.MemUsage}}' | python3 -c '
import re, sys
unit = {"B": 1, "KiB": 2**10, "MiB": 2**20, "GiB": 2**30, "KB": 1e3, "MB": 1e6, "GB": 1e9}
used, total = 0.0, 0.0
for line in sys.stdin:
    a, b = [s.strip() for s in line.split("/")]
    m, n = re.match(r"([\d.]+)(\w+)", a), re.match(r"([\d.]+)(\w+)", b)
    used += float(m.group(1)) * unit[m.group(2)]
    total = max(total, float(n.group(1)) * unit[n.group(2)])
print(int((total - used) / 2**30) if total else 99)')"
    if [ "$HEADROOM" -ge 10 ]; then break; fi
    [ "$i" = 31 ] && { echo "Docker memory headroom stayed below 10 GB for 30 min" >&2; exit 75; }
    say "Docker memory headroom ${HEADROOM} GB < 10 GB; waiting 60 s ($i/30)"
    sleep 60
  done
  PORT="$(python3 -c 'import random, socket
for _ in range(200):
    p = random.randint(10000, 60000); s = socket.socket()
    try: s.bind(("127.0.0.1", p)); s.close(); print(p); break
    except OSError: s.close()')"
  say "proof server $PROOF_NAME on 127.0.0.1:$PORT (headroom ${HEADROOM} GB)"
  docker run -d --name "$PROOF_NAME" -p "127.0.0.1:$PORT:6300" --memory 12g \
    -e MIDNIGHT_PP=/params -v "$PARAMS:/params" "$PROOF_IMAGE" >/dev/null
  for _ in $(seq 1 120); do curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null 2>&1 && break; sleep 1; done
  curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null || { docker logs --tail 40 "$PROOF_NAME" >&2; exit 1; }
  say "proof server version $(curl -fsS "http://127.0.0.1:$PORT/version" || echo '?')"
  NET_ARGS=(--network "container:$PROOF_NAME")
  SECRET_ARGS=(
    -v "$STAGENET_WALLET_FILE_HOST:/secrets/stagenet:ro" -e STAGENET_WALLET_FILE=/secrets/stagenet
    -v "$DEVICE_KEY:/secrets/evm-device.key:ro" -e EVM_DEVICE_KEY_FILE=/secrets/evm-device.key
  )
else
  SECRET_ARGS=(-v "$DEVICE_KEY:/secrets/evm-device.key:ro" -e EVM_DEVICE_KEY_FILE=/secrets/evm-device.key)
fi

LOG="$STATE/logs/$CMD-$(date -u +%Y%m%dT%H%M%SZ).log"
say "log $LOG"
set +e
docker run --rm --name "$RUN_NAME" --memory 8g \
  "${NET_ARGS[@]}" \
  "${SECRET_ARGS[@]}" \
  --entrypoint bun -w /state/work \
  -v "$CONTRACT/src:/aa/g/contract/src:ro" \
  -v "$CONTRACT/contracts/erc20-vault/deploy:/aa/g/contract/contracts/erc20-vault/deploy:ro" \
  -v "$KEYSETS/compactc:/aa/g/contract/contracts/managed:ro" \
  -v "$KEYSETS:/aa/keysets:ro" \
  -v "$HERE:/aa/g/scripts:ro" \
  -v "$STATE:/state" \
  -v "$CHECK_EVIDENCE_DIR_HOST:/evidence" \
  -e CHECK_STATE_DIR=/state -e CHECK_EVIDENCE_DIR=/evidence -e KEYSETS_DIR=/aa/keysets \
  -e MIDNIGHT_MANAGED_PATH=/aa/keysets \
  -e MIDNIGHT_NETWORK=stagenet \
  -e MIDNIGHT_PROOF_SERVER_URL=http://127.0.0.1:6300 -e PROOF_SERVER_URL=http://127.0.0.1:6300 \
  -e FEE_BLOCKS_MARGIN="${FEE_BLOCKS_MARGIN:-5}" \
  "$IMAGE" /aa/g/scripts/stagenet-check.ts "$CMD" "$@" 2>&1 | tee "$LOG"
STATUS="${PIPESTATUS[0]}"
set -e
exit "$STATUS"
