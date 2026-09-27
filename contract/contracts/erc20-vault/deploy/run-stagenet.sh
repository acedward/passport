#!/usr/bin/env bash
# run-stagenet.sh — run one deploy/stagenet.ts command against Midnight STAGENET and
# Sepolia, in Docker, with the owner's secrets mounted READ-ONLY and never on a command line.
#
# Project 00037 (plans/00037-stagenet-sepolia-stk-erc20-bridge.md).
#
#   deploy/run-stagenet.sh preflight
#   deploy/run-stagenet.sh deploy
#   deploy/run-stagenet.sh deposit-address
#   deploy/run-stagenet.sh deposit-fund  --token stkA --amount 100 --gas-eth 0.002
#   deploy/run-stagenet.sh deposit-start --token stkA --amount 100
#   deploy/run-stagenet.sh relay --request <id>
#   deploy/run-stagenet.sh deposit-complete --request <id>
#   deploy/run-stagenet.sh status | balances | withdraw-gas | withdraw-start | withdraw-complete | withdraw-refund
#
# What it does, per command:
#   * commands that PROVE (deploy, deposit-start, deposit-complete, withdraw-*) start a
#     local proof server (midnightntwrk/proof-server:9.0.0-rc.6, pinned by digest) on a
#     random free 127.0.0.1 port >= 10000, and the driver joins its network namespace;
#   * commands that open the Midnight wallet take the SHARED funding-wallet lock
#     (~/.stagenet-offer-ladders/funding.lock, the Offer Files protocol: one process per
#     seed) and mount the `.stagenet` mnemonic file read-only at /secrets/stagenet;
#   * commands that spend on Sepolia (deposit-fund, withdraw-gas) mount the `.sepolia` key
#     file read-only at /secrets/sepolia;
#   * the state directory (~/.config/aa-00037, mode 700: the initialise key, the contract
#     maintenance signing key, the run state, the private-state store) is mounted at /state;
#   * every container it starts is removed on exit, whatever happens.
#
# Environment (optional): STAGENET_WALLET_FILE_HOST, SEPOLIA_KEY_FILE_HOST, AA37_STATE_DIR_HOST,
# AA37_EVIDENCE_DIR_HOST, NODE_IMAGE, SEPOLIA_RPC_URL, FEE_BLOCKS_MARGIN (default 5).
set -euo pipefail

PKG="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"          # contracts/erc20-vault
CMD="${1:?usage: run-stagenet.sh <command> [--flags]}"
WALLET_FILE="${STAGENET_WALLET_FILE_HOST:-/Users/edwardalvarado/todo/Offer Files/.stagenet}"
SEPOLIA_FILE="${SEPOLIA_KEY_FILE_HOST:-/Users/edwardalvarado/todo/Offer Files/.sepolia}"
STATE_HOST="${AA37_STATE_DIR_HOST:-$HOME/.config/aa-00037}"
EVIDENCE_HOST="${AA37_EVIDENCE_DIR_HOST:-/Users/edwardalvarado/todo/AA/evidence/00037-stagenet-sepolia-stk-erc20-bridge}"
LOCK="$HOME/.stagenet-offer-ladders/funding.lock"
PROOF_IMAGE="midnightntwrk/proof-server:9.0.0-rc.6@sha256:38a819eacde273f725551fdf90ca7c31ebf3c0ff145f3ed58ee35f92fb7ce95b"
NODE_IMAGE="${NODE_IMAGE:-node:24-bookworm-slim}"
TAG="$$"
PROOF_NAME="aa37-proof-$TAG"
RUN_NAME="aa37-run-$CMD-$TAG"

case "$CMD" in
  deploy|deposit-start|deposit-complete|withdraw-start|withdraw-complete|withdraw-refund)
    NEEDS_PROOF=1; NEEDS_WALLET=1; NEEDS_SEPOLIA=0 ;;
  balances) NEEDS_PROOF=0; NEEDS_WALLET=1; NEEDS_SEPOLIA=0 ;;
  deposit-address) NEEDS_PROOF=0; NEEDS_WALLET=1; NEEDS_SEPOLIA=0 ;;
  deposit-fund|withdraw-gas) NEEDS_PROOF=0; NEEDS_WALLET=0; NEEDS_SEPOLIA=1 ;;
  preflight|status|relay) NEEDS_PROOF=0; NEEDS_WALLET=0; NEEDS_SEPOLIA=0 ;;
  *) echo "unknown command $CMD" >&2; exit 2 ;;
esac
# deposit-fund needs the recipient; it reads the recorded default from the state file.

mkdir -p "$STATE_HOST" "$EVIDENCE_HOST"
chmod 700 "$STATE_HOST"

cleanup() {
  docker rm -f "$RUN_NAME" >/dev/null 2>&1 || true
  docker rm -f "$PROOF_NAME" >/dev/null 2>&1 || true
  if [ "${LOCK_TAKEN:-0}" = 1 ]; then rm -f "$LOCK"; fi
}
trap cleanup EXIT INT TERM

if [ "$NEEDS_WALLET" = 1 ]; then
  [ -f "$WALLET_FILE" ] || { echo "no mnemonic file at the configured path" >&2; exit 2; }
  # Other users of the shared `.stagenet` wallet (AA 00034, Umbra 00021, Offer Files).
  IDS="$(docker ps -q)"
  if [ -n "$IDS" ] && docker inspect --format '{{.Name}} {{range .Mounts}}{{.Source}} {{end}}' $IDS 2>/dev/null | grep -F "/Offer Files/.stagenet" >/dev/null; then
    echo "another container has the .stagenet wallet mounted; refusing (one wallet process at a time)" >&2
    exit 75
  fi
  mkdir -p "$(dirname "$LOCK")"
  if ( set -o noclobber; printf '{"purpose":"aa-00037 %s","pid":%s,"host":"%s","at":"%s"}' "$CMD" "$$" "$(hostname)" "$(date -u +%FT%TZ)" > "$LOCK" ) 2>/dev/null; then
    LOCK_TAKEN=1
  else
    echo "the funding wallet is locked by: $(cat "$LOCK" 2>/dev/null)" >&2
    exit 75
  fi
fi

NET_ARGS=()
PROOF_URL="http://127.0.0.1:6300"
if [ "$NEEDS_PROOF" = 1 ]; then
  PORT="$(python3 -c 'import random,socket
for _ in range(200):
    p=random.randint(10000,60000); s=socket.socket()
    try: s.bind(("127.0.0.1",p)); s.close(); print(p); break
    except OSError: s.close()')"
  echo "== proof server $PROOF_NAME on 127.0.0.1:$PORT" >&2
  docker run -d --name "$PROOF_NAME" -p "127.0.0.1:$PORT:6300" "$PROOF_IMAGE" >/dev/null
  for _ in $(seq 1 120); do
    curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null 2>&1 && break
    sleep 1
  done
  curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null || { echo "proof server did not become healthy" >&2; docker logs --tail 40 "$PROOF_NAME" >&2; exit 1; }
  echo "== proof server version $(curl -fsS "http://127.0.0.1:$PORT/version" || echo '?')" >&2
  NET_ARGS=(--network "container:$PROOF_NAME")
fi

SECRET_ARGS=()
if [ "$NEEDS_WALLET" = 1 ]; then
  SECRET_ARGS+=(-v "$WALLET_FILE:/secrets/stagenet:ro" -e STAGENET_WALLET_FILE=/secrets/stagenet)
fi
if [ "$NEEDS_SEPOLIA" = 1 ]; then
  [ -f "$SEPOLIA_FILE" ] || { echo "no Sepolia key file at the configured path" >&2; exit 2; }
  SECRET_ARGS+=(-v "$SEPOLIA_FILE:/secrets/sepolia:ro" -e SEPOLIA_KEY_FILE=/secrets/sepolia)
fi

docker run --rm --name "$RUN_NAME" \
  ${NET_ARGS[@]+"${NET_ARGS[@]}"} \
  ${SECRET_ARGS[@]+"${SECRET_ARGS[@]}"} \
  -v "$PKG":/work \
  -v "$STATE_HOST":/state \
  -v "$EVIDENCE_HOST":/evidence \
  -e MIDNIGHT_NETWORK=stagenet \
  -e AA37_STATE_DIR=/state \
  -e AA37_EVIDENCE_DIR=/evidence \
  -e MIDNIGHT_LEVEL_DB=/state/midnight-level-db \
  -e PROOF_SERVER_URL="$PROOF_URL" \
  -e PROOF_SERVER_IMAGE="${PROOF_IMAGE%@*}" \
  -e FEE_BLOCKS_MARGIN="${FEE_BLOCKS_MARGIN:-5}" \
  ${SEPOLIA_RPC_URL:+-e SEPOLIA_RPC_URL="$SEPOLIA_RPC_URL"} \
  -w /work \
  "$NODE_IMAGE" \
  node_modules/.bin/tsx deploy/stagenet.ts "$@"
