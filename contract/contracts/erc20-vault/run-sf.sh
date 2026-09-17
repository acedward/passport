#!/usr/bin/env bash
# run-sf.sh — the PUBLIC demo of the bridge with OUR fakenet as the MPC.
#
# Project 00034, sub-plan plans/00034-sub-s-stagenet-bridge.md, phase S-F.
#
# Midnight STAGENET and real SEPOLIA, both public, with one substitution: the responder is
# our own patched fakenet rather than Sig Network's MPC, whose stagenet signer stopped
# answering (question Q61). Their singleton is unauthenticated by design — any party may
# post responses to it — and a vault verifies only against the response key pinned at its
# own `initialise`, so a SECOND vault initialised with OUR root key has a working MPC
# today. Security is demo-grade (we hold the root key); every artefact says so.
#
# Usage:
#   ./run-sf.sh proof-up        # the local proof server (stagenet has no hosted one)
#   ./run-sf.sh <cmd>           # one driver command (s1, s2, s3-fund, …, s8, status)
#   ./run-sf.sh fakenet-up      # the responder, allow-listed to OUR vault only
#   ./run-sf.sh fakenet-logs    # follow it
#   ./run-sf.sh fakenet-down    # stop it (REQUIRED before any command that drives wallet 2)
#   ./run-sf.sh proof-down      # tear the proof server down
#   ./run-sf.sh env             # print the public half of the configuration and exit
#
# WHAT THIS SCRIPT NEVER DOES: it never prints a secret, and it never lets the fakenet
# environment reach the driver. `MPC_ROOT_KEY` means OPPOSITE things on the two sides — a
# PRIVATE key in the responder's environment, the matching PUBLIC key in the driver's — so
# the private one is read in a subshell, handed to `docker run`, and never exported here.
#
# HOST RULE: one heavy workload at a time. Before `proof-up` or `fakenet-up`, read the
# "Stack in use" line at the top of plans/00034-passport-evm-account-zswap-questions.md and
# APPEND a claim to it (never replace another agent's); clear it at teardown.
#
# WALLET 2 IS THE RESPONDER'S FEE PAYER (question Q63), and it is also Test 3's second
# wallet. Two processes must never drive one seed, so the run order is:
#   s1 s2 s3-fund s3-start | fakenet-up | s3-relay | fakenet-down | s3-complete s4 s5 s6
#   s7-gas s7-start | fakenet-up | s7-relay | fakenet-down | s7-complete s8

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # contracts/erc20-vault
ACCOUNT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"               # contract/
CONFIG_DIR="$HOME/.config/aa-00034"

# ---- the public half of the configuration -----------------------------------------------

export MIDNIGHT_NETWORK=stagenet
export PRS_PROFILE=stagenet

PROOF_PORT="${PROOF_PORT:-27411}"
PROOF_CONTAINER="${PROOF_CONTAINER:-prsf-proof-server-$PROOF_PORT}"
PROOF_IMAGE="${PROOF_IMAGE:-midnightntwrk/proof-server:9.0.0-rc.6}"
export MIDNIGHT_PROOF_SERVER_URL="http://127.0.0.1:$PROOF_PORT"

FAKENET_CONTAINER="${FAKENET_CONTAINER:-prsf-fakenet}"
# The 00034 patched build: the `eth_call` output-recovery fallback for an RPC without the
# debug namespace (question Q62) PLUS the caller allow-list (question Q64), without which a
# responder on a SHARED singleton answers every request any party ever posted to it.
FAKENET_IMAGE="${FAKENET_IMAGE:-fakenet-00034:0.23.0-tracefallback-allowlist}"

# Stagenet's endpoints, from the sub-plan's header table. The driver reads its own copies
# from src/node/wallet.ts; these are the CONTAINER's, and they differ in one place only:
# fakenet talks /api/v3/graphql, the version the S-L rehearsal proved it on, while the
# driver talks v4. Stagenet's indexer answers both (probed 2026-09-16).
FAKENET_INDEXER_URL="${FAKENET_INDEXER_URL:-https://indexer.stagenet.shielded.tools/api/v3/graphql}"
FAKENET_INDEXER_WS_URL="${FAKENET_INDEXER_WS_URL:-wss://indexer.stagenet.shielded.tools/api/v3/graphql/ws}"
FAKENET_NODE_URL="${FAKENET_NODE_URL:-https://rpc.stagenet.shielded.tools}"

# The DRIVER's own indexer URL for commitment-tree lookups. `src/wallet/capture.ts` reads
# INDEXER_URL and otherwise defaults to http://localhost:8088 — and both of its callers are
# wrapped in a `.catch(...)` that falls back to mt_index 0, so leaving it unset does not fail
# loudly: it silently records a WRONG tree position for a freshly bridged coin, and the spend
# that follows dies at proving time with "invalid index into sparse merkle tree: 0". Measured
# the hard way at F5 (question Q68). `src/node/wallet.ts` honours the same variable, and this
# is the same stagenet indexer it would use anyway.
export INDEXER_URL="${INDEXER_URL:-https://indexer.stagenet.shielded.tools/api/v4/graphql}"

# Sig Network's deployed singleton — the one nobody can redeploy for us, whose verifier keys
# S0 re-checked byte for byte against our 0.34.0 rebuild (question Q20).
export MIDNIGHT_SIGNET_CONTRACT_ADDRESS="${MIDNIGHT_SIGNET_CONTRACT_ADDRESS:-1df4ce25fc9f9c03dc6f4d0eb12ddf3d0db094995d4c70aca1142eebb3b77a5d}"

# OUR fakenet root's PUBLIC key, derived offline from the private key in
# ~/.config/aa-00034/fakenet-stagenet.env. The driver's `mpcRoot()` reads MPC_ROOT_KEY and
# expects the public form; the private form never enters this shell.
export MPC_ROOT_KEY="${MPC_ROOT_KEY:-0x040a32a3dcec4485c2f0d251c97ca99f4eeea573a7ecc1e6ac94a0d1862a6cb5407a3a36c7c2a114487c53be18d1e46c5786031e93550b12b4cdf38fdb586d3781}"

# A state file and an evidence directory of its OWN: the first vault and account
# (`0f9de176…`, `e8d30439…`) and their three open requests belong to Sig Network's signer
# and must not be touched (question Q61).
export PRS_STATE="${PRS_STATE:-$CONFIG_DIR/stagenet-fakenet-prs-state.json}"
export PRS_EVIDENCE_DIR="${PRS_EVIDENCE_DIR:-/Users/edwardalvarado/todo/AA/evidence/00034-passport-evm-account-zswap/pr-s-fakenet}"

# Ten minutes, not stagenet's 45: our own responder either answers in about a minute or its
# logs say why. The sub-plan's stop rule keys off exactly this.
export PRS_MPC_TIMEOUT_MS="${PRS_MPC_TIMEOUT_MS:-600000}"

# ---- the secrets, sourced into this process only ----------------------------------------

need() { [ -f "$1" ] || { echo "missing $1" >&2; exit 1; }; }
need "$CONFIG_DIR/stagenet-wallet.env"
need "$CONFIG_DIR/sepolia.env"
need "$CONFIG_DIR/stagenet-device2.env"
need "$CONFIG_DIR/fakenet-stagenet.env"

set -a
# shellcheck disable=SC1090,SC1091
. "$CONFIG_DIR/stagenet-wallet.env"        # STAGENET_WALLET_SEED, STAGENET_WALLET2_SEED
# shellcheck disable=SC1090,SC1091
. "$CONFIG_DIR/sepolia.env"                # SEPOLIA_FUNDER_KEY, SEPOLIA_RPC_URL (Alchemy)
# shellcheck disable=SC1090,SC1091
. "$CONFIG_DIR/stagenet-device2.env"       # EVM_DEVICE_KEY — the SECOND account's device
set +a

# Deliberately NOT sourced here: fakenet-stagenet.env. Its MPC_ROOT_KEY is the PRIVATE key
# and would silently override the public one above.

# ---- commands ----------------------------------------------------------------------------

claim_warning() {
  echo "  HOST RULE: claim the stack in plans/00034-passport-evm-account-zswap-questions.md"
  echo "  (APPEND to the \"Stack in use\" line, never replace another agent's claim)."
}

proof_up() {
  if [ -n "$(docker ps -q -f "name=^${PROOF_CONTAINER}$")" ]; then
    echo "proof server already up on $MIDNIGHT_PROOF_SERVER_URL"; return
  fi
  docker rm -f "$PROOF_CONTAINER" >/dev/null 2>&1 || true
  echo "starting $PROOF_IMAGE as $PROOF_CONTAINER on 127.0.0.1:$PROOF_PORT"
  claim_warning
  docker run -d --name "$PROOF_CONTAINER" -p "127.0.0.1:$PROOF_PORT:6300" \
    -e RUST_BACKTRACE=full "$PROOF_IMAGE" 'midnight-proof-server -v' >/dev/null
  for _ in $(seq 1 60); do
    if curl -sf -m 3 "$MIDNIGHT_PROOF_SERVER_URL/health" >/dev/null 2>&1 \
      || curl -s -m 3 -o /dev/null "$MIDNIGHT_PROOF_SERVER_URL"; then
      echo "  proof server answering on $MIDNIGHT_PROOF_SERVER_URL"; return
    fi
    sleep 2
  done
  echo "  proof server did not answer in 120s" >&2; docker logs --tail 30 "$PROOF_CONTAINER" >&2; exit 1
}

proof_down() {
  docker rm -f "$PROOF_CONTAINER" >/dev/null 2>&1 && echo "proof server removed" || echo "no proof server"
}

# The allow-list: the ONE caller contract this responder serves. Read from the state file
# the driver writes at s1, so it can never drift from the vault actually deployed.
vault_address() {
  python3 - "$PRS_STATE" <<'PY'
import json, sys
try:
    s = json.load(open(sys.argv[1]))
except Exception:
    sys.exit('no state file yet — run s1 first')
v = (s.get('vault') or {}).get('address')
if not v:
    sys.exit('no vault in the state file — run s1 first')
print(v)
PY
}

fakenet_up() {
  local vault; vault="$(vault_address)"
  if [ -n "$(docker ps -q -f "name=^${FAKENET_CONTAINER}$")" ]; then
    echo "fakenet already up (allow-list $vault)"; return
  fi
  docker rm -f "$FAKENET_CONTAINER" >/dev/null 2>&1 || true
  [ -n "$(docker ps -q -f "name=^${PROOF_CONTAINER}$")" ] || { echo "start the proof server first" >&2; exit 1; }

  echo "starting $FAKENET_IMAGE as $FAKENET_CONTAINER"
  echo "  responder wallet : STAGENET_WALLET2_SEED (question Q63)"
  echo "  allow-list       : $vault  (and NOTHING else — question Q64)"
  echo "  singleton        : $MIDNIGHT_SIGNET_CONTRACT_ADDRESS"
  echo "  indexer          : $FAKENET_INDEXER_URL"
  echo "  EVM RPC          : Alchemy Sepolia (keyed; not printed)"
  claim_warning

  # The private root key is read HERE, in this command's own environment, and passed
  # straight to the container. It is never exported into the shell the driver runs in.
  docker run -d --name "$FAKENET_CONTAINER" \
    --add-host host.docker.internal:host-gateway \
    -e VERBOSE=true \
    -e DISABLE_SOLANA=true \
    -e EVM_RPC_URL="$SEPOLIA_RPC_URL" \
    -e MIDNIGHT_NETWORK_ID=stagenet \
    -e MIDNIGHT_INDEXER_URL="$FAKENET_INDEXER_URL" \
    -e MIDNIGHT_INDEXER_WS_URL="$FAKENET_INDEXER_WS_URL" \
    -e MIDNIGHT_NODE_URL="$FAKENET_NODE_URL" \
    -e MIDNIGHT_PROOF_SERVER_URL="http://host.docker.internal:$PROOF_PORT" \
    -e MIDNIGHT_SIGNET_CONTRACT_ADDRESS="$MIDNIGHT_SIGNET_CONTRACT_ADDRESS" \
    -e MIDNIGHT_WALLET_SEED="$STAGENET_WALLET2_SEED" \
    -e MIDNIGHT_CALLER_ALLOWLIST="$vault" \
    -e MPC_ROOT_KEY="$(grep -E '^MPC_ROOT_KEY=' "$CONFIG_DIR/fakenet-stagenet.env" | cut -d= -f2-)" \
    "$FAKENET_IMAGE" >/dev/null
  sleep 8
  docker ps --filter "name=^${FAKENET_CONTAINER}$" --format '  {{.Names}} {{.Status}}'
}

fakenet_down() {
  docker rm -f "$FAKENET_CONTAINER" >/dev/null 2>&1 && echo "fakenet removed" || echo "no fakenet"
}

print_env() {
  cat <<EOF
network              stagenet
proof server         $MIDNIGHT_PROOF_SERVER_URL  ($PROOF_IMAGE, container $PROOF_CONTAINER)
singleton            $MIDNIGHT_SIGNET_CONTRACT_ADDRESS
fakenet image        $FAKENET_IMAGE
fakenet indexer      $FAKENET_INDEXER_URL
MPC root (PUBLIC)    $MPC_ROOT_KEY
state file           $PRS_STATE
evidence             $PRS_EVIDENCE_DIR
MPC wait             $((PRS_MPC_TIMEOUT_MS / 60000)) minutes
secrets              \$HOME/.config/aa-00034/{stagenet-wallet,sepolia,stagenet-device2,fakenet-stagenet}.env
EOF
}

case "${1:-}" in
  proof-up)     proof_up ;;
  proof-down)   proof_down ;;
  fakenet-up)   fakenet_up ;;
  fakenet-down) fakenet_down ;;
  fakenet-logs) shift; docker logs "$@" "$FAKENET_CONTAINER" ;;
  env)          print_env ;;
  '')           echo "usage: $0 {proof-up|proof-down|fakenet-up|fakenet-down|fakenet-logs|env|<driver command>}" >&2; exit 2 ;;
  *)            cd "$ACCOUNT_DIR" && exec npx tsx src/tests/stagenet-run.ts "$@" ;;
esac
