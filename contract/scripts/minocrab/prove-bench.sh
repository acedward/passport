#!/usr/bin/env bash
# prove-bench.sh — real proofs and the paired benchmark, compactc against MinoCrab, on the pinned
# proof server (AA project 00040, P2.3 + P2.4). Everything runs in Docker.
#
#   contract/scripts/minocrab/prove-bench.sh <keysets-root> <out-dir> [N]
#
# <keysets-root> holds `compactc/account` and `mixed/account` (keyset.ts), plus the callee bundles
# the account's JavaScript imports (Erc20Vault, SignetSigner). <out-dir> receives the shared
# preimages, every proof, the per-run timings and the proof server's sampled memory.
#
# For every (circuit, arm) it starts a FRESH proof server (midnightntwrk/proof-server:9.0.0-rc.6, by
# digest) on a random free 127.0.0.1 port >= 10000, samples its memory once a second
# (`docker stats`), runs prove-bench.ts `bench` (a /check, one untimed warm-up proof, then N timed
# proofs of the SAME preimage), and removes the server. The two arms of a circuit run back to back
# and the order alternates between circuits. Containers are named aa00040-p2-*.
set -euo pipefail

ROOT="$(cd "$1" && pwd)"
OUT="$2"
N="${3:-5}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTRACT="$(cd "$HERE/../.." && pwd)"
IMAGE="${BENCH_IMAGE:-midnight-2-offers/aa-contracts:demo-infra-14580}"
PROOF_IMAGE="midnightntwrk/proof-server:9.0.0-rc.6@sha256:38a819eacde273f725551fdf90ca7c31ebf3c0ff145f3ed58ee35f92fb7ce95b"
# The proof server fetches its zswap and dust key material into MIDNIGHT_PP at start, so the
# directory must be WRITABLE: a dedicated cache seeded with the pinned SRS files, never the shared one.
PARAMS="${PS_PARAMS:-$HOME/.cache/aa-00040/ps-params}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

say() { printf '== %s\n' "$*" >&2; }
free_port() {
  python3 -c 'import random, socket
for _ in range(200):
    p = random.randint(10000, 60000); s = socket.socket()
    try: s.bind(("127.0.0.1", p)); s.close(); print(p); break
    except OSError: s.close()'
}

PS=""; SAMPLER=""
cleanup() {
  [ -n "$SAMPLER" ] && kill "$SAMPLER" 2>/dev/null || true
  [ -n "$PS" ] && docker rm -f "$PS" >/dev/null 2>&1 || true
  docker rm -f aa00040-p2-gen aa00040-p2-bench >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

bun_run() { # name network args...
  local name="$1" net="$2"; shift 2
  docker run --rm --name "$name" --network "$net" --entrypoint bun -w /aa/g \
    -v "$CONTRACT/src:/aa/g/contract/src:ro" \
    -v "$ROOT/compactc:/aa/g/contract/contracts/managed:ro" \
    -v "$ROOT:/keysets:ro" \
    -v "$HERE:/aa/g/scripts:ro" \
    -v "$OUT:/out" \
    "$IMAGE" /aa/g/scripts/prove-bench.ts "$@"
}

if [ ! -f "$OUT/append_inbox_with_evm.preimage" ]; then
  say "generating the shared preimages (offline)"
  bun_run aa00040-p2-gen none gen --out /out
fi

bench_one() { # circuit arm keysdir
  local circuit="$1" arm="$2" keys="$3" port
  port="$(free_port)"
  PS="aa00040-p2-ps-${arm}-${circuit%%_*}"
  say "$circuit / $arm: proof server $PS on 127.0.0.1:$port"
  docker run -d --name "$PS" -p "127.0.0.1:$port:6300" --memory 14g \
    -e MIDNIGHT_PP=/params -v "$PARAMS:/params" "$PROOF_IMAGE" >/dev/null
  for _ in $(seq 1 120); do curl -fsS "http://127.0.0.1:$port/health" >/dev/null 2>&1 && break; sleep 1; done
  curl -fsS "http://127.0.0.1:$port/health" >/dev/null || { docker logs --tail 20 "$PS" >&2; exit 1; }
  python3 - "$PS" "$OUT/$circuit.$arm.mem.csv" <<'PY' &
import re, subprocess, sys, time
name, out = sys.argv[1], sys.argv[2]
unit = {"B": 1, "KiB": 2**10, "MiB": 2**20, "GiB": 2**30, "KB": 1e3, "MB": 1e6, "GB": 1e9}
p = subprocess.Popen(["docker", "stats", "--format", "{{.MemUsage}}", name], stdout=subprocess.PIPE, text=True)
with open(out, "w") as f:
    f.write("ms,bytes\n")
    for line in p.stdout:
        line = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", line).strip()
        m = re.match(r"([\d.]+)\s*([A-Za-z]+)\s*/", line)
        if not m:
            continue
        f.write(f"{int(time.time() * 1000)},{int(float(m.group(1)) * unit.get(m.group(2), 1))}\n")
        f.flush()
PY
  SAMPLER=$!
  docker stats --no-stream --format '{{.Name}} {{.CPUPerc}} {{.MemUsage}}' > "$OUT/$circuit.$arm.load-before.txt" 2>&1 || true
  bun_run aa00040-p2-bench bridge bench --out /out --circuit "$circuit" --arm "$arm" \
    --keys "/keysets/$keys/account" --url "http://host.docker.internal:$port" --n "$N"
  docker stats --no-stream --format '{{.Name}} {{.CPUPerc}} {{.MemUsage}}' > "$OUT/$circuit.$arm.load-after.txt" 2>&1 || true
  kill "$SAMPLER" 2>/dev/null || true; SAMPLER=""
  docker logs "$PS" > "$OUT/$circuit.$arm.server.log" 2>&1 || true
  docker rm -f "$PS" >/dev/null; PS=""
}

bench_one append_inbox_with_evm compactc compactc
bench_one append_inbox_with_evm minocrab mixed
bench_one withdraw_shielded_with_evm minocrab mixed
bench_one withdraw_shielded_with_evm compactc compactc
say "done: $OUT"
