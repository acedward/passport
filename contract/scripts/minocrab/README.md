# MinoCrab keys, proofs and the stagenet check

Tooling around the MinoCrab port in `contract/minocrab/` (AA project 00040, phases P2 and P3). Every
step runs in Docker. Key files are never committed: `contract/minocrab/keys/SHA256SUMS` and
`contract/minocrab/keys/manifest.json` record them.

| Script | What it does |
|---|---|
| `keygen.sh <zkir-dir> <out-dir>` | Proving and verifying keys with compactc 0.34.0's own `zkir-v3 compile-many`, against the pinned SRS, in a `--network none` container. Re-keying compactc's own ZKIR with it reproduces compactc's keys byte for byte. |
| `compactc.Dockerfile` | The toolchain image `keygen.sh` builds when it is missing, from the SHA-256-pinned release archive. |
| `keyset.ts` | The mixed key set: compactc's `managed/account` tree with the ported circuits' ZKIR, BZKIR, prover and verifier keys swapped in, `expectedVk` patched and `contract-manifest.json` re-stamped. It asserts that the tree differs from compactc's in exactly those files. |
| `prove-bench.sh` / `prove-bench.ts` | Real proofs on `midnightntwrk/proof-server:9.0.0-rc.6` and the paired benchmark. Both arms prove one shared preimage, which the client's offline account simulator produces. |
| `bench-report.py` | The benchmark table (k, rows, prover-key size, median prove time, peak memory). |
| `stagenet-check.ts` / `run-check.sh` | The live check on stagenet: deploy with the compactc keys, keeping the maintenance authority; activate; deposit; swap the ported circuits' verifier keys by one maintenance update; read them back; then call the ported circuits with the MinoCrab keys. |

`contract/minocrab/passport-account-minocrab/tests/proof_verify.rs` verifies the proof server's
proofs with Midnight's own verifier (`PROOF_DIR`, `KEYSETS_DIR`). Without `PROOF_DIR` it passes
without checking anything.

## Rebuilding the keys

```sh
contract/minocrab/scripts/gate.sh emit /tmp/zkir
contract/scripts/minocrab/keygen.sh /tmp/zkir /tmp/keys      # SRS from ~/.cache/midnight/zk-params
(cd /tmp/keys && shasum -a 256 -c "$OLDPWD/contract/minocrab/keys/SHA256SUMS")
bun contract/scripts/minocrab/keyset.ts --compactc <managed/account> --minocrab /tmp/keys --out <new root>
```

## The stagenet check

```sh
export CHECK_EVIDENCE_DIR_HOST=<public evidence directory>
export STAGENET_WALLET_FILE_HOST=<the funding wallet's WALLET= file>   # read in-process only
contract/scripts/minocrab/run-check.sh preflight
contract/scripts/minocrab/run-check.sh run        # takes the shared funding-wallet lock
contract/scripts/minocrab/run-check.sh vk-check
```

The account's maintenance-authority key is written to `$CHECK_STATE_DIR_HOST`
(default `~/.config/aa-00040`, mode 700, file mode 600) as soon as the deploy creates it. A node
refusal of a MinoCrab key or proof stops the check (exit code 3), and the error goes to the evidence.
