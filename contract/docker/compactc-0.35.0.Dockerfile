# The pinned Compact toolchain for the account contract: compactc 0.35.0 (language 0.27.0,
# runtime 0.20.0, bundled zkir-v3 = midnight-zkir 3.1.0-rc.1), project 00047.
#
# THE PIN is the release archive's SHA-256, checked while the image is built. The release
# (LFDT-Minokawa/compact tag compactc-v0.35.0 @ debb05f9414b9d1e176741c2be289bb32233f0fc)
# publishes no checksum file; the digests below are GitHub's per-asset sha256 values, each
# re-checked against a download. scripts/compile-account.sh then checks `compactc --version`
# before anything is compiled.
#
#   docker build -f docker/compactc-0.35.0.Dockerfile -t passport-compactc:0.35.0 docker
FROM alpine:3.22

RUN apk add --no-cache libstdc++ libgcc unzip curl bash

ARG TARGETARCH
ARG BASE=https://github.com/LFDT-Minokawa/compact/releases/download/compactc-v0.35.0
ARG SHA_ARM64=3f74ec6fc98ccca7365c5c915f6015d8893db4527faafe04a90bc36effc40a3a
ARG SHA_AMD64=70f22fb8209cc5a8504b2b3d91796cfdab2d71d88807ceef12fab87fed03bae2

RUN set -eux; \
    case "${TARGETARCH:-arm64}" in \
      arm64) asset=compactc_v0.35.0_aarch64-unknown-linux-musl.zip; sha="$SHA_ARM64" ;; \
      amd64) asset=compactc_v0.35.0_x86_64-unknown-linux-musl.zip; sha="$SHA_AMD64" ;; \
      *) echo "unsupported arch ${TARGETARCH}"; exit 1 ;; \
    esac; \
    curl -sSL -o /tmp/compactc.zip "$BASE/$asset"; \
    echo "${sha}  /tmp/compactc.zip" | sha256sum -c -; \
    mkdir -p /opt/compactc; \
    unzip -q /tmp/compactc.zip -d /opt/compactc; \
    chmod +x /opt/compactc/compactc /opt/compactc/compactc.bin /opt/compactc/zkir /opt/compactc/zkir-v3; \
    rm -f /tmp/compactc.zip

ENV PATH="/opt/compactc:${PATH}"
WORKDIR /w
ENTRYPOINT []
CMD ["compactc", "--version"]
