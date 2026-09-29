# The pinned Compact toolchain for keygen.sh: compactc 0.34.0 (language 0.26.0, runtime 0.19.0),
# whose bundled `zkir-v3` keys both the compactc circuits and the MinoCrab ones.
#
# THE PIN is the release archive's SHA-256, checked while the image is built; keygen.sh then checks
# `compactc --version`, `--language-version` and the `zkir-v3` binary hash before any key is made.
# Same recipe as AA 00029 (`docker/compactc.Dockerfile`): the aarch64 musl archive, so this builds an
# arm64 image. The x86_64 archive is 775ccddf5a71399835329bbf7471ba5a8c54fcc825d372c75e19ba7042069584;
# switching to it is a re-pin (keygen.sh pins the arm64 `zkir-v3` hash).
FROM alpine:3.22

RUN apk add --no-cache libstdc++ libgcc unzip curl bash

ARG COMPACTC_URL=https://github.com/LFDT-Minokawa/compact/releases/download/compactc-v0.34.0/compactc_v0.34.0_aarch64-unknown-linux-musl.zip
ARG COMPACTC_SHA256=d3e292c4f48e257dcd6b3d3e3e4743d7d8ea0729f48953eab91a366d44cd026d

RUN set -eux; \
    curl -sSL -o /tmp/compactc.zip "$COMPACTC_URL"; \
    echo "${COMPACTC_SHA256}  /tmp/compactc.zip" | sha256sum -c -; \
    mkdir -p /opt/compactc; \
    unzip -q /tmp/compactc.zip -d /opt/compactc; \
    chmod +x /opt/compactc/compactc /opt/compactc/compactc.bin /opt/compactc/zkir /opt/compactc/zkir-v3; \
    rm -f /tmp/compactc.zip

ENV PATH="/opt/compactc:${PATH}"
WORKDIR /work
ENTRYPOINT []
CMD ["compactc", "--version"]
