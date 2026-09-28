# The build/test image for the MinoCrab port: the pinned Rust 1.95 toolchain (plus rustfmt and
# clippy) and nothing else. The source is bind-mounted at /src at run time (scripts/gate.sh); the
# cargo home and the target directory live in named volumes so a rebuild does not refetch or
# recompile the dependency tree.
FROM rust:1.95-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1
RUN rustup component add rustfmt clippy --toolchain 1.95.0
ENV CARGO_HOME=/cargo \
    CARGO_TARGET_DIR=/target \
    CARGO_TERM_COLOR=never \
    RUSTUP_TOOLCHAIN=1.95.0
WORKDIR /src
