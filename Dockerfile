# The desk backend adapter's image.
#
# Two stages: a static musl build, then the binary alone on distroless. Both
# bases are pinned by digest, so a rebuild of the same commit uses the same
# bases; a base moves only by a reviewed change to this file.
#
# linux/amd64 only: the desk backend (NVIDIA OpenShell) runs on Linux x86_64.

# rust:1.92-bookworm, the toolchain rust-toolchain.toml pins.
FROM rust:1.92-bookworm@sha256:e90e846de4124376164ddfbaab4b0774c7bdeef5e738866295e5a90a34a307a2 AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends musl-tools \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN rustup target add x86_64-unknown-linux-musl \
 && cargo build --release --locked --target x86_64-unknown-linux-musl -p ekka-backend \
 && cp target/x86_64-unknown-linux-musl/release/ekka-backend /ekka-backend

# gcr.io/distroless/static-debian12:nonroot: no shell, no package manager,
# runs as uid 65532.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /ekka-backend /usr/local/bin/ekka-backend
COPY LICENSE NOTICE THIRD-PARTY-NOTICES.md /usr/share/doc/ekka-backend/
USER nonroot
ENTRYPOINT ["/usr/local/bin/ekka-backend"]
# Healthy when the adapter answers on its own socket; exec form, since a
# distroless image has no shell. An installer's compose file may override it.
HEALTHCHECK --interval=10s --timeout=6s --start-period=15s --retries=3 CMD ["/usr/local/bin/ekka-backend", "health"]
