FROM rust:1.88.0-slim-bookworm@sha256:38bc5a86d998772d4aec2348656ed21438d20fcdce2795b56ca434cf21430d89 AS build
WORKDIR /src
COPY rust-toolchain.toml Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked \
    && install -m 0555 target/release/sanct-classifier /sanct-classifier

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=build /sanct-classifier /usr/local/bin/sanct-classifier
COPY models/sanct-spam.json models/sanct-spam.bin /app/models/
WORKDIR /app
ENV CLASSIFIER_MODEL=/app/models/sanct-spam.json \
    CLASSIFIER_LISTEN=0.0.0.0:8080 \
    RUST_LOG=info \
    GLIBC_TUNABLES=glibc.malloc.mmap_threshold=131072:glibc.malloc.arena_max=2
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s CMD ["/usr/local/bin/sanct-classifier", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/sanct-classifier"]
