FROM ghcr.io/evanrichter/cargo-fuzz as builder

ADD . /libsm
WORKDIR /libsm/fuzz
RUN cargo +nightly fuzz build 

FROM debian:bookworm
COPY --from=builder /libsm/fuzz/target/x86_64-unknown-linux-gnu/release/libsm-fuzz /