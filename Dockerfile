# syntax=docker/dockerfile:1
FROM rust:1.67 as builder
WORKDIR /usr/src/myapp
COPY . .
RUN cargo build --release

FROM ubuntu:latest
RUN apt-get update && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/src/myapp/target/release/r-signer /usr/local/bin/r-signer

ENTRYPOINT ["/usr/local/bin/r-signer"]