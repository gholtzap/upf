FROM rustlang/rust:nightly-slim as builder


WORKDIR /build

COPY Cargo.toml ./
COPY src ./src

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/target/release/upf /app/upf

EXPOSE 8080 2152/udp 8806/udp

CMD ["/app/upf"]
