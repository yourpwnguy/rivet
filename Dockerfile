FROM rust:1.91-slim as builder

WORKDIR /app
COPY . .
RUN cargo build --release -p rivet

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/rivet /usr/local/bin/

ENTRYPOINT ["rivet"]
