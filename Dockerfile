# Build stage
FROM rust:1.82-bookworm AS builder

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy source
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Build release
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binaries
COPY --from=builder /app/target/release/burrow-server /usr/local/bin/
COPY --from=builder /app/target/release/burrow /usr/local/bin/
COPY --from=builder /app/target/release/burrow-agent /usr/local/bin/

# Create data directory
RUN mkdir -p /data

ENV DATABASE_URL=sqlite:/data/burrow.db?mode=rwc
ENV BIND_ADDR=0.0.0.0:3000
ENV RUST_LOG=info

EXPOSE 3000

CMD ["burrow-server"]
