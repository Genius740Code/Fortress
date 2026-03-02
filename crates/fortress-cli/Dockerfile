# Multi-stage build for Fortress CLI
FROM rust:1.75-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy Cargo files
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/

# Build the CLI binary
RUN cargo build --release -p fortress-cli

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/bash fortress

# Create app directory
WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/target/release/fortress /usr/local/bin/fortress

# Create data directory
RUN mkdir -p /data && chown fortress:fortress /data

# Switch to non-root user
USER fortress

# Set environment variables
ENV RUST_LOG=info
ENV FORTRESS_DATA_DIR=/data

# Set entrypoint
ENTRYPOINT ["fortress"]
