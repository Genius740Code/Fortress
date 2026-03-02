# Multi-stage build for Fortress development environment
FROM rust:1.75-slim

# Install build and runtime dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    build-essential \
    ca-certificates \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/bash fortress

# Set working directory
WORKDIR /app

# Copy Cargo files
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/

# Build all components
RUN cargo build --release

# Create data directory
RUN mkdir -p /data && chown fortress:fortress /data

# Switch to non-root user
USER fortress

# Set environment variables
ENV RUST_LOG=info
ENV FORTRESS_DATA_DIR=/data

# Expose server port
EXPOSE 8080

# Default to server
CMD ["./target/release/fortress-server"]
