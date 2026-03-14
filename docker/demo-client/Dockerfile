FROM rust:1.70-slim as builder

WORKDIR /app
COPY .. .
RUN cargo build --release --bin fortress

FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Create demo user
RUN useradd -m -u 1000 demo

WORKDIR /app

# Copy the built binary
COPY --from=builder /app/target/release/fortress /usr/local/bin/fortress

# Copy demo scripts
COPY docker/demo-scripts /scripts

# Set permissions
RUN chown -R demo:demo /app
RUN chmod +x /scripts/*.sh

USER demo

# Default command - keep container running
CMD ["sleep", "infinity"]
