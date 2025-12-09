# Multi-stage Dockerfile for Secreton Production Ready
# Stage 1: Build
FROM rust:1.90-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libsqlite3-dev \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy Cargo files
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Build dependencies first for caching
RUN cargo build --release --bins

# Build the main application
RUN cargo build --release

# Stage 2: Runtime
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    sqlite3 \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 secreton

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/target/release/api_server /usr/local/bin/api_server

# Copy configuration files
COPY config ./config
COPY .env.example .env

# Create data directory
RUN mkdir -p /app/data && chown -R secreton:secreton /app

# Switch to non-root user
USER secreton

# Expose ports
EXPOSE 8080 8443 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Set environment variables
ENV RUST_LOG=info
ENV SECRETON_SERVER__HOST=0.0.0.0
ENV SECRETON_SERVER__PORT=8080
ENV SECRETON_SERVER__STORAGE_PATH=/app/data

# Run the application
CMD ["api_server"]
