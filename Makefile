.PHONY: build run test clean install dev

# Build the application
build:
	cargo build --release

# Run the application
run: build
	./target/release/vault-adhyaksa

# Run in development mode
dev:
	cargo run

# Run tests
test:
	cargo test

# Clean build artifacts
clean:
	cargo clean

# Install dependencies
install:
	cargo install --path .

# Format code
fmt:
	cargo fmt

# Check code
check:
	cargo check

# Clippy linting
clippy:
	cargo clippy

# Run with specific config
run-config:
	cargo run -- --config config/vault.toml

# Run with custom port
run-port:
	cargo run -- --port 9090

# Build for production
prod-build:
	RUSTFLAGS="-C target-cpu=native" cargo build --release

# Create database
init-db:
	sqlite3 vault.db "CREATE TABLE IF NOT EXISTS secrets (id INTEGER PRIMARY KEY, path TEXT UNIQUE, data TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);"

# Help
help:
	@echo "Available commands:"
	@echo "  build       - Build the application"
	@echo "  run         - Run the application"
	@echo "  dev         - Run in development mode"
	@echo "  test        - Run tests"
	@echo "  clean       - Clean build artifacts"
	@echo "  install     - Install the application"
	@echo "  fmt         - Format code"
	@echo "  check       - Check code"
	@echo "  clippy      - Run clippy linting"
	@echo "  run-config  - Run with config file"
	@echo "  run-port    - Run on custom port"
	@echo "  prod-build  - Build for production"
	@echo "  init-db     - Initialize database"
	@echo "  help        - Show this help" 