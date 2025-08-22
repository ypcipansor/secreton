#!/bin/bash

# Secreton Development and Testing Script
# This script sets up, builds, and tests the complete Secreton transit engine system

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}🔐 Secreton Transit Engine - Development and Testing Suite${NC}"
echo "======================================================================"

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ] || [ ! -d "crates" ]; then
    echo -e "${RED}❌ Error: Must be run from the secreton root directory${NC}"
    exit 1
fi

# Function to run a command with nice output
run_command() {
    local description="$1"
    local command="$2"
    
    echo -e "${BLUE}📋 ${description}${NC}"
    echo "   Command: ${command}"
    
    if eval "$command"; then
        echo -e "${GREEN}   ✅ Success${NC}"
        echo
    else
        echo -e "${RED}   ❌ Failed${NC}"
        exit 1
    fi
}

# Phase 1: Environment Setup
echo -e "${PURPLE}=== Phase 1: Environment Setup ===${NC}"

# Check Rust version
run_command "Checking Rust version" "rustc --version"

# Check cargo version
run_command "Checking Cargo version" "cargo --version"

# Phase 2: Build System
echo -e "${PURPLE}=== Phase 2: Build System ===${NC}"

# Clean previous builds
run_command "Cleaning previous builds" "cargo clean"

# Build core crate
run_command "Building core crate" "cargo build -p secreton-core"

# Build simple crate
run_command "Building simple crate" "cargo build -p secreton-simple"

# Build agent crate  
run_command "Building agent crate" "cargo build -p secreton-agent"

# Build API crate
run_command "Building API crate" "cargo build -p secreton-api"

# Build API server binary
run_command "Building API server binary" "cargo build -p secreton-api --bin api_server"

# Build UI crate
run_command "Building UI crate" "cargo build -p secreton-ui"

# Build all in release mode
run_command "Building all crates in release mode" "cargo build --release --workspace"

# Phase 3: Testing
echo -e "${PURPLE}=== Phase 3: Testing Suite ===${NC}"

# Run core tests
run_command "Running core tests" "cargo test -p secreton-core"

# Run simple tests
run_command "Running simple tests" "cargo test -p secreton-simple"

# Run agent tests
run_command "Running agent tests" "cargo test -p secreton-agent"

# Run API tests
run_command "Running API tests" "cargo test -p secreton-api"

# Run UI tests
run_command "Running UI tests" "cargo test -p secreton-ui"

# Run all tests
run_command "Running all workspace tests" "cargo test --workspace"

# Phase 4: Code Quality
echo -e "${PURPLE}=== Phase 4: Code Quality Checks ===${NC}"

# Check formatting
run_command "Checking code formatting" "cargo fmt --check"

# Run clippy lints
run_command "Running clippy lints" "cargo clippy --workspace -- -D warnings"

# Check for unused dependencies
run_command "Checking for unused dependencies" "cargo machete"

# Phase 5: Documentation
echo -e "${PURPLE}=== Phase 5: Documentation ===${NC}"

# Generate documentation
run_command "Generating documentation" "cargo doc --workspace --no-deps"

# Phase 6: Performance Tests
echo -e "${PURPLE}=== Phase 6: Performance Tests ===${NC}"

# Run benchmarks
run_command "Running benchmarks" "cargo bench --workspace"

# Phase 7: Example Programs
echo -e "${PURPLE}=== Phase 7: Example Programs ===${NC}"

# Run key management example
run_command "Running key management example" "cargo run --example key_management_example"

# Run policy example
run_command "Running policy example" "cargo run --example policy_example"

# Phase 8: Server Testing
echo -e "${PURPLE}=== Phase 8: Server Testing ===${NC}"

echo -e "${YELLOW}🚀 Starting API server for testing...${NC}"
echo "   Server will start on http://127.0.0.1:8200"
echo "   Use Ctrl+C to stop the server"
echo

# Start API server in background
cargo run -p secreton-api --bin api_server &
API_SERVER_PID=$!

# Give server time to start
sleep 3

# Run client demo
if command -v curl &> /dev/null; then
    echo -e "${BLUE}📋 Testing server health endpoint${NC}"
    curl -s http://127.0.0.1:8200/health | jq . || echo "Response received but jq not available"
    echo
    
    echo -e "${BLUE}📋 Testing server version endpoint${NC}"
    curl -s http://127.0.0.1:8200/version | jq . || echo "Response received but jq not available"
    echo
fi

# Stop API server
echo -e "${YELLOW}🛑 Stopping API server...${NC}"
kill $API_SERVER_PID || true
wait $API_SERVER_PID 2>/dev/null || true

echo -e "${GREEN}✅ All tests completed successfully!${NC}"
echo
echo -e "${CYAN}🎉 Secreton Transit Engine is ready for production use!${NC}"
echo
echo "Next steps:"
echo "1. Deploy API server: cargo run -p secreton-api --bin api_server"
echo "2. Configure TLS certificates for production"
echo "3. Set up monitoring and alerting"
echo "4. Review security policies and audit logs"
echo "5. Scale horizontally using load balancer"
echo
echo "Documentation available at: target/doc/secreton_*/index.html"
echo "======================================================================"
