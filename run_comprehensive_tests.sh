#!/bin/bash
set -euo pipefail

# Secreton Enterprise Vault - Comprehensive Test Runner
# Usage: ./run_comprehensive_tests.sh [options]

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
VERBOSE=false
PARALLEL=true
COVERAGE=false
BENCHMARKS=false
INTEGRATION=false
CLEAN_FIRST=false
PROFILE="dev"
TEST_TIMEOUT="300s"

# Print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Print usage information
usage() {
    cat << EOF
Secreton Enterprise Vault - Comprehensive Test Runner

Usage: $0 [OPTIONS]

OPTIONS:
    -h, --help              Show this help message
    -v, --verbose           Enable verbose output
    -c, --coverage          Generate code coverage report
    -b, --benchmarks        Run performance benchmarks
    -i, --integration       Run integration tests only
    -s, --sequential        Run tests sequentially (no parallel)
    -p, --profile PROFILE   Build profile (dev, release, security) [default: dev]
    -t, --timeout TIMEOUT   Test timeout [default: 300s]
    --clean                 Clean build artifacts before testing

EXAMPLES:
    $0                      # Run all unit tests
    $0 -v                   # Run with verbose output
    $0 -c                   # Run tests with coverage report
    $0 -b                   # Run benchmarks
    $0 -i                   # Run integration tests only
    $0 --clean -p release   # Clean build and run in release mode

EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -c|--coverage)
                COVERAGE=true
                shift
                ;;
            -b|--benchmarks)
                BENCHMARKS=true
                shift
                ;;
            -i|--integration)
                INTEGRATION=true
                shift
                ;;
            -s|--sequential)
                PARALLEL=false
                shift
                ;;
            -p|--profile)
                PROFILE="$2"
                shift 2
                ;;
            -t|--timeout)
                TEST_TIMEOUT="$2"
                shift 2
                ;;
            --clean)
                CLEAN_FIRST=true
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

# Check if cargo is installed
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    if ! command -v cargo &> /dev/null; then
        print_error "Cargo is not installed or not in PATH"
        exit 1
    fi
    
    if ! command -v rustc &> /dev/null; then
        print_error "Rust compiler is not installed or not in PATH"
        exit 1
    fi
    
    # Check for test dependencies
    if [[ "$COVERAGE" == "true" ]] && ! command -v cargo-tarpaulin &> /dev/null; then
        print_warning "cargo-tarpaulin not found. Installing..."
        cargo install cargo-tarpaulin || {
            print_error "Failed to install cargo-tarpaulin"
            exit 1
        }
    fi
    
    print_success "Prerequisites check passed"
}

# Clean build artifacts
clean_build() {
    if [[ "$CLEAN_FIRST" == "true" ]]; then
        print_status "Cleaning build artifacts..."
        cargo clean
        print_success "Build artifacts cleaned"
    fi
}

# Build the project
build_project() {
    print_status "Building project with profile: $PROFILE..."
    
    local build_args=()
    
    if [[ "$PROFILE" == "release" ]]; then
        build_args+=(--release)
    elif [[ "$PROFILE" == "security" ]]; then
        build_args+=(--profile security)
    fi
    
    if [[ "$VERBOSE" == "true" ]]; then
        build_args+=(--verbose)
    fi
    
    # Build all workspace members
    cargo build "${build_args[@]}" --workspace || {
        print_error "Build failed"
        exit 1
    }
    
    print_success "Build completed successfully"
}

# Run unit tests
run_unit_tests() {
    print_status "Running unit tests..."
    
    local test_args=()
    test_args+=(--test unit_tests)
    
    if [[ "$VERBOSE" == "true" ]]; then
        test_args+=(--verbose)
    fi
    
    if [[ "$PARALLEL" == "false" ]]; then
        test_args+=(-- --test-threads=1)
    fi
    
    timeout "$TEST_TIMEOUT" cargo test "${test_args[@]}" || {
        print_error "Unit tests failed"
        return 1
    }
    
    print_success "Unit tests passed"
}

# Run integration tests
run_integration_tests() {
    print_status "Running integration tests..."
    
    local test_args=()
    test_args+=(--test integration_tests)
    
    if [[ "$VERBOSE" == "true" ]]; then
        test_args+=(--verbose)
    fi
    
    if [[ "$PARALLEL" == "false" ]]; then
        test_args+=(-- --test-threads=1)
    fi
    
    timeout "$TEST_TIMEOUT" cargo test "${test_args[@]}" || {
        print_error "Integration tests failed"
        return 1
    }
    
    print_success "Integration tests passed"
}

# Run performance benchmarks
run_benchmarks() {
    if [[ "$BENCHMARKS" == "true" ]]; then
        print_status "Running performance benchmarks..."
        
        local bench_args=()
        bench_args+=(--test performance_tests)
        
        if [[ "$VERBOSE" == "true" ]]; then
            bench_args+=(--verbose)
        fi
        
        timeout "$TEST_TIMEOUT" cargo test "${bench_args[@]}" || {
            print_error "Performance benchmarks failed"
            return 1
        }
        
        print_success "Performance benchmarks completed"
    fi
}

# Generate coverage report
generate_coverage() {
    if [[ "$COVERAGE" == "true" ]]; then
        print_status "Generating code coverage report..."
        
        local coverage_args=()
        coverage_args+=(--out Html)
        coverage_args+=(--output-dir coverage)
        coverage_args+=(--exclude-files "tests/*")
        coverage_args+=(--exclude-files "examples/*")
        coverage_args+=(--exclude-files "target/*")
        coverage_args+=(--ignore-panics)
        coverage_args+=(--timeout "$TEST_TIMEOUT")
        
        if [[ "$VERBOSE" == "true" ]]; then
            coverage_args+=(--verbose)
        fi
        
        cargo tarpaulin "${coverage_args[@]}" || {
            print_error "Coverage generation failed"
            return 1
        }
        
        print_success "Coverage report generated in coverage/"
    fi
}

# Run all tests
run_all_tests() {
    local test_failed=false
    
    if [[ "$INTEGRATION" == "false" ]]; then
        run_unit_tests || test_failed=true
    fi
    
    run_integration_tests || test_failed=true
    run_benchmarks || test_failed=true
    
    if [[ "$test_failed" == "true" ]]; then
        print_error "Some tests failed"
        return 1
    fi
    
    print_success "All tests passed"
}

# Generate test report
generate_report() {
    print_status "Generating test report..."
    
    local report_file="test-report-$(date +%Y%m%d-%H%M%S).txt"
    
    cat > "$report_file" << EOF
Secreton Enterprise Vault - Test Report
Generated: $(date)
Profile: $PROFILE
Parallel: $PARALLEL
Coverage: $COVERAGE
Benchmarks: $BENCHMARKS

Test Results:
EOF
    
    echo "Unit Tests: $(cargo test --test unit_tests -- --list 2>/dev/null | grep -c "test " || echo "N/A")" >> "$report_file"
    echo "Integration Tests: $(cargo test --test integration_tests -- --list 2>/dev/null | grep -c "test " || echo "N/A")" >> "$report_file"
    echo "Performance Tests: $(cargo test --test performance_tests -- --list 2>/dev/null | grep -c "test " || echo "N/A")" >> "$report_file"
    
    print_success "Test report generated: $report_file"
}

# Main execution
main() {
    print_status "Starting Secreton Enterprise Vault comprehensive testing..."
    
    parse_args "$@"
    check_prerequisites
    clean_build
    build_project
    run_all_tests
    generate_coverage
    generate_report
    
    print_success "Comprehensive testing completed successfully!"
}

# Execute main function with all arguments
main "$@"
