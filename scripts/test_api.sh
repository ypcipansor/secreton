#!/bin/bash

# Brankas API Testing Script
# Tests all endpoints and validates functionality

set -e

BASE_URL="http://127.0.0.1:8200"
PASSED=0
FAILED=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "\n${BLUE}===========================================${NC}"
    echo -e "${BLUE}🔐 BRANKAS API TESTING SUITE${NC}"
    echo -e "${BLUE}===========================================${NC}"
    echo -e "${YELLOW}Base URL: ${BASE_URL}${NC}"
    echo -e "${YELLOW}Timestamp: $(date)${NC}\n"
}

print_test() {
    echo -e "${BLUE}🧪 Testing: $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ PASS: $1${NC}"
    ((PASSED++))
}

print_failure() {
    echo -e "${RED}❌ FAIL: $1${NC}"
    ((FAILED++))
}

print_info() {
    echo -e "${YELLOW}ℹ️  INFO: $1${NC}"
}

# Test function
test_endpoint() {
    local name="$1"
    local method="$2"
    local endpoint="$3"
    local expected_code="$4"
    local data="$5"
    
    print_test "$name"
    
    if [ -n "$data" ]; then
        response=$(curl -s -w "\n%{http_code}" -X "$method" \
            -H "Content-Type: application/json" \
            -d "$data" \
            "$BASE_URL$endpoint" 2>/dev/null)
    else
        response=$(curl -s -w "\n%{http_code}" -X "$method" \
            "$BASE_URL$endpoint" 2>/dev/null)
    fi
    
    if [ $? -ne 0 ]; then
        print_failure "$name - Connection failed"
        return 1
    fi
    
    # Extract HTTP code (last line) and body (everything else)
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    if [ "$http_code" = "$expected_code" ]; then
        print_success "$name - HTTP $http_code"
        if [ -n "$body" ] && [ "$body" != "null" ]; then
            echo -e "   ${GREEN}Response: ${body}${NC}"
        fi
        return 0
    else
        print_failure "$name - Expected HTTP $expected_code, got HTTP $http_code"
        if [ -n "$body" ]; then
            echo -e "   ${RED}Response: ${body}${NC}"
        fi
        return 1
    fi
}

# JSON validation function
validate_json() {
    local name="$1"
    local json="$2"
    local expected_field="$3"
    
    if echo "$json" | jq -e ".$expected_field" >/dev/null 2>&1; then
        local value=$(echo "$json" | jq -r ".$expected_field")
        print_success "$name - JSON field '$expected_field': $value"
        return 0
    else
        print_failure "$name - Missing JSON field '$expected_field'"
        return 1
    fi
}

# Wait for server to be ready
wait_for_server() {
    print_info "Waiting for server to be ready..."
    for i in {1..30}; do
        if curl -s "$BASE_URL/health" >/dev/null 2>&1; then
            print_success "Server is ready"
            return 0
        fi
        sleep 1
        echo -n "."
    done
    print_failure "Server failed to start within 30 seconds"
    exit 1
}

# Test Suite
run_tests() {
    print_header
    wait_for_server
    
    echo -e "\n${BLUE}📋 BASIC HEALTH CHECKS${NC}"
    echo "================================="
    
    # Test health endpoint
    if test_endpoint "Health Check" "GET" "/health" "200"; then
        health_response=$(curl -s "$BASE_URL/health")
        validate_json "Health Status" "$health_response" "status"
        validate_json "Health Timestamp" "$health_response" "timestamp"
        validate_json "Health Version" "$health_response" "version"
    fi
    
    # Test version endpoint
    if test_endpoint "Version Info" "GET" "/version" "200"; then
        version_response=$(curl -s "$BASE_URL/version")
        validate_json "Version Number" "$version_response" "version"
        validate_json "Build Info" "$version_response" "build"
    fi
    
    echo -e "\n${BLUE}🔑 TRANSIT KEY MANAGEMENT${NC}"
    echo "================================="
    
    # List keys (should be empty initially)
    test_endpoint "List Keys (Empty)" "GET" "/v1/transit/keys" "200"
    
    # Create a test key
    test_endpoint "Create AES Key" "POST" "/v1/transit/keys/test-aes" "200" \
        '{"key_type":"aes256-gcm"}'
    
    # Create another key with different algorithm
    test_endpoint "Create ChaCha20 Key" "POST" "/v1/transit/keys/test-chacha" "200" \
        '{"key_type":"chacha20-poly1305"}'
    
    # List keys again (should show our keys)
    if test_endpoint "List Keys (With Data)" "GET" "/v1/transit/keys" "200"; then
        keys_response=$(curl -s "$BASE_URL/v1/transit/keys")
        echo -e "   ${GREEN}Available Keys: $(echo $keys_response | jq -r '.keys[]' | tr '\n' ' ')${NC}"
    fi
    
    # Try to create duplicate key (should handle gracefully)
    test_endpoint "Create Duplicate Key" "POST" "/v1/transit/keys/test-aes" "200" \
        '{"key_type":"aes256-gcm"}'
    
    echo -e "\n${BLUE}🔒 ENCRYPTION OPERATIONS${NC}"
    echo "================================="
    
    # Test data for encryption
    TEST_DATA="SGVsbG8sIEJyYW5rYXMgU2VjdXJpdHkhCg=="  # "Hello, Brankas Security!" in base64
    
    # Encrypt with AES key
    if test_endpoint "Encrypt with AES" "POST" "/v1/transit/encrypt/test-aes" "200" \
        "{\"plaintext\":\"$TEST_DATA\"}"; then
        aes_ciphertext=$(curl -s -X POST -H "Content-Type: application/json" \
            -d "{\"plaintext\":\"$TEST_DATA\"}" \
            "$BASE_URL/v1/transit/encrypt/test-aes" | jq -r '.ciphertext')
        print_info "AES Ciphertext: ${aes_ciphertext:0:50}..."
    fi
    
    # Encrypt with ChaCha20 key  
    if test_endpoint "Encrypt with ChaCha20" "POST" "/v1/transit/encrypt/test-chacha" "200" \
        "{\"plaintext\":\"$TEST_DATA\"}"; then
        chacha_ciphertext=$(curl -s -X POST -H "Content-Type: application/json" \
            -d "{\"plaintext\":\"$TEST_DATA\"}" \
            "$BASE_URL/v1/transit/encrypt/test-chacha" | jq -r '.ciphertext')
        print_info "ChaCha20 Ciphertext: ${chacha_ciphertext:0:50}..."
    fi
    
    echo -e "\n${BLUE}🔓 DECRYPTION OPERATIONS${NC}"
    echo "================================="
    
    # Decrypt with AES key
    if [ -n "$aes_ciphertext" ] && [ "$aes_ciphertext" != "null" ]; then
        if test_endpoint "Decrypt with AES" "POST" "/v1/transit/decrypt/test-aes" "200" \
            "{\"ciphertext\":\"$aes_ciphertext\"}"; then
            aes_plaintext=$(curl -s -X POST -H "Content-Type: application/json" \
                -d "{\"ciphertext\":\"$aes_ciphertext\"}" \
                "$BASE_URL/v1/transit/decrypt/test-aes" | jq -r '.plaintext')
            if [ "$aes_plaintext" = "$TEST_DATA" ]; then
                print_success "AES Roundtrip Verification - Data matches"
            else
                print_failure "AES Roundtrip Verification - Data mismatch"
            fi
        fi
    fi
    
    # Decrypt with ChaCha20 key
    if [ -n "$chacha_ciphertext" ] && [ "$chacha_ciphertext" != "null" ]; then
        if test_endpoint "Decrypt with ChaCha20" "POST" "/v1/transit/decrypt/test-chacha" "200" \
            "{\"ciphertext\":\"$chacha_ciphertext\"}"; then
            chacha_plaintext=$(curl -s -X POST -H "Content-Type: application/json" \
                -d "{\"ciphertext\":\"$chacha_ciphertext\"}" \
                "$BASE_URL/v1/transit/decrypt/test-chacha" | jq -r '.plaintext')
            if [ "$chacha_plaintext" = "$TEST_DATA" ]; then
                print_success "ChaCha20 Roundtrip Verification - Data matches"
            else
                print_failure "ChaCha20 Roundtrip Verification - Data mismatch"
            fi
        fi
    fi
    
    echo -e "\n${BLUE}❌ ERROR HANDLING${NC}"
    echo "================================="
    
    # Test non-existent key
    test_endpoint "Encrypt Non-existent Key" "POST" "/v1/transit/encrypt/nonexistent" "500" \
        "{\"plaintext\":\"$TEST_DATA\"}"
    
    # Test invalid ciphertext
    test_endpoint "Decrypt Invalid Ciphertext" "POST" "/v1/transit/decrypt/test-aes" "500" \
        '{"ciphertext":"invalid-ciphertext"}'
    
    # Test malformed JSON
    test_endpoint "Malformed JSON" "POST" "/v1/transit/encrypt/test-aes" "400" \
        '{"invalid-json"'
    
    # Test non-existent endpoint
    test_endpoint "Non-existent Endpoint" "GET" "/v1/nonexistent" "404"
    
    echo -e "\n${BLUE}⚡ PERFORMANCE TESTS${NC}"
    echo "================================="
    
    # Performance test - multiple operations
    print_test "Performance - Multiple Encryptions"
    start_time=$(date +%s%N)
    for i in {1..10}; do
        curl -s -X POST -H "Content-Type: application/json" \
            -d "{\"plaintext\":\"$TEST_DATA\"}" \
            "$BASE_URL/v1/transit/encrypt/test-aes" >/dev/null
    done
    end_time=$(date +%s%N)
    duration=$((($end_time - $start_time) / 1000000))  # Convert to milliseconds
    print_success "Performance - 10 encryptions in ${duration}ms (avg: $((duration/10))ms)"
    
    # Generate summary
    echo -e "\n${BLUE}📊 TEST SUMMARY${NC}"
    echo "================================="
    total=$((PASSED + FAILED))
    success_rate=$((PASSED * 100 / total))
    
    echo -e "${GREEN}✅ Passed: $PASSED${NC}"
    echo -e "${RED}❌ Failed: $FAILED${NC}"
    echo -e "${BLUE}📈 Success Rate: $success_rate%${NC}"
    
    if [ $FAILED -eq 0 ]; then
        echo -e "\n${GREEN}🎉 All tests passed! Brankas API is working perfectly.${NC}"
        exit 0
    else
        echo -e "\n${RED}⚠️  Some tests failed. Please check the output above.${NC}"
        exit 1
    fi
}

# Handle script interruption
cleanup() {
    echo -e "\n${YELLOW}🛑 Testing interrupted${NC}"
    exit 130
}
trap cleanup INT

# Main execution
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo "Brankas API Testing Suite"
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -h, --help    Show this help message"
    echo "  --verbose     Enable verbose output"
    echo ""
    echo "Environment Variables:"
    echo "  BASE_URL      API base URL (default: http://127.0.0.1:8200)"
    exit 0
fi

if [ "$1" = "--verbose" ]; then
    set -x
fi

# Run the tests
run_tests
