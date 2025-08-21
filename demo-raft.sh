#!/bin/bash

# Brankas Vault - Raft Integrated Storage Demo
# This script demonstrates the Raft storage backend functionality

set -e

echo "🔐 Brankas Vault - Raft Storage Demo"
echo "==================================="
echo ""

# Configuration
API_URL="${API_URL:-http://127.0.0.1:8200}"
RAFT_URL="${RAFT_URL:-127.0.0.1:8201}"

echo "Testing endpoints:"
echo "  API: $API_URL"
echo "  Raft: $RAFT_URL"
echo ""

# Helper function to make HTTP requests with error handling
make_request() {
    local method="$1"
    local url="$2"
    local data="$3"
    local description="$4"
    
    echo "📡 $description"
    echo "   $method $url"
    
    if [[ -n "$data" ]]; then
        echo "   Data: $data"
        response=$(curl -s -X "$method" -H "Content-Type: application/json" -d "$data" "$url" || echo "ERROR")
    else
        response=$(curl -s -X "$method" "$url" || echo "ERROR")
    fi
    
    if [[ "$response" == "ERROR" ]]; then
        echo "   ❌ Request failed"
        return 1
    else
        echo "   ✅ Response: $response"
        echo ""
        return 0
    fi
}

echo "🚀 Starting Raft Storage Demo..."
echo ""

# Test 1: Health check
echo "=== Test 1: System Health ==="
make_request "GET" "$API_URL/health" "" "Checking system health"

# Test 2: Check Raft leadership status
echo "=== Test 2: Raft Leadership ==="
make_request "GET" "$API_URL/v1/sys/leader" "" "Checking Raft leadership"

# Test 3: Storage backend info
echo "=== Test 3: Storage Backend Info ==="
make_request "GET" "$API_URL/v1/sys/storage/raft/configuration" "" "Getting Raft configuration"

# Test 4: Transit Engine Operations
echo "=== Test 4: Transit Engine with Raft Storage ==="

# Create encryption key
make_request "POST" "$API_URL/v1/transit/keys/raft-test-key" "" "Creating transit key"

# Encrypt data
plaintext_b64=$(echo -n "Hello Raft Storage!" | base64)
encrypt_data="{\"plaintext\":\"$plaintext_b64\"}"
response=$(make_request "POST" "$API_URL/v1/transit/encrypt/raft-test-key" "$encrypt_data" "Encrypting data with Raft storage")

if [[ "$response" != *"ERROR"* ]]; then
    # Extract ciphertext
    ciphertext=$(echo "$response" | grep -o '"ciphertext":"[^"]*"' | cut -d'"' -f4)
    
    if [[ -n "$ciphertext" ]]; then
        # Decrypt data
        decrypt_data="{\"ciphertext\":\"$ciphertext\"}"
        make_request "POST" "$API_URL/v1/transit/decrypt/raft-test-key" "$decrypt_data" "Decrypting data from Raft storage"
    fi
fi

# List keys
make_request "GET" "$API_URL/v1/transit/keys" "" "Listing transit keys"

# Test 5: KV Secrets Engine with Raft Storage
echo "=== Test 5: KV Secrets Engine with Raft Storage ==="

# Store secret
secret_data='{"data":{"username":"admin","password":"secret123","api_key":"raft-key-12345","database_url":"postgresql://localhost:5432/raft_db"}}'
make_request "POST" "$API_URL/v1/secret/data/raft-app-config" "$secret_data" "Storing secret in Raft storage"

# Retrieve secret
make_request "GET" "$API_URL/v1/secret/data/raft-app-config" "" "Retrieving secret from Raft storage"

# List secrets
make_request "GET" "$API_URL/v1/secrets" "" "Listing all secrets"

# Test 6: Raft Storage Statistics
echo "=== Test 6: Raft Storage Statistics ==="
make_request "GET" "$API_URL/v1/sys/storage/raft/stats" "" "Getting Raft storage statistics"

# Test 7: Combined workflow - Encrypt then Store
echo "=== Test 7: Combined Workflow - Encrypt then Store ==="

# Create dedicated key for sensitive data
make_request "POST" "$API_URL/v1/transit/keys/raft-sensitive-key" "" "Creating key for sensitive data"

# Encrypt sensitive data
sensitive_data="super-secret-database-password"
sensitive_b64=$(echo -n "$sensitive_data" | base64)
encrypt_sensitive="{\"plaintext\":\"$sensitive_b64\"}"
response=$(make_request "POST" "$API_URL/v1/transit/encrypt/raft-sensitive-key" "$encrypt_sensitive" "Encrypting sensitive data")

if [[ "$response" != *"ERROR"* ]]; then
    # Extract encrypted password
    encrypted_pass=$(echo "$response" | grep -o '"ciphertext":"[^"]*"' | cut -d'"' -f4)
    
    if [[ -n "$encrypted_pass" ]]; then
        # Store configuration with encrypted password
        config_data="{\"data\":{\"host\":\"db.example.com\",\"port\":\"5432\",\"encrypted_password\":\"$encrypted_pass\",\"connection_pool\":\"10\"}}"
        make_request "POST" "$API_URL/v1/secret/data/raft-secure-db-config" "$config_data" "Storing config with encrypted password"
        
        # Retrieve and decrypt
        echo "📋 Demonstrating decrypt workflow:"
        make_request "GET" "$API_URL/v1/secret/data/raft-secure-db-config" "" "Retrieving secure config"
        
        # Decrypt the password
        decrypt_pass="{\"ciphertext\":\"$encrypted_pass\"}"
        make_request "POST" "$API_URL/v1/transit/decrypt/raft-sensitive-key" "$decrypt_pass" "Decrypting password from config"
    fi
fi

# Test 8: Performance Test
echo "=== Test 8: Raft Storage Performance ==="

echo "📊 Running performance test..."
start_time=$(date +%s%N)

for i in {1..10}; do
    key="perf-test-$i"
    test_data="{\"data\":{\"iteration\":$i,\"timestamp\":\"$(date)\",\"random\":\"$(uuidgen)\"}}"
    curl -s -X POST -H "Content-Type: application/json" -d "$test_data" "$API_URL/v1/secret/data/$key" >/dev/null
done

end_time=$(date +%s%N)
duration=$(( (end_time - start_time) / 1000000 ))

echo "   ✅ Stored 10 entries in ${duration}ms (avg: $((duration / 10))ms per entry)"

# Cleanup performance test entries
echo "🧹 Cleaning up performance test data..."
for i in {1..10}; do
    curl -s -X DELETE "$API_URL/v1/secret/data/perf-test-$i" >/dev/null
done

echo ""
echo "🎉 Raft Storage Demo Complete!"
echo ""
echo "Summary:"
echo "  ✅ System health check"
echo "  ✅ Raft leadership status"
echo "  ✅ Transit engine with Raft storage"
echo "  ✅ KV secrets engine with Raft storage"
echo "  ✅ Combined encrypt-then-store workflow"
echo "  ✅ Storage performance test"
echo ""
echo "💡 Key Benefits of Raft Integrated Storage:"
echo "  • No external dependencies (self-contained)"
echo "  • Built-in high availability and consensus"
echo "  • Automatic leader election and failover"
echo "  • Strong consistency guarantees"
echo "  • Integrated with vault security model"
echo "  • Compatible with HashiCorp Vault architecture"
echo ""
echo "🔧 Next Steps:"
echo "  • Scale to multi-node cluster for HA"
echo "  • Configure TLS for production security"
echo "  • Set up monitoring and alerting"
echo "  • Implement backup and disaster recovery"
