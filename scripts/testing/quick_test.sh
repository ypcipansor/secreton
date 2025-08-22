#!/bin/bash

# Quick test of the API endpoints
echo "🔥 Starting Secreton API Server..."

# Start the server in the background
cd /home/clouduser/vault/secreton
./target/debug/api_server &
SERVER_PID=$!

# Wait for server to start
echo "⏳ Waiting for server to start..."
sleep 5

# Test endpoints
echo "🧪 Testing Health Endpoint..."
curl -s http://127.0.0.1:8200/health | jq . || echo "❌ Health check failed"

echo -e "\n🧪 Testing Version Endpoint..."
curl -s http://127.0.0.1:8200/version | jq . || echo "❌ Version check failed"

echo -e "\n🧪 Creating a key..."
CREATE_RESPONSE=$(curl -s -X POST http://127.0.0.1:8200/v1/transit/keys/test-key)
echo "Create key response: $CREATE_RESPONSE"

echo -e "\n🧪 Testing Encryption..."
PLAINTEXT="SGVsbG8gV29ybGQ="  # "Hello World" in base64
ENCRYPT_REQUEST="{\"plaintext\":\"$PLAINTEXT\"}"
ENCRYPT_RESPONSE=$(curl -s -X POST \
  -H "Content-Type: application/json" \
  -d "$ENCRYPT_REQUEST" \
  http://127.0.0.1:8200/v1/transit/encrypt/test-key)
echo "Encrypt response: $ENCRYPT_RESPONSE"

# Extract ciphertext from response
CIPHERTEXT=$(echo "$ENCRYPT_RESPONSE" | jq -r '.ciphertext // empty')
if [ -n "$CIPHERTEXT" ] && [ "$CIPHERTEXT" != "null" ]; then
    echo -e "\n🧪 Testing Decryption..."
    DECRYPT_REQUEST="{\"ciphertext\":\"$CIPHERTEXT\"}"
    DECRYPT_RESPONSE=$(curl -s -X POST \
      -H "Content-Type: application/json" \
      -d "$DECRYPT_REQUEST" \
      http://127.0.0.1:8200/v1/transit/decrypt/test-key)
    echo "Decrypt response: $DECRYPT_RESPONSE"
    
    # Check if decrypted data matches original
    DECRYPTED=$(echo "$DECRYPT_RESPONSE" | jq -r '.plaintext // empty')
    if [ "$DECRYPTED" = "$PLAINTEXT" ]; then
        echo "✅ Encryption/Decryption roundtrip successful!"
    else
        echo "❌ Encryption/Decryption roundtrip failed!"
        echo "Original: $PLAINTEXT"
        echo "Decrypted: $DECRYPTED"
    fi
else
    echo "❌ No ciphertext received from encryption"
fi

# Clean up
echo -e "\n🛑 Stopping server..."
kill $SERVER_PID 2>/dev/null

echo "🎉 Test completed!"
