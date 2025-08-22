#!/bin/bash

# Test KV Secrets Engine functionality
echo "🧪 Testing Secreton KV Secrets Engine"
echo "===================================="

# Wait for server to start
sleep 2

# Test endpoints
echo "1. Health check:"
curl -s http://127.0.0.1:8200/health

echo -e "\n\n2. List secrets (should be empty initially):"
curl -s http://127.0.0.1:8200/v1/secrets

echo -e "\n\n3. Create a secret:"
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"data":{"username":"admin","password":"secret123","api_key":"abc123xyz"}}' \
  http://127.0.0.1:8200/v1/secret/data/myapp/database

echo -e "\n\n4. List secrets (should show our new secret):"
curl -s http://127.0.0.1:8200/v1/secrets

echo -e "\n\n5. Retrieve the secret:"
curl -s http://127.0.0.1:8200/v1/secret/data/myapp/database

echo -e "\n\n6. Create another secret:"
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"data":{"token":"jwt-token-123","endpoint":"https://api.example.com"}}' \
  http://127.0.0.1:8200/v1/secret/data/myapp/api-config

echo -e "\n\n7. List all secrets:"
curl -s http://127.0.0.1:8200/v1/secrets

echo -e "\n\n8. Test transit engine (should still work):"
echo "   Creating key:"
curl -s -X POST http://127.0.0.1:8200/v1/transit/keys/test-key

echo -e "\n   Encrypting data:"
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"plaintext":"SGVsbG8gS1YgV29ybGQ="}' \
  http://127.0.0.1:8200/v1/transit/encrypt/test-key

echo -e "\n\n✅ KV Secrets Engine test complete!"
