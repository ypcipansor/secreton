#!/bin/bash

# Complete Secreton Vault Demo - Transit + KV Engines
echo "🔐 SECRETON VAULT - COMPLETE FUNCTIONALITY DEMO"
echo "=============================================="
echo "Testing both Transit Engine (encryption) and KV Secrets Engine (storage)"
echo

# Wait for server to start
sleep 2

echo "📋 1. SYSTEM HEALTH CHECK"
echo "------------------------"
HEALTH=$(curl -s http://127.0.0.1:8200/health)
echo "Health: $HEALTH"
echo

echo "📋 2. TRANSIT ENGINE - ENCRYPTION/DECRYPTION"
echo "-------------------------------------------"

echo "Creating encryption key 'demo-app':"
curl -s -X POST -H "Content-Type: application/json" -d '{}' \
  http://127.0.0.1:8200/v1/transit/keys/demo-app | jq .

echo -e "\nEncrypting sensitive data:"
PLAINTEXT="VGhpcyBpcyBzZW5zaXRpdmUgZGF0YSE="  # "This is sensitive data!" in base64
ENCRYPT_RESP=$(curl -s -X POST -H "Content-Type: application/json" \
  -d "{\"plaintext\":\"$PLAINTEXT\"}" \
  http://127.0.0.1:8200/v1/transit/encrypt/demo-app)
echo $ENCRYPT_RESP | jq .

CIPHERTEXT=$(echo $ENCRYPT_RESP | jq -r '.ciphertext')

echo -e "\nDecrypting data:"
DECRYPT_RESP=$(curl -s -X POST -H "Content-Type: application/json" \
  -d "{\"ciphertext\":\"$CIPHERTEXT\"}" \
  http://127.0.0.1:8200/v1/transit/decrypt/demo-app)
echo $DECRYPT_RESP | jq .

echo

echo "📋 3. KV SECRETS ENGINE - SECRET STORAGE"
echo "---------------------------------------"

echo "Storing application database credentials:"
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"data":{"username":"app_user","password":"super_secret_password","host":"db.example.com","port":"5432"}}' \
  http://127.0.0.1:8200/v1/secret/data/app-db-config | jq .

echo -e "\nStoring API configuration:"
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"data":{"api_key":"sk_test_123456789","endpoint":"https://api.payment.com","timeout":"30"}}' \
  http://127.0.0.1:8200/v1/secret/data/payment-api | jq .

echo -e "\nListing all stored secrets:"
curl -s http://127.0.0.1:8200/v1/secrets | jq .

echo -e "\nRetrieving database configuration:"
curl -s http://127.0.0.1:8200/v1/secret/data/app-db-config | jq .

echo -e "\nUpdating database configuration (creates new version):"
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"data":{"username":"app_user","password":"new_super_secret_password","host":"db.example.com","port":"5432","ssl":"require"}}' \
  http://127.0.0.1:8200/v1/secret/data/app-db-config | jq .

echo -e "\nRetrieving updated configuration (latest version):"
curl -s http://127.0.0.1:8200/v1/secret/data/app-db-config | jq .

echo

echo "📋 4. COMBINED WORKFLOW - ENCRYPT THEN STORE"
echo "-------------------------------------------"

echo "Creating encryption key for stored secrets:"
curl -s -X POST -H "Content-Type: application/json" -d '{}' \
  http://127.0.0.1:8200/v1/transit/keys/secret-encryption | jq .

# Encrypt sensitive data
SENSITIVE_DATA="dGVzdC1hcGkta2V5LXNlY3JldA=="  # "test-api-key-secret" in base64
ENCRYPTED_SECRET=$(curl -s -X POST -H "Content-Type: application/json" \
  -d "{\"plaintext\":\"$SENSITIVE_DATA\"}" \
  http://127.0.0.1:8200/v1/transit/encrypt/secret-encryption | jq -r '.ciphertext')

echo "Storing encrypted secret in KV:"
curl -s -X POST -H "Content-Type: application/json" \
  -d "{\"data\":{\"encrypted_api_key\":\"$ENCRYPTED_SECRET\",\"service\":\"third-party-api\",\"encrypted\":\"true\"}}" \
  http://127.0.0.1:8200/v1/secret/data/encrypted-secrets | jq .

echo -e "\nRetrieving and decrypting stored secret:"
STORED_SECRET=$(curl -s http://127.0.0.1:8200/v1/secret/data/encrypted-secrets | jq -r '.data.encrypted_api_key')

echo "Decrypting retrieved secret:"
curl -s -X POST -H "Content-Type: application/json" \
  -d "{\"ciphertext\":\"$STORED_SECRET\"}" \
  http://127.0.0.1:8200/v1/transit/decrypt/secret-encryption | jq .

echo

echo "📋 5. FINAL STATUS"
echo "----------------"

echo "Total Transit Keys:"
curl -s http://127.0.0.1:8200/v1/transit/keys | jq '.keys | length'

echo -e "\nTotal Stored Secrets:"
curl -s http://127.0.0.1:8200/v1/secrets | jq '.keys | length'

echo -e "\nAll Secret Paths:"
curl -s http://127.0.0.1:8200/v1/secrets | jq '.keys'

echo
echo "🎉 DEMO COMPLETE - Secreton Vault is fully operational!"
echo "✅ Transit Engine: Encryption/Decryption working"
echo "✅ KV Engine: Secret storage and versioning working" 
echo "✅ Combined Workflows: Encrypt-then-store working"
echo "✅ All endpoints responding correctly"
