#!/bin/bash

# Script to generate sample certificates for testing mTLS
# Usage: ./generate_test_certs.sh

set -e

echo "🔐 Generating test certificates for Secreton mTLS..."

# Create directories
mkdir -p certs
cd certs

# Generate CA private key
echo "📝 Generating CA private key..."
openssl genpkey -algorithm RSA -out ca.key -aes256 -pass pass:testpass

# Generate CA certificate
echo "📝 Generating CA certificate..."
openssl req -new -x509 -key ca.key -out ca.crt -days 365 -passin pass:testpass \
    -subj "/C=US/ST=California/L=San Francisco/O=Cipherce/OU=Secreton/CN=Secreton Test CA"

# Generate server private key
echo "📝 Generating server private key..."
openssl genpkey -algorithm RSA -out server.key

# Generate server CSR
echo "📝 Generating server certificate signing request..."
openssl req -new -key server.key -out server.csr \
    -subj "/C=US/ST=California/L=San Francisco/O=Cipherce/OU=Secreton/CN=localhost"

# Generate server certificate signed by CA
echo "📝 Generating server certificate..."
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 365 -passin pass:testpass

# Generate client private key
echo "📝 Generating client private key..."
openssl genpkey -algorithm RSA -out client.key

# Generate client CSR
echo "📝 Generating client certificate signing request..."
openssl req -new -key client.key -out client.csr \
    -subj "/C=US/ST=California/L=San Francisco/O=Cipherce/OU=Secreton/CN=test-client"

# Generate client certificate signed by CA
echo "📝 Generating client certificate..."
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out client.crt -days 365 -passin pass:testpass

# Convert client certificate to DER format for testing
echo "📝 Converting client certificate to DER format..."
openssl x509 -in client.crt -out client.der -outform DER

# Set proper permissions
echo "📝 Setting certificate permissions..."
chmod 600 *.key
chmod 644 *.crt *.der

# Clean up CSRs
echo "📝 Cleaning up temporary files..."
rm -f *.csr ca.srl

echo ""
echo "✅ Certificate generation completed!"
echo ""
echo "📋 Generated files:"
echo "  - ca.crt, ca.key        - Certificate Authority"
echo "  - server.crt, server.key - Server certificate"
echo "  - client.crt, client.key - Client certificate"
echo "  - client.der            - Client certificate in DER format"
echo ""
echo "🔧 To use with Secreton:"
echo "  - Copy server.crt and server.key to /etc/tls/"
echo "  - Copy ca.crt to /etc/ssl/"
echo "  - Update configuration to point to these certificate paths"
echo ""
echo "🔐 Test mTLS connection:"
echo "  curl --cert client.crt --key client.key --cacert ca.crt https://localhost:8080/health"
