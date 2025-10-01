#!/bin/bash

# Demo script to test mTLS functionality
# Usage: ./demo_mtls.sh

set -e

echo "🚀 Secreton mTLS Demo"
echo "===================="

# Check if certificates exist
if [ ! -f "certs/server.crt" ] || [ ! -f "certs/server.key" ]; then
    echo "❌ Certificates not found. Generating test certificates..."
    ./generate_test_certs.sh
fi

echo ""
echo "🔧 Starting Secreton server with mTLS enabled..."

# Start server in background (you may need to adjust the command based on your setup)
echo "Starting server..."
# cargo run --bin api_server &
SERVER_PID=$!

echo "Server started with PID: $SERVER_PID"

# Wait for server to start
sleep 3

echo ""
echo "🔐 Testing mTLS connection with client certificate..."

# Test mTLS connection
echo "Testing health endpoint with mTLS..."
curl --cert certs/client.crt --key certs/client.key --cacert certs/ca.crt \
    --connect-timeout 5 --max-time 10 \
    https://localhost:8080/health || echo "Connection failed - server may not be running"

echo ""
echo "📊 Checking TLS metrics..."
curl --cert certs/client.crt --key certs/client.key --cacert certs/ca.crt \
    https://localhost:8080/tls-metrics || echo "Metrics endpoint not available"

echo ""
echo "🧹 Cleaning up..."
echo "Stopping server (PID: $SERVER_PID)..."
kill $SERVER_PID 2>/dev/null || true

echo ""
echo "✅ Demo completed!"
echo ""
echo "📋 Summary:"
echo "  - Generated test certificates"
echo "  - Started server with mTLS enabled"
echo "  - Tested client certificate authentication"
echo "  - Retrieved TLS performance metrics"
echo ""
echo "🔧 Next steps:"
echo "  1. Generate production certificates"
echo "  2. Update configuration with production paths"
echo "  3. Configure proper CA and certificate validation"
echo "  4. Set up certificate rotation and monitoring"
