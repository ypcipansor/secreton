#!/bin/bash
set -e

# Directory for SSL certs
SSL_DIR="./nginx/ssl"
mkdir -p "$SSL_DIR"

# Generate self-signed certificate if it doesn't exist
if [ ! -f "$SSL_DIR/cert.pem" ] || [ ! -f "$SSL_DIR/key.pem" ]; then
    echo "Generating self-signed SSL certificate for development..."
    openssl req -x509 -newkey rsa:4096 \
        -keyout "$SSL_DIR/key.pem" \
        -out "$SSL_DIR/cert.pem" \
        -days 365 -nodes \
        -subj "/CN=localhost"
    echo "Certificate generated at $SSL_DIR"
else
    echo "SSL certificate already exists."
fi
