#!/bin/sh
set -e

CERT_DIR="/etc/nginx/certs"
mkdir -p "$CERT_DIR"

if [ ! -f "$CERT_DIR/selfsigned.crt" ]; then
    echo "Generating self-signed certificate..."
    openssl req -x509 -nodes -days 365 \
        -newkey rsa:2048 \
        -keyout "$CERT_DIR/selfsigned.key" \
        -out "$CERT_DIR/selfsigned.crt" \
        -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
    echo "Certificate generated."
else
    echo "Certificate already exists."
fi

exec "$@"
