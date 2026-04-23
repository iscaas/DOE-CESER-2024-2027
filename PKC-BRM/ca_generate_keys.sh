#!/usr/bin/env bash
set -euo pipefail

KEY_DIR="./keys"
CERT_DIR="./certs"
mkdir -p "$KEY_DIR" "$CERT_DIR"

echo "[CA] Generating CA Ed25519 key and self-signed certificate..."
openssl genpkey -algorithm ED25519 -out "${KEY_DIR}/ca_ed25519_priv.pem"
openssl req -new -x509 -key "${KEY_DIR}/ca_ed25519_priv.pem" \
  -days 3650 -out "${CERT_DIR}/ca_certificate.pem" \
  -subj "/C=US/ST=State/L=City/O=Organization/OU=OrgUnit/CN=example-ca"

echo "[CA] Generating Server Ed25519 signing key and CSR..."
openssl genpkey -algorithm ED25519 -out "${KEY_DIR}/server_sign_ed25519_priv.pem"
openssl req -new -key "${KEY_DIR}/server_sign_ed25519_priv.pem" \
  -out "${KEY_DIR}/server.csr" \
  -subj "/C=US/ST=State/L=City/O=Organization/OU=OrgUnit/CN=server.example.com"

echo "[CA] Signing Server certificate with CA..."
openssl x509 -req -in "${KEY_DIR}/server.csr" \
  -CA "${CERT_DIR}/ca_certificate.pem" -CAkey "${KEY_DIR}/ca_ed25519_priv.pem" -CAcreateserial \
  -days 825 -out "${CERT_DIR}/server_certificate.pem"

echo "[CA] Generating Client Ed25519 signing key and CSR..."
openssl genpkey -algorithm ED25519 -out "${KEY_DIR}/client_sign_ed25519_priv.pem"
openssl req -new -key "${KEY_DIR}/client_sign_ed25519_priv.pem" \
  -out "${KEY_DIR}/client.csr" \
  -subj "/C=US/ST=State/L=City/O=Organization/OU=OrgUnit/CN=client.example.com"

echo "[CA] Signing Client certificate with CA..."
openssl x509 -req -in "${KEY_DIR}/client.csr" \
  -CA "${CERT_DIR}/ca_certificate.pem" -CAkey "${KEY_DIR}/ca_ed25519_priv.pem" \
  -days 825 -out "${CERT_DIR}/client_certificate.pem"

echo "[CA] Generating static X25519 keypairs (server/client) for ECDH..."
# Server X25519 static
openssl genpkey -algorithm X25519 -out "${KEY_DIR}/server_x25519_priv.pem"
openssl pkey -in "${KEY_DIR}/server_x25519_priv.pem" -pubout -out "${KEY_DIR}/server_x25519_pub.pem"

# Client X25519 static
openssl genpkey -algorithm X25519 -out "${KEY_DIR}/client_x25519_priv.pem"
openssl pkey -in "${KEY_DIR}/client_x25519_priv.pem" -pubout -out "${KEY_DIR}/client_x25519_pub.pem"

echo "[CA] Done."
echo "  Keys: ${KEY_DIR}"
echo "  Certs: ${CERT_DIR}"
