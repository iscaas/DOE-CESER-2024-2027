#!/bin/bash

# Directories
KEY_DIR="./keys"
CERT_DIR="./certs"
CA_KEY="$KEY_DIR/ca_private_key.pem"
CA_CERT="$CERT_DIR/ca_certificate.pem"

# Ensure clean directories
mkdir -p $KEY_DIR $CERT_DIR
rm -f $KEY_DIR/* $CERT_DIR/*

# 1. Generate CA's Private Key and Self-Signed Certificate
echo "[CA] Generating CA's Private Key and Self-Signed Certificate..."
openssl ecparam -genkey -name secp256k1 -out $CA_KEY
openssl req -new -x509 -key $CA_KEY -out $CA_CERT -days 365 \
    -subj "/C=US/ST=State/L=City/O=Organization/OU=OrgUnit/CN=ca.example.com"
echo "[CA] CA Certificate created: $CA_CERT"

# 2. Generate Server's Key, CSR, and Signed Certificate
echo "[CA] Generating Server's ECC Key Pair and Certificate..."
SERVER_KEY="$KEY_DIR/server_private_key.pem"
SERVER_CSR="$CERT_DIR/server.csr"
SERVER_CERT="$CERT_DIR/server_certificate.pem"

openssl ecparam -genkey -name secp256k1 -out $SERVER_KEY
openssl req -new -key $SERVER_KEY -out $SERVER_CSR \
    -subj "/C=US/ST=State/L=City/O=Organization/OU=OrgUnit/CN=server.example.com"
openssl x509 -req -in $SERVER_CSR -CA $CA_CERT -CAkey $CA_KEY -CAcreateserial \
    -out $SERVER_CERT -days 365
echo "[CA] Server Certificate created: $SERVER_CERT"

# 3. Generate Client's Key, CSR, and Signed Certificate
echo "[CA] Generating Client's ECC Key Pair and Certificate..."
CLIENT_KEY="$KEY_DIR/client_private_key.pem"
CLIENT_CSR="$CERT_DIR/client.csr"
CLIENT_CERT="$CERT_DIR/client_certificate.pem"

openssl ecparam -genkey -name secp256k1 -out $CLIENT_KEY
openssl req -new -key $CLIENT_KEY -out $CLIENT_CSR \
    -subj "/C=US/ST=State/L=City/O=Organization/OU=OrgUnit/CN=client.example.com"
openssl x509 -req -in $CLIENT_CSR -CA $CA_CERT -CAkey $CA_KEY -CAcreateserial \
    -out $CLIENT_CERT -days 365
echo "[CA] Client Certificate created: $CLIENT_CERT"

# 4. Export Public Keys
echo "[CA] Exporting Public Keys..."
SERVER_PUB="$KEY_DIR/server_public_key.pem"
CLIENT_PUB="$KEY_DIR/client_public_key.pem"
openssl ec -in $SERVER_KEY -pubout -out $SERVER_PUB
openssl ec -in $CLIENT_KEY -pubout -out $CLIENT_PUB
echo "[CA] Server Public Key: $SERVER_PUB"
echo "[CA] Client Public Key: $CLIENT_PUB"

# 5. Summary
echo "[CA] Key and Certificate Generation Complete!"
echo "Keys and certificates stored in:"
echo "  Keys: $KEY_DIR"
echo "  Certificates: $CERT_DIR"
