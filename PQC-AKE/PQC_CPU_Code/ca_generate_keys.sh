#!/bin/bash

# Directories
KEY_DIR="./keys"
CERT_DIR="./certs"
CA_KEY="$KEY_DIR/ca_private_key.pem"
CA_CERT="$CERT_DIR/ca_certificate.pem"

# Ensure clean directories
mkdir -p "$KEY_DIR" "$CERT_DIR"
rm -f "$KEY_DIR"/* "$CERT_DIR"/*

##########################################
# 1. Classical ECC Certificates (X.509) #
##########################################
echo "[CA] Generating CA's Private Key and Self-Signed Certificate..."
openssl ecparam -genkey -name secp256k1 -out "$CA_KEY"
openssl req -new -x509 -key "$CA_KEY" -out "$CA_CERT" -days 365 \
    -subj "/C=US/ST=State/L=City/O=Organization/OU=OrgUnit/CN=ca.example.com"
echo "[CA] CA Certificate created: $CA_CERT"

echo "[CA] Generating Server's ECC Key Pair and Certificate..."
SERVER_KEY="$KEY_DIR/server_private_key.pem"
SERVER_CSR="$CERT_DIR/server.csr"
SERVER_CERT="$CERT_DIR/server_certificate.pem"

openssl ecparam -genkey -name secp256k1 -out "$SERVER_KEY"
openssl req -new -key "$SERVER_KEY" -out "$SERVER_CSR" \
    -subj "/C=US/ST=State/L=City/O=Organization/OU=OrgUnit/CN=server.example.com"
openssl x509 -req -in "$SERVER_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
    -out "$SERVER_CERT" -days 365
echo "[CA] Server Certificate created: $SERVER_CERT"

echo "[CA] Generating Client's ECC Key Pair and Certificate..."
CLIENT_KEY="$KEY_DIR/client_private_key.pem"
CLIENT_CSR="$CERT_DIR/client.csr"
CLIENT_CERT="$CERT_DIR/client_certificate.pem"

openssl ecparam -genkey -name secp256k1 -out "$CLIENT_KEY"
openssl req -new -key "$CLIENT_KEY" -out "$CLIENT_CSR" \
    -subj "/C=US/ST=State/L=City/O=Organization/OU=OrgUnit/CN=client.example.com"
openssl x509 -req -in "$CLIENT_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
    -out "$CLIENT_CERT" -days 365
echo "[CA] Client Certificate created: $CLIENT_CERT"

echo "[CA] Exporting ECC Public Keys..."
openssl ec -in "$SERVER_KEY" -pubout -out "$KEY_DIR/server_public_key.pem"
openssl ec -in "$CLIENT_KEY" -pubout -out "$KEY_DIR/client_public_key.pem"

####################################
# 2. Falcon Key Generation (OQS)  #
####################################
echo "[CA] Generating Falcon-512 keypair using liboqs..."

# Check if oqs-siggen utility is available
if command -v oqs-siggen &> /dev/null; then
    oqs-siggen falcon-512 "$KEY_DIR/falcon_public.key" "$KEY_DIR/falcon_private.key"
    echo "[CA] Falcon keys generated using oqs-siggen."
else
    echo "[CA] oqs-siggen not found. Falling back to C-based keygen..."

    cat > falcon_keygen.c <<EOF
#include <stdio.h>
#include <stdlib.h>
#include <oqs/oqs.h>

int main() {
    OQS_SIG *sig = OQS_SIG_new("falcon-512");
    if (!sig) return 1;

    uint8_t *pub = malloc(sig->length_public_key);
    uint8_t *priv = malloc(sig->length_secret_key);
    if (!pub || !priv) return 2;

    if (OQS_SIG_keypair(sig, pub, priv) != OQS_SUCCESS) return 3;

    FILE *fp = fopen("$KEY_DIR/falcon_public.key", "wb");
    fwrite(pub, 1, sig->length_public_key, fp); fclose(fp);
    fp = fopen("$KEY_DIR/falcon_private.key", "wb");
    fwrite(priv, 1, sig->length_secret_key, fp); fclose(fp);

    free(pub); free(priv);
    OQS_SIG_free(sig);
    return 0;
}
EOF

    gcc falcon_keygen.c -o falcon_keygen -loqs -lssl -lcrypto -pthread -ldl && ./falcon_keygen && rm falcon_keygen falcon_keygen.c
    if [ $? -eq 0 ]; then
        echo "[CA] Falcon keys generated and saved in $KEY_DIR."
    else
        echo "[CA] Failed to generate Falcon keys."
        exit 1
    fi
fi

##################################
# 3. Kyber Key Generation (OQS) #
##################################
echo "[CA] Generating Kyber512 keypair using liboqs..."

cat > kyber_keygen.c <<EOF
#include <stdio.h>
#include <stdlib.h>
#include <oqs/oqs.h>

int main() {
    OQS_KEM *kem = OQS_KEM_new("Kyber512");
    if (!kem) return 1;

    uint8_t *pub = malloc(kem->length_public_key);
    uint8_t *priv = malloc(kem->length_secret_key);
    if (!pub || !priv) return 2;

    if (OQS_KEM_keypair(kem, pub, priv) != OQS_SUCCESS) return 3;

    FILE *fp = fopen("$KEY_DIR/kyber_public.key", "wb");
    fwrite(pub, 1, kem->length_public_key, fp); fclose(fp);
    fp = fopen("$KEY_DIR/kyber_private.key", "wb");
    fwrite(priv, 1, kem->length_secret_key, fp); fclose(fp);

    free(pub); free(priv);
    OQS_KEM_free(kem);
    return 0;
}
EOF

gcc kyber_keygen.c -o kyber_keygen -loqs -lssl -lcrypto -pthread -ldl && ./kyber_keygen && rm kyber_keygen kyber_keygen.c
if [ $? -eq 0 ]; then
    echo "[CA] Kyber keys generated and saved in $KEY_DIR."
else
    echo "[CA] Failed to generate Kyber keys."
    exit 1
fi

##########################################
# Summary
##########################################
echo "[CA] Key and Certificate Generation Complete!"
echo "  Keys: $KEY_DIR"
echo "  Certificates: $CERT_DIR"