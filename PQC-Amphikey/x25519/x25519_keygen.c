#include <stdio.h>
#include <sodium.h>

// Helper function to print a byte array as a hex string
void print_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    if (sodium_init() < 0) {
        fprintf(stderr, "Libsodium couldn't be initialized.\n");
        return 1;
    }

    unsigned char x25519_public_key[crypto_kx_PUBLICKEYBYTES];
    unsigned char x25519_secret_key[crypto_kx_SECRETKEYBYTES];

    if (crypto_kx_keypair(x25519_public_key, x25519_secret_key) != 0) {
        fprintf(stderr, "ERROR: X25519 key pair generation failed.\n");
        return 1;
    }

    printf("X25519 Ephemeral Key Pair Generated Successfully:\n");
    print_hex("Public Key ", x25519_public_key, crypto_kx_PUBLICKEYBYTES);
    print_hex("Secret Key ", x25519_secret_key, crypto_kx_SECRETKEYBYTES);

    sodium_memzero(x25519_secret_key, crypto_kx_SECRETKEYBYTES);
    return 0;
}
