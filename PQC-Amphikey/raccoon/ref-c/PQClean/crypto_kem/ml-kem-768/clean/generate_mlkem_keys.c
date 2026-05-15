// generate_mlkem_keys.c
#include <stdio.h>
#include <stdlib.h> // For malloc, free (if saving to file dynamically)
#include "api.h"    // This is the API header from PQClean for Kyber768

// Helper function to print bytes as hex
void print_hex(const char* label, const unsigned char* data, size_t len) {
    printf("%s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 32 == 0 || i == len - 1) { // Newline every 32 bytes or at the end
            printf("\n");
        } else if ((i+1) % 4 == 0) {
            printf(" "); // Space every 4 bytes for readability
        }
    }
    printf("\n");
}

// Helper function to write key to file (optional)
int write_key_to_file(const char* filename, const unsigned char* key_data, size_t key_len) {
    FILE *fp = fopen(filename, "wb"); // "wb" for write binary
    if (!fp) {
        perror("Error opening file for writing");
        fprintf(stderr, "Could not open key file: %s\n", filename);
        return -1;
    }
    size_t bytes_written = fwrite(key_data, 1, key_len, fp);
    fclose(fp);
    if (bytes_written != key_len) {
        fprintf(stderr, "Error writing key to %s (wrote %zu of %zu bytes)\n", filename, bytes_written, key_len);
        return -1;
    }
    printf("Successfully wrote key to %s\n", filename);
    return 0;
}

int main() {
    // Allocate memory for public and secret keys
    // These sizes are defined in "api.h" for the specific Kyber768 implementation
    unsigned char *pk = malloc(CRYPTO_PUBLICKEYBYTES);
    unsigned char *sk = malloc(CRYPTO_SECRETKEYBYTES);

    if (pk == NULL || sk == NULL) {
        fprintf(stderr, "Error: Memory allocation failed for keys.\n");
        if (pk) free(pk);
        if (sk) free(sk);
        return 1;
    }

    printf("Generating ML-KEM-768 (Kyber768) key pair...\n");
    printf("Public key size: %d bytes\n", CRYPTO_PUBLICKEYBYTES);
    printf("Secret key size: %d bytes\n", CRYPTO_SECRETKEYBYTES);

    // Generate keypair
    // The function name (e.g., PQCLEAN_KYBER768_CLEAN_crypto_kem_keypair)
    // is aliased to crypto_kem_keypair by api.h
    if (crypto_kem_keypair(pk, sk) != 0) {
        fprintf(stderr, "Error generating ML-KEM-768 key pair!\n");
        free(pk);
        free(sk);
        return 1;
    }

    printf("Key pair generated successfully.\n\n");

    // Print keys to console
    print_hex("Public Key (pk)", pk, CRYPTO_PUBLICKEYBYTES);
    print_hex("Secret Key (sk)", sk, CRYPTO_SECRETKEYBYTES);

    // Optionally, save keys to files
    printf("Saving keys to files...\n");
    if (write_key_to_file("mlkem768_public.key", pk, CRYPTO_PUBLICKEYBYTES) != 0) {
        fprintf(stderr, "Failed to save public key.\n");
    }
    if (write_key_to_file("mlkem768_secret.key", sk, CRYPTO_SECRETKEYBYTES) != 0) {
        fprintf(stderr, "Failed to save secret key.\n");
    }
    // Remember to set secure permissions for the secret key file in a real application!
    // e.g., chmod 600 mlkem768_secret.key

    // Clean up
    free(pk);
    free(sk);

    return 0;
}
