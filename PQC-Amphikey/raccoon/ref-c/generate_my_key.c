// generate_my_keys.c (with file saving)
#include <stdio.h>
#include <string.h>
#include "api.h" // From Raccoon ref-c implementation
// May need "randombytes.h" - check Raccoon's PQCgenKAT_sign.c for initialization if needed

// Helper function to print bytes as hex
void print_hex(const char* label, const unsigned char* data, unsigned long long len) {
    printf("%s: ", label);
    for (unsigned long long i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Helper function to write key to file
int write_key_to_file(const char* filename, const unsigned char* key_data, unsigned long long key_len) {
    FILE *fp = fopen(filename, "wb"); // "wb" for write binary
    if (!fp) {
        perror("Error opening file for writing");
        return -1;
    }
    size_t bytes_written = fwrite(key_data, 1, key_len, fp);
    fclose(fp);
    if (bytes_written != key_len) {
        fprintf(stderr, "Error writing key to %s (wrote %zu of %llu bytes)\n", filename, bytes_written, key_len);
        return -1;
    }
    printf("Successfully wrote key to %s\n", filename);
    return 0;
}

int main() {
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];

    // Initialize randombytes if necessary (refer to Raccoon's PQCgenKAT_sign.c)
    // e.g., randombytes_init(...);

    printf("Generating Raccoon key pair...\n");
    if (crypto_sign_keypair(pk, sk) != 0) {
        fprintf(stderr, "Error generating key pair!\n");
        return 1;
    }
    printf("Key pair generated successfully.\n");

    print_hex("Public Key (pk)", pk, CRYPTO_PUBLICKEYBYTES);
    print_hex("Secret Key (sk)", sk, CRYPTO_SECRETKEYBYTES);

    // Save keys to files
    if (write_key_to_file("raccoon_public.key", pk, CRYPTO_PUBLICKEYBYTES) != 0) {
        fprintf(stderr, "Failed to save public key.\n");
    }
    if (write_key_to_file("raccoon_secret.key", sk, CRYPTO_SECRETKEYBYTES) != 0) {
        fprintf(stderr, "Failed to save secret key.\n");
    }
    // IMPORTANT: In a real application, ensure raccoon_secret.key has strict file permissions
    // (e.g., readable only by the owner: chmod 600 raccoon_secret.key on Linux).

    return 0;
}
