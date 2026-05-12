#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>     // For X25519
#include "api_mlkem.h"  // For ML-KEM (using PQCLEAN_MLKEM768_CLEAN_ prefix)
#include "api_raccoon.h"// For Raccoon (using generic CRYPTO_ prefix for Raccoon)

// Forward declaration for Raccoon's RNG init function
// Ideally, this comes from a Raccoon header file (e.g., "rng.h" or "randombytes.h" from Raccoon's inc/ or util/)
// The actual signature might vary; check your Raccoon's nist_random.c or its header.
// This is a common signature from NIST PQC submissions.
void nist_randombytes_init(unsigned char *entropy_input, unsigned char *personalization_string, int security_strength);


// --- PASTE HELPER FUNCTIONS HERE (print_hex, write_binary_key_to_file, write_hex_key_to_file) ---
// Helper function to print bytes as hex
void print_hex(const char* label, const unsigned char* data, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}
// In server.c (and later in client.c)

// ... other includes like stdio.h, sodium.h, api_mlkem.h, api_raccoon.h ...

// Forward declaration for Raccoon's randombytes, assuming its signature is:
// void randombytes(unsigned char *output_buffer, unsigned long long output_length);
// This will be defined in nist_random.o (from nist_random.c)
extern void randombytes(unsigned char *x, unsigned long long xlen);

// Forward declaration for nist_randombytes_init (if not in an included header)
extern void nist_randombytes_init(unsigned char *entropy_input, unsigned char *personalization_string, int security_strength);


// Wrapper function to satisfy libml-kem-768_clean.a's dependency
// PQClean's randombytes.h usually declares: void randombytes(uint8_t *buf, size_t nbytes);
// We will match that for the wrapper name PQCLEAN_randombytes.
// The actual name called by the *library object code* is PQCLEAN_randombytes.
void PQCLEAN_randombytes(unsigned char *buf, size_t nbytes) {
    // Call Raccoon's randombytes function
    randombytes(buf, (unsigned long long)nbytes);
}

// --- PASTE HELPER FUNCTIONS HERE (print_hex, write_binary_key_to_file, write_hex_key_to_file) ---
// ...


// Helper function to write binary key to file
int write_binary_key_to_file(const char* filename, const unsigned char* key_data, size_t key_len) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        perror("Error opening file for writing");
        fprintf(stderr, "Filename: %s\n", filename);
        return -1;
    }
    size_t bytes_written = fwrite(key_data, 1, key_len, fp);
    fclose(fp);
    if (bytes_written != key_len) {
        fprintf(stderr, "Error writing key to %s (wrote %zu of %zu bytes)\n", filename, bytes_written, key_len);
        return -1;
    }
    printf("Successfully wrote binary key to %s\n", filename);
    return 0;
}

// Helper function to write key to file (hex encoded string)
int write_hex_key_to_file(const char* filename, const unsigned char* key_data, size_t key_len) {
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        perror("Error opening file for writing");
        fprintf(stderr, "Filename: %s\n", filename);
        return -1;
    }
    char *hex_string = (char *)sodium_malloc(key_len * 2 + 1);
    if (hex_string == NULL) {
        fprintf(stderr, "Failed to allocate memory for hex string for %s.\n", filename);
        fclose(fp);
        return -1;
    }
    if (sodium_bin2hex(hex_string, key_len * 2 + 1, key_data, key_len) == NULL) {
        fprintf(stderr, "sodium_bin2hex failed for %s.\n", filename);
        sodium_free(hex_string);
        fclose(fp);
        return -1;
    }
    fprintf(fp, "%s\n", hex_string);
    sodium_free(hex_string);
    fclose(fp);
    printf("Successfully wrote hex key to %s\n", filename);
    return 0;
}
// --- END OF HELPER FUNCTIONS ---


int main() {
    printf("--- SERVER KEY GENERATION ---\n");

    // 1. Initialize Randomness (using Raccoon's NIST DRBG)
    // IMPORTANT: For production, use a strong source of entropy.
    // This is a placeholder for the entropy input.
    unsigned char server_entropy_input[48];
    for (int i = 0; i < 48; i++) server_entropy_input[i] = (unsigned char)('S' + i); // Dummy entropy for server
    // The personalization string can be NULL for many implementations, or a short string.
    // Security strength 256 is common.
    // This init function should make randombytes() (from nist_random.c) usable by all schemes.
    nist_randombytes_init(server_entropy_input, (unsigned char *)"Server", 256);
    printf("Raccoon's NIST DRBG initialized for server.\n");

    // 2. Initialize libsodium (for X25519)
    if (sodium_init() < 0) {
        fprintf(stderr, "Libsodium couldn't be initialized!\n");
        return 1;
    }
    printf("Libsodium initialized for server.\n\n");

    // --- X25519 Key Generation for Server ---
    printf("Generating X25519 keys for server...\n");
    unsigned char server_x25519_pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char server_x25519_sk[crypto_kx_SECRETKEYBYTES];
    if (crypto_kx_keypair(server_x25519_pk, server_x25519_sk) != 0) {
        fprintf(stderr, "ERROR: Server X25519 key pair generation failed.\n");
    } else {
        print_hex("Server X25519 Public Key", server_x25519_pk, crypto_kx_PUBLICKEYBYTES);
        print_hex("Server X25519 Secret Key", server_x25519_sk, crypto_kx_SECRETKEYBYTES);
        write_hex_key_to_file("server_x25519_pk.hex", server_x25519_pk, crypto_kx_PUBLICKEYBYTES);
        write_hex_key_to_file("server_x25519_sk.hex", server_x25519_sk, crypto_kx_SECRETKEYBYTES);
        sodium_memzero(server_x25519_sk, crypto_kx_SECRETKEYBYTES);
    }
    printf("------------------------------------\n");

    // --- ML-KEM-768 Key Generation for Server ---
    // Note: Typically only one party in KEM generates a pair for encapsulation by the other.
    // Here we generate a pair for the server as requested.
    printf("Generating ML-KEM-768 keys for server...\n");
    unsigned char server_mlkem_pk[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    unsigned char server_mlkem_sk[PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES];
    if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(server_mlkem_pk, server_mlkem_sk) != 0) {
        fprintf(stderr, "ERROR: Server ML-KEM key pair generation failed.\n");
    } else {
        print_hex("Server ML-KEM Public Key", server_mlkem_pk, PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES);
        // print_hex("Server ML-KEM Secret Key", server_mlkem_sk, PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES); // Optionally print
        write_binary_key_to_file("server_mlkem_pk.key", server_mlkem_pk, PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES);
        write_binary_key_to_file("server_mlkem_sk.key", server_mlkem_sk, PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES);
    }
    printf("------------------------------------\n");

    // --- Raccoon Signature Key Generation for Server ---
    printf("Generating Raccoon keys for server...\n");
    // Using generic CRYPTO_ macros as defined in api_raccoon.h
    unsigned char server_raccoon_pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char server_raccoon_sk[CRYPTO_SECRETKEYBYTES];
    if (crypto_sign_keypair(server_raccoon_pk, server_raccoon_sk) != 0) {
        fprintf(stderr, "Error generating server Raccoon key pair!\n");
    } else {
        print_hex("Server Raccoon Public Key", server_raccoon_pk, CRYPTO_PUBLICKEYBYTES);
        // print_hex("Server Raccoon Secret Key", server_raccoon_sk, CRYPTO_SECRETKEYBYTES); // Optionally print
        write_binary_key_to_file("server_raccoon_pk.key", server_raccoon_pk, CRYPTO_PUBLICKEYBYTES);
        write_binary_key_to_file("server_raccoon_sk.key", server_raccoon_sk, CRYPTO_SECRETKEYBYTES);
    }
    printf("------------------------------------\n");

    printf("Server key generation complete.\n");
    return 0;
}
