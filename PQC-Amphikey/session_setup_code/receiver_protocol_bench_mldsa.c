#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

#include <sodium.h>
#include "api_mlkem.h"
#include "api_mldsa.h"
#include "constants.h" // For ACORN
#include "cipher.h"    // For ACORN

// --- BENCHMARKING HELPERS ---
#define BENCHMARK_ITERATIONS 1000

#if defined(__i386__) || defined(__x86_64__)
static inline unsigned long long rdtsc(void) {
    unsigned int lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((unsigned long long)hi << 32) | lo;
}
#else
static inline unsigned long long rdtsc(void) { return 0; }
#endif
// --- END BENCHMARKING HELPERS ---

/**
 * @brief Provides the randombytes implementation required by the PQClean library.
 * This acts as a bridge to the libsodium random number generator.
 */
void PQCLEAN_randombytes(uint8_t *out, size_t outlen) {
    randombytes_buf(out, outlen);
}

// --- HELPER FUNCTIONS ---
int write_binary_data_to_file(const char* filename, const unsigned char* data, size_t len) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) { perror("fopen for writing"); return -1; }
    size_t written = fwrite(data, 1, len, fp);
    fclose(fp);
    if (written != len) { fprintf(stderr, "Error writing to %s\n", filename); return -1; }
    printf("Successfully wrote %zu bytes to %s\n", len, filename);
    return 0;
}

int read_binary_data_from_file(const char* filename, unsigned char* buffer, size_t buffer_len, size_t* bytes_read_actual) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) { perror("fopen for reading"); return -1; }
    *bytes_read_actual = fread(buffer, 1, buffer_len, fp);
    fclose(fp);
    if (*bytes_read_actual == 0 && !feof(fp)) { fprintf(stderr, "Error reading from %s\n", filename); return -1; }
    printf("Successfully read %zu bytes from %s\n", *bytes_read_actual, filename);
    return 0;
}

int read_hex_key_from_file(const char* filename, unsigned char* bin_buffer, size_t bin_buffer_len, size_t* actual_bin_len) {
    FILE *fp = fopen(filename, "r");
    if (!fp) { perror("fopen for hex reading"); return -1; }
    char* hex_string_buf = (char*)malloc(bin_buffer_len * 2 + 3);
    if (!hex_string_buf) { fclose(fp); return -1; }
    if (fgets(hex_string_buf, bin_buffer_len * 2 + 3, fp) == NULL) {
        fclose(fp); free(hex_string_buf); return -1;
    }
    fclose(fp);
    hex_string_buf[strcspn(hex_string_buf, "\r\n")] = 0;
    if (sodium_hex2bin(bin_buffer, bin_buffer_len, hex_string_buf, strlen(hex_string_buf), NULL, actual_bin_len, NULL) != 0) {
        free(hex_string_buf); return -1;
    }
    free(hex_string_buf);
    printf("Successfully read and converted hex key from %s\n", filename);
    return 0;
}
// (You can add your HKDF helper functions here if they are not in a separate file)
// ...
// --- END HELPER FUNCTIONS ---


// --- Main Program ---
int main() {
    printf("--- RECEIVER PROTOCOL OPERATIONS (ML-DSA-65) ---\n\n");
    if (sodium_init() < 0) { fprintf(stderr, "Libsodium couldn't be initialized!\n"); return 1; }
    printf("Libsodium initialized.\n\n");

    // --- Declare and Load Receiver's (Client's) Keys ---
    unsigned char skr_ml_kem[PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES];
    unsigned char pkr_ml_kem[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    unsigned char skr_x25519[crypto_kx_SECRETKEYBYTES];
    unsigned char pkr_x25519[crypto_kx_PUBLICKEYBYTES];
    unsigned char pkr_mldsa[PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES];
    size_t bytes_read;

    printf("Loading Receiver's (Client's) own keys from files...\n");
    read_binary_data_from_file("client_mlkem_pk.key", pkr_ml_kem, sizeof(pkr_ml_kem), &bytes_read);
    read_binary_data_from_file("client_mlkem_sk.key", skr_ml_kem, sizeof(skr_ml_kem), &bytes_read);
    read_hex_key_from_file("client_x25519_pk.hex", pkr_x25519, sizeof(pkr_x25519), &bytes_read);
    read_hex_key_from_file("client_x25519_sk.hex", skr_x25519, sizeof(skr_x25519), &bytes_read);
    read_binary_data_from_file("client_mldsa_pk.key", pkr_mldsa, sizeof(pkr_mldsa), &bytes_read);

    // --- Declare and Load Sender's (Server's) Public Keys ---
    unsigned char pks_mldsa_from_sender[PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES];
    printf("\nLoading Sender's (Server's) public keys from files...\n");
    read_binary_data_from_file("server_mldsa_pk.key", pks_mldsa_from_sender, sizeof(pks_mldsa_from_sender), &bytes_read);

    // --- Load Transmitted Data from Sender ---
    // For ML-DSA, the signature file contains the signature AND the message.
    unsigned char sm_from_sender[PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES + PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES + crypto_kx_PUBLICKEYBYTES];
    size_t smlen_loaded;
    printf("\nLoading transmitted signed message from hybrid.c output...\n");
    read_binary_data_from_file("signed_message_mldsa.bin", sm_from_sender, sizeof(sm_from_sender), &smlen_loaded);
    printf("\n");

    // --- Receiver's Operations ---
    printf("Performing Receiver's operations...\n");

    // Declare benchmark variables
    struct timespec start_time, end_time;
    unsigned long long start_cycles, end_cycles, total_cycles;
    long long total_ns;

    // 1. ML-DSA-65 Signature Verification
    printf("\n--- Benchmarking ML-DSA-65 Signature Verification (%d iterations) ---\n", BENCHMARK_ITERATIONS);
    // The opened message will contain c1 and the sender's X25519 public key.
    size_t c_data_len = PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES + crypto_kx_PUBLICKEYBYTES;
    unsigned char *opened_message = malloc(c_data_len);
    if (!opened_message) { fprintf(stderr, "Malloc failed for opened_message.\n"); return 1; }
    unsigned long long opened_mlen;

    total_ns = 0;
    total_cycles = 0;
    for (int i = 0; i < BENCHMARK_ITERATIONS; ++i) {
        clock_gettime(CLOCK_MONOTONIC, &start_time);
        start_cycles = rdtsc();
        if (PQCLEAN_MLDSA65_CLEAN_crypto_sign_open(opened_message, &opened_mlen, sm_from_sender, smlen_loaded, pks_mldsa_from_sender) != 0) {
            fprintf(stderr, "Signature verification FAILED during benchmark!\n");
            free(opened_message); return 1;
        }
        end_cycles = rdtsc();
        clock_gettime(CLOCK_MONOTONIC, &end_time);
        total_ns += (end_time.tv_sec - start_time.tv_sec) * 1000000000LL + (end_time.tv_nsec - start_time.tv_nsec);
        if (end_cycles > start_cycles) total_cycles += (end_cycles - start_cycles);
    }
    printf("Average Time:   %lld ns\n", total_ns / BENCHMARK_ITERATIONS);
    printf("Average Cycles: %llu\n", total_cycles / BENCHMARK_ITERATIONS);
    if (opened_mlen != c_data_len) {
        fprintf(stderr, "Error: Opened message length (%llu) does not match expected length (%zu).\n", opened_mlen, c_data_len);
        free(opened_message); return 1;
    }
    printf("Signature verified successfully.\n");
    printf("------------------------------------\n");

    // Extract c1 and the sender's ephemeral X25519 public key from the verified message
    unsigned char c1_from_sender[PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    unsigned char pks_x25519_from_sender[crypto_kx_PUBLICKEYBYTES];
    memcpy(c1_from_sender, opened_message, sizeof(c1_from_sender));
    memcpy(pks_x25519_from_sender, opened_message + sizeof(c1_from_sender), sizeof(pks_x25519_from_sender));
    free(opened_message);

    // 2. ML-KEM Decapsulation
    printf("\n--- Benchmarking ML-KEM Decapsulation (%d iterations) ---\n", BENCHMARK_ITERATIONS);
    unsigned char k1_prime[PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES];
    total_ns = 0;
    total_cycles = 0;
    for (int i = 0; i < BENCHMARK_ITERATIONS; ++i) {
        clock_gettime(CLOCK_MONOTONIC, &start_time);
        start_cycles = rdtsc();
        if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(k1_prime, c1_from_sender, skr_ml_kem) != 0) {
            fprintf(stderr, "ML-KEM decapsulation failed.\n"); return 1;
        }
        end_cycles = rdtsc();
        clock_gettime(CLOCK_MONOTONIC, &end_time);
        total_ns += (end_time.tv_sec - start_time.tv_sec) * 1000000000LL + (end_time.tv_nsec - start_time.tv_nsec);
        if (end_cycles > start_cycles) total_cycles += (end_cycles - start_cycles);
    }
    printf("Average Time:   %lld ns\n", total_ns / BENCHMARK_ITERATIONS);
    printf("Average Cycles: %llu\n", total_cycles / BENCHMARK_ITERATIONS);
    printf("------------------------------------\n");

    // 3. X25519 Shared Secret
    printf("\n--- Benchmarking X25519 Shared Secret Calculation (%d iterations) ---\n", BENCHMARK_ITERATIONS);
    unsigned char k2_prime[crypto_scalarmult_BYTES];
    total_ns = 0;
    total_cycles = 0;
    for (int i = 0; i < BENCHMARK_ITERATIONS; ++i) {
        clock_gettime(CLOCK_MONOTONIC, &start_time);
        start_cycles = rdtsc();
        if (crypto_scalarmult(k2_prime, skr_x25519, pks_x25519_from_sender) != 0) {
            fprintf(stderr, "X25519 scalar multiplication failed for receiver.\n"); return 1;
        }
        end_cycles = rdtsc();
        clock_gettime(CLOCK_MONOTONIC, &end_time);
        total_ns += (end_time.tv_sec - start_time.tv_sec) * 1000000000LL + (end_time.tv_nsec - start_time.tv_nsec);
        if (end_cycles > start_cycles) total_cycles += (end_cycles - start_cycles);
    }
    printf("Average Time:   %lld ns\n", total_ns / BENCHMARK_ITERATIONS);
    printf("Average Cycles: %llu\n", total_cycles / BENCHMARK_ITERATIONS);
    printf("------------------------------------\n");

    // (The rest of the protocol, like HKDF and AEAD, would follow here)
    // ...

    // Final Cleanup
    sodium_memzero(skr_x25519, sizeof(skr_x25519));
    sodium_memzero(skr_ml_kem, sizeof(skr_ml_kem));

    printf("\nReceiver protocol operations complete.\n");
    return 0;
}

