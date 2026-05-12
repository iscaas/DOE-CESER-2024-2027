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
// --- END HELPER FUNCTIONS ---


// --- Main Program ---
int main() {
    printf("--- Hybrid Protocol: Sender Operations (ML-DSA-65) ---\n\n");
    if (sodium_init() < 0) { fprintf(stderr, "Libsodium couldn't be initialized!\n"); return 1; }
    printf("Libsodium initialized.\n\n");

    // --- Declare and Load Sender's (Server's) Keys ---
    unsigned char sks_ml_kem[PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES];
    unsigned char pks_ml_kem[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    unsigned char sks_x25519[crypto_kx_SECRETKEYBYTES];
    unsigned char pks_x25519[crypto_kx_PUBLICKEYBYTES];
    unsigned char sks_mldsa[PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES];
    unsigned char pks_mldsa[PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES];
    size_t bytes_read;

    printf("Loading Sender's (Server's) keys from files...\n");
    read_binary_data_from_file("server_mlkem_pk.key", pks_ml_kem, sizeof(pks_ml_kem), &bytes_read);
    read_binary_data_from_file("server_mlkem_sk.key", sks_ml_kem, sizeof(sks_ml_kem), &bytes_read);
    read_hex_key_from_file("server_x25519_pk.hex", pks_x25519, sizeof(pks_x25519), &bytes_read);
    read_hex_key_from_file("server_x25519_sk.hex", sks_x25519, sizeof(sks_x25519), &bytes_read);
    read_binary_data_from_file("server_mldsa_pk.key", pks_mldsa, sizeof(pks_mldsa), &bytes_read);
    read_binary_data_from_file("server_mldsa_sk.key", sks_mldsa, sizeof(sks_mldsa), &bytes_read);
    printf("Sender's (Server's) keys loaded successfully.\n\n");
    write_binary_data_to_file("sender_pks_x25519_for_protocol.key", pks_x25519, sizeof(pks_x25519));

    // --- Declare and Load Receiver's (Client's) Public Keys ---
    unsigned char pkr_ml_kem[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    unsigned char pkr_x25519[crypto_kx_PUBLICKEYBYTES];
    unsigned char pkr_mldsa[PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES];

    printf("Loading Receiver's (Client's) public keys from files...\n");
    read_binary_data_from_file("client_mlkem_pk.key", pkr_ml_kem, sizeof(pkr_ml_kem), &bytes_read);
    read_hex_key_from_file("client_x25519_pk.hex", pkr_x25519, sizeof(pkr_x25519), &bytes_read);
    read_binary_data_from_file("client_mldsa_pk.key", pkr_mldsa, sizeof(pkr_mldsa), &bytes_read);
    printf("Receiver's (Client's) public keys loaded successfully.\n\n");

    // --- Sender's Operations ---
    printf("Performing Sender's operations...\n");

    // Declare benchmark variables
    struct timespec start_time, end_time;
    unsigned long long start_cycles, end_cycles, total_cycles;
    long long total_ns;

    // 1. ML-KEM Encapsulation
    printf("\n--- Benchmarking ML-KEM Encapsulation (%d iterations) ---\n", BENCHMARK_ITERATIONS);
    unsigned char c1[PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    unsigned char k1[PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES];
    total_ns = 0;
    total_cycles = 0;
    for (int i = 0; i < BENCHMARK_ITERATIONS; ++i) {
        clock_gettime(CLOCK_MONOTONIC, &start_time);
        start_cycles = rdtsc();
        if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(c1, k1, pkr_ml_kem) != 0) {
            fprintf(stderr, "ML-KEM encapsulation failed.\n"); return 1;
        }
        end_cycles = rdtsc();
        clock_gettime(CLOCK_MONOTONIC, &end_time);
        total_ns += (end_time.tv_sec - start_time.tv_sec) * 1000000000LL + (end_time.tv_nsec - start_time.tv_nsec);
        if (end_cycles > start_cycles) total_cycles += (end_cycles - start_cycles);
    }
    printf("Average Time:   %lld ns\n", total_ns / BENCHMARK_ITERATIONS);
    printf("Average Cycles: %llu\n", total_cycles / BENCHMARK_ITERATIONS);
    write_binary_data_to_file("kem_ciphertext_c1.dat", c1, sizeof(c1));
    printf("------------------------------------\n");

    // 2. X25519 Shared Secret
    printf("\n--- Benchmarking X25519 Shared Secret Calculation (%d iterations) ---\n", BENCHMARK_ITERATIONS);
    unsigned char k2[crypto_scalarmult_BYTES];
    total_ns = 0;
    total_cycles = 0;
    for (int i = 0; i < BENCHMARK_ITERATIONS; ++i) {
        clock_gettime(CLOCK_MONOTONIC, &start_time);
        start_cycles = rdtsc();
        if (crypto_scalarmult(k2, sks_x25519, pkr_x25519) != 0) {
            fprintf(stderr, "X25519 scalar multiplication failed.\n"); return 1;
        }
        end_cycles = rdtsc();
        clock_gettime(CLOCK_MONOTONIC, &end_time);
        total_ns += (end_time.tv_sec - start_time.tv_sec) * 1000000000LL + (end_time.tv_nsec - start_time.tv_nsec);
        if (end_cycles > start_cycles) total_cycles += (end_cycles - start_cycles);
    }
    printf("Average Time:   %lld ns\n", total_ns / BENCHMARK_ITERATIONS);
    printf("Average Cycles: %llu\n", total_cycles / BENCHMARK_ITERATIONS);
    printf("------------------------------------\n");

    // 3. ML-DSA-65 Signing Operation
    printf("\n--- Benchmarking ML-DSA-65 Signing (%d iterations) ---\n", BENCHMARK_ITERATIONS);
    size_t c_data_len = sizeof(c1) + sizeof(pks_x25519);
    unsigned char *c_data = malloc(c_data_len);
    if (!c_data) { fprintf(stderr, "Malloc failed for c_data.\n"); return 1; }
    memcpy(c_data, c1, sizeof(c1));
    memcpy(c_data + sizeof(c1), pks_x25519, sizeof(pks_x25519));

    size_t sm_buf_len = c_data_len + PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES;
    unsigned char *sm_buf = malloc(sm_buf_len);
    if (!sm_buf) { fprintf(stderr, "Malloc failed for sm_buf.\n"); free(c_data); return 1; }
    size_t smlen;

    total_ns = 0;
    total_cycles = 0;
    for (int i = 0; i < BENCHMARK_ITERATIONS; ++i) {
        clock_gettime(CLOCK_MONOTONIC, &start_time);
        start_cycles = rdtsc();
        if (PQCLEAN_MLDSA65_CLEAN_crypto_sign(sm_buf, &smlen, c_data, c_data_len, sks_mldsa) != 0) {
            fprintf(stderr, "ML-DSA-65 signing failed.\n");
            free(c_data); free(sm_buf); return 1;
        }
        end_cycles = rdtsc();
        clock_gettime(CLOCK_MONOTONIC, &end_time);
        total_ns += (end_time.tv_sec - start_time.tv_sec) * 1000000000LL + (end_time.tv_nsec - start_time.tv_nsec);
        if (end_cycles > start_cycles) total_cycles += (end_cycles - start_cycles);
    }
    printf("Average Time:   %lld ns\n", total_ns / BENCHMARK_ITERATIONS);
    printf("Average Cycles: %llu\n", total_cycles / BENCHMARK_ITERATIONS);
    write_binary_data_to_file("signed_message_mldsa.bin", sm_buf, smlen);
    printf("------------------------------------\n");

    // (The rest of the protocol, like HKDF and AEAD, would follow here)
    // ...

    // Final Cleanup
    free(c_data);
    free(sm_buf);
    sodium_memzero(sks_x25519, sizeof(sks_x25519));
    sodium_memzero(sks_ml_kem, sizeof(sks_ml_kem));
    sodium_memzero(sks_mldsa, sizeof(sks_mldsa));

    printf("\nHybrid protocol sender operations complete.\n");
    return 0;
}

