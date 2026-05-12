#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> // Added for timing

#include <sodium.h>      // For X25519
#include "api_mlkem.h"   // For ML-KEM (using PQCLEAN_MLKEM768_CLEAN_ prefix)
#include "api_raccoon.h" // For Raccoon (using generic CRYPTO_ prefix for Raccoon)


// --- BENCHMARKING HELPERS ---
#define BENCHMARK_ITERATIONS 1000

#if defined(__i386__) || defined(__x86_64__)
// Reads the Time-Stamp Counter to get CPU cycles.
static inline unsigned long long rdtsc(void) {
    unsigned int lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((unsigned long long)hi << 32) | lo;
}
#else
// Fallback for non-x86 architectures where rdtsc is not available.
static inline unsigned long long rdtsc(void) {
    return 0;
}
#endif
// --- END BENCHMARKING HELPERS ---

// Forward declaration for Raccoon's RNG init function
void nist_randombytes_init(unsigned char *entropy_input, unsigned char *personalization_string, int security_strength);
extern void randombytes(unsigned char *x, unsigned long long xlen);

// Wrapper function to satisfy libml-kem-768_clean.a's dependency
void PQCLEAN_randombytes(unsigned char *buf, size_t nbytes) {
    randombytes(buf, (unsigned long long)nbytes);
}

// --- ORIGINAL HELPER FUNCTIONS ---
void print_hex(const char* label, const unsigned char* data, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

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
    printf("--- CLIENT KEY GENERATION ---\n");

    // 1. Initialize Randomness & Libsodium
    unsigned char client_entropy_input[48];
    for (int i = 0; i < 48; i++) client_entropy_input[i] = (unsigned char)('C' + i);
    nist_randombytes_init(client_entropy_input, (unsigned char *)"Client", 256);
    printf("Raccoon's NIST DRBG initialized for client.\n");

    if (sodium_init() < 0) {
        fprintf(stderr, "Libsodium couldn't be initialized!\n");
        return 1;
    }
    printf("Libsodium initialized for client.\n\n");

    // Declare benchmark variables
    struct timespec start_time, end_time;
    unsigned long long start_cycles, end_cycles;
    long long total_ns;
    unsigned long long total_cycles;

    // --- X25519 Key Generation for Client ---
    printf("--- Benchmarking X25519 Key Generation (%d iterations) ---\n", BENCHMARK_ITERATIONS);
    unsigned char client_x25519_pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char client_x25519_sk[crypto_kx_SECRETKEYBYTES];
    total_ns = 0;
    total_cycles = 0;
    for (int i = 0; i < BENCHMARK_ITERATIONS; ++i) {
        clock_gettime(CLOCK_MONOTONIC, &start_time);
        start_cycles = rdtsc();
        if (crypto_kx_keypair(client_x25519_pk, client_x25519_sk) != 0) {
            fprintf(stderr, "ERROR: Client X25519 key pair generation failed.\n"); return 1;
        }
        end_cycles = rdtsc();
        clock_gettime(CLOCK_MONOTONIC, &end_time);
        total_ns += (end_time.tv_sec - start_time.tv_sec) * 1000000000LL + (end_time.tv_nsec - start_time.tv_nsec);
        if (end_cycles > start_cycles) total_cycles += (end_cycles - start_cycles);
    }
    printf("Average Time:   %lld ns\n", total_ns / BENCHMARK_ITERATIONS);
    printf("Average Cycles: %llu\n", total_cycles / BENCHMARK_ITERATIONS);
    write_hex_key_to_file("client_x25519_pk.hex", client_x25519_pk, crypto_kx_PUBLICKEYBYTES);
    write_hex_key_to_file("client_x25519_sk.hex", client_x25519_sk, crypto_kx_SECRETKEYBYTES);
    sodium_memzero(client_x25519_sk, crypto_kx_SECRETKEYBYTES);
    printf("------------------------------------\n\n");

    // --- ML-KEM-768 Key Generation for Client ---
    printf("--- Benchmarking ML-KEM-768 Key Generation (%d iterations) ---\n", BENCHMARK_ITERATIONS);
    unsigned char client_mlkem_pk[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    unsigned char client_mlkem_sk[PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES];
    total_ns = 0;
    total_cycles = 0;
    for (int i = 0; i < BENCHMARK_ITERATIONS; ++i) {
        clock_gettime(CLOCK_MONOTONIC, &start_time);
        start_cycles = rdtsc();
        if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(client_mlkem_pk, client_mlkem_sk) != 0) {
            fprintf(stderr, "ERROR: Client ML-KEM key pair generation failed.\n"); return 1;
        }
        end_cycles = rdtsc();
        clock_gettime(CLOCK_MONOTONIC, &end_time);
        total_ns += (end_time.tv_sec - start_time.tv_sec) * 1000000000LL + (end_time.tv_nsec - start_time.tv_nsec);
        if (end_cycles > start_cycles) total_cycles += (end_cycles - start_cycles);
    }
    printf("Average Time:   %lld ns\n", total_ns / BENCHMARK_ITERATIONS);
    printf("Average Cycles: %llu\n", total_cycles / BENCHMARK_ITERATIONS);
    write_binary_key_to_file("client_mlkem_pk.key", client_mlkem_pk, PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES);
    write_binary_key_to_file("client_mlkem_sk.key", client_mlkem_sk, PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES);
    printf("------------------------------------\n\n");

    // --- Raccoon Signature Key Generation for Client ---
    printf("--- Benchmarking Raccoon Key Generation (%d iterations) ---\n", BENCHMARK_ITERATIONS);
    unsigned char client_raccoon_pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char client_raccoon_sk[CRYPTO_SECRETKEYBYTES];
    total_ns = 0;
    total_cycles = 0;
    for (int i = 0; i < BENCHMARK_ITERATIONS; ++i) {
        clock_gettime(CLOCK_MONOTONIC, &start_time);
        start_cycles = rdtsc();
        if (crypto_sign_keypair(client_raccoon_pk, client_raccoon_sk) != 0) {
            fprintf(stderr, "Error generating client Raccoon key pair!\n"); return 1;
        }
        end_cycles = rdtsc();
        clock_gettime(CLOCK_MONOTONIC, &end_time);
        total_ns += (end_time.tv_sec - start_time.tv_sec) * 1000000000LL + (end_time.tv_nsec - start_time.tv_nsec);
        if (end_cycles > start_cycles) total_cycles += (end_cycles - start_cycles);
    }
    printf("Average Time:   %lld ns\n", total_ns / BENCHMARK_ITERATIONS);
    printf("Average Cycles: %llu\n", total_cycles / BENCHMARK_ITERATIONS);
    write_binary_key_to_file("client_raccoon_pk.key", client_raccoon_pk, CRYPTO_PUBLICKEYBYTES);
    write_binary_key_to_file("client_raccoon_sk.key", client_raccoon_sk, CRYPTO_SECRETKEYBYTES);
    printf("------------------------------------\n");

    printf("\nClient key generation and benchmarking complete.\n");
    return 0;
}
