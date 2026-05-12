#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

#include <sodium.h>
#include "api_mlkem.h"
#include "api_mldsa.h"

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
 *
 * This function is named exactly as the library expects (`PQCLEAN_randombytes`).
 * It acts as a bridge to the strong random number generator provided by libsodium.
 */
void PQCLEAN_randombytes(uint8_t *out, size_t outlen) {
    randombytes_buf(out, outlen);
}


// --- HELPER FUNCTIONS ---
int write_binary_key_to_file(const char* filename, const unsigned char* key_data, size_t key_len) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) { perror("fopen"); return -1; }
    fwrite(key_data, 1, key_len, fp);
    fclose(fp);
    printf("Successfully wrote binary key to %s\n", filename);
    return 0;
}

int write_hex_key_to_file(const char* filename, const unsigned char* key_data, size_t key_len) {
    FILE *fp = fopen(filename, "w");
    if (!fp) { perror("fopen"); return -1; }
    char *hex_string = (char *)sodium_malloc(key_len * 2 + 1);
    if (!hex_string) { fclose(fp); return -1; }
    sodium_bin2hex(hex_string, key_len * 2 + 1, key_data, key_len);
    fprintf(fp, "%s\n", hex_string);
    sodium_free(hex_string);
    fclose(fp);
    printf("Successfully wrote hex key to %s\n", filename);
    return 0;
}
// --- END OF HELPER FUNCTIONS ---

int main() {
    printf("--- CLIENT KEY GENERATION (ML-KEM & ML-DSA-65) ---\n");
    if (sodium_init() < 0) {
        fprintf(stderr, "Libsodium couldn't be initialized!\n");
        return 1;
    }
    printf("Libsodium initialized.\n\n");

    struct timespec start_time, end_time;
    unsigned long long start_cycles, end_cycles, total_cycles;
    long long total_ns;

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

    // --- ML-DSA-65 Signature Key Generation for Client ---
    printf("--- Benchmarking ML-DSA-65 Key Generation (%d iterations) ---\n", BENCHMARK_ITERATIONS);
    unsigned char client_mldsa_pk[PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES];
    unsigned char client_mldsa_sk[PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES];
    total_ns = 0;
    total_cycles = 0;
    for (int i = 0; i < BENCHMARK_ITERATIONS; ++i) {
        clock_gettime(CLOCK_MONOTONIC, &start_time);
        start_cycles = rdtsc();
        if (PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(client_mldsa_pk, client_mldsa_sk) != 0) {
            fprintf(stderr, "Error generating client ML-DSA-65 key pair!\n"); return 1;
        }
        end_cycles = rdtsc();
        clock_gettime(CLOCK_MONOTONIC, &end_time);
        total_ns += (end_time.tv_sec - start_time.tv_sec) * 1000000000LL + (end_time.tv_nsec - start_time.tv_nsec);
        if (end_cycles > start_cycles) total_cycles += (end_cycles - start_cycles);
    }
    printf("Average Time:   %lld ns\n", total_ns / BENCHMARK_ITERATIONS);
    printf("Average Cycles: %llu\n", total_cycles / BENCHMARK_ITERATIONS);
    write_binary_key_to_file("client_mldsa_pk.key", client_mldsa_pk, PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES);
    write_binary_key_to_file("client_mldsa_sk.key", client_mldsa_sk, PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES);
    printf("------------------------------------\n");

    printf("\nClient key generation and benchmarking complete.\n");
    return 0;
}

