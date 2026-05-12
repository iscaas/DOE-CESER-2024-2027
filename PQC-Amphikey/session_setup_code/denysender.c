#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h> // For uint8_t
#include <time.h>   // Added for timing

#include <sodium.h>       // For X25519, HMAC-SHA256, randombytes_buf
#include "api_mlkem.h"   // For ML-KEM

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

// --- ML-KEM API Defines ---
#ifndef PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES
#define PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES 1184
#endif
#ifndef PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES
#define PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES 2400
#endif
#ifndef PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES 1088
#endif
#ifndef PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES
#define PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES 32
#endif

void PQCLEAN_randombytes(unsigned char *outbuf, size_t outlen) {
    randombytes_buf(outbuf, outlen);
}

// --- HELPER FUNCTIONS ---
void print_hex(const char* label, const unsigned char* data, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int write_binary_data_to_file(const char* filename, const unsigned char* data, size_t len) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) { perror("Error opening file for writing"); fprintf(stderr, "Filename: %s\n", filename); return -1; }
    size_t bytes_written = fwrite(data, 1, len, fp);
    fclose(fp);
    if (bytes_written != len) { fprintf(stderr, "Error writing complete data to %s\n", filename); return -1; }
    printf("Successfully wrote %zu bytes to %s\n", bytes_written, filename);
    return 0;
}

int read_binary_data_from_file(const char* filename, unsigned char* buffer, size_t buffer_len, size_t* bytes_read_actual) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) { perror("Error opening file for reading"); fprintf(stderr, "Filename: %s\n", filename); return -1; }
    *bytes_read_actual = fread(buffer, 1, buffer_len, fp);
    fclose(fp);
    if (*bytes_read_actual == 0 && !feof(fp) && ferror(fp)) { fprintf(stderr, "Error reading from %s\n", filename); return -1; }
    printf("Successfully read %zu bytes from %s\n", *bytes_read_actual, filename);
    return 0;
}

int read_hex_key_from_file(const char* filename, unsigned char* bin_buffer, size_t bin_buffer_len, size_t* actual_bin_len) {
    FILE *fp = fopen(filename, "r");
    if (!fp) { perror("Error opening hex key file"); fprintf(stderr, "Filename: %s\n", filename); return -1; }
    char* hex_string_buf = (char*)malloc(bin_buffer_len * 2 + 3);
    if (!hex_string_buf) { fprintf(stderr, "Malloc failed.\n"); fclose(fp); return -1; }
    if (fgets(hex_string_buf, bin_buffer_len * 2 + 3, fp) == NULL) { fprintf(stderr, "Failed to read hex key from %s\n", filename); fclose(fp); free(hex_string_buf); return -1; }
    fclose(fp);
    hex_string_buf[strcspn(hex_string_buf, "\r\n")] = 0;
    size_t hex_len = strlen(hex_string_buf);
    if (sodium_hex2bin(bin_buffer, bin_buffer_len, hex_string_buf, hex_len, NULL, actual_bin_len, NULL) != 0) {
        fprintf(stderr, "sodium_hex2bin failed for %s.\n", filename); free(hex_string_buf); return -1;
    }
    free(hex_string_buf);
    printf("Successfully read and converted hex key from %s\n", filename);
    return 0;
}

int hkdf_sha256_extract(unsigned char *prk, const unsigned char *salt, size_t salt_len, const unsigned char *ikm, size_t ikm_len) {
    unsigned char zero_key_salt[crypto_auth_hmacsha256_KEYBYTES];
    const unsigned char *hmac_key = salt;
    if (salt == NULL || salt_len == 0) {
        sodium_memzero(zero_key_salt, sizeof(zero_key_salt)); hmac_key = zero_key_salt;
    }
    int result = crypto_auth_hmacsha256(prk, ikm, ikm_len, hmac_key);
    sodium_memzero(zero_key_salt, sizeof(zero_key_salt));
    return result;
}

int hkdf_sha256_expand(unsigned char *okm, size_t okm_len, const unsigned char *prk, size_t prk_len, const unsigned char *info, size_t info_len) {
    if (okm_len > 255 * crypto_hash_sha256_BYTES) { return -1; }
    unsigned char T_prev[crypto_hash_sha256_BYTES];
    size_t T_len = 0, generated_len = 0;
    crypto_auth_hmacsha256_state hmac_state;
    size_t N = (okm_len + crypto_hash_sha256_BYTES - 1) / crypto_hash_sha256_BYTES;
    for (unsigned char i = 1; i <= N; i++) {
        crypto_auth_hmacsha256_init(&hmac_state, prk, prk_len);
        if (T_len > 0) { crypto_auth_hmacsha256_update(&hmac_state, T_prev, T_len); }
        if (info_len > 0 && info != NULL) { crypto_auth_hmacsha256_update(&hmac_state, info, info_len); }
        crypto_auth_hmacsha256_update(&hmac_state, &i, 1);
        unsigned char T_current[crypto_hash_sha256_BYTES];
        crypto_auth_hmacsha256_final(&hmac_state, T_current);
        size_t copy_len = (generated_len + crypto_hash_sha256_BYTES > okm_len) ? (okm_len - generated_len) : crypto_hash_sha256_BYTES;
        memcpy(okm + generated_len, T_current, copy_len);
        generated_len += copy_len;
        if (i < N) { memcpy(T_prev, T_current, crypto_hash_sha256_BYTES); T_len = crypto_hash_sha256_BYTES; }
        sodium_memzero(T_current, sizeof(T_current));
    }
    sodium_memzero(T_prev, sizeof(T_prev));
    return 0;
}


// --- Main Program (Sender Operations) ---
int main() {
    printf("--- Protocol Sender Operations (Loading Pre-generated Keys) ---\n\n");

    if (sodium_init() < 0) { fprintf(stderr, "Libsodium couldn't be initialized!\n"); return 1; }
    printf("Libsodium initialized.\n\n");

    // --- Load Sender's Keys (Sks, Pks) ---
    unsigned char sks1_x25519[crypto_scalarmult_BYTES];
    unsigned char pks1_x25519[crypto_scalarmult_BYTES];
    unsigned char sks2_mlkem[PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES];
    unsigned char pks2_mlkem[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    size_t actual_read;
    if (read_hex_key_from_file("server_x25519_sk.hex", sks1_x25519, sizeof(sks1_x25519), &actual_read) != 0) { return 1; }
    if (read_hex_key_from_file("server_x25519_pk.hex", pks1_x25519, sizeof(pks1_x25519), &actual_read) != 0) { return 1; }
    if (read_binary_data_from_file("server_mlkem_sk.key", sks2_mlkem, sizeof(sks2_mlkem), &actual_read) != 0) { return 1; }
    if (read_binary_data_from_file("server_mlkem_pk.key", pks2_mlkem, sizeof(pks2_mlkem), &actual_read) != 0) { return 1; }
    
    // --- Load Receiver's Public Keys (Pkr) ---
    unsigned char pkr1_x25519[crypto_scalarmult_BYTES];
    unsigned char pkr2_mlkem[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    if (read_hex_key_from_file("client_x25519_pk.hex", pkr1_x25519, sizeof(pkr1_x25519), &actual_read) != 0) { return 1; }
    if (read_binary_data_from_file("client_mlkem_pk.key", pkr2_mlkem, sizeof(pkr2_mlkem), &actual_read) != 0) { return 1; }
    printf("All keys loaded.\n\n");

    // Benchmark variables
    struct timespec start_time, end_time;
    unsigned long long start_cycles, end_cycles;
    long long total_ns;
    unsigned long long total_cycles;

    // --- BENCHMARK AKEM1 (X25519) ---
    printf("\n--- Benchmarking AKEM1 (X25519 Shared Secret) ---\n");
    unsigned char k1_x25519_ss[crypto_scalarmult_BYTES];
    total_ns = 0; total_cycles = 0;
    for (int i = 0; i < BENCHMARK_ITERATIONS; ++i) {
        clock_gettime(CLOCK_MONOTONIC, &start_time); start_cycles = rdtsc();
        if (crypto_scalarmult(k1_x25519_ss, sks1_x25519, pkr1_x25519) != 0) {
            fprintf(stderr, "X25519 scalar multiplication failed.\n"); return 1;
        }
        end_cycles = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &end_time);
        total_ns += (end_time.tv_sec - start_time.tv_sec) * 1000000000LL + (end_time.tv_nsec - start_time.tv_nsec);
        if (end_cycles > start_cycles) total_cycles += (end_cycles - start_cycles);
    }
    printf("Average Time:   %lld ns\n", total_ns / BENCHMARK_ITERATIONS);
    printf("Average Cycles: %llu\n", total_cycles / BENCHMARK_ITERATIONS);
    print_hex("DEBUG Sender k1", k1_x25519_ss, sizeof(k1_x25519_ss)); // <-- DEBUG
    printf("------------------------------------\n");
    unsigned char* c1_val = pks1_x25519;
    size_t c1_len = sizeof(pks1_x25519);

    // --- BENCHMARK AKEM2 (ML-KEM Encapsulation) ---
    printf("\n--- Benchmarking AKEM2 (ML-KEM Encapsulation) ---\n");
    unsigned char c2_mlkem_ct[PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    unsigned char k2_mlkem_ss[PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES];
    total_ns = 0; total_cycles = 0;
    for (int i = 0; i < BENCHMARK_ITERATIONS; ++i) {
        clock_gettime(CLOCK_MONOTONIC, &start_time); start_cycles = rdtsc();
        if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(c2_mlkem_ct, k2_mlkem_ss, pkr2_mlkem) != 0) {
            fprintf(stderr, "ML-KEM encapsulation failed.\n"); return 1;
        }
        end_cycles = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &end_time);
        total_ns += (end_time.tv_sec - start_time.tv_sec) * 1000000000LL + (end_time.tv_nsec - start_time.tv_nsec);
        if (end_cycles > start_cycles) total_cycles += (end_cycles - start_cycles);
    }
    printf("Average Time:   %lld ns\n", total_ns / BENCHMARK_ITERATIONS);
    printf("Average Cycles: %llu\n", total_cycles / BENCHMARK_ITERATIONS);
    print_hex("DEBUG Sender k2", k2_mlkem_ss, sizeof(k2_mlkem_ss)); // <-- DEBUG
    printf("------------------------------------\n");

    size_t c_data_len = c1_len + sizeof(c2_mlkem_ct);
    unsigned char *c_data = (unsigned char *)malloc(c_data_len);
    memcpy(c_data, c1_val, c1_len);
    memcpy(c_data + c1_len, c2_mlkem_ct, sizeof(c2_mlkem_ct));

    // --- BENCHMARK Nonce (n) Derivation (HKDF) ---
    printf("\n--- Benchmarking Nonce (n) Derivation (HKDF) ---\n");
    unsigned char n_nonce[16];
    size_t ikm_for_n_len = sizeof(k1_x25519_ss) + sizeof(k2_mlkem_ss);
    unsigned char *ikm_for_n = (unsigned char *)malloc(ikm_for_n_len);
    memcpy(ikm_for_n, k1_x25519_ss, sizeof(k1_x25519_ss));
    memcpy(ikm_for_n + sizeof(k1_x25519_ss), k2_mlkem_ss, sizeof(k2_mlkem_ss));
    total_ns = 0; total_cycles = 0;
    for (int i = 0; i < BENCHMARK_ITERATIONS; ++i) {
        unsigned char prk_for_n[crypto_auth_hmacsha256_BYTES];
        clock_gettime(CLOCK_MONOTONIC, &start_time); start_cycles = rdtsc();
        hkdf_sha256_extract(prk_for_n, NULL, 0, ikm_for_n, ikm_for_n_len);
        hkdf_sha256_expand(n_nonce, sizeof(n_nonce), prk_for_n, sizeof(prk_for_n), NULL, 0);
        end_cycles = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &end_time);
        total_ns += (end_time.tv_sec - start_time.tv_sec) * 1000000000LL + (end_time.tv_nsec - start_time.tv_nsec);
        if (end_cycles > start_cycles) total_cycles += (end_cycles - start_cycles);
    }
    free(ikm_for_n);
    printf("Average Time:   %lld ns\n", total_ns / BENCHMARK_ITERATIONS);
    printf("Average Cycles: %llu\n", total_cycles / BENCHMARK_ITERATIONS);
    print_hex("DEBUG Sender n", n_nonce, sizeof(n_nonce)); // <-- DEBUG
    printf("------------------------------------\n");

    // --- BENCHMARK Auth Key (k_auth) Derivation (HKDF) ---
    printf("\n--- Benchmarking Auth Key (k_auth) Derivation (HKDF) ---\n");
    unsigned char k_auth[crypto_auth_hmacsha256_KEYBYTES];
    size_t ikm_for_kauth_len = sizeof(k1_x25519_ss) + c1_len + sizeof(n_nonce);
    unsigned char *ikm_for_kauth = (unsigned char *)malloc(ikm_for_kauth_len);
    unsigned char *ptr_kauth_ikm = ikm_for_kauth;
    memcpy(ptr_kauth_ikm, k1_x25519_ss, sizeof(k1_x25519_ss)); ptr_kauth_ikm += sizeof(k1_x25519_ss);
    memcpy(ptr_kauth_ikm, c1_val, c1_len); ptr_kauth_ikm += c1_len;
    memcpy(ptr_kauth_ikm, n_nonce, sizeof(n_nonce));
    total_ns = 0; total_cycles = 0;
    for (int i = 0; i < BENCHMARK_ITERATIONS; ++i) {
        unsigned char prk_for_kauth[crypto_auth_hmacsha256_BYTES];
        clock_gettime(CLOCK_MONOTONIC, &start_time); start_cycles = rdtsc();
        hkdf_sha256_extract(prk_for_kauth, NULL, 0, ikm_for_kauth, ikm_for_kauth_len);
        hkdf_sha256_expand(k_auth, sizeof(k_auth), prk_for_kauth, sizeof(prk_for_kauth), NULL, 0);
        end_cycles = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &end_time);
        total_ns += (end_time.tv_sec - start_time.tv_sec) * 1000000000LL + (end_time.tv_nsec - start_time.tv_nsec);
        if (end_cycles > start_cycles) total_cycles += (end_cycles - start_cycles);
    }
    free(ikm_for_kauth);
    printf("Average Time:   %lld ns\n", total_ns / BENCHMARK_ITERATIONS);
    printf("Average Cycles: %llu\n", total_cycles / BENCHMARK_ITERATIONS);
    print_hex("DEBUG Sender k_auth", k_auth, sizeof(k_auth)); // <-- DEBUG
    printf("------------------------------------\n");

    // --- BENCHMARK Tag Computation (HMAC) ---
    printf("\n--- Benchmarking Tag Computation (HMAC-SHA256) ---\n");
    unsigned char tag[crypto_auth_hmacsha256_BYTES];
    total_ns = 0; total_cycles = 0;
    for (int i = 0; i < BENCHMARK_ITERATIONS; ++i) {
        clock_gettime(CLOCK_MONOTONIC, &start_time); start_cycles = rdtsc();
        crypto_auth_hmacsha256(tag, c_data, c_data_len, k_auth);
        end_cycles = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &end_time);
        total_ns += (end_time.tv_sec - start_time.tv_sec) * 1000000000LL + (end_time.tv_nsec - start_time.tv_nsec);
        if (end_cycles > start_cycles) total_cycles += (end_cycles - start_cycles);
    }
    printf("Average Time:   %lld ns\n", total_ns / BENCHMARK_ITERATIONS);
    printf("Average Cycles: %llu\n", total_cycles / BENCHMARK_ITERATIONS);
    printf("------------------------------------\n");

    // Save data for receiver
    write_binary_data_to_file("c_data_to_receiver.bin", c_data, c_data_len);
    write_binary_data_to_file("tag_to_receiver.bin", tag, sizeof(tag));
    write_binary_data_to_file("sender_ephemeral_mlkem_pk.bin", pks2_mlkem, sizeof(pks2_mlkem));
    printf("Data saved for receiver.\n");

    free(c_data);
    // Final cleanup
    // ...

    return 0;
}
