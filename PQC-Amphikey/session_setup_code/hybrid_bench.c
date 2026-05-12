#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h> // For uint8_t
#include <time.h>   // Added for timing

#include <sodium.h>       // For X25519, HMAC-SHA256, AEAD, and other utilities
#include "api_mlkem.h"   // For ML-KEM (using PQCLEAN_MLKEM768_CLEAN_ prefix)
#include "api_raccoon.h" // For Raccoon (using generic CRYPTO_ prefix for Raccoon)

// ACORN specific headers
#include "constants.h" // From ACORN_..._v02/source/
#include "cipher.h"    // From FELICS common/

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

// Forward declarations and wrappers...
extern void nist_randombytes_init(unsigned char *entropy_input, unsigned char *personalization_string, int security_strength);
extern void randombytes(unsigned char *x, unsigned long long xlen);

void PQCLEAN_randombytes(unsigned char *buf, size_t nbytes) {
    randombytes(buf, (unsigned long long)nbytes);
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
    if (!fp) {
        perror("Error opening file for writing");
        fprintf(stderr, "Filename: %s\n", filename);
        return -1;
    }
    size_t bytes_written = fwrite(data, 1, len, fp);
    fclose(fp);
    if (bytes_written != len) {
        fprintf(stderr, "Error writing complete data to %s (wrote %zu of %zu bytes)\n", filename, bytes_written, len);
        return -1;
    }
    printf("Successfully wrote data to %s\n", filename);
    return 0;
}

int read_binary_data_from_file(const char* filename, unsigned char* buffer, size_t buffer_len, size_t* bytes_read_actual) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("Error opening file for reading");
        fprintf(stderr, "Filename: %s\n", filename);
        return -1;
    }
    *bytes_read_actual = fread(buffer, 1, buffer_len, fp);
    fclose(fp);
    if (*bytes_read_actual == 0 && !feof(fp) && ferror(fp)) {
        fprintf(stderr, "Error reading from %s\n", filename);
        return -1;
    }
    if (buffer_len > 0 && *bytes_read_actual != buffer_len &&
        (strcmp(filename, "acorn_aead_ciphertext.dat") != 0) ) {
        fprintf(stderr, "Error: Read %zu bytes from %s, but expected %zu bytes.\n", *bytes_read_actual, filename, buffer_len);
        return -1;
    }
    printf("Successfully read %zu bytes from %s\n", *bytes_read_actual, filename);
    return 0;
}

int read_hex_key_from_file(const char* filename, unsigned char* bin_buffer, size_t bin_buffer_len, size_t* actual_bin_len) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("Error opening hex key file for reading");
        fprintf(stderr, "Filename: %s\n", filename);
        return -1;
    }
    char* hex_string_buf = (char*)malloc(bin_buffer_len * 2 + 3);
    if (!hex_string_buf) {
        fprintf(stderr, "Failed to allocate memory for hex string buffer.\n");
        fclose(fp);
        return -1;
    }
    if (fgets(hex_string_buf, bin_buffer_len * 2 + 3, fp) == NULL) {
        if (feof(fp) && strlen(hex_string_buf) == 0) {
             fprintf(stderr, "Error: Hex key file %s is empty.\n", filename);
        } else {
             fprintf(stderr, "Error reading hex string from %s\n", filename);
        }
        fclose(fp);
        free(hex_string_buf);
        return -1;
    }
    fclose(fp);
    hex_string_buf[strcspn(hex_string_buf, "\r\n")] = 0;
    size_t hex_len = strlen(hex_string_buf);
    if (hex_len == 0) {
        fprintf(stderr, "Error: Hex key file %s contains no actual hex data.\n", filename);
        free(hex_string_buf);
        return -1;
    }
    if (sodium_hex2bin(bin_buffer, bin_buffer_len, hex_string_buf, hex_len, NULL, actual_bin_len, NULL) != 0) {
        fprintf(stderr, "sodium_hex2bin failed for %s. Hex: '%s' (len %zu), Buffer: %zu\n", filename, hex_string_buf, hex_len, bin_buffer_len);
        free(hex_string_buf);
        return -1;
    }
    if (*actual_bin_len != bin_buffer_len) {
        fprintf(stderr, "Error: Converted hex key from %s has length %zu, expected %zu.\n", filename, *actual_bin_len, bin_buffer_len);
        free(hex_string_buf);
        return -1;
    }
    free(hex_string_buf);
    printf("Successfully read and converted hex key from %s (%zu hex chars -> %zu bin bytes)\n", filename, hex_len, *actual_bin_len);
    return 0;
}

int hkdf_sha256_extract(unsigned char *prk,
                        const unsigned char *salt, size_t salt_len,
                        const unsigned char *ikm, size_t ikm_len) {
    unsigned char zero_key_salt[crypto_auth_hmacsha256_KEYBYTES];
    const unsigned char *hmac_key = salt;
    if (salt == NULL || salt_len == 0) {
        sodium_memzero(zero_key_salt, sizeof(zero_key_salt));
        hmac_key = zero_key_salt;
    }
    int result = crypto_auth_hmacsha256(prk, ikm, ikm_len, hmac_key);
    sodium_memzero(zero_key_salt, sizeof(zero_key_salt));
    return result;
}

int hkdf_sha256_expand(unsigned char *okm, size_t okm_len,
                       const unsigned char *prk, size_t prk_len,
                       const unsigned char *info, size_t info_len) {
    if (okm_len == 0) return 0;
    if (okm_len > 255 * crypto_hash_sha256_BYTES) {
         fprintf(stderr, "Requested OKM length is too long for HKDF-SHA256.\n");
         return -1;
    }
    unsigned char T_prev[crypto_hash_sha256_BYTES];
    size_t T_len = 0;
    size_t N = (okm_len + crypto_hash_sha256_BYTES - 1) / crypto_hash_sha256_BYTES;
    size_t generated_len = 0;
    crypto_auth_hmacsha256_state hmac_state;
    for (unsigned char i = 1; i <= N; i++) {
        if (crypto_auth_hmacsha256_init(&hmac_state, prk, prk_len) != 0) return -1;
        if (T_len > 0) {
            if (crypto_auth_hmacsha256_update(&hmac_state, T_prev, T_len) != 0) return -1;
        }
        if (info_len > 0 && info != NULL) {
            if (crypto_auth_hmacsha256_update(&hmac_state, info, info_len) != 0) return -1;
        }
        if (crypto_auth_hmacsha256_update(&hmac_state, &i, 1) != 0) return -1;
        unsigned char T_current[crypto_hash_sha256_BYTES];
        if (crypto_auth_hmacsha256_final(&hmac_state, T_current) != 0) return -1;
        size_t copy_len = (generated_len + crypto_hash_sha256_BYTES > okm_len) ? (okm_len - generated_len) : crypto_hash_sha256_BYTES;
        memcpy(okm + generated_len, T_current, copy_len);
        generated_len += copy_len;
        if (i < N) {
            memcpy(T_prev, T_current, crypto_hash_sha256_BYTES);
            T_len = crypto_hash_sha256_BYTES;
        }
        sodium_memzero(T_current, sizeof(T_current));
    }
    sodium_memzero(T_prev, sizeof(T_prev));
    return 0;
}

// --- Main Program ---
int main() {
    printf("--- Hybrid Protocol: Sender Operations (Loading Pre-generated Keys) ---\n\n");

    // 1. Initialize Randomness & Libsodium
    unsigned char entropy_input[48];
    for (int i = 0; i < 48; i++) entropy_input[i] = (unsigned char)(i); // Dummy entropy
    nist_randombytes_init(entropy_input, (unsigned char *)"HybridSender", 256);
    printf("Raccoon's NIST DRBG initialized.\n");

    if (sodium_init() < 0) {
        fprintf(stderr, "Libsodium couldn't be initialized!\n");
        return 1;
    }
    printf("Libsodium initialized.\n\n");

    // Declare Key Buffers for Sender (Server)
    unsigned char sks_ml_kem[PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES];
    unsigned char pks_ml_kem[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    unsigned char sks_x25519[crypto_kx_SECRETKEYBYTES];
    unsigned char pks_x25519[crypto_kx_PUBLICKEYBYTES];
    unsigned char sks_rac[CRYPTO_SECRETKEYBYTES];
    unsigned char pks_rac[CRYPTO_PUBLICKEYBYTES];

    // Declare Key Buffers for Receiver's (Client's) Public Keys
    unsigned char pkr_ml_kem[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    unsigned char pkr_x25519[crypto_kx_PUBLICKEYBYTES];
    unsigned char pkr_rac[CRYPTO_PUBLICKEYBYTES];
    size_t bytes_read_actual;

    // --- Load Sender's (Server's) Keys from Files ---
    printf("Loading Sender's (Server's) keys from files...\n");
    if (read_binary_data_from_file("server_mlkem_pk.key", pks_ml_kem, sizeof(pks_ml_kem), &bytes_read_actual) != 0 ) { fprintf(stderr, "Load server_mlkem_pk.key failed.\n"); return 1; }
    if (read_binary_data_from_file("server_mlkem_sk.key", sks_ml_kem, sizeof(sks_ml_kem), &bytes_read_actual) != 0 ) { fprintf(stderr, "Load server_mlkem_sk.key failed.\n"); return 1; }
    if (read_hex_key_from_file("server_x25519_pk.hex", pks_x25519, sizeof(pks_x25519), &bytes_read_actual) != 0 ) { fprintf(stderr, "Load server_x25519_pk.hex failed.\n"); return 1; }
    if (read_hex_key_from_file("server_x25519_sk.hex", sks_x25519, sizeof(sks_x25519), &bytes_read_actual) != 0 ) { fprintf(stderr, "Load server_x25519_sk.hex failed.\n"); return 1; }
    if (read_binary_data_from_file("server_raccoon_pk.key", pks_rac, sizeof(pks_rac), &bytes_read_actual) != 0 ) { fprintf(stderr, "Load server_raccoon_pk.key failed.\n"); return 1; }
    if (read_binary_data_from_file("server_raccoon_sk.key", sks_rac, sizeof(sks_rac), &bytes_read_actual) != 0 ) { fprintf(stderr, "Load server_raccoon_sk.key failed.\n"); return 1; }
    printf("Sender's (Server's) keys loaded successfully.\n");
    if (write_binary_data_to_file("sender_pks_x25519_for_protocol.key", pks_x25519, sizeof(pks_x25519)) != 0) {
        fprintf(stderr, "Failed to save sender's binary X25519 PK for protocol use.\n"); return 1;
    }
    printf("\n");

    // --- Load Receiver's (Client's) Public Keys from Files ---
    printf("Loading Receiver's (Client's) public keys from files...\n");
    if (read_binary_data_from_file("client_mlkem_pk.key", pkr_ml_kem, sizeof(pkr_ml_kem), &bytes_read_actual) != 0 ) { fprintf(stderr, "Load client_mlkem_pk.key failed.\n"); return 1; }
    if (read_hex_key_from_file("client_x25519_pk.hex", pkr_x25519, sizeof(pkr_x25519), &bytes_read_actual) != 0 ) { fprintf(stderr, "Load client_x25519_pk.hex failed.\n"); return 1; }
    if (read_binary_data_from_file("client_raccoon_pk.key", pkr_rac, sizeof(pkr_rac), &bytes_read_actual) != 0 ) { fprintf(stderr, "Load client_raccoon_pk.key failed.\n"); return 1; }
    printf("Receiver's (Client's) public keys loaded successfully.\n\n");


    // --- Sender's Operations ---
    printf("Performing Sender's operations using loaded keys...\n");

    // Declare benchmark variables
    struct timespec start_time, end_time;
    unsigned long long start_cycles, end_cycles;
    long long total_ns;
    unsigned long long total_cycles;

    // --- BENCHMARK ML-KEM ENCAPSULATION ---
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

    // --- BENCHMARK X25519 SHARED SECRET ---
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

    // --- CONTINUE PROTOCOL LOGIC (SIGNATURE, HKDF, etc.) ---
    // c_data = c1 || Pks_x25519
    size_t c_len = sizeof(c1) + sizeof(pks_x25519);
    unsigned char *c_data = (unsigned char *)malloc(c_len);
    if (!c_data) { fprintf(stderr, "Malloc failed for c_data.\n"); return 1; }
    memcpy(c_data, c1, sizeof(c1));
    memcpy(c_data + sizeof(c1), pks_x25519, sizeof(pks_x25519));

    unsigned char sig[CRYPTO_BYTES];
    unsigned long long smlen;
    unsigned char *sm_buf = (unsigned char *)malloc(CRYPTO_BYTES + c_len);
    if (!sm_buf) { fprintf(stderr, "Malloc failed for sm_buf.\n"); free(c_data); return 1; }
    if (crypto_sign(sm_buf, &smlen, c_data, c_len, sks_rac) != 0) {
         fprintf(stderr, "Raccoon signing (crypto_sign) failed.\n");
         free(c_data); free(sm_buf); return 1;
    }
    if (smlen < CRYPTO_BYTES) {
        fprintf(stderr, "Signed message length too short!\n");
        free(c_data); free(sm_buf); return 1;
    }
    memcpy(sig, sm_buf, CRYPTO_BYTES);
    free(sm_buf);
    write_binary_data_to_file("signature_on_c.sig", sig, CRYPTO_BYTES);

    // Construct Pks_bytes (Sender's aggregated public keys)
    size_t pks_bytes_len = sizeof(pks_ml_kem) + sizeof(pks_x25519) + sizeof(pks_rac);
    unsigned char *pks_bytes = (unsigned char *)malloc(pks_bytes_len);
    if (!pks_bytes) { fprintf(stderr, "Malloc failed for pks_bytes.\n"); free(c_data); return 1; }
    unsigned char *ptr_pks = pks_bytes;
    memcpy(ptr_pks, pks_ml_kem, sizeof(pks_ml_kem)); ptr_pks += sizeof(pks_ml_kem);
    memcpy(ptr_pks, pks_x25519, sizeof(pks_x25519)); ptr_pks += sizeof(pks_x25519);
    memcpy(ptr_pks, pks_rac, sizeof(pks_rac));

    // Construct Pkr_bytes (Receiver's aggregated public keys)
    size_t pkr_bytes_len = sizeof(pkr_ml_kem) + sizeof(pkr_x25519) + sizeof(pkr_rac);
    unsigned char *pkr_bytes = (unsigned char *)malloc(pkr_bytes_len);
    if (!pkr_bytes) { fprintf(stderr, "Malloc failed for pkr_bytes.\n"); free(c_data); free(pks_bytes); return 1; }
    unsigned char *ptr_pkr = pkr_bytes;
    memcpy(ptr_pkr, pkr_ml_kem, sizeof(pkr_ml_kem)); ptr_pkr += sizeof(pkr_ml_kem);
    memcpy(ptr_pkr, pkr_x25519, sizeof(pkr_x25519)); ptr_pkr += sizeof(pkr_x25519);
    memcpy(ptr_pkr, pkr_rac, sizeof(pkr_rac));

    // HKDF IKM
    size_t ikm_len = sizeof(k1) + sizeof(k2) + c_len + sizeof(sig) + pkr_bytes_len + pks_bytes_len;
    unsigned char *ikm = (unsigned char *)malloc(ikm_len);
    if (!ikm) { fprintf(stderr, "Malloc failed for IKM.\n"); free(c_data); free(pks_bytes); free(pkr_bytes); return 1;}
    unsigned char *ptr_ikm = ikm;
    memcpy(ptr_ikm, k1, sizeof(k1)); ptr_ikm += sizeof(k1);
    memcpy(ptr_ikm, k2, sizeof(k2)); ptr_ikm += sizeof(k2);
    memcpy(ptr_ikm, c_data, c_len); ptr_ikm += c_len;
    memcpy(ptr_ikm, sig, sizeof(sig)); ptr_ikm += sizeof(sig);
    memcpy(ptr_ikm, pkr_bytes, pkr_bytes_len); ptr_ikm += pkr_bytes_len;
    memcpy(ptr_ikm, pks_bytes, pks_bytes_len);

    unsigned char final_shared_secret[32];
    unsigned char prk_buf[crypto_auth_hmacsha256_BYTES];
    const unsigned char *hkdf_salt = NULL;
    size_t hkdf_salt_len = 0;
    const unsigned char *hkdf_info = (const unsigned char *)"HybridProto SharedSecret";
    size_t hkdf_info_len = strlen((const char*)hkdf_info);

    if (hkdf_sha256_extract(prk_buf, hkdf_salt, hkdf_salt_len, ikm, ikm_len) != 0) {
        fprintf(stderr, "HKDF Extract failed.\n"); free(c_data); free(pks_bytes); free(pkr_bytes); free(ikm); return 1;
    }
    if (hkdf_sha256_expand(final_shared_secret, sizeof(final_shared_secret),
                           prk_buf, sizeof(prk_buf), hkdf_info, hkdf_info_len) != 0) {
        fprintf(stderr, "HKDF Expand failed.\n"); free(c_data); free(pks_bytes); free(pkr_bytes); free(ikm); return 1;
    }
    print_hex("final_shared_secret",final_shared_secret,sizeof(final_shared_secret));
    
    sodium_memzero(prk_buf, sizeof(prk_buf));

    // --- BENCHMARK AEAD Encryption using ACORN ---
    printf("\n--- Benchmarking ACORN-128 AEAD Encryption (%d iterations) ---\n", BENCHMARK_ITERATIONS);
    unsigned char acorn_key[KEY_SIZE];
    memcpy(acorn_key, final_shared_secret, KEY_SIZE);
    unsigned char acorn_nonce[NONCE_SIZE];
    randombytes(acorn_nonce, sizeof(acorn_nonce));
    const char *plaintext_message = "This is a top secret message for the receiver!";
    size_t plaintext_len = strlen(plaintext_message);
    unsigned char *message_buffer = (unsigned char *)malloc(plaintext_len);
    memcpy(message_buffer, plaintext_message, plaintext_len);
    unsigned char acorn_tag[TAG_SIZE];
    uint8_t acorn_state[STATE_SIZE];
    const unsigned char *associated_data = NULL;
    uint32_t associated_data_len = 0;

    total_ns = 0;
    total_cycles = 0;
    for (int i = 0; i < BENCHMARK_ITERATIONS; ++i) {
        memcpy(message_buffer, plaintext_message, plaintext_len);

        clock_gettime(CLOCK_MONOTONIC, &start_time);
        start_cycles = rdtsc();

        Initialize(acorn_state, acorn_key, acorn_nonce);
        if (associated_data_len > 0) {
            ProcessAssociatedData(acorn_state, (uint8_t*)associated_data, associated_data_len);
        }
        ProcessPlaintext(acorn_state, message_buffer, plaintext_len);
        Finalize(acorn_state, acorn_key);
        TagGeneration(acorn_state, acorn_tag);

        end_cycles = rdtsc();
        clock_gettime(CLOCK_MONOTONIC, &end_time);
        total_ns += (end_time.tv_sec - start_time.tv_sec) * 1000000000LL + (end_time.tv_nsec - start_time.tv_nsec);
        if (end_cycles > start_cycles) total_cycles += (end_cycles - start_cycles);
    }
    size_t acorn_aead_ciphertext_len = plaintext_len + TAG_SIZE;
    unsigned char *acorn_aead_ciphertext = (unsigned char *)malloc(acorn_aead_ciphertext_len);
    memcpy(acorn_aead_ciphertext, message_buffer, plaintext_len);
    memcpy(acorn_aead_ciphertext + plaintext_len, acorn_tag, TAG_SIZE);

    printf("Plaintext length: %zu bytes\n", plaintext_len);
    printf("Average Time:     %lld ns\n", total_ns / BENCHMARK_ITERATIONS);
    printf("Average Cycles:   %llu\n", total_cycles / BENCHMARK_ITERATIONS);

    write_binary_data_to_file("acorn_nonce.dat", acorn_nonce, sizeof(acorn_nonce));
    write_binary_data_to_file("acorn_aead_ciphertext.dat", acorn_aead_ciphertext, acorn_aead_ciphertext_len);

    free(message_buffer);
    free(acorn_aead_ciphertext);
    sodium_memzero(acorn_key, sizeof(acorn_key));
    sodium_memzero(acorn_state, sizeof(acorn_state));

    // Final Cleanup
    free(c_data); free(pks_bytes); free(pkr_bytes); free(ikm);
    sodium_memzero(sks_x25519, sizeof(sks_x25519));
    sodium_memzero(sks_ml_kem, sizeof(sks_ml_kem));
    sodium_memzero(sks_rac, sizeof(sks_rac));

    printf("\nHybrid protocol sender operations and benchmarking complete.\n");
    return 0;
}
