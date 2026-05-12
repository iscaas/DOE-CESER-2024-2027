#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h> // For uint8_t
#include <time.h>   // Added for timing

#include <sodium.h>       // For X25519, HMAC-SHA256, randombytes_buf, sodium_memcmp
#include "api_mlkem.h"   // For ML-KEM
#include "api.h"
int crypto_aead_encrypt(unsigned char*,unsigned long long*,const unsigned char*,unsigned long long,const unsigned char*,unsigned long long,const unsigned char*,const unsigned char*,const unsigned char*);         // Ascon-128 NIST LWCA one-shot API
int crypto_aead_decrypt(unsigned char *m,  unsigned long long *mlen,
                        unsigned char *nsec,
                        const unsigned char *c,   unsigned long long clen,
                        const unsigned char *ad,  unsigned long long adlen,
                        const unsigned char *npub,
                        const unsigned char *k);

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

// --- ML-KEM API Defines and Helper Functions... ---
// [All helper functions and defines from your original file are included here]
void PQCLEAN_randombytes(unsigned char *outbuf, size_t outlen) { randombytes_buf(outbuf, outlen); }
void print_hex(const char* label, const unsigned char* data, size_t len) { printf("%s (%zu bytes): ", label, len); for (size_t i = 0; i < len; i++) { printf("%02x", data[i]); } printf("\n"); }
int read_binary_data_from_file(const char* filename, unsigned char* buffer, size_t buffer_len, size_t* bytes_read_actual) { FILE *fp = fopen(filename, "rb"); if (!fp) { perror("Error opening file"); fprintf(stderr, "Filename: %s\n", filename); return -1; } *bytes_read_actual = fread(buffer, 1, buffer_len, fp); fclose(fp); if (*bytes_read_actual == 0 && !feof(fp) && ferror(fp)) { fprintf(stderr, "Error reading from %s\n", filename); return -1; } printf("Successfully read %zu bytes from %s\n", *bytes_read_actual, filename); return 0; }
int read_hex_key_from_file(const char* filename, unsigned char* bin_buffer, size_t bin_buffer_len, size_t* actual_bin_len) { FILE *fp = fopen(filename, "r"); if (!fp) { perror("Error opening hex file"); fprintf(stderr, "Filename: %s\n", filename); return -1; } char* hex_string_buf = (char*)malloc(bin_buffer_len * 2 + 3); if (!hex_string_buf) { fprintf(stderr, "Malloc failed.\n"); fclose(fp); return -1; } if (fgets(hex_string_buf, bin_buffer_len * 2 + 3, fp) == NULL) { fprintf(stderr, "Failed to read hex key from %s\n", filename); fclose(fp); free(hex_string_buf); return -1; } fclose(fp); hex_string_buf[strcspn(hex_string_buf, "\r\n")] = 0; size_t hex_len = strlen(hex_string_buf); if (sodium_hex2bin(bin_buffer, bin_buffer_len, hex_string_buf, hex_len, NULL, actual_bin_len, NULL) != 0) { fprintf(stderr, "sodium_hex2bin failed for %s.\n", filename); free(hex_string_buf); return -1; } free(hex_string_buf); printf("Successfully read and converted hex key from %s\n", filename); return 0; }
int hkdf_sha256_extract(unsigned char *prk, const unsigned char *salt, size_t salt_len, const unsigned char *ikm, size_t ikm_len) { unsigned char z[32]; const unsigned char *s = salt; if(!s){s=z;sodium_memzero(z,32);} int r=crypto_auth_hmacsha256(prk,ikm,ikm_len,s); return r;}
int hkdf_sha256_expand(unsigned char *okm, size_t okm_len, const unsigned char *prk, size_t prk_len, const unsigned char *info, size_t info_len) { if (okm_len > 255 * 32) return -1; unsigned char T[32]=""; size_t Tl=0, p=0; crypto_auth_hmacsha256_state st; for(unsigned char i=0; p<okm_len; i++){ crypto_auth_hmacsha256_init(&st,prk,prk_len); if(Tl>0) crypto_auth_hmacsha256_update(&st,T,Tl); if(info_len>0&&info) crypto_auth_hmacsha256_update(&st,info,info_len); crypto_auth_hmacsha256_update(&st,&i,1); crypto_auth_hmacsha256_final(&st,T); Tl=32; size_t cl=p+32>okm_len?okm_len-p:32; memcpy(okm+p,T,cl); p+=cl; } return 0; }

// --- Main Program (Receiver Operations) ---
int main() {
    printf("--- Protocol Receiver Operations ---\n\n");

    if (sodium_init() < 0) { fprintf(stderr, "Libsodium couldn't be initialized!\n"); return 1; }
    printf("Libsodium initialized.\n\n");

    // --- Load Receiver's Own Keys (Skr, Pkr) ---
    unsigned char skr1_x25519[crypto_scalarmult_BYTES];
    unsigned char pkr1_x25519_own[crypto_scalarmult_BYTES];
    unsigned char skr2_mlkem[PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES];
    unsigned char pkr2_mlkem_own[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    size_t actual_read;
    if (read_hex_key_from_file("client_x25519_sk.hex", skr1_x25519, sizeof(skr1_x25519), &actual_read) != 0) { return 1; }
    if (read_hex_key_from_file("client_x25519_pk.hex", pkr1_x25519_own, sizeof(pkr1_x25519_own), &actual_read) != 0) { return 1; }
    if (read_binary_data_from_file("client_mlkem_sk.key", skr2_mlkem, sizeof(skr2_mlkem), &actual_read) != 0) { return 1; }
    if (read_binary_data_from_file("client_mlkem_pk.key", pkr2_mlkem_own, sizeof(pkr2_mlkem_own), &actual_read) != 0) { return 1; }
    
    // --- Load Data from Sender ---
    unsigned char received_c_data[crypto_scalarmult_BYTES + PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    size_t received_c_data_len;
    unsigned char received_tag[crypto_auth_hmacsha256_BYTES];
    size_t received_tag_len;
    if (read_binary_data_from_file("c_data_to_receiver.bin", received_c_data, sizeof(received_c_data), &received_c_data_len) != 0) { return 1; }
    if (read_binary_data_from_file("tag_to_receiver.bin", received_tag, sizeof(received_tag), &received_tag_len) != 0) { return 1; }
    printf("All keys and received data loaded.\n\n");

    // --- Parse received_c_data ---
    if (received_c_data_len < crypto_scalarmult_BYTES) { fprintf(stderr, "Received c_data is too short.\n"); return 1; }
    unsigned char* pks1_x25519_sender_pk = received_c_data;
    size_t pks1_sender_len = crypto_scalarmult_BYTES;
    unsigned char* c2_mlkem_received_ct = received_c_data + pks1_sender_len;
    size_t c2_received_len = received_c_data_len - pks1_sender_len;
    if (c2_received_len != PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES) { fprintf(stderr, "Length of c2 is incorrect.\n"); return 1; }
    
    // Benchmark variables
    struct timespec start_time, end_time;
    unsigned long long start_cycles, end_cycles;
    long long total_ns;
    unsigned long long total_cycles;

    // --- BENCHMARK AKEM1 (X25519) Decapsulation ---
    printf("\n--- Benchmarking AKEM1 (X25519) Decapsulation ---\n");
    unsigned char k1_x25519_ss_receiver[crypto_scalarmult_BYTES];
    total_ns = 0; total_cycles = 0;
    for (int i = 0; i < BENCHMARK_ITERATIONS; ++i) {
        clock_gettime(CLOCK_MONOTONIC, &start_time); start_cycles = rdtsc();
        if (crypto_scalarmult(k1_x25519_ss_receiver, skr1_x25519, pks1_x25519_sender_pk) != 0) {
            fprintf(stderr, "X25519 scalar multiplication failed.\n"); return 1;
        }
        end_cycles = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &end_time);
        total_ns += (end_time.tv_sec - start_time.tv_sec) * 1000000000LL + (end_time.tv_nsec - start_time.tv_nsec);
        if (end_cycles > start_cycles) total_cycles += (end_cycles - start_cycles);
    }
    printf("Average Time:   %lld ns\n", total_ns / BENCHMARK_ITERATIONS);
    printf("Average Cycles: %llu\n", total_cycles / BENCHMARK_ITERATIONS);
    print_hex("DEBUG Receiver K1", k1_x25519_ss_receiver, sizeof(k1_x25519_ss_receiver)); // <-- DEBUG
    printf("------------------------------------\n");

    // --- BENCHMARK AKEM2 (ML-KEM) Decapsulation ---
    printf("\n--- Benchmarking AKEM2 (ML-KEM) Decapsulation ---\n");
    unsigned char k2_mlkem_ss_receiver[PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES];
    total_ns = 0; total_cycles = 0;
    for (int i = 0; i < BENCHMARK_ITERATIONS; ++i) {
        clock_gettime(CLOCK_MONOTONIC, &start_time); start_cycles = rdtsc();
        if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(k2_mlkem_ss_receiver, c2_mlkem_received_ct, skr2_mlkem) != 0) {
            fprintf(stderr, "ML-KEM decapsulation failed.\n"); return 1;
        }
        end_cycles = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &end_time);
        total_ns += (end_time.tv_sec - start_time.tv_sec) * 1000000000LL + (end_time.tv_nsec - start_time.tv_nsec);
        if (end_cycles > start_cycles) total_cycles += (end_cycles - start_cycles);
    }
    printf("Average Time:   %lld ns\n", total_ns / BENCHMARK_ITERATIONS);
    printf("Average Cycles: %llu\n", total_cycles / BENCHMARK_ITERATIONS);
    print_hex("DEBUG Receiver K2", k2_mlkem_ss_receiver, sizeof(k2_mlkem_ss_receiver)); // <-- DEBUG
    printf("------------------------------------\n");
    
    // --- BENCHMARK Nonce (n_receiver) Derivation (HKDF) ---
    printf("\n--- Benchmarking Nonce (n_receiver) Derivation (HKDF) ---\n");
    unsigned char n_nonce_receiver[16];
    size_t ikm_for_n_len_rec = sizeof(k1_x25519_ss_receiver) + sizeof(k2_mlkem_ss_receiver);
    unsigned char *ikm_for_n_rec = (unsigned char *)malloc(ikm_for_n_len_rec);
    memcpy(ikm_for_n_rec, k1_x25519_ss_receiver, sizeof(k1_x25519_ss_receiver));
    memcpy(ikm_for_n_rec + sizeof(k1_x25519_ss_receiver), k2_mlkem_ss_receiver, sizeof(k2_mlkem_ss_receiver));
    total_ns = 0; total_cycles = 0;
    for (int i = 0; i < BENCHMARK_ITERATIONS; ++i) {
        unsigned char prk_for_n_rec[crypto_auth_hmacsha256_BYTES];
        clock_gettime(CLOCK_MONOTONIC, &start_time); start_cycles = rdtsc();
        hkdf_sha256_extract(prk_for_n_rec, NULL, 0, ikm_for_n_rec, ikm_for_n_len_rec);
        hkdf_sha256_expand(n_nonce_receiver, sizeof(n_nonce_receiver), prk_for_n_rec, sizeof(prk_for_n_rec), NULL, 0);
        end_cycles = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &end_time);
        total_ns += (end_time.tv_sec - start_time.tv_sec) * 1000000000LL + (end_time.tv_nsec - start_time.tv_nsec);
        if (end_cycles > start_cycles) total_cycles += (end_cycles - start_cycles);
    }
    free(ikm_for_n_rec);
    printf("Average Time:   %lld ns\n", total_ns / BENCHMARK_ITERATIONS);
    printf("Average Cycles: %llu\n", total_cycles / BENCHMARK_ITERATIONS);
    print_hex("DEBUG Receiver n", n_nonce_receiver, sizeof(n_nonce_receiver)); // <-- DEBUG
    printf("------------------------------------\n");

    // --- BENCHMARK Auth Key (k_auth_receiver) Derivation (HKDF) ---
    printf("\n--- Benchmarking Auth Key (k_auth_receiver) Derivation (HKDF) ---\n");
    unsigned char k_auth_receiver[crypto_auth_hmacsha256_KEYBYTES];
    size_t ikm_for_kauth_len_rec = sizeof(k1_x25519_ss_receiver) + pks1_sender_len + sizeof(n_nonce_receiver);
    unsigned char *ikm_for_kauth_rec = (unsigned char *)malloc(ikm_for_kauth_len_rec);
    unsigned char *ptr_kauth_ikm_rec = ikm_for_kauth_rec;
    memcpy(ptr_kauth_ikm_rec, k1_x25519_ss_receiver, sizeof(k1_x25519_ss_receiver)); ptr_kauth_ikm_rec += sizeof(k1_x25519_ss_receiver);
    memcpy(ptr_kauth_ikm_rec, pks1_x25519_sender_pk, pks1_sender_len); ptr_kauth_ikm_rec += pks1_sender_len;
    memcpy(ptr_kauth_ikm_rec, n_nonce_receiver, sizeof(n_nonce_receiver));
    total_ns = 0; total_cycles = 0;
    for (int i = 0; i < BENCHMARK_ITERATIONS; ++i) {
        unsigned char prk_for_kauth_rec[crypto_auth_hmacsha256_BYTES];
        clock_gettime(CLOCK_MONOTONIC, &start_time); start_cycles = rdtsc();
        hkdf_sha256_extract(prk_for_kauth_rec, NULL, 0, ikm_for_kauth_rec, ikm_for_kauth_len_rec);
        hkdf_sha256_expand(k_auth_receiver, sizeof(k_auth_receiver), prk_for_kauth_rec, sizeof(prk_for_kauth_rec), NULL, 0);
        end_cycles = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &end_time);
        total_ns += (end_time.tv_sec - start_time.tv_sec) * 1000000000LL + (end_time.tv_nsec - start_time.tv_nsec);
        if (end_cycles > start_cycles) total_cycles += (end_cycles - start_cycles);
    }
    free(ikm_for_kauth_rec);
    printf("Average Time:   %lld ns\n", total_ns / BENCHMARK_ITERATIONS);
    printf("Average Cycles: %llu\n", total_cycles / BENCHMARK_ITERATIONS);
    print_hex("DEBUG Receiver k_auth", k_auth_receiver, sizeof(k_auth_receiver)); // <-- DEBUG
    printf("------------------------------------\n");

    // --- BENCHMARK Tag Verification (HMAC) ---
    printf("\n--- Benchmarking Tag Verification (HMAC-SHA256) ---\n");
    unsigned char computed_tag[crypto_auth_hmacsha256_BYTES];
    total_ns = 0; total_cycles = 0;
    for (int i = 0; i < BENCHMARK_ITERATIONS; ++i) {
        clock_gettime(CLOCK_MONOTONIC, &start_time); start_cycles = rdtsc();
        crypto_auth_hmacsha256(computed_tag, received_c_data, received_c_data_len, k_auth_receiver);
        end_cycles = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &end_time);
        total_ns += (end_time.tv_sec - start_time.tv_sec) * 1000000000LL + (end_time.tv_nsec - start_time.tv_nsec);
        if (end_cycles > start_cycles) total_cycles += (end_cycles - start_cycles);
    }
    if (sodium_memcmp(computed_tag, received_tag, sizeof(received_tag)) != 0) {
        fprintf(stderr, "PROTOCOL ABORT: TAG MISMATCH!\n"); return 1;
    }
    printf("Average Time:   %lld ns\n", total_ns / BENCHMARK_ITERATIONS);
    printf("Average Cycles: %llu\n", total_cycles / BENCHMARK_ITERATIONS);
    printf("TAG VERIFIED SUCCESSFULLY!\n");
    printf("------------------------------------\n");

    // --- BENCHMARK ksh Derivation (HKDF) ---
    printf("\n--- Benchmarking ksh Derivation (HKDF-SHA256) ---\n");
    unsigned char ksh[32];
    total_ns = 0; total_cycles = 0;
    for (int i = 0; i < BENCHMARK_ITERATIONS; ++i) {
        unsigned char prk[crypto_auth_hmacsha256_BYTES];
        unsigned char zero[crypto_auth_hmacsha256_KEYBYTES];
        memset(zero, 0, sizeof(zero));
        clock_gettime(CLOCK_MONOTONIC, &start_time); start_cycles = rdtsc();
        crypto_auth_hmacsha256(prk, k_auth_receiver, sizeof(k_auth_receiver), zero);
        unsigned char T[32]; unsigned char ctr = 1;
        crypto_auth_hmacsha256_state st;
        crypto_auth_hmacsha256_init(&st, prk, sizeof(prk));
        crypto_auth_hmacsha256_update(&st, (const unsigned char*)"ksh", 3);
        crypto_auth_hmacsha256_update(&st, &ctr, 1);
        crypto_auth_hmacsha256_final(&st, T);
        memcpy(ksh, T, 32);
        end_cycles = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &end_time);
        total_ns += (end_time.tv_sec - start_time.tv_sec) * 1000000000LL +
                    (end_time.tv_nsec - start_time.tv_nsec);
        if (end_cycles > start_cycles) total_cycles += (end_cycles - start_cycles);
    }
    printf("Average Time:   %lld ns\n", total_ns / BENCHMARK_ITERATIONS);
    printf("Average Cycles: %llu\n",    total_cycles / BENCHMARK_ITERATIONS);
    printf("------------------------------------\n");

    // --- BENCHMARK Ascon-128 AEAD Decrypt ---
    printf("\n--- Benchmarking Ascon-128 AEAD Decrypt ---\n");
    const char *meter = "0.18,0.18,0,0.18,0,0,0,0,131.8,0,0,0.4,0,0,54,0,0,54,54,C0.99,0,0,90,15 Minutes,0.18,0,0,6,0,0,6,60.03,Forward,Forward,Forward";
    size_t meter_len = strlen(meter);
    unsigned char ascon_key[16], ascon_nonce[16];
    memcpy(ascon_key, ksh, 16);
    randombytes_buf(ascon_nonce, 16);
    unsigned char *ct_ascon = malloc(meter_len + 16);
    unsigned long long ct_len_enc = 0;
    crypto_aead_encrypt(ct_ascon, &ct_len_enc,
                        (const unsigned char*)meter, meter_len,
                        NULL, 0, NULL, ascon_nonce, ascon_key);

    unsigned char *pt_ascon = malloc(meter_len + 1);
    unsigned long long pt_len_dec = 0;
    total_ns = 0; total_cycles = 0;
    for (int i = 0; i < BENCHMARK_ITERATIONS; ++i) {
        unsigned long long tmp = 0;
        clock_gettime(CLOCK_MONOTONIC, &start_time); start_cycles = rdtsc();
        crypto_aead_decrypt(pt_ascon, &tmp,
                            NULL,
                            ct_ascon, ct_len_enc,
                            NULL, 0, ascon_nonce, ascon_key);
        end_cycles = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &end_time);
        total_ns += (end_time.tv_sec - start_time.tv_sec) * 1000000000LL +
                    (end_time.tv_nsec - start_time.tv_nsec);
        if (end_cycles > start_cycles) total_cycles += (end_cycles - start_cycles);
        pt_len_dec = tmp;
    }
    pt_ascon[pt_len_dec] = '\0';
    printf("  Ciphertext+tag: %llu B  →  Plaintext: %llu B\n", ct_len_enc, pt_len_dec);
    printf("Average Time:   %lld ns\n", total_ns / BENCHMARK_ITERATIONS);
    printf("Average Cycles: %llu\n",    total_cycles / BENCHMARK_ITERATIONS);
    printf("------------------------------------\n");
    free(ct_ascon); free(pt_ascon);

    return 0;
}
