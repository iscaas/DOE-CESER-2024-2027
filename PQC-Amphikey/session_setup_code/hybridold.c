#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h> // For uint8_t

#include <sodium.h>       // For X25519, HMAC-SHA256, and other utilities
#include "api_mlkem.h"   // For ML-KEM (using PQCLEAN_MLKEM768_CLEAN_ prefix)
#include "api_raccoon.h" // For Raccoon (using generic CRYPTO_ prefix for Raccoon)

// Forward declaration for Raccoon's RNG init function
extern void nist_randombytes_init(unsigned char *entropy_input, unsigned char *personalization_string, int security_strength);
// Forward declaration for Raccoon's randombytes, used by the wrapper
extern void randombytes(unsigned char *x, unsigned long long xlen);

// Wrapper function for ML-KEM's randombytes
void PQCLEAN_randombytes(unsigned char *buf, size_t nbytes) {
    randombytes(buf, (unsigned long long)nbytes);
}

// Helper function to print bytes as hex
void print_hex(const char* label, const unsigned char* data, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Helper function to write binary data to file
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


// --- HKDF-SHA256 Implementation using Libsodium Primitives ---
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
    printf("--- Hybrid Protocol Key Material Generation and Sender Operations ---\n\n");

    // 1. Initialize Randomness & Libsodium
    unsigned char entropy_input[48];
    for (int i = 0; i < 48; i++) entropy_input[i] = (unsigned char)(i);
    nist_randombytes_init(entropy_input, (unsigned char *)"HybridProto", 256);
    printf("Raccoon's NIST DRBG initialized.\n");

    if (sodium_init() < 0) {
        fprintf(stderr, "Libsodium couldn't be initialized!\n");
        return 1;
    }
    printf("Libsodium initialized.\n\n");

    // Declare Key Buffers
    unsigned char sks_ml_kem[PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES];
    unsigned char pks_ml_kem[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    unsigned char sks_x25519[crypto_kx_SECRETKEYBYTES];
    unsigned char pks_x25519[crypto_kx_PUBLICKEYBYTES];
    unsigned char sks_rac[CRYPTO_SECRETKEYBYTES];
    unsigned char pks_rac[CRYPTO_PUBLICKEYBYTES];
    unsigned char skr_ml_kem[PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES];
    unsigned char pkr_ml_kem[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    unsigned char skr_x25519[crypto_kx_SECRETKEYBYTES];
    unsigned char pkr_x25519[crypto_kx_PUBLICKEYBYTES];
    unsigned char skr_rac[CRYPTO_SECRETKEYBYTES];
    unsigned char pkr_rac[CRYPTO_PUBLICKEYBYTES];

    printf("Generating Sender's keys...\n");
    if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pks_ml_kem, sks_ml_kem) != 0) { fprintf(stderr, "Sender ML-KEM keygen failed.\n"); return 1; }
    if (crypto_kx_keypair(pks_x25519, sks_x25519) != 0) { fprintf(stderr, "Sender X25519 keygen failed.\n"); return 1; }
    if (crypto_sign_keypair(pks_rac, sks_rac) != 0) { fprintf(stderr, "Sender Raccoon keygen failed.\n"); return 1; }
    print_hex("Pks_ml_kem", pks_ml_kem, PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES);
    print_hex("Pks_x25519", pks_x25519, crypto_kx_PUBLICKEYBYTES);
    print_hex("Pks_rac", pks_rac, CRYPTO_PUBLICKEYBYTES);
    // Save Sender's Public Keys
    write_binary_data_to_file("sender_pks_mlkem.key", pks_ml_kem, PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES);
    write_binary_data_to_file("sender_pks_x25519.key", pks_x25519, crypto_kx_PUBLICKEYBYTES); // Saving X25519 PK as binary too
    write_binary_data_to_file("sender_pks_rac.key", pks_rac, CRYPTO_PUBLICKEYBYTES);
    printf("Sender keys generated and public keys saved.\n\n");

    printf("Generating Receiver's keys...\n");
    if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pkr_ml_kem, skr_ml_kem) != 0) { fprintf(stderr, "Receiver ML-KEM keygen failed.\n"); return 1; }
    if (crypto_kx_keypair(pkr_x25519, skr_x25519) != 0) { fprintf(stderr, "Receiver X25519 keygen failed.\n"); return 1; }
    if (crypto_sign_keypair(pkr_rac, skr_rac) != 0) { fprintf(stderr, "Receiver Raccoon keygen failed.\n"); return 1; }
    print_hex("Pkr_ml_kem", pkr_ml_kem, PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES);
    print_hex("Pkr_x25519", pkr_x25519, crypto_kx_PUBLICKEYBYTES);
    print_hex("Pkr_rac", pkr_rac, CRYPTO_PUBLICKEYBYTES);
    // Save Receiver's Public Keys (optional, but good for consistency in this demo)
    write_binary_data_to_file("receiver_pkr_mlkem.key", pkr_ml_kem, PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES);
    write_binary_data_to_file("receiver_pkr_x25519.key", pkr_x25519, crypto_kx_PUBLICKEYBYTES);
    write_binary_data_to_file("receiver_pkr_rac.key", pkr_rac, CRYPTO_PUBLICKEYBYTES);
    printf("Receiver keys generated and public keys saved.\n\n");

    printf("Performing Sender's operations...\n");
    unsigned char c1[PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    unsigned char k1[PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES];
    if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(c1, k1, pkr_ml_kem) != 0) { fprintf(stderr, "ML-KEM encapsulation failed.\n"); return 1; }
    print_hex("c1 (ML-KEM Ciphertext)", c1, PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    write_binary_data_to_file("kem_ciphertext_c1.dat", c1, PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES); // Save c1

    unsigned char k2[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(k2, sks_x25519, pkr_x25519) != 0) { fprintf(stderr, "X25519 scalar multiplication failed.\n"); return 1; }
    print_hex("k2 (X25519 Shared Secret)", k2, crypto_scalarmult_BYTES);

    size_t c_len = PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES + crypto_kx_PUBLICKEYBYTES;
    unsigned char *c_data = (unsigned char *)malloc(c_len);
    if (!c_data) { fprintf(stderr, "Malloc failed for c_data.\n"); return 1; }
    memcpy(c_data, c1, PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    memcpy(c_data + PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES, pks_x25519, crypto_kx_PUBLICKEYBYTES);
    print_hex("c_data = c1 || Pks_x25519", c_data, c_len);
    write_binary_data_to_file("combined_c_for_signature.dat", c_data, c_len); // Save c_data

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
    print_hex("sig (Raccoon Signature on c - extracted)", sig, CRYPTO_BYTES);
    write_binary_data_to_file("signature_on_c.sig", sig, CRYPTO_BYTES); // Save sig

    // Construct Pks_bytes and Pkr_bytes for HKDF IKM
    size_t pks_bytes_len = PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES + crypto_kx_PUBLICKEYBYTES + CRYPTO_PUBLICKEYBYTES;
    unsigned char *pks_bytes = (unsigned char *)malloc(pks_bytes_len);
    if (!pks_bytes) { fprintf(stderr, "Malloc failed for pks_bytes.\n"); free(c_data); return 1; }
    memcpy(pks_bytes, pks_ml_kem, PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES);
    memcpy(pks_bytes + PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES, pks_x25519, crypto_kx_PUBLICKEYBYTES);
    memcpy(pks_bytes + PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES + crypto_kx_PUBLICKEYBYTES, pks_rac, CRYPTO_PUBLICKEYBYTES);

    size_t pkr_bytes_len = PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES + crypto_kx_PUBLICKEYBYTES + CRYPTO_PUBLICKEYBYTES;
    unsigned char *pkr_bytes = (unsigned char *)malloc(pkr_bytes_len);
    if (!pkr_bytes) { fprintf(stderr, "Malloc failed for pkr_bytes.\n"); free(c_data); free(pks_bytes); return 1; }
    memcpy(pkr_bytes, pkr_ml_kem, PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES);
    memcpy(pkr_bytes + PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES, pkr_x25519, crypto_kx_PUBLICKEYBYTES);
    memcpy(pkr_bytes + PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES + crypto_kx_PUBLICKEYBYTES, pkr_rac, CRYPTO_PUBLICKEYBYTES);

    size_t ikm_len = PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES + crypto_scalarmult_BYTES + c_len + CRYPTO_BYTES + pkr_bytes_len + pks_bytes_len;
    unsigned char *ikm = (unsigned char *)malloc(ikm_len);
    if (!ikm) { fprintf(stderr, "Malloc failed for IKM.\n"); free(c_data); free(pks_bytes); free(pkr_bytes); return 1;}
    unsigned char *ptr = ikm;
    memcpy(ptr, k1, PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES); ptr += PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES;
    memcpy(ptr, k2, crypto_scalarmult_BYTES); ptr += crypto_scalarmult_BYTES;
    memcpy(ptr, c_data, c_len); ptr += c_len;
    memcpy(ptr, sig, CRYPTO_BYTES); ptr += CRYPTO_BYTES; 
    memcpy(ptr, pkr_bytes, pkr_bytes_len); ptr += pkr_bytes_len;
    memcpy(ptr, pks_bytes, pks_bytes_len);
    print_hex("IKM for HKDF", ikm, ikm_len);

    unsigned char final_shared_secret[32]; 
    unsigned char prk[crypto_auth_hmacsha256_BYTES]; 
    const unsigned char *hkdf_salt = NULL; 
    size_t hkdf_salt_len = 0;
    const unsigned char *hkdf_info = (const unsigned char *)"HybridProto SharedSecret";
    size_t hkdf_info_len = strlen((const char*)hkdf_info);

    printf("Deriving final shared secret using custom HKDF-SHA256 (Extract then Expand)...\n");
    if (hkdf_sha256_extract(prk, hkdf_salt, hkdf_salt_len, ikm, ikm_len) != 0) {
        fprintf(stderr, "HKDF Extract failed.\n");
        free(c_data); free(pks_bytes); free(pkr_bytes); free(ikm); return 1;
    }
    print_hex("PRK from HKDF-Extract", prk, sizeof(prk));
    if (hkdf_sha256_expand(final_shared_secret, sizeof(final_shared_secret),
                           prk, sizeof(prk), hkdf_info, hkdf_info_len) != 0) {
        fprintf(stderr, "HKDF Expand failed.\n");
        free(c_data); free(pks_bytes); free(pkr_bytes); free(ikm); return 1;
    }
    sodium_memzero(prk, sizeof(prk)); 
    print_hex("Final Shared Secret", final_shared_secret, sizeof(final_shared_secret));

    // Cleanup
    free(c_data); free(pks_bytes); free(pkr_bytes); free(ikm);
    sodium_memzero(sks_x25519, crypto_kx_SECRETKEYBYTES); 
    sodium_memzero(skr_x25519, crypto_kx_SECRETKEYBYTES); // Receiver's SK also cleared as this is a demo
    sodium_memzero(sks_ml_kem, PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES);
    sodium_memzero(skr_ml_kem, PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES); // Receiver's SK
    sodium_memzero(sks_rac, CRYPTO_SECRETKEYBYTES);
    sodium_memzero(skr_rac, CRYPTO_SECRETKEYBYTES); // Receiver's SK

    printf("\nHybrid protocol demonstration complete.\n");
    return 0;
}
