#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h> // For uint8_t

#include <sodium.h>       // For X25519, HKDF, and other utilities
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

// Helper function to read binary data from file
int read_binary_data_from_file(const char* filename, unsigned char* buffer, size_t buffer_len, size_t* bytes_read_actual) {
    FILE *fp = fopen(filename, "rb"); // "rb" for read binary
    if (!fp) {
        perror("Error opening file for reading");
        fprintf(stderr, "Filename: %s\n", filename);
        return -1;
    }
    *bytes_read_actual = fread(buffer, 1, buffer_len, fp);
    if (*bytes_read_actual == 0 && !feof(fp) && ferror(fp)) {
        fprintf(stderr, "Error reading from %s\n", filename);
        fclose(fp);
        return -1;
    }
    fclose(fp);
    printf("Successfully read %zu bytes from %s\n", *bytes_read_actual, filename);
    // Optional: Check if *bytes_read_actual matches an expected length if known
    // if (*bytes_read_actual != expected_len) {
    //     fprintf(stderr, "Warning: Read %zu bytes from %s, expected %zu\n", *bytes_read_actual, filename, expected_len);
    // }
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
    printf("--- RECEIVER PROTOCOL OPERATIONS ---\n\n");

    // 1. Initialize Randomness & Libsodium
    unsigned char entropy_input[48];
    for (int i = 0; i < 48; i++) entropy_input[i] = (unsigned char)('R' + i); // Dummy entropy for Receiver
    nist_randombytes_init(entropy_input, (unsigned char *)"HybridProtoRecv", 256);
    printf("Raccoon's NIST DRBG initialized for Receiver.\n");

    if (sodium_init() < 0) {
        fprintf(stderr, "Libsodium couldn't be initialized!\n");
        return 1;
    }
    printf("Libsodium initialized for Receiver.\n\n");

    // --- Generate Receiver's Own Keys ---
    unsigned char skr_ml_kem[PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES];
    unsigned char pkr_ml_kem[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    unsigned char skr_x25519[crypto_kx_SECRETKEYBYTES];
    unsigned char pkr_x25519[crypto_kx_PUBLICKEYBYTES];
    unsigned char skr_rac[CRYPTO_SECRETKEYBYTES]; 
    unsigned char pkr_rac[CRYPTO_PUBLICKEYBYTES]; 

    printf("Generating Receiver's keys...\n");
    if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pkr_ml_kem, skr_ml_kem) != 0) { fprintf(stderr, "Receiver ML-KEM keygen failed.\n"); return 1; }
    if (crypto_kx_keypair(pkr_x25519, skr_x25519) != 0) { fprintf(stderr, "Receiver X25519 keygen failed.\n"); return 1; }
    if (crypto_sign_keypair(pkr_rac, skr_rac) != 0) { fprintf(stderr, "Receiver Raccoon keygen failed.\n"); return 1; }
    print_hex("Pkr_ml_kem (Receiver's own)", pkr_ml_kem, PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES);
    print_hex("Pkr_x25519 (Receiver's own)", pkr_x25519, crypto_kx_PUBLICKEYBYTES);
    print_hex("Pkr_rac (Receiver's own)", pkr_rac, CRYPTO_PUBLICKEYBYTES);
    printf("Receiver keys generated.\n\n");

    // --- Load Data from Sender (that hybrid.c would have saved) ---
    unsigned char c1_from_sender[PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    unsigned char pks_x25519_from_sender[crypto_kx_PUBLICKEYBYTES];
    unsigned char sig_from_sender[CRYPTO_BYTES]; // Raccoon's signature size
    unsigned char pks_ml_kem_from_sender[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    unsigned char pks_rac_from_sender[CRYPTO_PUBLICKEYBYTES]; // Raccoon's public key size
    size_t bytes_read;

    printf("Loading data from sender's files...\n");
    if (read_binary_data_from_file("kem_ciphertext_c1.dat", c1_from_sender, sizeof(c1_from_sender), &bytes_read) != 0 || bytes_read != sizeof(c1_from_sender)) {
        fprintf(stderr, "Failed to load or fully read kem_ciphertext_c1.dat\n"); return 1;
    }
    if (read_binary_data_from_file("sender_pks_x25519.key", pks_x25519_from_sender, sizeof(pks_x25519_from_sender), &bytes_read) != 0 || bytes_read != sizeof(pks_x25519_from_sender)) {
        fprintf(stderr, "Failed to load or fully read sender_pks_x25519.key\n"); return 1;
    }
    if (read_binary_data_from_file("signature_on_c.sig", sig_from_sender, sizeof(sig_from_sender), &bytes_read) != 0 || bytes_read != sizeof(sig_from_sender)) {
        fprintf(stderr, "Failed to load or fully read signature_on_c.sig\n"); return 1;
    }
    if (read_binary_data_from_file("sender_pks_mlkem.key", pks_ml_kem_from_sender, sizeof(pks_ml_kem_from_sender), &bytes_read) != 0 || bytes_read != sizeof(pks_ml_kem_from_sender)) {
        fprintf(stderr, "Failed to load or fully read sender_pks_mlkem.key\n"); return 1;
    }
    if (read_binary_data_from_file("sender_pks_rac.key", pks_rac_from_sender, sizeof(pks_rac_from_sender), &bytes_read) != 0 || bytes_read != sizeof(pks_rac_from_sender)) {
        fprintf(stderr, "Failed to load or fully read sender_pks_rac.key\n"); return 1;
    }
    printf("Sender's data loaded from files.\n\n");

    print_hex("c1_from_sender (loaded)", c1_from_sender, sizeof(c1_from_sender));
    print_hex("pks_x25519_from_sender (loaded)", pks_x25519_from_sender, sizeof(pks_x25519_from_sender));
    print_hex("sig_from_sender (loaded)", sig_from_sender, sizeof(sig_from_sender));
    print_hex("pks_ml_kem_from_sender (loaded)", pks_ml_kem_from_sender, sizeof(pks_ml_kem_from_sender));
    print_hex("pks_rac_from_sender (loaded)", pks_rac_from_sender, sizeof(pks_rac_from_sender));
    printf("\n");


    // --- Receiver's Operations ---
    printf("Performing Receiver's operations...\n");

    // 1. Reconstruct 'c' (c_received = c1_from_sender || pks_x25519_from_sender)
    size_t c_received_len = sizeof(c1_from_sender) + sizeof(pks_x25519_from_sender);
    unsigned char *c_received = (unsigned char *)malloc(c_received_len);
    if (!c_received) { fprintf(stderr, "Malloc failed for c_received.\n"); return 1; }
    memcpy(c_received, c1_from_sender, sizeof(c1_from_sender));
    memcpy(c_received + sizeof(c1_from_sender), pks_x25519_from_sender, sizeof(pks_x25519_from_sender));
    print_hex("c_received (reconstructed by receiver)", c_received, c_received_len);

    // 2. Verify Sender's Signature
    printf("Receiver verifying signature from sender...\n");
    unsigned long long sm_received_len = (unsigned long long)sizeof(sig_from_sender) + c_received_len; // crypto_sign_open expects smlen to be exact
    unsigned char *sm_received = (unsigned char *)malloc(sm_received_len);
    if (!sm_received) { fprintf(stderr, "Malloc failed for sm_received.\n"); free(c_received); return 1; }
    memcpy(sm_received, sig_from_sender, sizeof(sig_from_sender));
    memcpy(sm_received + sizeof(sig_from_sender), c_received, c_received_len);

    unsigned char *m_after_open = (unsigned char *)malloc(c_received_len + 1); // +1 for safety, though should match c_received_len
    if(!m_after_open) { fprintf(stderr, "Malloc failed for m_after_open.\n"); free(c_received); free(sm_received); return 1; }
    unsigned long long m_len_after_open;

    if (crypto_sign_open(m_after_open, &m_len_after_open, sm_received, sm_received_len, pks_rac_from_sender) != 0) {
        fprintf(stderr, "Signature verification failed!\n");
        free(c_received); free(sm_received); free(m_after_open);
        return 1;
    }
    if (m_len_after_open != c_received_len || memcmp(m_after_open, c_received, c_received_len) != 0) {
        fprintf(stderr, "Opened message does not match reconstructed c_data!\n");
        free(c_received); free(sm_received); free(m_after_open);
        return 1;
    }
    printf("Signature verified successfully.\n");
    free(sm_received);
    free(m_after_open);

    // 3. ML-KEM Decapsulation by Receiver
    unsigned char k1_prime[PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES];
    printf("Receiver decapsulating c1_from_sender with Skr_ml_kem...\n");
    if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(k1_prime, c1_from_sender, skr_ml_kem) != 0) {
        fprintf(stderr, "ML-KEM decapsulation failed.\n");
        free(c_received); return 1;
    }
    print_hex("k1' (ML-KEM Shared Secret - Receiver)", k1_prime, sizeof(k1_prime));

    // 4. X25519 Shared Secret by Receiver
    unsigned char k2_prime[crypto_scalarmult_BYTES];
    printf("Receiver computing X25519 shared secret k2'...\n");
    if (crypto_scalarmult(k2_prime, skr_x25519, pks_x25519_from_sender) != 0) {
        fprintf(stderr, "X25519 scalar multiplication failed for receiver.\n");
        free(c_received); return 1;
    }
    print_hex("k2' (X25519 Shared Secret - Receiver)", k2_prime, sizeof(k2_prime));

    // 5. Form Aggregated Public Keys (Pkr_bytes for receiver, Pks_bytes_from_sender for sender)
    size_t pkr_bytes_len = PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES + crypto_kx_PUBLICKEYBYTES + CRYPTO_PUBLICKEYBYTES;
    unsigned char *pkr_bytes = (unsigned char *)malloc(pkr_bytes_len);
    if (!pkr_bytes) { fprintf(stderr, "Malloc failed for pkr_bytes.\n"); free(c_received); return 1; }
    memcpy(pkr_bytes, pkr_ml_kem, PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES);
    memcpy(pkr_bytes + PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES, pkr_x25519, crypto_kx_PUBLICKEYBYTES);
    memcpy(pkr_bytes + PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES + crypto_kx_PUBLICKEYBYTES, pkr_rac, CRYPTO_PUBLICKEYBYTES);

    size_t pks_bytes_from_sender_len = PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES + crypto_kx_PUBLICKEYBYTES + CRYPTO_PUBLICKEYBYTES;
    unsigned char *pks_bytes_from_sender_data = (unsigned char *)malloc(pks_bytes_from_sender_len); // Renamed to avoid conflict with function parameter in some scopes
    if (!pks_bytes_from_sender_data) { fprintf(stderr, "Malloc failed for pks_bytes_from_sender_data.\n"); free(c_received); free(pkr_bytes); return 1; }
    memcpy(pks_bytes_from_sender_data, pks_ml_kem_from_sender, PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES);
    // Corrected the incomplete line from user's paste and ensuring correct variable names
    memcpy(pks_bytes_from_sender_data + PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES, 
           pks_x25519_from_sender, 
           crypto_kx_PUBLICKEYBYTES); 
    memcpy(pks_bytes_from_sender_data + PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES + crypto_kx_PUBLICKEYBYTES, 
           pks_rac_from_sender, 
           CRYPTO_PUBLICKEYBYTES);


    // 6. HKDF for Final Shared Secret
    // IKM_prime = k1_prime || k2_prime || c_received || sig_from_sender || Pkr_bytes || Pks_bytes_from_sender_data
    size_t ikm_prime_len = sizeof(k1_prime) + sizeof(k2_prime) + c_received_len + sizeof(sig_from_sender) + pkr_bytes_len + pks_bytes_from_sender_len;
    unsigned char *ikm_prime = (unsigned char *)malloc(ikm_prime_len);
    if (!ikm_prime) { fprintf(stderr, "Malloc failed for IKM_prime.\n"); free(c_received); free(pkr_bytes); free(pks_bytes_from_sender_data); return 1;}

    unsigned char *ptr = ikm_prime;
    memcpy(ptr, k1_prime, sizeof(k1_prime)); ptr += sizeof(k1_prime);
    memcpy(ptr, k2_prime, sizeof(k2_prime)); ptr += sizeof(k2_prime);
    memcpy(ptr, c_received, c_received_len); ptr += c_received_len;
    memcpy(ptr, sig_from_sender, sizeof(sig_from_sender)); ptr += sizeof(sig_from_sender);
    memcpy(ptr, pkr_bytes, pkr_bytes_len); ptr += pkr_bytes_len;
    memcpy(ptr, pks_bytes_from_sender_data, pks_bytes_from_sender_len);

    print_hex("IKM_prime for HKDF (Receiver)", ikm_prime, ikm_prime_len);

    unsigned char final_shared_secret_prime[32];
    unsigned char prk[crypto_auth_hmacsha256_BYTES];
    const unsigned char *hkdf_salt = NULL; 
    size_t hkdf_salt_len = 0;
    const unsigned char *hkdf_info = (const unsigned char *)"HybridProto SharedSecret"; // Must be same as sender
    size_t hkdf_info_len = strlen((const char*)hkdf_info);

    printf("Receiver deriving final shared secret using custom HKDF-SHA256...\n");
    if (hkdf_sha256_extract(prk, hkdf_salt, hkdf_salt_len, ikm_prime, ikm_prime_len) != 0) {
        fprintf(stderr, "HKDF Extract failed for Receiver.\n");
        free(c_received); free(pkr_bytes); free(pks_bytes_from_sender_data); free(ikm_prime); return 1;
    }
    print_hex("PRK from HKDF-Extract (Receiver)", prk, sizeof(prk));
    if (hkdf_sha256_expand(final_shared_secret_prime, sizeof(final_shared_secret_prime),
                           prk, sizeof(prk), hkdf_info, hkdf_info_len) != 0) {
        fprintf(stderr, "HKDF Expand failed for Receiver.\n");
        free(c_received); free(pkr_bytes); free(pks_bytes_from_sender_data); free(ikm_prime); return 1;
    }
    sodium_memzero(prk, sizeof(prk));
    print_hex("Final Shared Secret (Receiver)", final_shared_secret_prime, sizeof(final_shared_secret_prime));

    // Cleanup
    free(c_received);
    free(pkr_bytes);
    free(pks_bytes_from_sender_data);
    free(ikm_prime);
    sodium_memzero(skr_x25519, crypto_kx_SECRETKEYBYTES);
    sodium_memzero(skr_ml_kem, PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES);
    sodium_memzero(skr_rac, CRYPTO_SECRETKEYBYTES);

    printf("\nReceiver protocol operations demonstration complete.\n");
    return 0;
}
