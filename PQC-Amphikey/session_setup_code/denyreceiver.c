#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h> // For uint8_t

#include <sodium.h>       // For X25519, HMAC-SHA256, randombytes_buf, sodium_memcmp
#include "api_mlkem.h"   // For ML-KEM (e.g., using PQCLEAN_MLKEM768_CLEAN_ prefix)
                         // Make sure this header file and the corresponding ML-KEM implementation
                         // are available and linked.

// --- ML-KEM API Defines (ensure these match your api_mlkem.h) ---
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

// int PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

// PQClean's randombytes wrapper (less critical for receiver's decapsulation, but good for consistency if ML-KEM lib expects it)
void PQCLEAN_randombytes(unsigned char *outbuf, size_t outlen) {
    randombytes_buf(outbuf, outlen);
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
    printf("Successfully read %zu bytes from %s\n", *bytes_read_actual, filename);
    return 0;
}

// Helper function to read a hex key from a file and convert to binary
int read_hex_key_from_file(const char* filename, unsigned char* bin_buffer, size_t bin_buffer_len, size_t* actual_bin_len) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("Error opening hex key file for reading");
        fprintf(stderr, "Filename: %s\n", filename);
        return -1;
    }
    char* hex_string_buf = (char*)malloc(bin_buffer_len * 2 + 3); // Max possible hex length + newline + null
    if (!hex_string_buf) {
        fprintf(stderr, "Failed to allocate memory for hex string buffer.\n");
        fclose(fp);
        return -1;
    }
    hex_string_buf[0] = '\0'; // Initialize for safe strlen if fgets reads nothing but EOF
    if (fgets(hex_string_buf, bin_buffer_len * 2 + 3, fp) == NULL) {
        if (feof(fp) && strlen(hex_string_buf) == 0) { // Check if truly empty or only EOF encountered
             fprintf(stderr, "Error: Hex key file %s is empty or could not be read.\n", filename);
        } else if (ferror(fp)) { // Check for read error
             fprintf(stderr, "Error reading hex string from %s\n", filename);
        } else { // fgets returned NULL but not EOF and no error, possibly empty or only newline
             fprintf(stderr, "Warning: fgets returned NULL for %s, file might be empty or contain only a newline.\n", filename);
        }
        fclose(fp);
        free(hex_string_buf);
        return -1;
    }
    fclose(fp);
    hex_string_buf[strcspn(hex_string_buf, "\r\n")] = 0; // Remove trailing newline
    size_t hex_len = strlen(hex_string_buf);
    if (hex_len == 0) {
        fprintf(stderr, "Error: Hex key file %s contains no actual hex data after removing newline.\n", filename);
        free(hex_string_buf);
        return -1;
    }
    if (sodium_hex2bin(bin_buffer, bin_buffer_len, hex_string_buf, hex_len, NULL, actual_bin_len, NULL) != 0) {
        fprintf(stderr, "sodium_hex2bin failed for %s. Hex: '%s' (len %zu), Buffer: %zu\n", filename, hex_string_buf, hex_len, bin_buffer_len);
        free(hex_string_buf);
        return -1;
    }
    // For X25519 keys, actual_bin_len should be crypto_scalarmult_BYTES
    if (*actual_bin_len != crypto_scalarmult_BYTES && bin_buffer_len == crypto_scalarmult_BYTES) {
        fprintf(stderr, "Error: Converted X25519 key from %s has length %zu, expected %d.\n", filename, *actual_bin_len, crypto_scalarmult_BYTES);
        free(hex_string_buf);
        return -1;
    }
    free(hex_string_buf);
    printf("Successfully read and converted hex key from %s (%zu hex chars -> %zu bin bytes)\n", filename, hex_len, *actual_bin_len);
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
    if (crypto_auth_hmacsha256(prk, ikm, ikm_len, hmac_key) != 0) {
        sodium_memzero(zero_key_salt, sizeof(zero_key_salt));
        return -1;
    }
    sodium_memzero(zero_key_salt, sizeof(zero_key_salt));
    return 0;
}

int hkdf_sha256_expand(unsigned char *okm, size_t okm_len,
                       const unsigned char *prk, size_t prk_len,
                       const unsigned char *info, size_t info_len) {
    if (okm_len == 0) return 0;
     if (prk_len < crypto_auth_hmacsha256_KEYBYTES) {
        fprintf(stderr, "PRK length is too short for HKDF-SHA256 expand.\n");
        return -1;
    }
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

// --- Main Program (Receiver Operations) ---
int main() {
    printf("--- Protocol Receiver Operations (Loading Pre-generated Keys) ---\n\n");

    // 1. Initialize Libsodium
    if (sodium_init() < 0) {
        fprintf(stderr, "Libsodium couldn't be initialized!\n");
        return 1;
    }
    printf("Libsodium initialized.\n\n");

    // --- 2. Load Receiver's Own Keys (Skr, Pkr) from client files ---
    // These files MUST exist and contain the receiver's actual keys.
    printf("Loading Receiver's own keys from client files...\n");
    unsigned char skr1_x25519[crypto_scalarmult_BYTES];
    unsigned char pkr1_x25519_own[crypto_scalarmult_BYTES]; // Receiver's own X25519 public key
    unsigned char skr2_mlkem[PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES];
    unsigned char pkr2_mlkem_own[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES]; // Receiver's own ML-KEM public key
    size_t actual_read;

    // REMOVED DUMMY KEY GENERATION BLOCK
    // The following files must exist:
    // client_x25519_sk.hex, client_x25519_pk.hex
    // client_mlkem_sk.key, client_mlkem_pk.key

    if (read_hex_key_from_file("client_x25519_sk.hex", skr1_x25519, sizeof(skr1_x25519), &actual_read) != 0) {
        fprintf(stderr, "Failed to load receiver's X25519 secret key (Skr1) from client_x25519_sk.hex.\n"); return 1;
    }
    if (read_hex_key_from_file("client_x25519_pk.hex", pkr1_x25519_own, sizeof(pkr1_x25519_own), &actual_read) != 0) {
        fprintf(stderr, "Failed to load receiver's X25519 public key (Pkr1_own) from client_x25519_pk.hex.\n"); return 1;
    }
    if (read_binary_data_from_file("client_mlkem_sk.key", skr2_mlkem, sizeof(skr2_mlkem), &actual_read) != 0 || actual_read != sizeof(skr2_mlkem)) {
        fprintf(stderr, "Failed to load receiver's ML-KEM secret key (Skr2) from client_mlkem_sk.key.\n"); return 1;
    }
    if (read_binary_data_from_file("client_mlkem_pk.key", pkr2_mlkem_own, sizeof(pkr2_mlkem_own), &actual_read) != 0 || actual_read != sizeof(pkr2_mlkem_own)) {
        fprintf(stderr, "Failed to load receiver's ML-KEM public key (Pkr2_own) from client_mlkem_pk.key.\n"); return 1;
    }
    print_hex("Skr1 (Receiver X25519 Secret - Loaded)", skr1_x25519, sizeof(skr1_x25519));
    print_hex("Pkr1_own (Receiver X25519 Public - Loaded)", pkr1_x25519_own, sizeof(pkr1_x25519_own));
    // print_hex("Skr2 (Receiver ML-KEM Secret - Loaded)", skr2_mlkem, sizeof(skr2_mlkem)); // Keep SK private
    print_hex("Pkr2_own (Receiver ML-KEM Public - Loaded)", pkr2_mlkem_own, sizeof(pkr2_mlkem_own));
    printf("Receiver's own keys loaded.\n\n");


    // --- 3. Load Data from Sender ---
    printf("Loading data from sender...\n");
    // Max possible size for c_data is Pks1_len + MLKEM_CT_len
    unsigned char received_c_data[crypto_scalarmult_BYTES + PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    size_t received_c_data_len;
    unsigned char received_tag[crypto_auth_hmacsha256_BYTES];
    size_t received_tag_len;
    unsigned char pks2_mlkem_sender_pk[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES]; // Sender's Pks2
    size_t pks2_sender_len;

    if (read_binary_data_from_file("c_data_to_receiver.bin", received_c_data, sizeof(received_c_data), &received_c_data_len) != 0) {
        fprintf(stderr, "Failed to load c_data from sender.\n"); return 1;
    }
    if (read_binary_data_from_file("tag_to_receiver.bin", received_tag, sizeof(received_tag), &received_tag_len) != 0 || received_tag_len != sizeof(received_tag)) {
        fprintf(stderr, "Failed to load tag from sender.\n"); return 1;
    }
    if (read_binary_data_from_file("sender_ephemeral_mlkem_pk.bin", pks2_mlkem_sender_pk, sizeof(pks2_mlkem_sender_pk), &pks2_sender_len) != 0 || pks2_sender_len != sizeof(pks2_mlkem_sender_pk)) {
        fprintf(stderr, "Failed to load sender's ML-KEM public key (Pks2).\n"); return 1;
    }
    print_hex("Received c_data", received_c_data, received_c_data_len);
    print_hex("Received tag", received_tag, received_tag_len);
    print_hex("Pks2 (Sender ML-KEM Public - Loaded)", pks2_mlkem_sender_pk, pks2_sender_len);
    printf("Data from sender loaded.\n\n");

    // --- 4. Parse received_c_data into Pks1 (c1) and c2_mlkem_received_ct ---
    printf("Parsing received c_data...\n");
    if (received_c_data_len < crypto_scalarmult_BYTES) {
        fprintf(stderr, "Received c_data is too short.\n"); return 1;
    }
    unsigned char* pks1_x25519_sender_pk = received_c_data; // This is c1
    size_t pks1_sender_len = crypto_scalarmult_BYTES;
    unsigned char* c2_mlkem_received_ct = received_c_data + pks1_sender_len;
    size_t c2_received_len = received_c_data_len - pks1_sender_len;

    if (c2_received_len != PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES) {
        fprintf(stderr, "Length of extracted ML-KEM ciphertext c2 is incorrect. Expected %d, got %zu\n",
                PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES, c2_received_len);
        return 1;
    }
    print_hex("Pks1 (Sender X25519 Public, c1 - Parsed)", pks1_x25519_sender_pk, pks1_sender_len);
    print_hex("c2 (ML-KEM Ciphertext - Parsed)", c2_mlkem_received_ct, c2_received_len);
    printf("Received c_data parsed.\n\n");

    // --- 5. AKEM1 Decapsulation (X25519) ---
    printf("Performing AKEM1 (X25519) decapsulation...\n");
    unsigned char k1_x25519_ss_receiver[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(k1_x25519_ss_receiver, skr1_x25519, pks1_x25519_sender_pk) != 0) {
        fprintf(stderr, "X25519 scalar multiplication (K1) failed. Sender's public key might be invalid.\n");
    }
    print_hex("K1 (Receiver X25519 Shared Secret)", k1_x25519_ss_receiver, sizeof(k1_x25519_ss_receiver));
    printf("AKEM1 decapsulation complete.\n\n");

    // --- 6. AKEM2 Decapsulation (ML-KEM) ---
    printf("Performing AKEM2 (ML-KEM) decapsulation...\n");
    unsigned char k2_mlkem_ss_receiver[PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES];
    if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(k2_mlkem_ss_receiver, c2_mlkem_received_ct, skr2_mlkem) != 0) {
        fprintf(stderr, "ML-KEM decapsulation (K2) failed. Ciphertext c2 might be invalid.\n");
        printf("PROTOCOL ABORT: ML-KEM decapsulation failed.\n");
        return 1; 
    }
    print_hex("K2 (Receiver ML-KEM Shared Secret)", k2_mlkem_ss_receiver, sizeof(k2_mlkem_ss_receiver));
    printf("AKEM2 decapsulation complete.\n\n");

    // --- 7. Derive nonce n_receiver = HKDF-SHA-256(K1||K2)[0:16] ---
    printf("Deriving nonce n_receiver...\n");
    size_t ikm_for_n_len_rec = sizeof(k1_x25519_ss_receiver) + sizeof(k2_mlkem_ss_receiver);
    unsigned char *ikm_for_n_rec = (unsigned char *)malloc(ikm_for_n_len_rec);
    if (!ikm_for_n_rec) { fprintf(stderr, "Malloc failed for IKM for n_receiver.\n"); return 1; }
    memcpy(ikm_for_n_rec, k1_x25519_ss_receiver, sizeof(k1_x25519_ss_receiver));
    memcpy(ikm_for_n_rec + sizeof(k1_x25519_ss_receiver), k2_mlkem_ss_receiver, sizeof(k2_mlkem_ss_receiver));

    unsigned char n_nonce_receiver[16];
    unsigned char prk_for_n_rec[crypto_auth_hmacsha256_BYTES];
    if (hkdf_sha256_extract(prk_for_n_rec, NULL, 0, ikm_for_n_rec, ikm_for_n_len_rec) != 0) {
        fprintf(stderr, "HKDF Extract for n_receiver failed.\n"); free(ikm_for_n_rec); return 1;
    }
    if (hkdf_sha256_expand(n_nonce_receiver, sizeof(n_nonce_receiver), prk_for_n_rec, sizeof(prk_for_n_rec), NULL, 0) != 0) {
        fprintf(stderr, "HKDF Expand for n_receiver failed.\n"); free(ikm_for_n_rec); return 1;
    }
    free(ikm_for_n_rec);
    sodium_memzero(prk_for_n_rec, sizeof(prk_for_n_rec));
    print_hex("n_receiver (nonce)", n_nonce_receiver, sizeof(n_nonce_receiver));
    printf("Nonce n_receiver derived.\n\n");

    // --- 8. Derive k_auth_receiver = HKDF(K1||c1||n_receiver) ---
    printf("Deriving k_auth_receiver...\n");
    size_t ikm_for_kauth_len_rec = sizeof(k1_x25519_ss_receiver) + pks1_sender_len + sizeof(n_nonce_receiver);
    unsigned char *ikm_for_kauth_rec = (unsigned char *)malloc(ikm_for_kauth_len_rec);
    if (!ikm_for_kauth_rec) { fprintf(stderr, "Malloc failed for IKM for k_auth_receiver.\n"); return 1; }
    unsigned char *ptr_kauth_ikm_rec = ikm_for_kauth_rec;
    memcpy(ptr_kauth_ikm_rec, k1_x25519_ss_receiver, sizeof(k1_x25519_ss_receiver)); ptr_kauth_ikm_rec += sizeof(k1_x25519_ss_receiver);
    memcpy(ptr_kauth_ikm_rec, pks1_x25519_sender_pk, pks1_sender_len); ptr_kauth_ikm_rec += pks1_sender_len;
    memcpy(ptr_kauth_ikm_rec, n_nonce_receiver, sizeof(n_nonce_receiver));

    unsigned char k_auth_receiver[crypto_auth_hmacsha256_KEYBYTES];
    unsigned char prk_for_kauth_rec[crypto_auth_hmacsha256_BYTES];
    if (hkdf_sha256_extract(prk_for_kauth_rec, NULL, 0, ikm_for_kauth_rec, ikm_for_kauth_len_rec) != 0) {
        fprintf(stderr, "HKDF Extract for k_auth_receiver failed.\n"); free(ikm_for_kauth_rec); return 1;
    }
    if (hkdf_sha256_expand(k_auth_receiver, sizeof(k_auth_receiver), prk_for_kauth_rec, sizeof(prk_for_kauth_rec), NULL, 0) != 0) {
        fprintf(stderr, "HKDF Expand for k_auth_receiver failed.\n"); free(ikm_for_kauth_rec); return 1;
    }
    free(ikm_for_kauth_rec);
    sodium_memzero(prk_for_kauth_rec, sizeof(prk_for_kauth_rec));
    print_hex("k_auth_receiver", k_auth_receiver, sizeof(k_auth_receiver));
    printf("k_auth_receiver derived.\n\n");

    // --- 9. Verify Tag ---
    printf("Verifying received tag...\n");
    unsigned char computed_tag[crypto_auth_hmacsha256_BYTES];
    if (crypto_auth_hmacsha256(computed_tag, received_c_data, received_c_data_len, k_auth_receiver) != 0) {
        fprintf(stderr, "HMAC-SHA256 computation for tag verification failed.\n");
        return 1;
    }
    print_hex("Computed tag by receiver", computed_tag, sizeof(computed_tag));
    print_hex("Received tag from sender", received_tag, received_tag_len);

    if (sodium_memcmp(computed_tag, received_tag, sizeof(received_tag)) != 0) {
        fprintf(stderr, "PROTOCOL ABORT: TAG MISMATCH! Authentication failed.\n");
        return 1;
    }
    printf("TAG VERIFIED SUCCESSFULLY!\n\n");

    // --- 10. Derive SSk_receiver = HKDF(K1||K2||c||n||Pkr_own) ---
    printf("Deriving SSk_receiver (final shared secret)...\n");
    size_t pkr_own_concat_len = sizeof(pkr1_x25519_own) + sizeof(pkr2_mlkem_own);
    unsigned char *pkr_own_concat = (unsigned char *)malloc(pkr_own_concat_len);
    if (!pkr_own_concat) { fprintf(stderr, "Malloc failed for Pkr_own_concat.\n"); return 1; }
    memcpy(pkr_own_concat, pkr1_x25519_own, sizeof(pkr1_x25519_own));
    memcpy(pkr_own_concat + sizeof(pkr1_x25519_own), pkr2_mlkem_own, sizeof(pkr2_mlkem_own));
    print_hex("Pkr_own (Receiver's Pkr1_own||Pkr2_own)", pkr_own_concat, pkr_own_concat_len);

    size_t ikm_for_ssk_len_rec = sizeof(k1_x25519_ss_receiver) + sizeof(k2_mlkem_ss_receiver) + received_c_data_len + sizeof(n_nonce_receiver) + pkr_own_concat_len;
    unsigned char *ikm_for_ssk_rec = (unsigned char *)malloc(ikm_for_ssk_len_rec);
    if (!ikm_for_ssk_rec) { fprintf(stderr, "Malloc failed for IKM for SSk_receiver.\n"); free(pkr_own_concat); return 1;}
    unsigned char *ptr_ssk_ikm_rec = ikm_for_ssk_rec;
    memcpy(ptr_ssk_ikm_rec, k1_x25519_ss_receiver, sizeof(k1_x25519_ss_receiver)); ptr_ssk_ikm_rec += sizeof(k1_x25519_ss_receiver);
    memcpy(ptr_ssk_ikm_rec, k2_mlkem_ss_receiver, sizeof(k2_mlkem_ss_receiver)); ptr_ssk_ikm_rec += sizeof(k2_mlkem_ss_receiver);
    memcpy(ptr_ssk_ikm_rec, received_c_data, received_c_data_len); ptr_ssk_ikm_rec += received_c_data_len;
    memcpy(ptr_ssk_ikm_rec, n_nonce_receiver, sizeof(n_nonce_receiver)); ptr_ssk_ikm_rec += sizeof(n_nonce_receiver);
    memcpy(ptr_ssk_ikm_rec, pkr_own_concat, pkr_own_concat_len);
    
    unsigned char ssk_receiver[32]; 
    unsigned char prk_for_ssk_rec[crypto_auth_hmacsha256_BYTES];
    const unsigned char ssk_info[] = "SESSION_SHARED_SECRET_KEY"; 
    if (hkdf_sha256_extract(prk_for_ssk_rec, NULL, 0, ikm_for_ssk_rec, ikm_for_ssk_len_rec) != 0) {
        fprintf(stderr, "HKDF Extract for SSk_receiver failed.\n"); free(pkr_own_concat); free(ikm_for_ssk_rec); return 1;
    }
    if (hkdf_sha256_expand(ssk_receiver, sizeof(ssk_receiver), prk_for_ssk_rec, sizeof(prk_for_ssk_rec), ssk_info, sizeof(ssk_info)-1) != 0) {
        fprintf(stderr, "HKDF Expand for SSk_receiver failed.\n"); free(pkr_own_concat); free(ikm_for_ssk_rec); return 1;
    }
    free(ikm_for_ssk_rec);
    free(pkr_own_concat);
    sodium_memzero(prk_for_ssk_rec, sizeof(prk_for_ssk_rec));
    print_hex("SSk_receiver (Final Shared Secret)", ssk_receiver, sizeof(ssk_receiver));
    printf("SSk_receiver derived.\n\n");

    printf("PROTOCOL SUCCESSFUL: Shared secret SSk established and tag verified.\n");

    // Cleanup
    sodium_memzero(skr1_x25519, sizeof(skr1_x25519));
    sodium_memzero(skr2_mlkem, sizeof(skr2_mlkem));
    sodium_memzero(k1_x25519_ss_receiver, sizeof(k1_x25519_ss_receiver));
    sodium_memzero(k2_mlkem_ss_receiver, sizeof(k2_mlkem_ss_receiver));
    sodium_memzero(k_auth_receiver, sizeof(k_auth_receiver));
    sodium_memzero(n_nonce_receiver, sizeof(n_nonce_receiver));
    sodium_memzero(ssk_receiver, sizeof(ssk_receiver));

    return 0;
}
