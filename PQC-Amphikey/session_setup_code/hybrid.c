#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h> // For uint8_t

#include <sodium.h>       // For X25519, HMAC-SHA256, AEAD, and other utilities
#include "api_mlkem.h"   // For ML-KEM (using PQCLEAN_MLKEM768_CLEAN_ prefix)
#include "api_raccoon.h" // For Raccoon (using generic CRYPTO_ prefix for Raccoon)

// ACORN specific headers
#include "constants.h" // From ACORN_..._v02/source/
#include "cipher.h"    // From FELICS common/

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
    if (buffer_len > 0 && *bytes_read_actual != buffer_len && 
        (strcmp(filename, "acorn_aead_ciphertext.dat") != 0) ) {
        fprintf(stderr, "Error: Read %zu bytes from %s, but expected %zu bytes.\n", *bytes_read_actual, filename, buffer_len);
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
    unsigned char pks_x25519[crypto_kx_PUBLICKEYBYTES]; // This will hold the binary key after loading from hex
    unsigned char sks_rac[CRYPTO_SECRETKEYBYTES];
    unsigned char pks_rac[CRYPTO_PUBLICKEYBYTES];
    
    // Declare Key Buffers for Receiver's (Client's) Public Keys
    unsigned char pkr_ml_kem[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    unsigned char pkr_x25519[crypto_kx_PUBLICKEYBYTES]; // This will hold the binary key after loading from hex
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
    print_hex("Pks_ml_kem (loaded from server_mlkem_pk.key)", pks_ml_kem, sizeof(pks_ml_kem));
    print_hex("Pks_x25519 (loaded from server_x25519_pk.hex, now binary)", pks_x25519, sizeof(pks_x25519));
    print_hex("Pks_rac (loaded from server_raccoon_pk.key)", pks_rac, sizeof(pks_rac));
    // Save the binary pks_x25519 that will be part of c_data, for the receiver to load directly as binary
    if (write_binary_data_to_file("sender_pks_x25519_for_protocol.key", pks_x25519, sizeof(pks_x25519)) != 0) {
        fprintf(stderr, "Failed to save sender's binary X25519 PK for protocol use.\n"); return 1;
    }
    printf("\n");

    // --- Load Receiver's (Client's) Public Keys from Files ---
    printf("Loading Receiver's (Client's) public keys from files...\n");
    if (read_binary_data_from_file("client_mlkem_pk.key", pkr_ml_kem, sizeof(pkr_ml_kem), &bytes_read_actual) != 0 ) { fprintf(stderr, "Load client_mlkem_pk.key failed.\n"); return 1; }
    if (read_hex_key_from_file("client_x25519_pk.hex", pkr_x25519, sizeof(pkr_x25519), &bytes_read_actual) != 0 ) { fprintf(stderr, "Load client_x25519_pk.hex failed.\n"); return 1; }
    if (read_binary_data_from_file("client_raccoon_pk.key", pkr_rac, sizeof(pkr_rac), &bytes_read_actual) != 0 ) { fprintf(stderr, "Load client_raccoon_pk.key failed.\n"); return 1; }
    printf("Receiver's (Client's) public keys loaded successfully.\n");
    print_hex("Pkr_ml_kem (loaded from client_mlkem_pk.key)", pkr_ml_kem, sizeof(pkr_ml_kem));
    print_hex("Pkr_x25519 (loaded from client_x25519_pk.hex, now binary)", pkr_x25519, sizeof(pkr_x25519));
    print_hex("Pkr_rac (loaded from client_raccoon_pk.key)", pkr_rac, sizeof(pkr_rac));
    printf("\n");


    // --- Sender's Operations ---
    printf("Performing Sender's operations using loaded keys...\n");
    unsigned char c1[PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    unsigned char k1[PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES];
    if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(c1, k1, pkr_ml_kem) != 0) { fprintf(stderr, "ML-KEM encapsulation failed.\n"); return 1; }
    print_hex("c1 (ML-KEM Ciphertext)", c1, sizeof(c1));
    write_binary_data_to_file("kem_ciphertext_c1.dat", c1, sizeof(c1));

    unsigned char k2[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(k2, sks_x25519, pkr_x25519) != 0) { fprintf(stderr, "X25519 scalar multiplication failed.\n"); return 1; }
    print_hex("k2 (X25519 Shared Secret)", k2, sizeof(k2));

    // c_data = c1 || Pks_x25519 (using the loaded and binary pks_x25519)
    size_t c_len = sizeof(c1) + sizeof(pks_x25519); 
    unsigned char *c_data = (unsigned char *)malloc(c_len);
    if (!c_data) { fprintf(stderr, "Malloc failed for c_data.\n"); return 1; }
    memcpy(c_data, c1, sizeof(c1));
    memcpy(c_data + sizeof(c1), pks_x25519, sizeof(pks_x25519)); // pks_x25519 is already binary
    print_hex("c_data = c1 || Pks_x25519", c_data, c_len);
    // No need to save c_data directly, receiver reconstructs it.

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
    write_binary_data_to_file("signature_on_c.sig", sig, CRYPTO_BYTES);

    // Construct Pks_bytes (Sender's aggregated public keys) from loaded keys
    size_t pks_bytes_len = sizeof(pks_ml_kem) + sizeof(pks_x25519) + sizeof(pks_rac);
    unsigned char *pks_bytes = (unsigned char *)malloc(pks_bytes_len);
    if (!pks_bytes) { fprintf(stderr, "Malloc failed for pks_bytes.\n"); free(c_data); return 1; }
    unsigned char *ptr_pks = pks_bytes;
    memcpy(ptr_pks, pks_ml_kem, sizeof(pks_ml_kem)); ptr_pks += sizeof(pks_ml_kem);
    memcpy(ptr_pks, pks_x25519, sizeof(pks_x25519)); ptr_pks += sizeof(pks_x25519);
    memcpy(ptr_pks, pks_rac, sizeof(pks_rac));

    // Construct Pkr_bytes (Receiver's aggregated public keys) from loaded keys
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
    print_hex("IKM for HKDF (Sender)", ikm, ikm_len);

    unsigned char final_shared_secret[32]; 
    unsigned char prk_buf[crypto_auth_hmacsha256_BYTES]; 
    const unsigned char *hkdf_salt = NULL; 
    size_t hkdf_salt_len = 0;
    const unsigned char *hkdf_info = (const unsigned char *)"HybridProto SharedSecret";
    size_t hkdf_info_len = strlen((const char*)hkdf_info);

    printf("Sender deriving final shared secret using custom HKDF-SHA256...\n");
    if (hkdf_sha256_extract(prk_buf, hkdf_salt, hkdf_salt_len, ikm, ikm_len) != 0) {
        fprintf(stderr, "HKDF Extract failed.\n"); free(c_data); free(pks_bytes); free(pkr_bytes); free(ikm); return 1;
    }
    print_hex("PRK from HKDF-Extract (Sender)", prk_buf, sizeof(prk_buf));
    if (hkdf_sha256_expand(final_shared_secret, sizeof(final_shared_secret),
                           prk_buf, sizeof(prk_buf), hkdf_info, hkdf_info_len) != 0) {
        fprintf(stderr, "HKDF Expand failed.\n"); free(c_data); free(pks_bytes); free(pkr_bytes); free(ikm); return 1;
    }
    sodium_memzero(prk_buf, sizeof(prk_buf)); 
    print_hex("Final Shared Secret (Sender)", final_shared_secret, sizeof(final_shared_secret));

    // --- AEAD Encryption using ACORN ---
    printf("\n--- AEAD Encryption (ACORN-128 using derived shared secret) ---\n");
    unsigned char acorn_key[KEY_SIZE]; 
    memcpy(acorn_key, final_shared_secret, KEY_SIZE); 
    print_hex("ACORN Key (derived from Final Shared Secret)", acorn_key, KEY_SIZE);

    unsigned char acorn_nonce[NONCE_SIZE]; 
    randombytes(acorn_nonce, sizeof(acorn_nonce)); 
    print_hex("ACORN Nonce (IV)", acorn_nonce, sizeof(acorn_nonce));

    const char *plaintext_message = "This is a top secret message for the receiver!";
    size_t plaintext_len = strlen(plaintext_message);
    unsigned char *message_buffer = (unsigned char *)malloc(plaintext_len);
    if(!message_buffer) { fprintf(stderr, "Malloc failed for ACORN message_buffer.\n"); /* free other stuff */ return 1; }
    memcpy(message_buffer, plaintext_message, plaintext_len);
    
    unsigned char acorn_tag[TAG_SIZE]; 
    uint8_t acorn_state[STATE_SIZE];   

    const unsigned char *associated_data = NULL;
    uint32_t associated_data_len = 0;

    printf("Encrypting with ACORN-128...\n");
    print_hex("Plaintext for ACORN", message_buffer, plaintext_len);

    Initialize(acorn_state, acorn_key, acorn_nonce);
    if (associated_data_len > 0) {
        ProcessAssociatedData(acorn_state, (uint8_t*)associated_data, associated_data_len);
    }
    ProcessPlaintext(acorn_state, message_buffer, plaintext_len); 
    Finalize(acorn_state, acorn_key); 
    TagGeneration(acorn_state, acorn_tag);

    size_t acorn_aead_ciphertext_len = plaintext_len + TAG_SIZE;
    unsigned char *acorn_aead_ciphertext = (unsigned char *)malloc(acorn_aead_ciphertext_len);
    if (!acorn_aead_ciphertext) { fprintf(stderr, "Malloc failed for ACORN AEAD ciphertext.\n"); free(message_buffer); /* free other stuff */ return 1;}
    memcpy(acorn_aead_ciphertext, message_buffer, plaintext_len);
    memcpy(acorn_aead_ciphertext + plaintext_len, acorn_tag, TAG_SIZE);
    
    print_hex("ACORN AEAD Ciphertext (Encrypted Plaintext || Tag)", acorn_aead_ciphertext, acorn_aead_ciphertext_len);

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
    // Receiver's public keys were loaded, no secret parts in this program's memory for them.

    printf("\nHybrid protocol sender operations complete. Transmitted data saved.\n");
    return 0;
}
