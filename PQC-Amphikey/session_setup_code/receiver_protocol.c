#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h> // For uint8_t

#include <sodium.h>       // For X25519, HKDF, AEAD, and other utilities
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
    printf("--- RECEIVER PROTOCOL OPERATIONS (Loading All Pre-generated Keys and Sender Data) ---\n\n");

    // 1. Initialize Randomness & Libsodium
    unsigned char entropy_input[48];
    for (int i = 0; i < 48; i++) entropy_input[i] = (unsigned char)('R' + i + 30); 
    nist_randombytes_init(entropy_input, (unsigned char *)"HybridReceiverOp", 256);
    printf("Raccoon's NIST DRBG initialized for Receiver.\n");

    if (sodium_init() < 0) { fprintf(stderr, "Libsodium couldn't be initialized!\n"); return 1; }
    printf("Libsodium initialized for Receiver.\n\n");

    // --- Declare buffers for Receiver's (Client's) own keys (to be loaded) ---
    unsigned char skr_ml_kem[PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES];
    unsigned char pkr_ml_kem[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    unsigned char skr_x25519[crypto_kx_SECRETKEYBYTES];
    unsigned char pkr_x25519[crypto_kx_PUBLICKEYBYTES]; // Will hold binary after loading from hex
    unsigned char skr_rac[CRYPTO_SECRETKEYBYTES]; 
    unsigned char pkr_rac[CRYPTO_PUBLICKEYBYTES]; 

    // --- Declare buffers for Sender's (Server's) public keys (to be loaded) ---
    unsigned char pks_ml_kem_from_sender[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    unsigned char pks_x25519_from_sender[crypto_kx_PUBLICKEYBYTES]; // This will be loaded from sender_pks_x25519_for_protocol.key
    unsigned char pks_rac_from_sender[CRYPTO_PUBLICKEYBYTES]; 

    // --- Declare buffers for data transmitted by Sender (to be loaded from hybrid.c output) ---
    unsigned char c1_from_sender[PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    unsigned char sig_from_sender[CRYPTO_BYTES]; 
    unsigned char acorn_nonce_loaded[NONCE_SIZE]; 
    unsigned char loaded_aead_ciphertext[2048]; 
    size_t aead_ct_len_loaded;
    size_t bytes_read_actual;

    // --- Load Receiver's (Client's) Own Keys ---
    printf("Loading Receiver's (Client's) own keys from files...\n");
    if (read_binary_data_from_file("client_mlkem_pk.key", pkr_ml_kem, sizeof(pkr_ml_kem), &bytes_read_actual) != 0 ) { return 1;}
    if (read_binary_data_from_file("client_mlkem_sk.key", skr_ml_kem, sizeof(skr_ml_kem), &bytes_read_actual) != 0 ) { return 1;}
    if (read_hex_key_from_file("client_x25519_pk.hex", pkr_x25519, sizeof(pkr_x25519), &bytes_read_actual) != 0 ) { return 1;}
    if (read_hex_key_from_file("client_x25519_sk.hex", skr_x25519, sizeof(skr_x25519), &bytes_read_actual) != 0 ) { return 1;}
    if (read_binary_data_from_file("client_raccoon_pk.key", pkr_rac, sizeof(pkr_rac), &bytes_read_actual) != 0 ) { return 1;}
    if (read_binary_data_from_file("client_raccoon_sk.key", skr_rac, sizeof(skr_rac), &bytes_read_actual) != 0 ) { return 1;}
    printf("Receiver's (Client's) own keys loaded.\n");
    print_hex("Pkr_ml_kem (Receiver's loaded PK)", pkr_ml_kem, sizeof(pkr_ml_kem));
    print_hex("Pkr_x25519 (Receiver's loaded PK, binary)", pkr_x25519, sizeof(pkr_x25519));
    print_hex("Pkr_rac (Receiver's loaded PK)", pkr_rac, sizeof(pkr_rac));
    printf("\n");

    // --- Load Sender's (Server's) Public Keys ---
    printf("Loading Sender's (Server's) public keys from files...\n");
    if (read_binary_data_from_file("server_mlkem_pk.key", pks_ml_kem_from_sender, sizeof(pks_ml_kem_from_sender), &bytes_read_actual) != 0 ) { return 1;}
    // pks_x25519_from_sender (the one used in c_data) is loaded with other transmitted data below.
    if (read_binary_data_from_file("server_raccoon_pk.key", pks_rac_from_sender, sizeof(pks_rac_from_sender), &bytes_read_actual) != 0 ) { return 1;}
    printf("Sender's (Server's) ML-KEM and Raccoon public keys loaded.\n\n");

    // --- Load Transmitted Data (c1, sender's X25519 PK for protocol, sig, acorn data) from Sender (hybrid.c output) ---
    printf("Loading transmitted data from hybrid.c output files...\n");
    if (read_binary_data_from_file("kem_ciphertext_c1.dat", c1_from_sender, sizeof(c1_from_sender), &bytes_read_actual) != 0 ) { return 1; }
    if (read_binary_data_from_file("sender_pks_x25519_for_protocol.key", pks_x25519_from_sender, sizeof(pks_x25519_from_sender), &bytes_read_actual) != 0 ) {
        fprintf(stderr, "Failed to load sender_pks_x25519_for_protocol.key\n"); return 1;
    }
    if (read_binary_data_from_file("signature_on_c.sig", sig_from_sender, sizeof(sig_from_sender), &bytes_read_actual) != 0 ) { return 1; }
    if (read_binary_data_from_file("acorn_nonce.dat", acorn_nonce_loaded, sizeof(acorn_nonce_loaded), &bytes_read_actual) != 0 ) { return 1; }
    
    FILE *ct_fp = fopen("acorn_aead_ciphertext.dat", "rb");
    if (!ct_fp) { perror("Error opening acorn_aead_ciphertext.dat"); /* Free allocated memory if any before returning */ return 1; }
    aead_ct_len_loaded = fread(loaded_aead_ciphertext, 1, sizeof(loaded_aead_ciphertext), ct_fp);
    if (ferror(ct_fp)) { fprintf(stderr, "Error reading acorn_aead_ciphertext.dat\n"); fclose(ct_fp); /* Free memory */ return 1; }
    fclose(ct_fp);
    if (aead_ct_len_loaded == 0 && !feof(ct_fp)) { fprintf(stderr, "No data read from acorn_aead_ciphertext.dat\n"); return 1;} // Should not happen if sender wrote data
    if (aead_ct_len_loaded < TAG_SIZE) { fprintf(stderr, "Loaded AEAD ciphertext is too short.\n"); return 1; }
    printf("Transmitted data (c1, sender's X25519 PK for protocol, sig, acorn_nonce, acorn_ciphertext) loaded.\n\n");

    print_hex("c1_from_sender (loaded)", c1_from_sender, sizeof(c1_from_sender));
    print_hex("pks_x25519_from_sender (loaded from sender_pks_x25519_for_protocol.key)", pks_x25519_from_sender, sizeof(pks_x25519_from_sender));
    print_hex("sig_from_sender (loaded)", sig_from_sender, sizeof(sig_from_sender));
    print_hex("acorn_nonce_loaded", acorn_nonce_loaded, sizeof(acorn_nonce_loaded));
    print_hex("loaded_aead_ciphertext", loaded_aead_ciphertext, aead_ct_len_loaded);
    printf("\n");

    // --- Receiver's Operations ---
    printf("Performing Receiver's operations...\n");

    // 1. Reconstruct 'c_received' = c1_from_sender || pks_x25519_from_sender
    size_t c_received_len = sizeof(c1_from_sender) + sizeof(pks_x25519_from_sender);
    unsigned char *c_received = (unsigned char *)malloc(c_received_len);
    if (!c_received) { fprintf(stderr, "Malloc failed for c_received.\n"); return 1; }
    memcpy(c_received, c1_from_sender, sizeof(c1_from_sender));
    memcpy(c_received + sizeof(c1_from_sender), pks_x25519_from_sender, sizeof(pks_x25519_from_sender));
    print_hex("c_received (reconstructed by receiver)", c_received, c_received_len);

    // 2. Verify Sender's Signature using loaded pks_rac_from_sender (from server_raccoon_pk.key)
    printf("Receiver verifying signature from sender...\n");
    unsigned long long sm_received_len = (unsigned long long)sizeof(sig_from_sender) + c_received_len;
    unsigned char *sm_received = (unsigned char *)malloc(sm_received_len);
    if (!sm_received) { fprintf(stderr, "Malloc failed for sm_received.\n"); free(c_received); return 1; }
    memcpy(sm_received, sig_from_sender, sizeof(sig_from_sender));
    memcpy(sm_received + sizeof(sig_from_sender), c_received, c_received_len);
    unsigned char *m_after_open = (unsigned char *)malloc(c_received_len + 1); 
    if(!m_after_open) { fprintf(stderr, "Malloc failed for m_after_open.\n"); free(c_received); free(sm_received); return 1; }
    unsigned long long m_len_after_open;
    if (crypto_sign_open(m_after_open, &m_len_after_open, sm_received, sm_received_len, pks_rac_from_sender) != 0) {
        fprintf(stderr, "Signature verification FAILED!\n");
        free(c_received); free(sm_received); free(m_after_open); return 1;
    }
    if (m_len_after_open != c_received_len || memcmp(m_after_open, c_received, c_received_len) != 0) {
        fprintf(stderr, "Opened message does not match reconstructed c_data!\n");
        free(c_received); free(sm_received); free(m_after_open); return 1;
    }
    printf("Signature verified successfully.\n");
    free(sm_received);
    free(m_after_open);

    // 3. ML-KEM Decapsulation by Receiver using loaded skr_ml_kem (from client_mlkem_sk.key)
    unsigned char k1_prime[PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES];
    printf("Receiver decapsulating c1_from_sender with loaded Skr_ml_kem...\n");
    if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(k1_prime, c1_from_sender, skr_ml_kem) != 0) {
        fprintf(stderr, "ML-KEM decapsulation failed.\n");
        free(c_received); return 1;
    }
    print_hex("k1' (ML-KEM Shared Secret - Receiver)", k1_prime, sizeof(k1_prime));

    // 4. X25519 Shared Secret by Receiver using loaded skr_x25519 (from client_x25519_sk.hex)
    // and loaded pks_x25519_from_sender (from sender_pks_x25519_for_protocol.key)
    unsigned char k2_prime[crypto_scalarmult_BYTES];
    printf("Receiver computing X25519 shared secret k2' with loaded Skr_x25519...\n");
    if (crypto_scalarmult(k2_prime, skr_x25519, pks_x25519_from_sender) != 0) {
        fprintf(stderr, "X25519 scalar multiplication failed for receiver.\n");
        free(c_received); return 1;
    }
    print_hex("k2' (X25519 Shared Secret - Receiver)", k2_prime, sizeof(k2_prime));

    // 5. Form Aggregated Public Keys for HKDF
    // Pkr_bytes uses receiver's (client's) loaded public keys
    size_t pkr_bytes_len = sizeof(pkr_ml_kem) + sizeof(pkr_x25519) + sizeof(pkr_rac);
    unsigned char *pkr_bytes = (unsigned char *)malloc(pkr_bytes_len);
    if (!pkr_bytes) { fprintf(stderr, "Malloc failed for pkr_bytes.\n"); free(c_received); return 1; }
    unsigned char *ptr_pkr = pkr_bytes;
    memcpy(ptr_pkr, pkr_ml_kem, sizeof(pkr_ml_kem)); ptr_pkr += sizeof(pkr_ml_kem);
    memcpy(ptr_pkr, pkr_x25519, sizeof(pkr_x25519)); ptr_pkr += sizeof(pkr_x25519);
    memcpy(ptr_pkr, pkr_rac, sizeof(pkr_rac));

    // Pks_bytes uses sender's (server's) loaded public keys
    size_t pks_bytes_len = sizeof(pks_ml_kem_from_sender) + sizeof(pks_x25519_from_sender) + sizeof(pks_rac_from_sender);
    unsigned char *pks_bytes = (unsigned char *)malloc(pks_bytes_len);
    if (!pks_bytes) { fprintf(stderr, "Malloc failed for pks_bytes.\n"); free(c_received); free(pkr_bytes); return 1; }
    unsigned char *ptr_pks = pks_bytes;
    memcpy(ptr_pks, pks_ml_kem_from_sender, sizeof(pks_ml_kem_from_sender)); ptr_pks += sizeof(pks_ml_kem_from_sender);
    memcpy(ptr_pks, pks_x25519_from_sender, sizeof(pks_x25519_from_sender)); ptr_pks += sizeof(pks_x25519_from_sender); 
    memcpy(ptr_pks, pks_rac_from_sender, sizeof(pks_rac_from_sender)); 

    // 6. HKDF for Final Shared Secret
    size_t ikm_prime_len = sizeof(k1_prime) + sizeof(k2_prime) + c_received_len + sizeof(sig_from_sender) + pkr_bytes_len + pks_bytes_len;
    unsigned char *ikm_prime = (unsigned char *)malloc(ikm_prime_len);
    if (!ikm_prime) { fprintf(stderr, "Malloc failed for IKM_prime.\n"); free(c_received); free(pkr_bytes); free(pks_bytes); return 1;}
    unsigned char *ptr_ikm = ikm_prime;
    memcpy(ptr_ikm, k1_prime, sizeof(k1_prime)); ptr_ikm += sizeof(k1_prime);
    memcpy(ptr_ikm, k2_prime, sizeof(k2_prime)); ptr_ikm += sizeof(k2_prime);
    memcpy(ptr_ikm, c_received, c_received_len); ptr_ikm += c_received_len;
    memcpy(ptr_ikm, sig_from_sender, sizeof(sig_from_sender)); ptr_ikm += sizeof(sig_from_sender);
    memcpy(ptr_ikm, pkr_bytes, pkr_bytes_len); ptr_ikm += pkr_bytes_len;
    memcpy(ptr_ikm, pks_bytes, pks_bytes_len);
    print_hex("IKM_prime for HKDF (Receiver)", ikm_prime, ikm_prime_len);

    unsigned char final_shared_secret_prime[32];
    unsigned char prk_buf[crypto_auth_hmacsha256_BYTES];
    const unsigned char *hkdf_salt = NULL; 
    size_t hkdf_salt_len = 0;
    const unsigned char *hkdf_info = (const unsigned char *)"HybridProto SharedSecret";
    size_t hkdf_info_len = strlen((const char*)hkdf_info);

    printf("Receiver deriving final shared secret using custom HKDF-SHA256...\n");
    if (hkdf_sha256_extract(prk_buf, hkdf_salt, hkdf_salt_len, ikm_prime, ikm_prime_len) != 0) {
        fprintf(stderr, "HKDF Extract failed for Receiver.\n");
        free(c_received); free(pkr_bytes); free(pks_bytes); free(ikm_prime); return 1;
    }
    print_hex("PRK from HKDF-Extract (Receiver)", prk_buf, sizeof(prk_buf));
    if (hkdf_sha256_expand(final_shared_secret_prime, sizeof(final_shared_secret_prime),
                           prk_buf, sizeof(prk_buf), hkdf_info, hkdf_info_len) != 0) {
        fprintf(stderr, "HKDF Expand failed for Receiver.\n");
        free(c_received); free(pkr_bytes); free(pks_bytes); free(ikm_prime); return 1;
    }
    sodium_memzero(prk_buf, sizeof(prk_buf));
    print_hex("Final Shared Secret (Receiver)", final_shared_secret_prime, sizeof(final_shared_secret_prime));

    // --- AEAD Decryption using ACORN ---
    printf("\n--- AEAD Decryption (ACORN-128 using derived shared secret) ---\n");
    unsigned char acorn_key_prime[KEY_SIZE]; 
    memcpy(acorn_key_prime, final_shared_secret_prime, KEY_SIZE);
    print_hex("ACORN Key (derived by Receiver)", acorn_key_prime, KEY_SIZE);
    print_hex("ACORN Nonce (loaded from file)", acorn_nonce_loaded, sizeof(acorn_nonce_loaded)); 
    print_hex("ACORN AEAD Ciphertext (loaded from file)", loaded_aead_ciphertext, aead_ct_len_loaded); 
    
    size_t encrypted_message_len = aead_ct_len_loaded - TAG_SIZE;
    unsigned char *encrypted_message_part = (unsigned char *)malloc(encrypted_message_len);
    if(!encrypted_message_part) { fprintf(stderr, "Malloc failed for encrypted_message_part\n"); /* free memory */ return 1; }
    unsigned char received_tag[TAG_SIZE];

    memcpy(encrypted_message_part, loaded_aead_ciphertext, encrypted_message_len);
    memcpy(received_tag, loaded_aead_ciphertext + encrypted_message_len, TAG_SIZE);

    unsigned char *decrypted_message = (unsigned char *)malloc(encrypted_message_len + 1); 
    if(!decrypted_message) { fprintf(stderr, "Malloc failed for decrypted_message\n"); free(encrypted_message_part); return 1; }
    memcpy(decrypted_message, encrypted_message_part, encrypted_message_len); // Copy to decrypt in-place

    uint8_t acorn_state_receiver[STATE_SIZE];
    const unsigned char *associated_data = NULL; 
    uint32_t associated_data_len = 0;

    printf("Decrypting with ACORN-128...\n");
    Initialize(acorn_state_receiver, acorn_key_prime, acorn_nonce_loaded);
    if (associated_data_len > 0) {
        ProcessAssociatedData(acorn_state_receiver, (uint8_t*)associated_data, associated_data_len);
    }
    // ProcessCiphertext decrypts the message in-place (in decrypted_message buffer)
    ProcessCiphertext(acorn_state_receiver, decrypted_message, encrypted_message_len); 
    Finalize(acorn_state_receiver, acorn_key_prime); 
    
    int tag_verification_result = TagVerification(acorn_state_receiver, received_tag);

    if (tag_verification_result == 0) {
        printf("ACORN AEAD Decryption SUCCESSFUL! Tag Verified.\n");
        decrypted_message[encrypted_message_len] = '\0'; 
        print_hex("Decrypted Plaintext", decrypted_message, encrypted_message_len);
        printf("Decrypted Message: %s\n", (char*)decrypted_message);
    } else {
        fprintf(stderr, "ACORN AEAD Decryption FAILED! Tag verification failed (result: %d).\n", tag_verification_result);
    }

    free(encrypted_message_part);
    free(decrypted_message);
    sodium_memzero(acorn_key_prime, sizeof(acorn_key_prime));
    sodium_memzero(acorn_state_receiver, sizeof(acorn_state_receiver));

    // Final Cleanup
    free(c_received);
    free(pkr_bytes);
    free(pks_bytes); 
    free(ikm_prime);
    sodium_memzero(skr_x25519, sizeof(skr_x25519));
    sodium_memzero(skr_ml_kem, sizeof(skr_ml_kem));
    sodium_memzero(skr_rac, sizeof(skr_rac));

    return 0;
}
