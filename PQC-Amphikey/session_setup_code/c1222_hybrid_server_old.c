/**
 * c1222_hybrid_server.c
 *
 * This program merges the hybrid key-exchange and AEAD logic from hybrid_bench.c
 * with the C12.22 UDP server from main_server.c.
 *
 * 1. On startup, it performs a full hybrid key exchange using pre-generated keys
 * (ML-KEM, X25519, Raccoon) to derive a single shared secret via HKDF.
 * 2. It then starts a UDP server listening for C12.22 requests on port 1153.
 * 3. When a request is received, it generates the appropriate C12.22 response in plaintext.
 * 4. It then encrypts the EPSEM payload of that response using ACORN-128 AEAD
 * with the derived shared secret.
 * 5. Finally, it sends the encrypted payload back to the client.
 */

// Standard C/System Headers
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stddef.h>

// --- Cryptographic Library Headers ---
#include <sodium.h>
#include "api_mlkem.h"
#include "api_raccoon.h"
#include "constants.h" // ACORN
#include "cipher.h"    // ACORN

// --- C12.22 Project Headers ---
#include "ansi_c1222.h"
#include "ansi_c1218.h"

#define SERVER_PORT 1153
#define BUFFER_SIZE 2048

// --- HELPER FUNCTIONS ---

// Forward declarations for randombytes used by crypto libraries
extern void nist_randombytes_init(unsigned char *entropy_input, unsigned char *personalization_string, int security_strength);
extern void randombytes(unsigned char *x, unsigned long long xlen);

void PQCLEAN_randombytes(unsigned char *buf, size_t nbytes) {
    randombytes(buf, (unsigned long long)nbytes);
}

void print_hex(const char* label, const unsigned char* data, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int read_binary_data_from_file(const char* filename, unsigned char* buffer, size_t buffer_len, size_t* bytes_read_actual) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("Error opening file for reading");
        return -1;
    }
    *bytes_read_actual = fread(buffer, 1, buffer_len, fp);
    fclose(fp);
    if (*bytes_read_actual == 0 && !feof(fp) && ferror(fp)) return -1;
    return 0;
}

int read_hex_key_from_file(const char* filename, unsigned char* bin_buffer, size_t bin_buffer_len, size_t* actual_bin_len) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("Error opening hex key file for reading");
        return -1;
    }
    char* hex_string_buf = (char*)malloc(bin_buffer_len * 2 + 3);
    if (!hex_string_buf) {
        fclose(fp);
        return -1;
    }
    if (fgets(hex_string_buf, bin_buffer_len * 2 + 3, fp) == NULL) {
        fclose(fp); free(hex_string_buf); return -1;
    }
    fclose(fp);
    hex_string_buf[strcspn(hex_string_buf, "\r\n")] = 0;
    if (sodium_hex2bin(bin_buffer, bin_buffer_len, hex_string_buf, strlen(hex_string_buf), NULL, actual_bin_len, NULL) != 0) {
        free(hex_string_buf); return -1;
    }
    if (*actual_bin_len != bin_buffer_len) {
        free(hex_string_buf); return -1;
    }
    free(hex_string_buf);
    return 0;
}

int hkdf_sha256_extract(unsigned char *prk, const unsigned char *salt, size_t salt_len, const unsigned char *ikm, size_t ikm_len) {
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

int hkdf_sha256_expand(unsigned char *okm, size_t okm_len, const unsigned char *prk, size_t prk_len, const unsigned char *info, size_t info_len) {
    if (okm_len > 255 * crypto_hash_sha256_BYTES) return -1;
    unsigned char T_prev[crypto_hash_sha256_BYTES];
    size_t T_len = 0;
    size_t N = (okm_len + crypto_hash_sha256_BYTES - 1) / crypto_hash_sha256_BYTES;
    size_t generated_len = 0;
    crypto_auth_hmacsha256_state hmac_state;
    for (unsigned char i = 1; i <= N; i++) {
        crypto_auth_hmacsha256_init(&hmac_state, prk, prk_len);
        if (T_len > 0) crypto_auth_hmacsha256_update(&hmac_state, T_prev, T_len);
        if (info_len > 0 && info != NULL) crypto_auth_hmacsha256_update(&hmac_state, info, info_len);
        crypto_auth_hmacsha256_update(&hmac_state, &i, 1);
        unsigned char T_current[crypto_hash_sha256_BYTES];
        crypto_auth_hmacsha256_final(&hmac_state, T_current);
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


int main() {
    printf("--- C12.22 Hybrid Security Server ---\n\n");

    // =========================================================================
    // PART 1: HYBRID KEY ESTABLISHMENT
    // =========================================================================
    printf("## STEP 1: Performing Hybrid Key Establishment ##\n");

    unsigned char entropy_input[48];
    for (int i = 0; i < 48; i++) entropy_input[i] = (unsigned char)(i);
    nist_randombytes_init(entropy_input, (unsigned char *)"HybridServer", 256);
    if (sodium_init() < 0) {
        fprintf(stderr, "Libsodium couldn't be initialized!\n"); return 1;
    }

    unsigned char sks_ml_kem[PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES];
    unsigned char pks_ml_kem[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    unsigned char sks_x25519[crypto_kx_SECRETKEYBYTES];
    unsigned char pks_x25519[crypto_kx_PUBLICKEYBYTES];
    unsigned char sks_rac[CRYPTO_SECRETKEYBYTES];
    unsigned char pks_rac[CRYPTO_PUBLICKEYBYTES];
    unsigned char pkr_ml_kem[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    unsigned char pkr_x25519[crypto_kx_PUBLICKEYBYTES];
    unsigned char pkr_rac[CRYPTO_PUBLICKEYBYTES];
    size_t bytes_read_actual;

    printf("Loading server's secret keys and client's public keys...\n");
    if (read_binary_data_from_file("server_mlkem_sk.key", sks_ml_kem, sizeof(sks_ml_kem), &bytes_read_actual) != 0 ) return 1;
    if (read_hex_key_from_file("server_x25519_sk.hex", sks_x25519, sizeof(sks_x25519), &bytes_read_actual) != 0 ) return 1;
    if (read_binary_data_from_file("server_raccoon_sk.key", sks_rac, sizeof(sks_rac), &bytes_read_actual) != 0 ) return 1;
    if (read_binary_data_from_file("client_mlkem_pk.key", pkr_ml_kem, sizeof(pkr_ml_kem), &bytes_read_actual) != 0 ) return 1;
    if (read_hex_key_from_file("client_x25519_pk.hex", pkr_x25519, sizeof(pkr_x25519), &bytes_read_actual) != 0 ) return 1;
    if (read_binary_data_from_file("client_raccoon_pk.key", pkr_rac, sizeof(pkr_rac), &bytes_read_actual) != 0 ) return 1;
    if (read_binary_data_from_file("server_mlkem_pk.key", pks_ml_kem, sizeof(pks_ml_kem), &bytes_read_actual) != 0 ) return 1;
    if (read_hex_key_from_file("server_x25519_pk.hex", pks_x25519, sizeof(pks_x25519), &bytes_read_actual) != 0 ) return 1;
    if (read_binary_data_from_file("server_raccoon_pk.key", pks_rac, sizeof(pks_rac), &bytes_read_actual) != 0 ) return 1;
    printf("All keys loaded successfully.\n");

    unsigned char c1[PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    unsigned char k1[PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES];
    if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(c1, k1, pkr_ml_kem) != 0) {
        fprintf(stderr, "ML-KEM encapsulation failed.\n"); return 1;
    }
    unsigned char k2[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(k2, sks_x25519, pkr_x25519) != 0) {
        fprintf(stderr, "X25519 scalar multiplication failed.\n"); return 1;
    }

    size_t c_len = sizeof(c1) + sizeof(pks_x25519);
    unsigned char *c_data = (unsigned char *)malloc(c_len);
    memcpy(c_data, c1, sizeof(c1));
    memcpy(c_data + sizeof(c1), pks_x25519, sizeof(pks_x25519));

    unsigned char sig[CRYPTO_BYTES];
    unsigned long long smlen;
    unsigned char *sm_buf = (unsigned char *)malloc(CRYPTO_BYTES + c_len);
    crypto_sign(sm_buf, &smlen, c_data, c_len, sks_rac);
    memcpy(sig, sm_buf, CRYPTO_BYTES);
    free(sm_buf);

    size_t pks_bytes_len = sizeof(pks_ml_kem) + sizeof(pks_x25519) + sizeof(pks_rac);
    unsigned char *pks_bytes = (unsigned char *)malloc(pks_bytes_len);
    memcpy(pks_bytes, pks_ml_kem, sizeof(pks_ml_kem));
    memcpy(pks_bytes + sizeof(pks_ml_kem), pks_x25519, sizeof(pks_x25519));
    memcpy(pks_bytes + sizeof(pks_ml_kem) + sizeof(pks_x25519), pks_rac, sizeof(pks_rac));

    size_t pkr_bytes_len = sizeof(pkr_ml_kem) + sizeof(pkr_x25519) + sizeof(pkr_rac);
    unsigned char *pkr_bytes = (unsigned char *)malloc(pkr_bytes_len);
    memcpy(pkr_bytes, pkr_ml_kem, sizeof(pkr_ml_kem));
    memcpy(pkr_bytes + sizeof(pkr_ml_kem), pkr_x25519, sizeof(pkr_x25519));
    memcpy(pkr_bytes + sizeof(pkr_ml_kem) + sizeof(pkr_x25519), pkr_rac, sizeof(pkr_rac));

    size_t ikm_len = sizeof(k1) + sizeof(k2) + c_len + sizeof(sig) + pkr_bytes_len + pks_bytes_len;
    unsigned char *ikm = (unsigned char *)malloc(ikm_len);
    unsigned char *ptr_ikm = ikm;
    memcpy(ptr_ikm, k1, sizeof(k1)); ptr_ikm += sizeof(k1);
    memcpy(ptr_ikm, k2, sizeof(k2)); ptr_ikm += sizeof(k2);
    memcpy(ptr_ikm, c_data, c_len); ptr_ikm += c_len;
    memcpy(ptr_ikm, sig, sizeof(sig)); ptr_ikm += sizeof(sig);
    memcpy(ptr_ikm, pkr_bytes, pkr_bytes_len); ptr_ikm += pkr_bytes_len;
    memcpy(ptr_ikm, pks_bytes, pks_bytes_len);

    unsigned char final_shared_secret[32];
    unsigned char prk_buf[crypto_auth_hmacsha256_BYTES];
    const unsigned char *hkdf_info = (const unsigned char *)"HybridProto SharedSecret";

    hkdf_sha256_extract(prk_buf, NULL, 0, ikm, ikm_len);
    hkdf_sha256_expand(final_shared_secret, sizeof(final_shared_secret), prk_buf, sizeof(prk_buf), hkdf_info, strlen((char*)hkdf_info));

    print_hex("Derived Final Shared Secret", final_shared_secret, sizeof(final_shared_secret));
    printf("Key Establishment Complete.\n\n");

    free(c_data); free(pks_bytes); free(pkr_bytes); free(ikm);
    sodium_memzero(prk_buf, sizeof(prk_buf));

    // =========================================================================
    // PART 2: C12.22 UDP SERVER
    // =========================================================================
    printf("## STEP 2: Starting C12.22 UDP Server ##\n");

    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;
    uint8_t received_data[BUFFER_SIZE];

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed"); exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    memset(&client_addr, 0, sizeof(client_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(SERVER_PORT);

    if (bind(sockfd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed"); close(sockfd); exit(EXIT_FAILURE);
    }

    printf("Server listening on UDP port %d...\n", SERVER_PORT);

    while (1) {
        client_len = sizeof(client_addr);
        printf("\nWaiting for request...\n");

        int len = recvfrom(sockfd, received_data, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &client_len);

        if (len > 0) {
            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
            printf("Received %d bytes from client %s\n", len, client_ip);
            print_hex("Request Packet", received_data, len);

            // --- Generate Plaintext C12.22 Response ---
            stEpsemPayload plaintext_payload; // This struct now holds the data buffer directly.
            stEpsemFrame plaintext_epsem_frame;
            int plaintext_epsem_frame_len = 0;

            uint8_t *pUserPsemData = NULL;
            InitC1222AcseInfo();
            ParseC1222AcsePdu(received_data);

            if (g_user_info.nSize != 0) {
                pUserPsemData = ParseC1222EpsemFrame(g_user_info.pData);
                if (g_ansiC1222Status.ctrlByte.bits.RESPONSE_CONTROL == E_EPSEM_ALWAYS_RESP) {
                    memset(&plaintext_payload, 0, sizeof(plaintext_payload));
                    BuildC1222EpsemPayload(pUserPsemData, &plaintext_payload);

                    memset(&plaintext_epsem_frame, 0, sizeof(plaintext_epsem_frame));
                    plaintext_epsem_frame.pEpsemPayload = &plaintext_payload;
                    BuildC1222EpsemFrame(&plaintext_payload, &plaintext_epsem_frame);

                    plaintext_epsem_frame_len = plaintext_epsem_frame.nSize;
                }
            }

            if (plaintext_epsem_frame_len == 0) {
                printf("Could not generate a plaintext C12.22 response.\n");
                continue;
            }

            // Reconstruct the full EPSEM frame for encryption
            uint8_t full_plaintext_epsem_frame[BUFFER_SIZE];
            int header_len = plaintext_epsem_frame.nSize - plaintext_payload.nSize;
            memcpy(full_plaintext_epsem_frame, plaintext_epsem_frame.pHeader, header_len);
            memcpy(full_plaintext_epsem_frame + header_len, plaintext_payload.pData, plaintext_payload.nSize);

            print_hex("Plaintext EPSEM Frame to be Encrypted", full_plaintext_epsem_frame, plaintext_epsem_frame_len);

            // --- Encrypt the EPSEM Frame with ACORN ---
            unsigned char acorn_key[KEY_SIZE];
            memcpy(acorn_key, final_shared_secret, KEY_SIZE);
            unsigned char acorn_nonce[NONCE_SIZE];
            randombytes(acorn_nonce, sizeof(acorn_nonce));
            unsigned char acorn_tag[TAG_SIZE];
            uint8_t acorn_state[STATE_SIZE];

            // The full_plaintext_epsem_frame will be encrypted in-place
            Initialize(acorn_state, acorn_key, acorn_nonce);
            ProcessPlaintext(acorn_state, full_plaintext_epsem_frame, plaintext_epsem_frame_len);
            Finalize(acorn_state, acorn_key);
            TagGeneration(acorn_state, acorn_tag);

            // Final secure payload: [nonce || ciphertext || tag]
            size_t secure_payload_len = NONCE_SIZE + plaintext_epsem_frame_len + TAG_SIZE;
            unsigned char* secure_payload = (unsigned char*)malloc(secure_payload_len);
            memcpy(secure_payload, acorn_nonce, NONCE_SIZE);
            memcpy(secure_payload + NONCE_SIZE, full_plaintext_epsem_frame, plaintext_epsem_frame_len);
            memcpy(secure_payload + NONCE_SIZE + plaintext_epsem_frame_len, acorn_tag, TAG_SIZE);

            print_hex("Final Encrypted Payload (Nonce+Ciphertext+Tag)", secure_payload, secure_payload_len);

            // --- Send the secure payload back to the client ---
            sendto(sockfd, secure_payload, secure_payload_len, 0, (const struct sockaddr *)&client_addr, client_len);
            printf("Sent %zu byte encrypted response back to %s\n", secure_payload_len, client_ip);

            free(secure_payload);
            sodium_memzero(acorn_key, sizeof(acorn_key));
        }
    }

    close(sockfd);
    sodium_memzero(final_shared_secret, sizeof(final_shared_secret));
    return 0;
}

