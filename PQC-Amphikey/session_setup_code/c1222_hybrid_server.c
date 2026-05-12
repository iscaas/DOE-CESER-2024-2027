/**
 * c1222_hybrid_server_ascon_final.c
 * This server uses the NIST standard ASCON with all compilation errors fixed.
 */

/**
 * c1222_hybrid_server_ascon_final.c
 * This server uses the NIST standard ASCON with all compilation errors fixed.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stddef.h>
#include <time.h> 
#include <sodium.h>
#include <ctype.h> // For isprint()

// --- CORRECTED INCLUDES ---
// These headers provide the function declarations for all libraries.
#include "api_mlkem.h"
#include "api_raccoon.h"
#include "crypto_aead.h" // For ASCON functions
#include "ansi_c1222.h"
#include "ansi_c1218.h"



#define CLIENT_IP "10.150.132.12"
#define SERVER_PORT 1153
#define BUFFER_SIZE 20000
#define c2_CHUNK_SIZE 4000
#define SIG_CHUNK_SIZE 4000

#define MSG_TYPE_CLIENT_HELLO_PART1 0x01
#define MSG_TYPE_SERVER_HELLO 0x02
#define MSG_TYPE_SECURE_C1222_REQUEST 0x03
#define MSG_TYPE_SECURE_C1222_RESPONSE 0x04
#define MSG_TYPE_c2_CHUNK 0x15
#define MSG_TYPE_SIG_CHUNK 0x11
#define C1219_ACK 0x00

// Define the standard ASCON-128 constants
#define CRYPTO_KEYBYTES 16
#define CRYPTO_NPUBBYTES 16
#define CRYPTO_ABYTES 16

#define KEY_SIZE 16
#define NONCE_SIZE 16
#define TAG_SIZE 16
#define STATE_SIZE 40 // ASCON state is 320 bits = 40 bytes
#define CPU_FREQUENCY_GHZ 3.5
#define START_TIMER() clock_gettime(CLOCK_MONOTONIC, &start)
#define STOP_TIMER(label) do { \
    clock_gettime(CLOCK_MONOTONIC, &end); \
    double elapsed_ns = (end.tv_sec - start.tv_sec) * 1.0e9 + (end.tv_nsec - start.tv_nsec); \
    unsigned long long cycles = (unsigned long long)(elapsed_ns * CPU_FREQUENCY_GHZ); \
    printf("[BENCHMARK] %-35s: %.3f us | Approx. Cycles: %llu\n", label, elapsed_ns / 1000.0, cycles); \
} while (0)

// --- HELPER FUNCTIONS ---
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


// Simple implementation for a C12.18 Read command
int build_c1222_read_request(unsigned char* buffer, uint16_t table_id, uint32_t offset, uint16_t count) {
    buffer[0] = 0x30; // C12.18 Read command
    buffer[1] = 2 + 4 + 2; // Length of payload (Table ID + Offset + Count)

    buffer[2] = table_id & 0xFF;
    buffer[3] = (table_id >> 8) & 0xFF;

    buffer[4] = offset & 0xFF;
    buffer[5] = (offset >> 8) & 0xFF;
    buffer[6] = (offset >> 16) & 0xFF;
    buffer[7] = (offset >> 24) & 0xFF;

    buffer[8] = count & 0xFF;
    buffer[9] = (count >> 8) & 0xFF;

    return 10; // Total length of the command
}

// --- NEW FUNCTION: C12.18 Response Parser ---
void parse_and_print_c1218_response(const unsigned char* data, size_t len) {
    if (len < 3) {
        fprintf(stderr, "C12.18 Error: Response is too short to be valid (%zu bytes).\n", len);
        return;
    }

    uint8_t command = data[0];
    uint16_t data_len = data[1] | (data[2] << 8); // Length is 2 bytes in response
    uint8_t result_code = data[3];

    printf("\n--- Parsed C12.18 Response ---\n");
    printf("  Command Echo: 0x%02x\n", command);
    printf("  Data Length:  %u bytes\n", data_len);
    printf("  Result Code:  0x%02x ", result_code);

    switch (result_code) {
        case 0x00: printf("(OK - Success)\n"); break;
        case 0x01: printf("(ERR - Service Not Supported)\n"); break;
        case 0x02: printf("(ISC - Insufficient Security Clearance)\n"); break;
        case 0x03: printf("(ONP - Operation Not Possible)\n"); break;
        case 0x04: printf("(IAR - Inappropriate Action Requested)\n"); break;
        case 0x05: printf("(BSY - Device Busy)\n"); break;
        case 0x06: printf("(DNR - Data Not Ready)\n"); break;
        case 0x07: printf("(DLK - Data Locked)\n"); break;
        case 0x08: printf("(RNO - Renegotiate Request)\n"); break;
        case 0x09: printf("(ISSS - Invalid Service Sequence State)\n"); break;
        default:   printf("(Unknown Result Code)\n"); break;
    }

    if (result_code != 0x00) {
        printf("--- End of Response ---\n\n");
        return;
    }

    const unsigned char* table_data = data + 4;
    size_t table_data_len = len - 4;

    printf("\n  --- Table Data (Hex Dump) ---\n");
    for (size_t i = 0; i < table_data_len; i += 16) {
        printf("  %04zx: ", i); // Print offset
        // Print hex bytes
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < table_data_len) {
                printf("%02x ", table_data[i + j]);
            } else {
                printf("   "); // Pad for alignment
            }
        }
        printf(" |");
        // Print ASCII representation
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < table_data_len) {
                printf("%c", isprint(table_data[i + j]) ? table_data[i + j] : '.');
            }
        }
        printf("|\n");
    }
    printf("--- End of Response ---\n\n");
}


int main() {
    struct timespec start, end;
    printf("--- C12.22 Interactive Hybrid Security Server (Server-Initiated, Chunking Enabled) ---\n\n");

    // =========================================================================
    // PART 1: INITIALIZE CRYPTO AND GENERATE SERVER KEYS
    // =========================================================================
    unsigned char entropy_input[48];
    for (int i = 0; i < 48; i++) entropy_input[i] = (unsigned char)(i);
    nist_randombytes_init(entropy_input, (unsigned char *)"HybridServer", 256);
    if (sodium_init() < 0) {
        fprintf(stderr, "Libsodium couldn't be initialized!\n"); return 1;
    }

    // Generate server's ephemeral key pairs (kprs, kpubs)
    unsigned char sks_ml_kem[PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES];
    unsigned char pks_ml_kem[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    unsigned char sks_x25519[crypto_kx_SECRETKEYBYTES];
    unsigned char pks_x25519[crypto_kx_PUBLICKEYBYTES];
    unsigned char sks_rac[CRYPTO_SECRETKEYBYTES];
    unsigned char pks_rac[CRYPTO_PUBLICKEYBYTES];

    printf("Generating server's ephemeral keys...\n");
    START_TIMER();
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pks_ml_kem, sks_ml_kem);
    STOP_TIMER("ML-KEM Keypair Generation");
    
    START_TIMER();
    crypto_kx_keypair(pks_x25519, sks_x25519);
    STOP_TIMER("X25519 Keypair Generation");

    START_TIMER();
    crypto_sign_keypair(pks_rac, sks_rac);
    STOP_TIMER("Raccoon Signing Keypair Generation");
    printf("Server keys generated successfully.\n\n");
    printf("Server keys generated successfully.\n\n");

    // =========================================================================
    // PART 2: SETUP SOCKET AND SEND SERVER HELLO
    // =========================================================================
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;
    uint8_t buffer[BUFFER_SIZE];

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) { perror("Socket creation failed"); exit(EXIT_FAILURE); }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(SERVER_PORT);

    if (bind(sockfd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed"); close(sockfd); exit(EXIT_FAILURE);
    }
    printf("Server socket bound to port %d.\n", SERVER_PORT);

    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, CLIENT_IP, &client_addr.sin_addr);

    // Pack and send Server Hello
    unsigned char server_hello[BUFFER_SIZE];
    unsigned char *sp = server_hello;
    *sp++ = MSG_TYPE_SERVER_HELLO;
    memcpy(sp, pks_ml_kem, sizeof(pks_ml_kem)); sp += sizeof(pks_ml_kem);
    memcpy(sp, pks_x25519, sizeof(pks_x25519)); sp += sizeof(pks_x25519);
    memcpy(sp, pks_rac, sizeof(pks_rac));       sp += sizeof(pks_rac);
    int server_hello_len = sp - server_hello;

    sendto(sockfd, server_hello, server_hello_len, 0, (const struct sockaddr *)&client_addr, sizeof(client_addr));
    printf("Sent Server Hello to %s:%d\n", CLIENT_IP, SERVER_PORT);


    // =========================================================================
    // PART 3: RECEIVE CLIENT DATA AND PERFORM HANDSHAKE
    // =========================================================================
    int handshake_complete = 0;
    unsigned char final_shared_secret_prime[32]; 
    // **FIX:** Declare session_key here, outside the loop, so it's visible later.
    unsigned char session_key[CRYPTO_KEYBYTES];

    while (handshake_complete == 0) {
        client_len = sizeof(client_addr);

        // --- Stage 1: Receive Client Hello Part 1 (Keys and Ciphertexts) ---
        printf("\nWaiting for Client Hello Part 1...\n");
        int len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &client_len);

        if (len <= 0 || buffer[0] != MSG_TYPE_CLIENT_HELLO_PART1) {
            fprintf(stderr, "Did not receive a valid Client Hello Part 1. Retrying...\n");
            continue;
        }

        printf("Received Client Hello Part 1. Unpacking keys and ciphertexts...\n");
        unsigned char *p = buffer + 1;
        unsigned char pkr_ml_kem[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
        unsigned char pkr_x25519[crypto_kx_PUBLICKEYBYTES];
        unsigned char pkr_rac[CRYPTO_PUBLICKEYBYTES];
        unsigned char c1[crypto_kx_PUBLICKEYBYTES]; // This is the client's X25519 PK
        unsigned char c2[PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES]; // This is the ML-KEM ciphertext

        memcpy(pkr_ml_kem, p, sizeof(pkr_ml_kem)); p += sizeof(pkr_ml_kem);
        memcpy(pkr_x25519, p, sizeof(pkr_x25519)); p += sizeof(pkr_x25519);
        memcpy(pkr_rac, p, sizeof(pkr_rac));       p += sizeof(pkr_rac);
        memcpy(c1, p, sizeof(c1));                 p += sizeof(c1);
        print_hex("pkr_rac",pkr_rac,sizeof(pkr_rac));
        print_hex("c1",c1,sizeof(c1));

        size_t c2_bytes_received = 0;
        printf("Waiting for signature chunks (%zu total bytes)...\n", (size_t)PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES);

        while (c2_bytes_received < PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES) {
            len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &client_len);

            if (len <= 0 || buffer[0] != MSG_TYPE_c2_CHUNK) {
                fprintf(stderr, "Received non-chunk packet while waiting for signature. Ignoring.\n");
                continue;
            }

            unsigned char chunk_index = buffer[1];
            unsigned char* chunk_data = buffer + 2;
            size_t chunk_len = len - 2;
            size_t offset = (size_t)chunk_index * c2_CHUNK_SIZE;

            if (offset + chunk_len > PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES) {
                fprintf(stderr, "Error: Received chunk that would overflow the signature buffer. Aborting.\n");
     
            }

            memcpy(c2 + offset, chunk_data, chunk_len);
            c2_bytes_received += chunk_len;
            printf("Received c2 chunk #%d (%zu bytes). Total received: %zu/%zu\n",
                   chunk_index, chunk_len, c2_bytes_received, (size_t)PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES);
        }

        printf("All c2 chunks received. Reassembled full c2.\n");


        
        

        // --- Stage 2: Receive and Reassemble Signature Chunks ---
        unsigned char reassembled_sig[CRYPTO_BYTES];
        size_t sig_bytes_received = 0;
        printf("Waiting for signature chunks (%zu total bytes)...\n", (size_t)CRYPTO_BYTES);

        while (sig_bytes_received < CRYPTO_BYTES) {
            len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &client_len);

            if (len <= 0 || buffer[0] != MSG_TYPE_SIG_CHUNK) {
                fprintf(stderr, "Received non-chunk packet while waiting for signature. Ignoring.\n");
                continue;
            }

            unsigned char chunk_index = buffer[1];
            unsigned char* chunk_data = buffer + 2;
            size_t chunk_len = len - 2;
            size_t offset = (size_t)chunk_index * SIG_CHUNK_SIZE;

            if (offset + chunk_len > CRYPTO_BYTES) {
                fprintf(stderr, "Error: Received chunk that would overflow the signature buffer. Aborting.\n");
                
            }

            memcpy(reassembled_sig + offset, chunk_data, chunk_len);
            sig_bytes_received += chunk_len;
            printf("Received signature chunk #%d (%zu bytes). Total received: %zu/%zu\n",
                   chunk_index, chunk_len, sig_bytes_received, (size_t)CRYPTO_BYTES);
        }

        printf("All signature chunks received. Reassembled full signature.\n");

        // --- Stage 3: Verify Signature and Derive Shared Secret ---
        printf("Finalizing handshake...\n");

        size_t c_received_len = sizeof(c1) + sizeof(pkr_x25519);
        unsigned char *c_received = (unsigned char *)malloc(c_received_len);
        if (!c_received) { fprintf(stderr, "Malloc failed for c_received.\n"); return 1; }
        memcpy(c_received, c1, sizeof(c1));
        memcpy(c_received + sizeof(c1), pkr_x25519, sizeof(pkr_x25519));

        // Verify Sender's Signature
        printf("Server verifying signature from sender...\n");
        unsigned long long sm_received_len = (unsigned long long)sizeof(reassembled_sig) + c_received_len;
        unsigned char *sm_received = (unsigned char *)malloc(sm_received_len);
        if (!sm_received) { fprintf(stderr, "Malloc failed for sm_received.\n"); free(c_received); return 1; }
        memcpy(sm_received, reassembled_sig, sizeof(reassembled_sig));
        memcpy(sm_received + sizeof(reassembled_sig), c_received, c_received_len);

        unsigned char *m_after_open = (unsigned char *)malloc(c_received_len + 1);
        if(!m_after_open) { fprintf(stderr, "Malloc failed for m_after_open.\n"); free(c_received); free(sm_received); return 1; }
        unsigned long long m_len_after_open;
        START_TIMER();
        if (crypto_sign_open(m_after_open, &m_len_after_open, sm_received, sm_received_len, pkr_rac) != 0) {
               fprintf(stderr, "Signature verification failed!\n");
               free(c_received); free(sm_received); free(m_after_open); return 1;
        }
        STOP_TIMER("Raccoon Signature Verification");
        printf("Signature verified successfully.\n");
        free(sm_received);
        free(m_after_open);

        // ML-KEM Decapsulation
        unsigned char k1_prime[PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES];
        printf("Receiver decapsulating with loaded Skr_ml_kem...\n");
        START_TIMER();
        // CORRECTED: Use c2 (the ciphertext) for decapsulation, not c1.
        if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(k1_prime, c2, sks_ml_kem) != 0) {
         fprintf(stderr, "ML-KEM decapsulation failed.\n");
         free(c_received); return 1;
        }
        STOP_TIMER("ML-KEM Decapsulation");
        print_hex("k1' (ML-KEM Shared Secret - Receiver)", k1_prime, sizeof(k1_prime));

        // X25519 Shared Secret
        unsigned char k2_prime[crypto_scalarmult_BYTES];
        printf("Receiver computing X25519 shared secret k2'...\n");
        START_TIMER();
        if (crypto_scalarmult(k2_prime, sks_x25519, pkr_x25519) != 0) {
           fprintf(stderr, "X25519 scalar multiplication failed for receiver.\n");
           free(c_received); return 1;
        }
        STOP_TIMER("X25519 Scalar Multiplication");
        print_hex("k2' (X25519 Shared Secret - Receiver)", k2_prime, sizeof(k2_prime));

        // Form Aggregated Public Keys for HKDF
        size_t pkr_bytes_len = sizeof(pkr_ml_kem) + sizeof(pkr_x25519) + sizeof(pkr_rac);
        unsigned char *pkr_bytes = (unsigned char *)malloc(pkr_bytes_len);
        if (!pkr_bytes) { fprintf(stderr, "Malloc failed for pkr_bytes.\n"); free(c_received); return 1; }
        unsigned char *ptr_pkr = pkr_bytes;
        memcpy(ptr_pkr, pkr_ml_kem, sizeof(pkr_ml_kem)); ptr_pkr += sizeof(pkr_ml_kem);
        memcpy(ptr_pkr, pkr_x25519, sizeof(pkr_x25519)); ptr_pkr += sizeof(pkr_x25519);
        memcpy(ptr_pkr, pkr_rac, sizeof(pkr_rac));

        size_t pks_bytes_len = sizeof(pks_ml_kem) + sizeof(pks_x25519) + sizeof(pks_rac);
        unsigned char *pks_bytes = (unsigned char *)malloc(pks_bytes_len);
        if (!pks_bytes) { fprintf(stderr, "Malloc failed for pks_bytes.\n"); free(c_received); free(pks_bytes); return 1; }
        unsigned char *ptr_pks = pks_bytes;
        memcpy(ptr_pks, pks_ml_kem, sizeof(pks_ml_kem)); ptr_pks += sizeof(pks_ml_kem);
        memcpy(ptr_pks, pks_x25519, sizeof(pks_x25519)); ptr_pks += sizeof(pks_x25519);
        memcpy(ptr_pks, pks_rac, sizeof(pks_rac));

        // HKDF for Final Shared Secret
        size_t ikm_prime_len = sizeof(k2_prime) + sizeof(k1_prime) + c_received_len + sizeof(reassembled_sig) + pkr_bytes_len + pks_bytes_len;
        unsigned char *ikm_prime = (unsigned char *)malloc(ikm_prime_len);
        if (!ikm_prime) { fprintf(stderr, "Malloc failed for IKM_prime.\n"); free(c_received); free(pkr_bytes); free(pks_bytes); return 1;}
        unsigned char *ptr_ikm = ikm_prime;

        // CORRECTED: Match the client's IKM order: X25519 key (k2_prime), then KEM key (k1_prime)
        memcpy(ptr_ikm, k1_prime, sizeof(k1_prime)); ptr_ikm += sizeof(k1_prime);
        memcpy(ptr_ikm, k2_prime, sizeof(k2_prime)); ptr_ikm += sizeof(k2_prime);
        memcpy(ptr_ikm, c_received, c_received_len); ptr_ikm += c_received_len;
        memcpy(ptr_ikm, reassembled_sig, sizeof(reassembled_sig)); ptr_ikm += sizeof(reassembled_sig);
        memcpy(ptr_ikm, pkr_bytes, pkr_bytes_len); ptr_ikm += pkr_bytes_len;
        memcpy(ptr_ikm, pks_bytes, pks_bytes_len);
        print_hex("IKM_prime for HKDF (Server)", ikm_prime, ikm_prime_len);

        // unsigned char final_shared_secret_prime[32]; // This is now declared before the loop
        unsigned char prk_buf[crypto_auth_hmacsha256_BYTES];
        const unsigned char *hkdf_info = (const unsigned char *)"HybridProto SharedSecret";
        size_t hkdf_info_len = strlen((const char*)hkdf_info);

        printf("Receiver deriving final shared secret using custom HKDF-SHA256...\n");
        START_TIMER();
        if (hkdf_sha256_extract(prk_buf, NULL, 0, ikm_prime, ikm_prime_len) != 0) {
         fprintf(stderr, "HKDF Extract failed for Receiver.\n");
         free(c_received); free(pkr_bytes); free(pks_bytes); free(ikm_prime); return 1;
        }
        STOP_TIMER("HKDF-SHA256 Extract");
        print_hex("PRK from HKDF-Extract (Receiver)", prk_buf, sizeof(prk_buf));
        START_TIMER();
        if (hkdf_sha256_expand(final_shared_secret_prime, sizeof(final_shared_secret_prime),
                           prk_buf, sizeof(prk_buf), hkdf_info, hkdf_info_len) != 0) {
         fprintf(stderr, "HKDF Expand failed for Receiver.\n");
         free(c_received); free(pkr_bytes); free(pks_bytes); free(ikm_prime); return 1;
        }
        STOP_TIMER("HKDF-SHA256 Expand");
        sodium_memzero(prk_buf, sizeof(prk_buf));
        print_hex("Final Shared Secret (Receiver)", final_shared_secret_prime, sizeof(final_shared_secret_prime));

        // Cleanup
        free(c_received);
        free(pkr_bytes);
        free(pks_bytes);
        free(ikm_prime);
        sodium_memzero(sks_x25519, sizeof(sks_x25519));
        sodium_memzero(sks_ml_kem, sizeof(sks_ml_kem));
        sodium_memzero(sks_rac, sizeof(sks_rac));

        printf("Handshake complete. Secure session established.\n\n");
        // **FIX:** The declaration was moved. Now we just copy the data into the existing variable.
        memcpy(session_key, final_shared_secret_prime, CRYPTO_KEYBYTES);
        
        //`LOGIC FIX: The handshake is complete, so we break out of the loop.
        handshake_complete = 1;
        break; 

    // This brace closes the `while (handshake_complete == 0)` loop.
    }
    
    if (handshake_complete) {
        
        // =========================================================================
        // PART 4: SEND SECURE C12.22 REQUEST (USING ONE-SHOT ASCON)
        // =========================================================================
        printf("## STEP 4: Preparing and Sending Secure C12.22 Request with ASCON ##\n");

        unsigned char plaintext_request[256];
        int request_len = build_c1222_read_request(plaintext_request, 21, 0, 1024);
        print_hex("Plaintext Request", plaintext_request, request_len);

        unsigned char request_nonce[CRYPTO_NPUBBYTES];
        randombytes(request_nonce, CRYPTO_NPUBBYTES);
        print_hex("request_nonce Request", request_nonce, sizeof(request_nonce));
        
        // --- MODIFIED SECTION: Replaced stateful ASCON with a single function call ---
        
        // The output buffer needs space for the ciphertext plus the authentication tag.
        unsigned char *encrypted_output = malloc(request_len + CRYPTO_ABYTES);
        if (!encrypted_output) { fprintf(stderr, "Malloc failed!\n"); return 1; }
        print_hex("session_key", session_key, sizeof(session_key));
        
        unsigned long long encrypted_output_len = 0;

        printf("Encrypting request with one-shot ASCON...\n");
        // A single call to encrypt the data and generate the tag.
        START_TIMER();
        crypto_aead_encrypt(encrypted_output, &encrypted_output_len,
                            plaintext_request, request_len,
                            NULL, 0, // No Associated Data
                            NULL, request_nonce, session_key);
        STOP_TIMER("ASCON-128a AEAD Encryption");

        // The secure message now contains the nonce and the combined ciphertext+tag.
        size_t secure_msg_len = 1 + CRYPTO_NPUBBYTES + encrypted_output_len;
        print_hex("encrypted_output",encrypted_output,encrypted_output_len);
        unsigned char *secure_message = malloc(secure_msg_len);

        unsigned char *ptr = secure_message;
        *ptr++ = MSG_TYPE_SECURE_C1222_REQUEST;
        memcpy(ptr, request_nonce, CRYPTO_NPUBBYTES); ptr += CRYPTO_NPUBBYTES;
        memcpy(ptr, encrypted_output, encrypted_output_len);
        print_hex("secure_message",secure_message,secure_msg_len);

        sendto(sockfd, secure_message, secure_msg_len, 0, (const struct sockaddr *)&client_addr, sizeof(client_addr));
        printf("Sent secure ASCON request to client.\n");

        free(encrypted_output);
        free(secure_message);

        // =========================================================================
        // PART 5: RECEIVE AND PROCESS SECURE RESPONSE (USING ONE-SHOT ASCON)
        // =========================================================================
        printf("\n## STEP 5: Waiting for Secure C12.22 Response ##\n");
        int len1 = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &client_len);

        if (len1 <= 0) {
            perror("Failed to receive response from client");
        } else if (buffer[0] != MSG_TYPE_SECURE_C1222_RESPONSE) {
            fprintf(stderr, "Received message of unexpected type: 0x%02x\n", buffer[0]);
        } else if (len1 < 1 + CRYPTO_NPUBBYTES + CRYPTO_ABYTES) {
            fprintf(stderr, "Error: Packet is too small to be a valid secure message (%d bytes).\n", len1);
        } else {
            printf("Received secure response from client (%d bytes).\n", len1);
            
            // --- MODIFIED SECTION: Replaced stateful ASCON with a single function call ---

            unsigned char* p1 = buffer + 1;
            unsigned char received_nonce[CRYPTO_NPUBBYTES];
            memcpy(received_nonce, p1, CRYPTO_NPUBBYTES);
            p1 += CRYPTO_NPUBBYTES;
            
            size_t received_ciphertext_len = len1 - 1 - CRYPTO_NPUBBYTES;
            unsigned char* received_ciphertext = p1;

            unsigned char *decrypted_response = malloc(received_ciphertext_len);
            if (!decrypted_response) { fprintf(stderr, "Malloc failed!\n"); return 1; }
            
            unsigned long long decrypted_len = 0;
            
            printf("Decrypting response with one-shot ASCON...\n");
            START_TIMER();
            // A single call to decrypt the data and verify the tag.
            int result = crypto_aead_decrypt(decrypted_response, &decrypted_len,
                                             NULL,
                                             received_ciphertext, received_ciphertext_len,
                                             NULL, 0, // No Associated Data
                                             received_nonce, session_key);
            STOP_TIMER("ASCON-128a AEAD Decryption");
            if (result == 0) {
                printf("SUCCESS: ASCON tag verification successful!\n");
                // **MODIFIED CALL:** Use the new parsing function instead of the raw hex print.
                parse_and_print_c1218_response(decrypted_response, decrypted_len);
            } else {
                fprintf(stderr, "ERROR: ASCON tag verification FAILED! Message is not authentic.\n");
            }
            free(decrypted_response);
        }
    }
    close(sockfd);
    return 0;
}

