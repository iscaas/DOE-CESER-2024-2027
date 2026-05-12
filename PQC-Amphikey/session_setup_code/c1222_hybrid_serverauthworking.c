/**
 * c1222_hybrid_server_chunking.c (Server-Initiated with Signature Chunking)
 *
 * This server is modified to handle a client that sends its signature
 * in multiple chunks. It receives the initial hello, then enters a loop
 * to reassemble the full signature before verification.
 *
 * This version uses crypto_sign_open for verification.
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

#define CLIENT_IP "10.150.132.12" // IMPORTANT: IP of your Raspberry Pi Client
#define SERVER_PORT 1153
#define BUFFER_SIZE 13000 // Large enough for the biggest possible message part
#define SIG_CHUNK_SIZE 4000 // Must match the client's chunk size

// --- Message Types for Handshake ---
#define MSG_TYPE_CLIENT_HELLO_PART1 0x01
#define MSG_TYPE_SERVER_HELLO 0x02
#define MSG_TYPE_SECURE_C1222_REQUEST 0x03
#define MSG_TYPE_SECURE_C1222_RESPONSE 0x04
#define MSG_TYPE_SIG_CHUNK 0x11


// --- HELPER FUNCTIONS ---
extern void nist_randombytes_init(unsigned char*, unsigned char*, int);
extern void randombytes(unsigned char*, unsigned long long);
void PQCLEAN_randombytes(unsigned char *buf, size_t nbytes) { randombytes(buf, (unsigned long long)nbytes); }
void print_hex(const char* l, const unsigned char* d, size_t len) { printf("%s (%zu bytes): ", l, len); for (size_t i=0; i<len; ++i) printf("%02x", d[i]); printf("\n"); }
int hkdf_sha256_extract(unsigned char *prk, const unsigned char *salt, size_t salt_len, const unsigned char *ikm, size_t ikm_len) { unsigned char ZSK[32]; if(!salt) {sodium_memzero(ZSK,32); salt=ZSK;} return crypto_auth_hmacsha256(prk,ikm,ikm_len,salt); }
int hkdf_sha256_expand(unsigned char *okm, size_t okm_len, const unsigned char *prk, size_t prk_len, const unsigned char *info, size_t info_len) { if(okm_len>8160)return-1; unsigned char T[32]; size_t T_len=0; size_t gen_len=0; crypto_auth_hmacsha256_state st; for(unsigned char i=1; gen_len<okm_len; ++i) { crypto_auth_hmacsha256_init(&st,prk,prk_len); if(T_len>0)crypto_auth_hmacsha256_update(&st,T,T_len); if(info_len>0)crypto_auth_hmacsha256_update(&st,info,info_len); crypto_auth_hmacsha256_update(&st,&i,1); crypto_auth_hmacsha256_final(&st,T); size_t c= (gen_len+32>okm_len)?(okm_len-gen_len):32; memcpy(okm+gen_len,T,c); gen_len+=c; T_len=32; } sodium_memzero(T,32); return 0; }
int build_c1222_read_request(unsigned char* buffer, uint16_t table_id, uint32_t offset, uint16_t count);


int main() {
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
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pks_ml_kem, sks_ml_kem);
    crypto_kx_keypair(pks_x25519, sks_x25519);
    crypto_sign_keypair(pks_rac, sks_rac);
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
        unsigned char c1[crypto_kx_PUBLICKEYBYTES]; // c1 is the client's X25519 PK
        unsigned char c2[PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES];
        
        memcpy(pkr_ml_kem, p, sizeof(pkr_ml_kem)); p += sizeof(pkr_ml_kem);
        memcpy(pkr_x25519, p, sizeof(pkr_x25519)); p += sizeof(pkr_x25519);
        memcpy(pkr_rac, p, sizeof(pkr_rac));       p += sizeof(pkr_rac);
        memcpy(c1, p, sizeof(c1));                 p += sizeof(c1);
        memcpy(c2, p, sizeof(c2));

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
                goto handshake_failed;
            }

            memcpy(reassembled_sig + offset, chunk_data, chunk_len);
            sig_bytes_received += chunk_len;
            printf("Received signature chunk #%d (%zu bytes). Total received: %zu/%zu\n",
                   chunk_index, chunk_len, sig_bytes_received, (size_t)CRYPTO_BYTES);
        }

        printf("All signature chunks received. Reassembled full signature.\n");

        // --- Stage 3: Verify Signature and Derive Shared Secret ---
        printf("Finalizing handshake...\n");
        print_hex("reassembled_sig:",reassembled_sig,sizeof(reassembled_sig));

        size_t c_received_len = sizeof(c1) + sizeof(pkr_x25519);
        unsigned char *c_received = (unsigned char *)malloc(c_received_len);
        if (!c_received) { fprintf(stderr, "Malloc failed for c_received.\n"); return 1; }
        memcpy(c_received, c1, sizeof(c1));
        memcpy(c_received + sizeof(c1), pkr_x25519, sizeof(pkr_x25519));
        print_hex("c_received (reconstructed by receiver)", c_received, c_received_len);

    // 2. Verify Sender's Signature using loaded pkr_rac from receiver
        printf("Server verifying signature from sender...\n");
        unsigned long long sm_received_len = (unsigned long long)sizeof(reassembled_sig) + c_received_len;
        unsigned char *sm_received = (unsigned char *)malloc(sm_received_len);
        if (!sm_received) { fprintf(stderr, "Malloc failed for sm_received.\n"); free(c_received); return 1; }
        memcpy(sm_received, reassembled_sig, sizeof(reassembled_sig));
        memcpy(sm_received + sizeof(reassembled_sig), c_received, c_received_len);

        unsigned char *m_after_open = (unsigned char *)malloc(c_received_len + 1); 
        if(!m_after_open) { fprintf(stderr, "Malloc failed for m_after_open.\n"); free(c_received); free(sm_received); return 1; }
        unsigned long long m_len_after_open;

        if (crypto_sign_open(m_after_open, &m_len_after_open, sm_received, sm_received_len, pkr_rac) != 0) {
               fprintf(stderr, "Signature verification failed!\n");
               free(c_received); free(sm_received); free(m_after_open); return 1;
        }
        if (m_len_after_open != c_received_len || memcmp(m_after_open, c_received, c_received_len) != 0) {
          fprintf(stderr, "Opened message does not match reconstructed c_data!\n");
          free(c_received); free(sm_received); free(m_after_open); return 1;
        }
        printf("Signature verified successfully.\n");
        free(sm_received);
        free(m_after_open);


        // 3. ML-KEM Decapsulation by Receiver using loaded skr_ml_kem
        unsigned char k1_prime[PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES];
        printf("Receiver decapsulating c1_from_sender with loaded Skr_ml_kem...\n");
        if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(k1_prime, c1, sks_ml_kem) != 0) {
         fprintf(stderr, "ML-KEM decapsulation failed.\n");
         free(c_received); return 1;
        }
        print_hex("k1' (ML-KEM Shared Secret - Receiver)", k1_prime, sizeof(k1_prime));

    // 4. X25519 Shared Secret by Receiver using loaded skr_x25519 and loaded pkr_x25519_from_sender
        unsigned char k2_prime[crypto_scalarmult_BYTES];
        printf("Receiver computing X25519 shared secret k2' with loaded Skr_x25519...\n");
        if (crypto_scalarmult(k2_prime, sks_x25519, pkr_x25519) != 0) {
           fprintf(stderr, "X25519 scalar multiplication failed for receiver.\n");
           free(c_received); return 1;
        }
        print_hex("k2' (X25519 Shared Secret - Receiver)", k2_prime, sizeof(k2_prime));

    // 5. Form Aggregated Public Keys for HKDF
    // Pkr_bytes uses receiver's loaded public keys
        size_t pkr_bytes_len = sizeof(pkr_ml_kem) + sizeof(pkr_x25519) + sizeof(pkr_rac);
        unsigned char *pkr_bytes = (unsigned char *)malloc(pkr_bytes_len);
        if (!pkr_bytes) { fprintf(stderr, "Malloc failed for pkr_bytes.\n"); free(c_received); return 1; }
        unsigned char *ptr_pkr = pkr_bytes;
        memcpy(ptr_pkr, pkr_ml_kem, sizeof(pkr_ml_kem)); ptr_pkr += sizeof(pkr_ml_kem);
        memcpy(ptr_pkr, pkr_x25519, sizeof(pkr_x25519)); ptr_pkr += sizeof(pkr_x25519);
        memcpy(ptr_pkr, pkr_rac, sizeof(pkr_rac));

    // Pkr_bytes_from_sender uses receiver's loaded public keys
        size_t pks_bytes_from_sender_len = sizeof(pks_ml_kem) + sizeof(pks_x25519) + sizeof(pks_rac);
        unsigned char *pks_bytes_from_sender_data = (unsigned char *)malloc(pks_bytes_from_sender_len);
        if (!pks_bytes_from_sender_data) { fprintf(stderr, "Malloc failed for pkr_bytes_from_sender_data.\n"); free(c_received); free(pkr_bytes); return 1; }
        unsigned char *ptr_pks = pks_bytes_from_sender_data;
        memcpy(ptr_pks, pks_ml_kem, sizeof(pks_ml_kem)); ptr_pks += sizeof(pks_ml_kem);
        memcpy(ptr_pks, pks_x25519, sizeof(pks_x25519)); ptr_pks += sizeof(pks_x25519); 
        memcpy(ptr_pks, pks_rac, sizeof(pks_rac)); 

    // 6. HKDF for Final Shared Secret
        size_t ikm_prime_len = sizeof(k1_prime) + sizeof(k2_prime) + c_received_len + sizeof(reassembled_sig) + pkr_bytes_len + pks_bytes_from_sender_len;
        unsigned char *ikm_prime = (unsigned char *)malloc(ikm_prime_len);
        if (!ikm_prime) { fprintf(stderr, "Malloc failed for IKM_prime.\n"); free(c_received); free(pkr_bytes); free(pks_bytes_from_sender_data); return 1;}
        unsigned char *ptr_ikm = ikm_prime;
        memcpy(ptr_ikm, k1_prime, sizeof(k1_prime)); ptr_ikm += sizeof(k1_prime);
        memcpy(ptr_ikm, k2_prime, sizeof(k2_prime)); ptr_ikm += sizeof(k2_prime);
        memcpy(ptr_ikm, c_received, c_received_len); ptr_ikm += c_received_len;
        memcpy(ptr_ikm, reassembled_sig, sizeof(reassembled_sig)); ptr_ikm += sizeof(reassembled_sig);
        memcpy(ptr_ikm, pkr_bytes, pkr_bytes_len); ptr_ikm += pkr_bytes_len;
        memcpy(ptr_ikm, pks_bytes_from_sender_data, pks_bytes_from_sender_len);
        print_hex("IKM_prime for HKDF (Server)", ikm_prime, ikm_prime_len);

        unsigned char final_shared_secret_prime[32];
        unsigned char prk_buf[crypto_auth_hmacsha256_BYTES]; // Renamed prk to prk_buf to avoid conflict
        const unsigned char *hkdf_salt = NULL; 
        size_t hkdf_salt_len = 0;
        const unsigned char *hkdf_info = (const unsigned char *)"HybridProto SharedSecret";
        size_t hkdf_info_len = strlen((const char*)hkdf_info);

        printf("Receiver deriving final shared secret using custom HKDF-SHA256...\n");
        if (hkdf_sha256_extract(prk_buf, hkdf_salt, hkdf_salt_len, ikm_prime, ikm_prime_len) != 0) {
         fprintf(stderr, "HKDF Extract failed for Receiver.\n");
         free(c_received); free(pkr_bytes); free(pks_bytes_from_sender_data); free(ikm_prime); return 1;
        }
        print_hex("PRK from HKDF-Extract (Receiver)", prk_buf, sizeof(prk_buf));
        if (hkdf_sha256_expand(final_shared_secret_prime, sizeof(final_shared_secret_prime),
                           prk_buf, sizeof(prk_buf), hkdf_info, hkdf_info_len) != 0) {
         fprintf(stderr, "HKDF Expand failed for Receiver.\n");
         free(c_received); free(pkr_bytes); free(pks_bytes_from_sender_data); free(ikm_prime); return 1;
        }
        sodium_memzero(prk_buf, sizeof(prk_buf));
        print_hex("Final Shared Secret (Receiver)", final_shared_secret_prime, sizeof(final_shared_secret_prime));

    // Cleanup
        free(c_received);
        free(pkr_bytes);
        free(pks_bytes_from_sender_data);
        free(ikm_prime);
        sodium_memzero(sks_x25519, sizeof(sks_x25519));
        sodium_memzero(sks_ml_kem, sizeof(sks_ml_kem));
        sodium_memzero(sks_rac, sizeof(sks_rac));

        printf("Handshake complete. Secure session established.\n\n");
        
        handshake_complete = 1;
        
        
        break; 

    handshake_failed: 
        printf("Handshake failed. Resetting...\n");
    }

    if(handshake_complete) {
        printf("## STEP 4: Sending Secure C12.22 Request ##\n");
    }

    close(sockfd);
    return 0;
}
