/**
 * c1222_hybrid_client.c (Server-Initiated with Signature Chunking)
 * This version uses the standard one-shot ASCON AEAD API.
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
#include <sodium.h>

#include "api_mlkem.h"
#include "api_raccoon.h"
#include "api.h"
#include "crypto_aead.h"

#include "ansi_c1222.h"
#include "ansi_c1218.h"

#define SERVER_IP "10.132.171.195"
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

// (Include the full helper and main function code from the previous correct response here)
// ...
// --- HELPER FUNCTIONS ---
extern void nist_randombytes_init(unsigned char*, unsigned char*, int);
extern void randombytes(unsigned char*, unsigned long long);
void PQCLEAN_randombytes(unsigned char *buf, size_t nbytes) { randombytes(buf, (unsigned long long)nbytes); }
void print_hex(const char* l, const unsigned char* d, size_t len) { printf("%s (%zu bytes): ", l, len); for (size_t i=0; i<len; ++i) printf("%02x", d[i]); printf("\n"); }
int hkdf_sha256_extract(unsigned char *prk, const unsigned char *salt, size_t salt_len, const unsigned char *ikm, size_t ikm_len) { unsigned char ZSK[32]; if(!salt) {sodium_memzero(ZSK,32); salt=ZSK;} return crypto_auth_hmacsha256(prk,ikm,ikm_len,salt); }
int hkdf_sha256_expand(unsigned char *okm, size_t okm_len, const unsigned char *prk, size_t prk_len, const unsigned char *info, size_t info_len) { if(okm_len>8160)return-1; unsigned char T[32]; size_t T_len=0; size_t gen_len=0; crypto_auth_hmacsha256_state st; for(unsigned char i=1; gen_len<okm_len; ++i) { crypto_auth_hmacsha256_init(&st,prk,prk_len); if(T_len>0)crypto_auth_hmacsha256_update(&st,T,T_len); if(info_len>0)crypto_auth_hmacsha256_update(&st,info,info_len); crypto_auth_hmacsha256_update(&st,&i,1); crypto_auth_hmacsha256_final(&st,T); size_t c= (gen_len+32>okm_len)?(okm_len-gen_len):32; memcpy(okm+gen_len,T,c); gen_len+=c; T_len=32; } sodium_memzero(T,32); return 0; }
int build_c1222_read_request(unsigned char* buffer, uint16_t table_id, uint32_t offset, uint16_t count);


int main() {
    printf("--- C12.22 Interactive Hybrid Security Client (Server-Initiated) ---\n\n");

    // =========================================================================
    // PART 1: GENERATE CLIENT KEYS AND BIND SOCKET
    // =========================================================================
    printf("## STEP 1: Generating client keys and preparing to listen ##\n");

    unsigned char entropy_input[48];
    for (int i = 0; i < 48; i++) entropy_input[i] = (unsigned char)('C' + i);
    nist_randombytes_init(entropy_input, (unsigned char *)"HybridClient", 256);
    if (sodium_init() < 0) {
        fprintf(stderr, "Libsodium couldn't be initialized!\n"); return 1;
    }

    // Generate client's ephemeral key pairs (kprr, kpubr)
    unsigned char pkr_ml_kem[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    unsigned char skr_ml_kem[PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES];
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pkr_ml_kem, skr_ml_kem);

    unsigned char pkr_x25519[crypto_kx_PUBLICKEYBYTES];
    unsigned char skr_x25519[crypto_kx_SECRETKEYBYTES];
    crypto_kx_keypair(pkr_x25519, skr_x25519);

    unsigned char pkr_rac[CRYPTO_PUBLICKEYBYTES];
    unsigned char skr_rac[CRYPTO_SECRETKEYBYTES];
    crypto_sign_keypair(pkr_rac, skr_rac);
    printf("Client ephemeral keys generated.\n");

    // Setup UDP socket to listen
    int sockfd;
    struct sockaddr_in client_listen_addr, server_addr;
    socklen_t server_len;
    uint8_t buffer[BUFFER_SIZE] = {0};

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) { perror("Socket creation failed"); exit(EXIT_FAILURE); }
    
    memset(&client_listen_addr, 0, sizeof(client_listen_addr));
    client_listen_addr.sin_family = AF_INET;
    client_listen_addr.sin_addr.s_addr = INADDR_ANY;
    client_listen_addr.sin_port = htons(SERVER_PORT);

    if (bind(sockfd, (const struct sockaddr *)&client_listen_addr, sizeof(client_listen_addr)) < 0) {
        perror("Bind failed"); close(sockfd); exit(EXIT_FAILURE); }

    // =========================================================================
    // PART 2: RECEIVE SERVER HELLO AND ESTABLISH SESSION
    // =========================================================================
    printf("\nWaiting for Server Hello on UDP port %d...\n", SERVER_PORT);
    server_len = sizeof(server_addr);
    int len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&server_addr, &server_len);

    if (len <= 0 || buffer[0] != MSG_TYPE_SERVER_HELLO) {
        fprintf(stderr, "Did not receive a valid Server Hello.\n");
        return 1;
    }
    printf("Server Hello received.\n");

    // Unpack server's public keys (kpubs)
    unsigned char *sp = buffer + 1;
    unsigned char pks_ml_kem[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    unsigned char pks_x25519[crypto_kx_PUBLICKEYBYTES];
    unsigned char pks_rac[CRYPTO_PUBLICKEYBYTES];

    memcpy(pks_ml_kem, sp, sizeof(pks_ml_kem)); sp += sizeof(pks_ml_kem);
    memcpy(pks_x25519, sp, sizeof(pks_x25519)); sp += sizeof(pks_x25519);
    memcpy(pks_rac, sp, sizeof(pks_rac));
    
    // Client performs its side of the handshake
    unsigned char c1[crypto_kx_PUBLICKEYBYTES];
    unsigned char k1[crypto_scalarmult_BYTES];
    memcpy(c1, pkr_x25519, sizeof(c1));
    crypto_scalarmult(k1, skr_x25519, pks_x25519);

    unsigned char c2[PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    unsigned char k2[PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES];
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(c2, k2, pks_ml_kem);
    print_hex("c2:",c2,sizeof(c2));

    size_t c_len = sizeof(c1) + sizeof(pkr_x25519);
    unsigned char *c_data = (unsigned char *)malloc(c_len);
    if (!c_data) { fprintf(stderr, "Malloc failed for c_data.\n"); return 1; }
    memcpy(c_data, c1, sizeof(c1));
    memcpy(c_data + sizeof(c1), pkr_x25519, sizeof(pkr_x25519));
    unsigned char sig[CRYPTO_BYTES];
    unsigned long long smlen;
    unsigned char *sm_buf = (unsigned char *)malloc(CRYPTO_BYTES + c_len);
    if (!sm_buf) { fprintf(stderr, "Malloc failed for sm_buf.\n"); free(c_data); return 1; }
    if (crypto_sign(sm_buf, &smlen, c_data, c_len, skr_rac) != 0) {
         fprintf(stderr, "Raccoon signing (crypto_sign) failed.\n");
         free(c_data); free(sm_buf); return 1;
    }
    if (smlen < CRYPTO_BYTES) {
        fprintf(stderr, "Signed message length too short!\n");
        free(c_data); free(sm_buf); return 1;
    }
    memcpy(sig, sm_buf, CRYPTO_BYTES);
    free(sm_buf);

    // =========================================================================
    // PART 3: SEND CLIENT HELLO AND SIGNATURE IN SEPARATE MESSAGES
    // =========================================================================
    printf("## STEP 3: Sending Client Hello and Signature ##\n");

    // --- Message 1: Client Hello (without signature) ---
    unsigned char client_hello_part1[BUFFER_SIZE];
    unsigned char *p = client_hello_part1;
    *p++ = MSG_TYPE_CLIENT_HELLO_PART1;
    memcpy(p, pkr_ml_kem, sizeof(pkr_ml_kem)); p += sizeof(pkr_ml_kem);
    memcpy(p, pkr_x25519, sizeof(pkr_x25519)); p += sizeof(pkr_x25519);
    memcpy(p, pkr_rac, sizeof(pkr_rac));       p += sizeof(pkr_rac);
    memcpy(p, c1, sizeof(c1));                 p += sizeof(c1);
    
    print_hex("pkr_rac",pkr_rac,sizeof(pkr_rac));
    int client_hello_len = p - client_hello_part1;

    sendto(sockfd, client_hello_part1, client_hello_len, 0, (struct sockaddr *)&server_addr, server_len);
    printf("Sent Client Hello Part 1.\n");
    
    const int num_chunks1 = (PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES + c2_CHUNK_SIZE - 1) / c2_CHUNK_SIZE;
    printf("c2 is %d bytes, sending in %d chunks of %d bytes...\n", (int)PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES, num_chunks1, c2_CHUNK_SIZE);

    for (int i = 0; i < num_chunks1; ++i) {
        unsigned char c2_chunk_msg[c2_CHUNK_SIZE + 2]; // type + index + data
        unsigned char *scp = c2_chunk_msg;
        
        *scp++ = MSG_TYPE_c2_CHUNK;
        *scp++ = (unsigned char)i; // Chunk index

        size_t offset = i * c2_CHUNK_SIZE;
        size_t chunk_len = (offset + c2_CHUNK_SIZE > PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES) ? (PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES - offset) : c2_CHUNK_SIZE;
        
        memcpy(scp, c2 + offset, chunk_len);
        
        int c2_chunk_len = chunk_len + 2;
        sendto(sockfd, c2_chunk_msg, c2_chunk_len, 0, (struct sockaddr *)&server_addr, server_len);
        printf("Sent c2 chunk #%d (%zu bytes)\n", i, chunk_len);
        usleep(10000); // Small delay to prevent packet loss
    }

    // --- Messages 2, 3, 4...: Signature Chunks ---
    const int num_chunks = (CRYPTO_BYTES + SIG_CHUNK_SIZE - 1) / SIG_CHUNK_SIZE;
    printf("Signature is %d bytes, sending in %d chunks of %d bytes...\n", (int)CRYPTO_BYTES, num_chunks, SIG_CHUNK_SIZE);

    for (int i = 0; i < num_chunks; ++i) {
        unsigned char sig_chunk_msg[SIG_CHUNK_SIZE + 2]; // type + index + data
        unsigned char *scp = sig_chunk_msg;
        
        *scp++ = MSG_TYPE_SIG_CHUNK;
        *scp++ = (unsigned char)i; // Chunk index

        size_t offset = i * SIG_CHUNK_SIZE;
        size_t chunk_len = (offset + SIG_CHUNK_SIZE > CRYPTO_BYTES) ? (CRYPTO_BYTES - offset) : SIG_CHUNK_SIZE;
        
        memcpy(scp, sig + offset, chunk_len);
        
        int sig_chunk_len = chunk_len + 2;
        sendto(sockfd, sig_chunk_msg, sig_chunk_len, 0, (struct sockaddr *)&server_addr, server_len);
        printf("Sent signature chunk #%d (%zu bytes)\n", i, chunk_len);
        usleep(10000); // Small delay to prevent packet loss
    }

    //Construct Pkr_bytes (client's aggregated public keys)
    size_t pkr_bytes_len = sizeof(pkr_ml_kem) + sizeof(pkr_x25519) + sizeof(pkr_rac);
    unsigned char *pkr_bytes = (unsigned char *)malloc(pkr_bytes_len);
    if (!pkr_bytes) { fprintf(stderr, "Malloc failed for pkr_bytes.\n"); free(c_data); return 1; }
    unsigned char *ptr_pkr = pkr_bytes;
    memcpy(ptr_pkr, pkr_ml_kem, sizeof(pkr_ml_kem)); ptr_pkr += sizeof(pkr_ml_kem);
    memcpy(ptr_pkr, pkr_x25519, sizeof(pkr_x25519)); ptr_pkr += sizeof(pkr_x25519);
    memcpy(ptr_pkr, pkr_rac, sizeof(pkr_rac));

    // Construct Pks_bytes (server's aggregated public keys)
    size_t pks_bytes_len = sizeof(pks_ml_kem) + sizeof(pks_x25519) + sizeof(pks_rac);
    unsigned char *pks_bytes = (unsigned char *)malloc(pks_bytes_len);
    if (!pks_bytes) { fprintf(stderr, "Malloc failed for pks_bytes.\n"); free(c_data); free(pkr_bytes); return 1; }
    unsigned char *ptr_pks = pks_bytes;
    memcpy(ptr_pks, pks_ml_kem, sizeof(pks_ml_kem)); ptr_pks += sizeof(pks_ml_kem);
    memcpy(ptr_pks, pks_x25519, sizeof(pks_x25519)); ptr_pks += sizeof(pks_x25519);
    memcpy(ptr_pks, pks_rac, sizeof(pks_rac));

    // HKDF IKM
    size_t ikm_len = sizeof(k1) + sizeof(k2) + c_len + sizeof(sig) + pkr_bytes_len + pks_bytes_len;
    unsigned char *ikm = (unsigned char *)malloc(ikm_len);
    if (!ikm) { fprintf(stderr, "Malloc failed for IKM.\n"); free(c_data); free(pks_bytes); free(pkr_bytes); return 1;}
    unsigned char *ptr_ikm = ikm;
    memcpy(ptr_ikm, k2, sizeof(k2)); ptr_ikm += sizeof(k2);
    memcpy(ptr_ikm, k1, sizeof(k1)); ptr_ikm += sizeof(k1);
    memcpy(ptr_ikm, c_data, c_len); ptr_ikm += c_len;
    memcpy(ptr_ikm, sig, sizeof(sig)); ptr_ikm += sizeof(sig); 
    memcpy(ptr_ikm, pkr_bytes, pkr_bytes_len); ptr_ikm += pkr_bytes_len;
    memcpy(ptr_ikm, pks_bytes, pks_bytes_len);
    print_hex("k1 (Sender)", k1, sizeof(k1));
    print_hex("k2 (Sender)", k2, sizeof(k2));
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
    printf("Handshake complete. Secure session established.\n");

   // =========================================================================
    // PART 5: HANDLE SECURE DATA EXCHANGE
    // =========================================================================
    printf("\n## STEP 5: Waiting for secure request from server ##\n");

    int len1 = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&server_addr, &server_len);

    if (len1 <= 0) {
        fprintf(stderr, "Failed to receive secure request from server.\n");
    } else if (buffer[0] != MSG_TYPE_SECURE_C1222_REQUEST) {
        fprintf(stderr, "Received message of unexpected type: 0x%02x\n", buffer[0]);
    } else if (len1 < 1 + 16 + 16) {
        fprintf(stderr, "Error: Packet is too small to be a valid secure message (%d bytes).\n", len1);
    } else {
        printf("Received encrypted request from server (%d bytes).\n", len1);

        unsigned char session_key[16];
        memcpy(session_key, final_shared_secret, 16);
        print_hex("Session Key", session_key, sizeof(session_key));

        // --- 1. Deconstruct the secure message from the server ---
        unsigned char* p_in = buffer + 1;
        unsigned char received_nonce[16];
        memcpy(received_nonce, p_in, 16);
        p_in += 16;

        size_t ciphertext_len = len1 - 1 - 16;
        unsigned char* ciphertext = p_in;

        // --- 2. Perform ASCON AEAD Decryption ---
        unsigned char* decrypted_request = (unsigned char *)malloc(ciphertext_len);
        if (!decrypted_request) { fprintf(stderr, "Malloc failed!\n"); return 1; }
        
        unsigned long long decrypted_len = 0;

        printf("Decrypting with one-shot ASCON...\n");
        int result = crypto_aead_decrypt(decrypted_request, &decrypted_len,
                                         NULL,
                                         ciphertext, ciphertext_len,
                                         NULL, 0, // No Associated Data
                                         received_nonce, session_key);

        if (result == 0) {
            printf("SUCCESS: ASCON AEAD Decryption SUCCESSFUL! Tag Verified.\n");
            print_hex("Decrypted Plaintext", decrypted_request, decrypted_len);

            // --- 3. Prepare and send the encrypted response ---
            const unsigned char table21_data[] = {
                'G','E','M','I','N','I',' ',' ', 'H','Y','B','R','I','D','-','M','T','R',
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            };
            size_t response_payload_len = 1 + sizeof(table21_data);
            unsigned char* response_payload = (unsigned char*)malloc(response_payload_len);
            response_payload[0] = 0x00; // C1219_ACK
            memcpy(response_payload + 1, table21_data, sizeof(table21_data));

            unsigned char response_nonce[16];
            randombytes(response_nonce, 16);
            
            unsigned char* encrypted_response = (unsigned char*)malloc(response_payload_len + 16);
            unsigned long long encrypted_response_len = 0;

            printf("Encrypting response with one-shot ASCON...\n");
            crypto_aead_encrypt(encrypted_response, &encrypted_response_len,
                                response_payload, response_payload_len,
                                NULL, 0, // No Associated Data
                                NULL, response_nonce, session_key);
            
            size_t final_message_len = 1 + 16 + encrypted_response_len;
            unsigned char *final_message_buf = (unsigned char*)malloc(final_message_len);
            
            unsigned char* p_out = final_message_buf;
            *p_out++ = MSG_TYPE_SECURE_C1222_RESPONSE;
            memcpy(p_out, response_nonce, 16); p_out += 16;
            memcpy(p_out, encrypted_response, encrypted_response_len);
            
            printf("Sending encrypted response to server (%zu bytes)...\n", final_message_len);
            sendto(sockfd, final_message_buf, final_message_len, 0, (struct sockaddr *)&server_addr, server_len);
            
            free(response_payload);
            free(encrypted_response);
            free(final_message_buf);

        } else {
            fprintf(stderr, "ERROR: ASCON AEAD Decryption FAILED! Tag verification failed.\n");
        }
        
        free(decrypted_request);
    }

    // Final cleanup
    // ...
    
    close(sockfd);
    return 0;
}
