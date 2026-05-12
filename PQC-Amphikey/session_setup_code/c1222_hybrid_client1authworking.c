/**
 * c1222_hybrid_client_aligned_signing.c (Server-Initiated Handshake)
 *
 * This version is completely rewritten to align with the signing logic
 * from the hybrid_bench.c protocol.
 *
 * It corrects the composition of the data being signed to be:
 * c_data = ML-KEM_ciphertext || Server_X25519_Public_Key
 *
 * This ensures compatibility with a server expecting the benchmark logic.
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

#define SERVER_IP "10.150.70.18" // IP of your VirtualBox VM Server
#define SERVER_PORT 1153
#define BUFFER_SIZE 11528

// --- Message Types for Handshake ---
#define MSG_TYPE_CLIENT_HELLO 0x01
#define MSG_TYPE_SERVER_HELLO 0x02
#define MSG_TYPE_SECURE_C1222_REQUEST 0x03
#define MSG_TYPE_SECURE_C1222_RESPONSE 0x04
#define MSG_TYPE_CLIENT_SIGNATURE 0x05

// --- HELPER FUNCTIONS ---
extern void nist_randombytes_init(unsigned char*, unsigned char*, int);
extern void randombytes(unsigned char*, unsigned long long);
void PQCLEAN_randombytes(unsigned char *buf, size_t nbytes) { randombytes(buf, (unsigned long long)nbytes); }
void print_hex(const char* l, const unsigned char* d, size_t len) { printf("%s (%zu bytes): ", l, len); for (size_t i=0; i<len; ++i) printf("%02x", d[i]); printf("\n"); }

int main() {
    printf("--- C12.22 Interactive Client (Aligned with hybrid_bench.c Signing) ---\n\n");

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
        perror("Bind failed"); close(sockfd); exit(EXIT_FAILURE);
    }

    // =========================================================================
    // PART 2: RECEIVE SERVER HELLO AND PERFORM HANDSHAKE
    // =========================================================================
    printf("\n## STEP 2: Waiting for Server Hello and performing handshake ##\n");
    printf("Waiting on UDP port %d...\n", SERVER_PORT);
    server_len = sizeof(server_addr);
    int len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&server_addr, &server_len);

    if (len <= 0 || buffer[0] != MSG_TYPE_SERVER_HELLO) {
        fprintf(stderr, "Did not receive a valid Server Hello.\n");
        return 1;
    }
    printf("Server Hello received. Performing client-side handshake...\n");

    // Unpack server's public keys (pks_*)
    unsigned char *sp = buffer + 1;
    unsigned char pks_ml_kem[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    unsigned char pks_x25519[crypto_kx_PUBLICKEYBYTES];
    unsigned char pks_rac[CRYPTO_PUBLICKEYBYTES];

    memcpy(pks_ml_kem, sp, sizeof(pks_ml_kem)); sp += sizeof(pks_ml_kem);
    memcpy(pks_x25519, sp, sizeof(pks_x25519)); sp += sizeof(pks_x25519);
    memcpy(pks_rac, sp, sizeof(pks_rac));

    // --- Client performs its side of the handshake (Aligned with hybrid_bench.c) ---

    // ML-KEM Encapsulation to get k1 and c1
    unsigned char c1[PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    unsigned char k1[PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES];
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(c1, k1, pks_ml_kem);

    // X25519 Key Exchange to get k2
    unsigned char k2[crypto_scalarmult_BYTES];
    crypto_scalarmult(k2, skr_x25519, pks_x25519);

    // --- CONSTRUCT AND SIGN THE CORRECT DATA ---
    // According to hybrid_bench.c, the signed data is c1 || pks_x25519
    size_t c_data_len = sizeof(c1) + sizeof(pks_x25519);
    unsigned char *c_data = (unsigned char *)malloc(c_data_len);
    if (!c_data) { fprintf(stderr, "Malloc failed for c_data\n"); return 1; }
    memcpy(c_data, c1, sizeof(c1)); // Copy ML-KEM ciphertext
    memcpy(c_data + sizeof(c1), pks_x25519, sizeof(pks_x25519)); // Copy Server's X25519 PK
    printf("Signing data constructed as: ML-KEM Ciphertext || Server's X25519 PK\n");

    // **FIXED**: Use the correct length variable 'c_data_len' instead of 'sizeof(c_data)'
    print_hex("c_data", c_data, c_data_len);

    // Sign using crypto_sign and extract signature (matches hybrid_bench.c)
    unsigned char sig[CRYPTO_BYTES];
    unsigned long long smlen;
    unsigned char *sm_buf = (unsigned char *)malloc(CRYPTO_BYTES + c_data_len);
    if (!sm_buf) { fprintf(stderr, "Malloc failed for sm_buf\n"); free(c_data); return 1; }

    if (crypto_sign(sm_buf, &smlen, c_data, c_data_len, skr_rac) != 0) {
        fprintf(stderr, "Signature generation failed!\n");
        free(c_data); free(sm_buf); return 1;
    }
    
    // **FIXED**: Print the signed message *after* it has been created and use the correct length 'smlen'
    print_hex("sm_buf (Signed Message)", sm_buf, smlen);

    memcpy(sig, sm_buf, sizeof(sig)); // Extract just the signature part
    free(sm_buf);

    printf("Handshake calculations complete. Secure session established.\n");

    // =========================================================================
    // PART 3: SEND CLIENT HELLO AND SIGNATURE IN SEPARATE MESSAGES
    // =========================================================================
    printf("\n## STEP 3: Sending Client Hello and Signature ##\n");

    // --- Message 1: Client Hello ---
    // This message must contain the client's public keys and the new ciphertext c1
    unsigned char client_hello[BUFFER_SIZE];
    unsigned char *p = client_hello;

    *p++ = MSG_TYPE_CLIENT_HELLO;
    memcpy(p, pkr_ml_kem, sizeof(pkr_ml_kem)); p += sizeof(pkr_ml_kem);
    memcpy(p, pkr_x25519, sizeof(pkr_x25519)); p += sizeof(pkr_x25519);
    memcpy(p, pkr_rac, sizeof(pkr_rac));       p += sizeof(pkr_rac);
    memcpy(p, c1, sizeof(c1));                 p += sizeof(c1); // Send the ML-KEM ciphertext

    int client_hello_len = p - client_hello;
    printf("Client Hello message size (w/o signature): %d bytes.\n", client_hello_len);
    sendto(sockfd, client_hello, client_hello_len, 0, (const struct sockaddr *)&server_addr, server_len);
    printf("Sent Client Hello.\n");

    // --- Message 2: Client Signature ---
    unsigned char client_sig_msg[BUFFER_SIZE];
    p = client_sig_msg;

    *p++ = MSG_TYPE_CLIENT_SIGNATURE;
    memcpy(p, sig, sizeof(sig));
    p += sizeof(sig);

    int client_sig_len = p - client_sig_msg;
    printf("Client Signature message size: %d bytes.\n", client_sig_len);
    sendto(sockfd, client_sig_msg, client_sig_len, 0, (const struct sockaddr *)&server_addr, server_len);
    printf("Sent Client Signature in a separate message.\n");

    // =========================================================================
    // PART 4: CLEANUP AND EXIT
    // =========================================================================
    printf("\n## STEP 4: Ready to process secure application data ##\n");

    free(c_data);
    close(sockfd);
    return 0;
}
