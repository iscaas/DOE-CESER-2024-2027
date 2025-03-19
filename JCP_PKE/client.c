#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

#define PORT 3000
#define SERVER_IP "127.0.0.1"
#define BUFFER_SIZE 1024

// Function to print data in hexadecimal format
void print_hex(const char *label, const unsigned char *data, int length) {
    printf("%s (hex): ", label);
    for (int i = 0; i < length; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

// Verify certificate signature and validity
int verify_certificate(X509 *cert, X509 *ca_cert) {
    EVP_PKEY *ca_pub_key = X509_get_pubkey(ca_cert);
    if (!ca_pub_key) {
        fprintf(stderr, "[Server] Failed to extract CA public key\n");
        return 0;
    }

    if (X509_verify(cert, ca_pub_key) != 1) {
        fprintf(stderr, "[Server] Certificate verification failed\n");
        EVP_PKEY_free(ca_pub_key);
        return 0;
    }

    EVP_PKEY_free(ca_pub_key);
    return 1;
}

// Verify HMAC
int verify_hmac(const unsigned char *key, const unsigned char *data, int data_len, const unsigned char *received_hmac, unsigned int received_hmac_len) {
    unsigned char calculated_hmac[EVP_MAX_MD_SIZE];
    unsigned int calculated_hmac_len;

    HMAC_CTX *ctx = HMAC_CTX_new();
    if (!ctx) {
        perror("[Client] Failed to create HMAC context");
        return 0;
    }

    // Calculate HMAC
    if (HMAC_Init_ex(ctx, key, 32, EVP_sha256(), NULL) != 1 ||
        HMAC_Update(ctx, data, data_len) != 1 ||
        HMAC_Final(ctx, calculated_hmac, &calculated_hmac_len) != 1) {
        perror("[Client] Failed to calculate HMAC");
        HMAC_CTX_free(ctx);
        return 0;
    }

    HMAC_CTX_free(ctx);

    // Log received and calculated HMACs
    printf("[Client] Received HMAC: ");
    print_hex("", received_hmac, received_hmac_len);

    printf("[Client] Calculated HMAC: ");
    print_hex("", calculated_hmac, calculated_hmac_len);

    // Compare HMAC lengths and values
    if (calculated_hmac_len != received_hmac_len ||
        CRYPTO_memcmp(calculated_hmac, received_hmac, calculated_hmac_len) != 0) {
        fprintf(stderr, "[Client] HMAC verification failed\n");
        return 0;
    }

    printf("[Client] HMAC verified successfully\n");
    return 1;
}


// Function to calculate elapsed time
double calculate_elapsed_time(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1e6;
}

// Function to perform AES encryption
int aes_encrypt(const unsigned char *plaintext, int plaintext_len, const unsigned char *key,
                unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        perror("[Client] Failed to create EVP context");
        return -1;
    }

    int len, ciphertext_len;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        perror("[Client] AES Encryption initialization failed");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        perror("[Client] AES Encryption failed");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        perror("[Client] AES Encryption finalization failed");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

// AES decryption
int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                const unsigned char *key, const unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handle_error("[Server] Failed to create EVP context");
    }

    int len, plaintext_len;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1 ||
        EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        handle_error("[Server] AES decryption failed");
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        fprintf(stderr, "[Server] AES decryption finalization failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

// Handle error and exit
void handle_error(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

// Generate HMAC
void generate_hmac(const unsigned char *key, const unsigned char *data, int data_len, unsigned char *hmac, unsigned int *hmac_len) {
    HMAC_CTX *ctx = HMAC_CTX_new();
    if (!ctx) {
        handle_error("[Server] Failed to create HMAC context");
    }

    if (HMAC_Init_ex(ctx, key, 32, EVP_sha256(), NULL) != 1 ||
        HMAC_Update(ctx, data, data_len) != 1 ||
        HMAC_Final(ctx, hmac, hmac_len) != 1) {
        handle_error("[Server] Failed to generate HMAC");
    }

    HMAC_CTX_free(ctx);
    print_hex("[Client] Generated HMAC", hmac, *hmac_len);
}

// Function to derive shared secret using ECC
void derive_shared_secret(const char *server_pub_key_file, const char *client_priv_key_file,
                          unsigned char *shared_secret, size_t *shared_secret_len) {
    FILE *server_pub_fp = fopen(server_pub_key_file, "r");
    FILE *client_priv_fp = fopen(client_priv_key_file, "r");
    if (!server_pub_fp || !client_priv_fp) {
        perror("[Client] Failed to open ECC key files");
        exit(EXIT_FAILURE);
    }

    EVP_PKEY *server_pub_key = PEM_read_PUBKEY(server_pub_fp, NULL, NULL, NULL);
    EVP_PKEY *client_priv_key = PEM_read_PrivateKey(client_priv_fp, NULL, NULL, NULL);
    fclose(server_pub_fp);
    fclose(client_priv_fp);

    if (!server_pub_key || !client_priv_key) {
        perror("[Client] Failed to load ECC keys");
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(client_priv_key, NULL);
    if (!ctx) {
        perror("[Client] Failed to create EVP_PKEY context");
        exit(EXIT_FAILURE);
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        perror("[Client] Failed to initialize key derivation");
        EVP_PKEY_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (EVP_PKEY_derive_set_peer(ctx, server_pub_key) <= 0) {
        perror("[Client] Failed to set peer key for derivation");
        EVP_PKEY_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (EVP_PKEY_derive(ctx, NULL, shared_secret_len) <= 0) {
        perror("[Client] Failed to determine shared secret length");
        EVP_PKEY_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (EVP_PKEY_derive(ctx, shared_secret, shared_secret_len) <= 0) {
        perror("[Client] Failed to derive shared secret");
        EVP_PKEY_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(server_pub_key);
    EVP_PKEY_free(client_priv_key);
    print_hex("[Client] Derived Shared Secret", shared_secret, *shared_secret_len);
}

//////////////////////////////////////////////////////////////////////////////////////////////
void start_client(const char *server_ip, int port) {
    struct timespec start, end, t_start, t_end, s1_start, s1_end, s2_start, s2_end;
    double total_time = 0, time_signing = 0, time_verification = 0, time_hmac = 0, time_hmac_ver = 0, time_encryption = 0, time_decryption = 0, time_local_key = 0, time_step1 = 0, time_step2 = 0;

    int client_fd;
    struct sockaddr_in server_address;

    // Create the socket
    if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("[Client] Socket creation failed");
        exit(EXIT_FAILURE);
    }

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    if (inet_pton(AF_INET, server_ip, &server_address.sin_addr) <= 0) {
        perror("[Client] Invalid server address");
        close(client_fd);
        exit(EXIT_FAILURE);
    }

    // Connect to the server
    if (connect(client_fd, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        perror("[Client] Connection to server failed");
        close(client_fd);
        exit(EXIT_FAILURE);
    }

    printf("[Client] Connected to server\n");

    ///////////////////////////////////////////////////////////////////////////////
    // Step 1: Receive and verify the server's certificate
    unsigned char cert_buffer[BUFFER_SIZE] = {0};

    clock_gettime(CLOCK_MONOTONIC, &t_start); // Start total client time
    clock_gettime(CLOCK_MONOTONIC, &s1_start);
    clock_gettime(CLOCK_MONOTONIC, &start); 

    if (recv(client_fd, cert_buffer, BUFFER_SIZE, 0) <= 0) {
        perror("[Client] Failed to receive server certificate");
        close(client_fd);
        exit(EXIT_FAILURE);
    }

    FILE *ca_fp = fopen("./certs/ca_certificate.pem", "r");
    if (!ca_fp) {
        perror("[Client] Failed to open CA certificate");
        close(client_fd);
        exit(EXIT_FAILURE);
    }

    X509 *ca_cert = PEM_read_X509(ca_fp, NULL, NULL, NULL);
    fclose(ca_fp);

    BIO *bio = BIO_new_mem_buf(cert_buffer, -1);
    X509 *server_cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!server_cert || !verify_certificate(server_cert, ca_cert)) {
        fprintf(stderr, "[Client] Server certificate verification failed. Exiting...\n");
        close(client_fd);
        exit(EXIT_FAILURE);
    }
    clock_gettime(CLOCK_MONOTONIC, &end); // End timing for signing or verification
    time_verification += (end.tv_sec - start.tv_sec) * 1e3 + (end.tv_nsec - start.tv_nsec) / 1e6; // Time in ms

    printf("[Client] Server certificate verified successfully\n");

    ///////////////////////////////////////////////////////////////////////////
    // Step 2: Derive the shared secret
    unsigned char shared_secret[32];
    size_t shared_secret_len = sizeof(shared_secret);

    clock_gettime(CLOCK_MONOTONIC, &start); // Start timing key derivation
    derive_shared_secret("./keys/server_public_key.pem", "./keys/client_private_key.pem",
                     shared_secret, &shared_secret_len);

    unsigned char local_key[32]; // SHA-3-256 output is 32 bytes
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "[Client] Failed to create EVP_MD_CTX\n");
        close(client_fd);
        exit(EXIT_FAILURE);
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL) != 1 ||
        EVP_DigestUpdate(mdctx, shared_secret, shared_secret_len) != 1 ||
        EVP_DigestFinal_ex(mdctx, local_key, NULL) != 1) {
        fprintf(stderr, "[Client] SHA-3-256 computation failed\n");
        EVP_MD_CTX_free(mdctx);
        close(client_fd);
        exit(EXIT_FAILURE);
    }
    clock_gettime(CLOCK_MONOTONIC, &end); // End timing local key derivation
    time_local_key += (end.tv_sec - start.tv_sec) * 1e3 + (end.tv_nsec - start.tv_nsec) / 1e6; // Time in ms

    EVP_MD_CTX_free(mdctx);

    printf("[Client] Derived Local Key:\n");
    print_hex(NULL, local_key, sizeof(local_key));

    ///////////////////////////////////////////////////////////////////////////

    // Step 3: Generate nonce and encrypt message
    unsigned char nonce[16];
    RAND_bytes(nonce, sizeof(nonce));
    print_hex("[Client] Generated Nonce", nonce, sizeof(nonce));

    clock_gettime(CLOCK_MONOTONIC, &start); // Start timing key derivation
    unsigned char cert_buffer_local[BUFFER_SIZE] = {0};
    FILE *client_cert_fp = fopen("./certs/client_certificate.pem", "r");
    if (!client_cert_fp) {
        perror("[Client] Failed to open client certificate");
        close(client_fd);
        exit(EXIT_FAILURE);
    }

    size_t cert_len = fread(cert_buffer_local, 1, BUFFER_SIZE, client_cert_fp);
    fclose(client_cert_fp);
    clock_gettime(CLOCK_MONOTONIC, &end); // End timing key derivation
    time_signing += (end.tv_sec - start.tv_sec) * 1e3 + (end.tv_nsec - start.tv_nsec) / 1e6; // Time in ms

    unsigned char concatenated_message[BUFFER_SIZE] = {0};
    size_t concatenated_len = cert_len + sizeof(nonce);
    memcpy(concatenated_message, cert_buffer_local, cert_len);
    memcpy(concatenated_message + cert_len, nonce, sizeof(nonce));

    unsigned char encrypted_message[BUFFER_SIZE] = {0};
    clock_gettime(CLOCK_MONOTONIC, &start); // Start timing encryption
    int encrypted_len = aes_encrypt(concatenated_message, concatenated_len, shared_secret, NULL, encrypted_message);
    clock_gettime(CLOCK_MONOTONIC, &end); // End timing encryption
    time_encryption += (end.tv_sec - start.tv_sec) * 1e3 + (end.tv_nsec - start.tv_nsec) / 1e6; // Time in ms
    clock_gettime(CLOCK_MONOTONIC, &s1_end); // End timing encryption
    time_step1 += (s1_end.tv_sec - s1_start.tv_sec) * 1e3 + (s1_end.tv_nsec - s1_start.tv_nsec) / 1e6;

    if (encrypted_len <= 0) {
        fprintf(stderr, "[Client] Encryption failed\n");
        close(client_fd);
        exit(EXIT_FAILURE);
    }

    // Send the encrypted message
    if (send(client_fd, encrypted_message, encrypted_len, 0) <= 0) {
        perror("[Client] Failed to send encrypted message");
        close(client_fd);
        exit(EXIT_FAILURE);
    }

    printf("[Client] Sent encrypted message to server\n");

    // Wait for READY message from server
    char ready_buffer[16] = {0};
    if (recv(client_fd, ready_buffer, sizeof(ready_buffer), 0) <= 0) {
        perror("[Client] Failed to receive READY message");
        close(client_fd);
        exit(EXIT_FAILURE);
    }

    if (strcmp(ready_buffer, "READY") != 0) {
        fprintf(stderr, "[Client] Unexpected message from server: %s\n", ready_buffer);
        close(client_fd);
        exit(EXIT_FAILURE);
    }

    // Generate HMAC for the encrypted message
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmac_len = 0;
    clock_gettime(CLOCK_MONOTONIC, &start); // Start timing HMAC generation
    generate_hmac(shared_secret, encrypted_message, encrypted_len, hmac, &hmac_len);
    clock_gettime(CLOCK_MONOTONIC, &end); // End timing HMAC generation
    time_hmac += (end.tv_sec - start.tv_sec) * 1e3 + (end.tv_nsec - start.tv_nsec) / 1e6; // Time in ms

    // Send the HMAC
    if (send(client_fd, hmac, hmac_len, 0) <= 0) {
        perror("[Client] Failed to send HMAC");
        close(client_fd);
        exit(EXIT_FAILURE);
    }

    printf("[Client] Sent HMAC to server\n");

        ////////////////////////////////////////////////////////////////////////////
    // Step 4: Receive encrypted message from server
    unsigned char encrypted_message_step4[BUFFER_SIZE] = {0};
    int encrypted_len_step4 = recv(client_fd, encrypted_message_step4, BUFFER_SIZE, 0);
    if (encrypted_len_step4 <= 0) {
        perror("[Client] Failed to receive encrypted message");
        close(client_fd);
        exit(EXIT_FAILURE);
    }
    printf("[Client] Received Encrypted Message:\n");
    print_hex(NULL, encrypted_message_step4, encrypted_len_step4);

    // Send READY message to server before receiving HMAC
    const char *ready_message_step4 = "READY";
    if (send(client_fd, ready_message_step4, strlen(ready_message_step4), 0) <= 0) {
        perror("[Client] Failed to send READY message to server");
        close(client_fd);
        exit(EXIT_FAILURE);
    }

    // Receive HMAC from server
    unsigned char received_hmac_step4[EVP_MAX_MD_SIZE];
    int hmac_len_step4 = recv(client_fd, received_hmac_step4, 32, 0); // Expect 32 bytes for HMAC-SHA256
    if (hmac_len_step4 <= 0) {
        perror("[Client] Failed to receive HMAC");
        close(client_fd);
        exit(EXIT_FAILURE);
    }
    printf("[Client] Received HMAC:\n");
    print_hex(NULL, received_hmac_step4, hmac_len_step4);

    // Verify HMAC
    unsigned char calculated_hmac_step4[EVP_MAX_MD_SIZE];
    unsigned int calculated_hmac_len_step4 = 0;
    clock_gettime(CLOCK_MONOTONIC, &start); // Start timing HMAC verification
    clock_gettime(CLOCK_MONOTONIC, &s2_start);
    generate_hmac(shared_secret, encrypted_message_step4, encrypted_len_step4, calculated_hmac_step4, &calculated_hmac_len_step4);

    if (memcmp(received_hmac_step4, calculated_hmac_step4, hmac_len_step4) != 0) {
        fprintf(stderr, "[Client] HMAC verification failed. Exiting...\n");
        close(client_fd);
        exit(EXIT_FAILURE);
    }
    clock_gettime(CLOCK_MONOTONIC, &end); // End timing HMAC verification
    time_hmac_ver += (end.tv_sec - start.tv_sec) * 1e3 + (end.tv_nsec - start.tv_nsec) / 1e6; // Time in ms
    printf("[Client] HMAC verified successfully\n");

    // Decrypt the message
    unsigned char decrypted_message_step4[BUFFER_SIZE] = {0};
    clock_gettime(CLOCK_MONOTONIC, &start); // Start timing decryption
    int decrypted_len_step4 = aes_decrypt(encrypted_message_step4, encrypted_len_step4, shared_secret, NULL, decrypted_message_step4);
    clock_gettime(CLOCK_MONOTONIC, &end); // End timing decryption
    time_decryption += (end.tv_sec - start.tv_sec) * 1e3 + (end.tv_nsec - start.tv_nsec) / 1e6; // Time in ms

    if (decrypted_len_step4 <= 0) {
        fprintf(stderr, "[Client] Decryption failed\n");
        close(client_fd);
        exit(EXIT_FAILURE);
    }

    // Parse decrypted data
    unsigned char symmetric_key_step4[32]; // Length for AES-256 key
    unsigned char received_nonce_step4[16];
    time_t received_time_step4;
    unsigned char received_id_step4[BUFFER_SIZE] = {0};

    size_t offset_step4 = 0;
    memcpy(symmetric_key_step4, decrypted_message_step4 + offset_step4, sizeof(symmetric_key_step4));
    offset_step4 += sizeof(symmetric_key_step4);

    memcpy(received_nonce_step4, decrypted_message_step4 + offset_step4, sizeof(received_nonce_step4));
    offset_step4 += sizeof(received_nonce_step4);

    memcpy(&received_time_step4, decrypted_message_step4 + offset_step4, sizeof(received_time_step4));
    offset_step4 += sizeof(received_time_step4);

    size_t id_len_step4 = decrypted_len_step4 - offset_step4;
    memcpy(received_id_step4, decrypted_message_step4 + offset_step4, id_len_step4);

    printf("[Client] Decrypted Symmetric Key:\n");
    print_hex(NULL, symmetric_key_step4, sizeof(symmetric_key_step4));
    print_hex("[Client] Decrypted Nonce", received_nonce_step4, sizeof(received_nonce_step4));
    printf("[Client] Decrypted Time: %s", ctime(&received_time_step4)); // Convert time to readable format
    printf("[Client] Decrypted ID: %s\n", received_id_step4);

    // Verify Nonce
    if (memcmp(received_nonce_step4, nonce, sizeof(nonce)) != 0) {
        fprintf(stderr, "[Client] Nonce verification failed. Exiting...\n");
        close(client_fd);
        exit(EXIT_FAILURE);
    }
    printf("[Client] Nonce verified successfully\n");

    // Verify ID
    const char *expected_id = "Server123"; // Replace with actual expected ID
    if (strncmp((const char *)received_id_step4, expected_id, id_len_step4) != 0) {
        fprintf(stderr, "[Client] ID verification failed. Expected: %s, Received: %s\n", expected_id, received_id_step4);
        close(client_fd);
        exit(EXIT_FAILURE);
    }
    printf("[Client] ID verified successfully\n");

    clock_gettime(CLOCK_MONOTONIC, &s2_end); // End total time
    time_step2 += (s2_end.tv_sec - s2_start.tv_sec) * 1e3 + (s2_end.tv_nsec - s2_start.tv_nsec) / 1e6;

    // Store symmetric key for Time T
    printf("[Client] Storing symmetric key for time T...\n");

    clock_gettime(CLOCK_MONOTONIC, &end); // End total time
    clock_gettime(CLOCK_MONOTONIC, &t_end); // End total time
    total_time += (t_end.tv_sec - t_start.tv_sec) * 1e3 + (t_end.tv_nsec - t_start.tv_nsec) / 1e6;

    printf("[Client] Timing Summary:\n");
    printf("    Signing/Key Derivation Time: %.3f ms\n", time_signing);
    printf("    Verification Time: %.3f ms\n", time_verification);
    printf("    Local Key Derivation Time: %.3f ms\n", time_local_key);
    printf("    Encryption Time: %.3f ms\n", time_encryption);
    printf("    Decryption Time: %.3f ms\n", time_decryption);
    printf("    HMAC Time: %.3f ms\n", time_hmac);
    printf("    HMAC Time Verifcation: %.3f ms\n", time_hmac_ver);
    printf("    Total Client Time: %.3f ms\n", total_time);

    printf("    Step2: %.3f ms\n", time_step1);
    printf("    Step4: %.3f ms\n", time_step2);

    close(client_fd);
}



int main() {
    printf("[Client] Starting...\n");
    start_client(SERVER_IP, PORT);
    return 0;
}
