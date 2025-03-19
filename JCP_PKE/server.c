#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

#define PORT 3000
#define BUFFER_SIZE 1024

// Function declarations
void print_hex(const char *label, const unsigned char *data, int length);
void handle_error(const char *msg);
int verify_certificate(X509 *cert, X509 *ca_cert);
void derive_shared_secret(const char *client_pub_key_file, const char *server_priv_key_file,
                          unsigned char *shared_secret, size_t *shared_secret_len);
int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                const unsigned char *key, const unsigned char *iv, unsigned char *plaintext);

// Helper function to print data in hex format
void print_hex(const char *label, const unsigned char *data, int length) {
    printf("%s (hex): ", label);
    for (int i = 0; i < length; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

// Function to calculate elapsed time
double calculate_elapsed_time(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1e6;
}

// Handle error and exit
void handle_error(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
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

// Derive shared secret using ECC
void derive_shared_secret(const char *client_pub_key_file, const char *server_priv_key_file,
                          unsigned char *shared_secret, size_t *shared_secret_len) {
    FILE *client_pub_fp = fopen(client_pub_key_file, "r");
    FILE *server_priv_fp = fopen(server_priv_key_file, "r");

    if (!client_pub_fp || !server_priv_fp) {
        handle_error("[Server] Failed to open ECC key files");
    }

    EVP_PKEY *client_pub_key = PEM_read_PUBKEY(client_pub_fp, NULL, NULL, NULL);
    EVP_PKEY *server_priv_key = PEM_read_PrivateKey(server_priv_fp, NULL, NULL, NULL);
    fclose(client_pub_fp);
    fclose(server_priv_fp);

    if (!client_pub_key || !server_priv_key) {
        handle_error("[Server] Failed to load ECC keys");
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(server_priv_key, NULL);
    if (!ctx) {
        handle_error("[Server] Failed to create EVP_PKEY context");
    }

    if (EVP_PKEY_derive_init(ctx) <= 0 || EVP_PKEY_derive_set_peer(ctx, client_pub_key) <= 0) {
        handle_error("[Server] Key derivation initialization failed");
    }

    if (EVP_PKEY_derive(ctx, NULL, shared_secret_len) <= 0) {
        handle_error("[Server] Failed to determine shared secret length");
    }

    if (EVP_PKEY_derive(ctx, shared_secret, shared_secret_len) <= 0) {
        handle_error("[Server] Failed to derive shared secret");
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(client_pub_key);
    EVP_PKEY_free(server_priv_key);

    print_hex("[Server] Derived Shared Secret", shared_secret, *shared_secret_len);
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
    print_hex("[Server] Generated HMAC", hmac, *hmac_len);
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

// Server function
void start_server(int port) {
    int server_fd, client_fd;
    struct sockaddr_in server_address, client_address;
    socklen_t client_address_len = sizeof(client_address);
    unsigned char nonce[16];
    unsigned char hmac[EVP_MAX_MD_SIZE];
    //unsigned int hmac_len = 0;
    unsigned char concatenated_message[BUFFER_SIZE] = {0};

    struct timespec start, end, t_start, t_end, s1_start, s1_end, s2_start, s2_end;
    double total_time = 0, time_signing = 0, time_verification = 0, time_hmac = 0, time_hmac_ver = 0, time_encryption = 0, time_decryption = 0, time_local_key = 0, time_step1 = 0, time_step2 = 0;


    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        handle_error("[Server] Socket creation failed");
    }

    // Enable SO_REUSEADDR to reuse the address/port
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("[Server] setsockopt failed");
        exit(EXIT_FAILURE);
    }

    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        handle_error("[Server] Bind failed");
    }

    if (listen(server_fd, 3) < 0) {
        handle_error("[Server] Listen failed");
    }

    printf("[Server] Listening on port %d...\n", port);

    while (1) {
        if ((client_fd = accept(server_fd, (struct sockaddr *)&client_address, &client_address_len)) < 0) {
            perror("[Server] Accept failed");
            continue;
        }

        unsigned char buffer[BUFFER_SIZE] = {0};
        /////////////////////////////////////////////////////////////////////////

        clock_gettime(CLOCK_MONOTONIC, &t_start);
        // Step 1: Send server certificate to client
        clock_gettime(CLOCK_MONOTONIC, &start);
        FILE *server_cert_fp = fopen("./certs/server_certificate.pem", "r");
        if (!server_cert_fp) {
            perror("[Server] Failed to open server certificate");
            close(client_fd);
            continue;
        }

        unsigned char cert_buffer[BUFFER_SIZE] = {0};
        int cert_len = fread(cert_buffer, 1, BUFFER_SIZE, server_cert_fp);
        fclose(server_cert_fp);
        clock_gettime(CLOCK_MONOTONIC, &end); // End timing for signing or verification
        time_signing += (end.tv_sec - start.tv_sec) * 1e3 + (end.tv_nsec - start.tv_nsec) / 1e6; // Time in ms


        if (send(client_fd, cert_buffer, cert_len, 0) <= 0) {
            perror("[Server] Failed to send server certificate");
            close(client_fd);
            continue;
        }
        printf("[Server] Sent server certificate to client\n");

        /////////////////////////////////////////////////////////////////////////
        // Step 2: Derive the shared secret using the server's private key and the client's public key
        unsigned char shared_secret[32];
        size_t shared_secret_len = sizeof(shared_secret);

        clock_gettime(CLOCK_MONOTONIC, &start); // Start timing key derivation
        clock_gettime(CLOCK_MONOTONIC, &s2_start);
        // Derive the shared secret (assuming the function sets the shared_secret directly)
        derive_shared_secret("./keys/client_public_key.pem", "./keys/server_private_key.pem",
                     shared_secret, &shared_secret_len);

        unsigned char local_key[32]; // SHA-3-256 output is 32 bytes
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        if (!mdctx) {
            fprintf(stderr, "[Server] Failed to create EVP_MD_CTX\n");
            close(client_fd);
            return;
        }

        if (EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL) != 1 ||
            EVP_DigestUpdate(mdctx, shared_secret, shared_secret_len) != 1 ||
            EVP_DigestFinal_ex(mdctx, local_key, NULL) != 1) {
            fprintf(stderr, "[Server] SHA-3-256 computation failed\n");
            EVP_MD_CTX_free(mdctx);
            close(client_fd);
            return;
        }
        clock_gettime(CLOCK_MONOTONIC, &end); // End timing local key derivation
        time_local_key += (end.tv_sec - start.tv_sec) * 1e3 + (end.tv_nsec - start.tv_nsec) / 1e6; // Time in ms

        EVP_MD_CTX_free(mdctx);

        // Print the derived shared secret
        printf("[Server] Derived Local Key:\n");
        print_hex(NULL, local_key, sizeof(local_key));

        /////////////////////////////////////////////////////////////////////////
        // Step 3: Receive encrypted message from client
        unsigned char encrypted_message[BUFFER_SIZE] = {0};
        unsigned char received_hmac[EVP_MAX_MD_SIZE];
        unsigned char decrypted_message[BUFFER_SIZE] = {0};

        // Receive encrypted message
        int encrypted_len = recv(client_fd, encrypted_message, BUFFER_SIZE, 0);
        if (encrypted_len <= 0) {
            perror("[Server] Failed to receive encrypted message");
            close(client_fd);
            return;
        }
        printf("[Server] Received Encrypted Message:\n");
        print_hex(NULL, encrypted_message, encrypted_len);

        // Send READY message to client
        const char *ready_message = "READY";
        if (send(client_fd, ready_message, strlen(ready_message), 0) <= 0) {
            perror("[Server] Failed to send READY message");
            close(client_fd);
            return;
        }
        //printf("[Server] Sent READY message to client\n");

        // Receive HMAC
        int hmac_len = recv(client_fd, received_hmac, EVP_MAX_MD_SIZE, 0);
        if (hmac_len <= 0) {
            perror("[Server] Failed to receive HMAC");
            close(client_fd);
            return;
        }
        printf("[Server] Received HMAC:\n");
        print_hex(NULL, received_hmac, hmac_len);

        // Verify HMAC
        unsigned char calculated_hmac[EVP_MAX_MD_SIZE];
        unsigned int calculated_hmac_len = 0;
        clock_gettime(CLOCK_MONOTONIC, &start);
        generate_hmac(shared_secret, encrypted_message, encrypted_len, calculated_hmac, &calculated_hmac_len);

        if (memcmp(received_hmac, calculated_hmac, hmac_len) != 0) {
            fprintf(stderr, "[Server] HMAC verification failed. Closing connection.\n");
            close(client_fd);
            return;
        }
        clock_gettime(CLOCK_MONOTONIC, &end); // End timing HMAC verification
        time_hmac_ver += (end.tv_sec - start.tv_sec) * 1e3 + (end.tv_nsec - start.tv_nsec) / 1e6; // Time in ms
        printf("[Server] HMAC verified successfully\n");

        // Decrypt the message
        clock_gettime(CLOCK_MONOTONIC, &start);
        int decrypted_len = aes_decrypt(encrypted_message, encrypted_len, shared_secret, NULL, decrypted_message);
        if (decrypted_len <= 0) {
            fprintf(stderr, "[Server] Decryption failed\n");
            close(client_fd);
            return;
        }
        clock_gettime(CLOCK_MONOTONIC, &end); // End timing decryption
        time_decryption += (end.tv_sec - start.tv_sec) * 1e3 + (end.tv_nsec - start.tv_nsec) / 1e6; // Time in ms

        // Parse decrypted data
        unsigned char received_cert[BUFFER_SIZE] = {0};
        unsigned char received_nonce[16];
        memcpy(received_cert, decrypted_message, decrypted_len - sizeof(received_nonce));
        memcpy(received_nonce, decrypted_message + decrypted_len - sizeof(received_nonce), sizeof(received_nonce));

        printf("[Server] Decrypted Client Certificate:\n%s\n", received_cert);
        print_hex("[Server] Decrypted Nonce", received_nonce, sizeof(received_nonce));

        // Verify the client certificate
        clock_gettime(CLOCK_MONOTONIC, &start);
        FILE *ca_fp = fopen("./certs/ca_certificate.pem", "r");
        if (!ca_fp) {
            fprintf(stderr, "[Server] Failed to open CA certificate\n");
            close(client_fd);
            return;
        }

        X509 *ca_cert = PEM_read_X509(ca_fp, NULL, NULL, NULL);
        fclose(ca_fp);

        BIO *bio = BIO_new_mem_buf(received_cert, -1);
        X509 *client_cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        BIO_free(bio);

        if (!client_cert || !verify_certificate(client_cert, ca_cert)) {
            fprintf(stderr, "[Server] Client certificate verification failed. Closing connection.\n");
            close(client_fd);
            return;
        }
        clock_gettime(CLOCK_MONOTONIC, &end); // End timing for signing or verification
        time_verification += (end.tv_sec - start.tv_sec) * 1e3 + (end.tv_nsec - start.tv_nsec) / 1e6; // Time in ms

        printf("[Server] Client certificate verified successfully\n");

        ///////////////////////////////////////////////////////////////////////////////////////////////
        // Step 4: Generate symmetric key for a specified time T
        unsigned char symmetric_key_step4[32]; // Length for AES-256 key
        clock_gettime(CLOCK_MONOTONIC, &s1_start);
        RAND_bytes(symmetric_key_step4, sizeof(symmetric_key_step4));
        print_hex("[Server] Generated Symmetric Key", symmetric_key_step4, sizeof(symmetric_key_step4));

        // Define time T and ID
        time_t current_time_step4 = time(NULL);
        unsigned char time_buffer_step4[sizeof(current_time_step4)];
        memcpy(time_buffer_step4, &current_time_step4, sizeof(current_time_step4)); // Serialize time
        clock_gettime(CLOCK_MONOTONIC, &s1_end); // End timing for signing or verification
        time_step1 += (s1_end.tv_sec - s1_start.tv_sec) * 1e3 + (s1_end.tv_nsec - s1_start.tv_nsec) / 1e6; // Time in ms

        const char *id_step4 = "Server123"; // Example ID
        size_t id_len_step4 = strlen(id_step4);

        // Concatenate symmetric key, nonce, time, and ID
        unsigned char data_to_encrypt_step4[BUFFER_SIZE] = {0};
        size_t offset_step4 = 0;

        // Append symmetric key
        memcpy(data_to_encrypt_step4 + offset_step4, symmetric_key_step4, sizeof(symmetric_key_step4));
        offset_step4 += sizeof(symmetric_key_step4);

        // Append nonce
        memcpy(data_to_encrypt_step4 + offset_step4, received_nonce, sizeof(received_nonce));
        offset_step4 += sizeof(received_nonce);

        // Append time
        memcpy(data_to_encrypt_step4 + offset_step4, time_buffer_step4, sizeof(time_buffer_step4));
        offset_step4 += sizeof(time_buffer_step4);

        // Append ID
        memcpy(data_to_encrypt_step4 + offset_step4, id_step4, id_len_step4);
        offset_step4 += id_len_step4;

        // Encrypt the data
        unsigned char encrypted_data_step4[BUFFER_SIZE] = {0};
        clock_gettime(CLOCK_MONOTONIC, &start); // Start timing encryption
        int encrypted_len_step4 = aes_encrypt(data_to_encrypt_step4, offset_step4, shared_secret, NULL, encrypted_data_step4);
        if (encrypted_len_step4 <= 0) {
            fprintf(stderr, "[Server] Encryption of symmetric key data failed\n");
            close(client_fd);
            return;
        }
        clock_gettime(CLOCK_MONOTONIC, &end); // End timing encryption
        time_encryption += (end.tv_sec - start.tv_sec) * 1e3 + (end.tv_nsec - start.tv_nsec) / 1e6;

        // Generate HMAC for the encrypted message
        unsigned char hmac_step4[EVP_MAX_MD_SIZE];
        unsigned int hmac_len_step4 = 0;
        clock_gettime(CLOCK_MONOTONIC, &start); 
        generate_hmac(shared_secret, encrypted_data_step4, encrypted_len_step4, hmac_step4, &hmac_len_step4);
        clock_gettime(CLOCK_MONOTONIC, &end); // End timing encryption
        time_hmac += (end.tv_sec - start.tv_sec) * 1e3 + (end.tv_nsec - start.tv_nsec) / 1e6;
        clock_gettime(CLOCK_MONOTONIC, &s2_end); // End timing encryption
        time_step2 += (s2_end.tv_sec - s2_start.tv_sec) * 1e3 + (s2_end.tv_nsec - s2_start.tv_nsec) / 1e6;

        // Send the encrypted message
        if (send(client_fd, encrypted_data_step4, encrypted_len_step4, 0) <= 0) {
            perror("[Server] Failed to send encrypted symmetric key data");
            close(client_fd);
            return;
        }

        // Wait for READY message from client before sending HMAC
        char ready_buffer_step4[16] = {0};
        if (recv(client_fd, ready_buffer_step4, sizeof(ready_buffer_step4), 0) <= 0) {
            perror("[Server] Failed to receive READY message from client");
            close(client_fd);
            return;
        }

        if (strcmp(ready_buffer_step4, "READY") != 0) {
            fprintf(stderr, "[Server] Unexpected message from client: %s\n", ready_buffer_step4);
            close(client_fd);
            return;
        }
        //printf("[Server] Received READY message from client\n");

        // Send the HMAC
        if (send(client_fd, hmac_step4, hmac_len_step4, 0) <= 0) {
            perror("[Server] Failed to send HMAC for encrypted symmetric key data");
            close(client_fd);
            return;
        }

        printf("[Server] Sent encrypted symmetric key, nonce, time, and ID with HMAC to client\n");

        clock_gettime(CLOCK_MONOTONIC, &t_end); // End total time
        total_time += (t_end.tv_sec - t_start.tv_sec) * 1e3 + (t_end.tv_nsec - t_start.tv_nsec) / 1e6;

        printf("[SERVER] Timing Summary:\n");
        printf("    Signing/Key Derivation Time: %.3f ms\n", time_signing);
        printf("    Verification Time: %.3f ms\n", time_verification);
        printf("    Local Key Derivation Time: %.3f ms\n", time_local_key);
        printf("    Encryption Time: %.3f ms\n", time_encryption);
        printf("    Decryption Time: %.3f ms\n", time_decryption);
        printf("    HMAC Time: %.3f ms\n", time_hmac);
        printf("    HMAC Time Verifcation: %.3f ms\n", time_hmac_ver);
        printf("    Total Client Time: %.3f ms\n", total_time);

        printf("    Step2: %.3f ms\n", time_step1);
        printf("    Step3: %.3f ms\n", time_step2-time_step1);

        close(client_fd);
        printf("\n\n\n");
        printf("[Server] Next client Communication Started\n");
    }

    close(server_fd);
}

int main() {
    printf("[Server] Starting...\n");
    start_server(PORT);
    return 0;
}
