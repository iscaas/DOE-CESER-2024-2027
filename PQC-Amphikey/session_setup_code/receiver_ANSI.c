#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <memory>

// ANSI C12.22 Adapter Headers
#include <MCOM/ProtocolC1222.h>
#include <MCOM/ChannelSocket.h>
#include <MCOM/MCOMExceptions.h>

// Your original cryptographic headers
#include <sodium.h>
#include "api_mlkem.h"
#include "api_raccoon.h"
#include "constants.h"
#include "cipher.h"

// Forward declarations from your original code
extern "C" void nist_randombytes_init(unsigned char *entropy_input, unsigned char *personalization_string, int security_strength);
extern "C" void randombytes(unsigned char *x, unsigned long long xlen);

void PQCLEAN_randombytes(unsigned char *buf, size_t nbytes) {
    randombytes(buf, (unsigned long long)nbytes);
}

// (Helper functions: print_hex, file I/O, HKDF, etc., are placed here)
// Helper function to print bytes as hex
void print_hex(const char* label, const unsigned char* data, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}
// (Include the same helper functions as the sender: read_binary_data_from_file, read_hex_key_from_file, HKDF)
// HKDF Implementation
int hkdf_sha256_extract(unsigned char *prk, const unsigned char *salt, size_t salt_len, const unsigned char *ikm, size_t ikm_len);
int hkdf_sha256_expand(unsigned char *okm, size_t okm_len, const unsigned char *prk, size_t prk_len, const unsigned char *info, size_t info_len);
// (Full HKDF function bodies from your original file go here)
int hkdf_sha256_extract(unsigned char *prk,
                        const unsigned char *salt, size_t salt_len,
                        const unsigned char *ikm, size_t ikm_len) {
    unsigned char zero_key_salt[crypto_auth_hmacsha256_KEYBYTES];
    const unsigned char *hmac_key = salt;
    if (salt == NULL || salt_len == 0) {
        sodium_memzero(zero_key_salt, sizeof(zero_key_salt));
        hmac_key = zero_key_salt;
    }
    return crypto_auth_hmacsha256(prk, ikm, ikm_len, hmac_key);
}

int hkdf_sha256_expand(unsigned char *okm, size_t okm_len,
                       const unsigned char *prk, size_t prk_len,
                       const unsigned char *info, size_t info_len) {
    if (okm_len == 0) return 0;
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
    }
    return 0;
}


// This function encapsulates your original decryption and verification logic
void process_secure_payload(const std::vector<unsigned char>& payload) {
    std::cout << "\n--- Received secure payload. Processing... ---\n";
    print_hex("Received Payload", payload.data(), payload.size());

    if (payload.size() < (NONCE_SIZE + TAG_SIZE)) {
        std::cerr << "Received payload is too small to be valid." << std::endl;
        return;
    }

    // ... (All key loading, signature verification, KEM decapsulation, HKDF, and AEAD logic) ...
    // ... This logic from your receiver_protocol.c main function is assumed to be here. ...
    // The key change is that the payload comes from the function argument, not a file.

    // --- AEAD Decryption using ACORN ---
    // (This is a simplified representation of your full crypto setup)
    unsigned char final_shared_secret_prime[32];
    randombytes(final_shared_secret_prime, sizeof(final_shared_secret_prime)); // Placeholder for your HKDF result

    const unsigned char* acorn_nonce_loaded = payload.data();
    const unsigned char* encrypted_message_part = payload.data() + NONCE_SIZE;
    size_t encrypted_message_len = payload.size() - NONCE_SIZE - TAG_SIZE;
    const unsigned char* received_tag = payload.data() + NONCE_SIZE + encrypted_message_len;

    unsigned char acorn_key_prime[KEY_SIZE];
    memcpy(acorn_key_prime, final_shared_secret_prime, KEY_SIZE);

    std::unique_ptr<unsigned char[]> decrypted_message(new unsigned char[encrypted_message_len + 1]);
    memcpy(decrypted_message.get(), encrypted_message_part, encrypted_message_len);

    uint8_t acorn_state_receiver[STATE_SIZE];
    
    Initialize(acorn_state_receiver, acorn_key_prime, acorn_nonce_loaded);
    ProcessCiphertext(acorn_state_receiver, decrypted_message.get(), encrypted_message_len);
    Finalize(acorn_state_receiver, acorn_key_prime);

    int tag_verification_result = TagVerification(acorn_state_receiver, received_tag);

    if (tag_verification_result == 0) {
        std::cout << "\n>>> ACORN AEAD Decryption SUCCESSFUL! Tag Verified. <<<\n";
        decrypted_message[encrypted_message_len] = '\0';
        print_hex("Decrypted Plaintext", decrypted_message.get(), encrypted_message_len);
        std::cout << "Decrypted Message: " << decrypted_message.get() << std::endl;
    } else {
        std::cerr << "\n>>> ACORN AEAD Decryption FAILED! Tag verification failed. <<<\n";
    }
}


int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "USAGE: " << argv[0] << " <port_to_listen_on>" << std::endl;
        return 1;
    }

    int port = std::stoi(argv[1]);

    // Initialize Libsodium and Raccoon's RNG
    if (sodium_init() < 0) {
        std::cerr << "Libsodium couldn't be initialized!" << std::endl;
        return 1;
    }
    unsigned char entropy_input[48];
    for (int i=0; i<48; ++i) entropy_input[i] = 'R' + i;
    nist_randombytes_init(entropy_input, (unsigned char *)"HybridReceiver", 256);
    std::cout << "Libsodium and RNG initialized." << std::endl;
    
    try {
        std::cout << "\n--- Initializing ANSI C12.22 Receiver (Server) ---\n";
        MProtocolC1222 protocol;
        MChannelSocket channel;

        protocol.SetChannel(&channel);
        protocol.SetCalledApTitle("C1222_RECEIVER"); // The ApTitle the sender will call

        std::cout << "Listening for C12.22 connections on port " << port << "..." << std::endl;
        channel.Listen(port);

        // Accept one connection and then exit. A real server would loop.
        MChannel* clientChannel = channel.Accept();
        if (clientChannel) {
             std::cout << "Incoming connection accepted." << std::endl;
             protocol.SetChannel(clientChannel); // Use the new channel for the connected client
             protocol.AcceptSession(); // Handle the session negotiation
             std::cout << "C12.22 session established." << std::endl;

             // Read the data from the user-defined table we agreed on
             int secure_table_id = 65001;
             MByteString received_data;
             std::cout << "Reading encrypted payload from table " << secure_table_id << "..." << std::endl;
             protocol.Read(received_data, secure_table_id);

             if (received_data.IsEmpty()) {
                 std::cerr << "No data received from the client." << std::endl;
             } else {
                 // Convert MByteString to std::vector to process it
                 std::vector<unsigned char> payload(received_data.begin(), received_data.end());
                 process_secure_payload(payload);
             }

             protocol.Disconnect();
             delete clientChannel; // Clean up the client channel
             std::cout << "Session finished." << std::endl;
        }

    } catch (const MException& e) {
        std::cerr << "A C12.22 error occurred: " << e.GetWhat() << std::endl;
        return 1;
    }

    return 0;
}
