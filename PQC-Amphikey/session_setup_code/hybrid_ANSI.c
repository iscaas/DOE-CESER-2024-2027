#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring> // For memcpy, strlen
#include <memory>  // For std::unique_ptr

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

// Helper to read binary data
int read_binary_data_from_file(const char* filename, unsigned char* buffer, size_t buffer_len) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error opening file for reading: " << filename << std::endl;
        return -1;
    }
    file.read(reinterpret_cast<char*>(buffer), buffer_len);
    if (!file) {
        std::cerr << "Error reading " << buffer_len << " bytes from " << filename << std::endl;
        return -1;
    }
    std::cout << "Successfully read " << buffer_len << " bytes from " << filename << std::endl;
    return 0;
}

// Helper to read hex key from file
int read_hex_key_from_file(const char* filename, unsigned char* bin_buffer, size_t bin_buffer_len) {
    std::ifstream file(filename);
    if (!file) {
        std::cerr << "Error opening hex key file: " << filename << std::endl;
        return -1;
    }
    std::string hex_str;
    file >> hex_str;
    if (sodium_hex2bin(bin_buffer, bin_buffer_len, hex_str.c_str(), hex_str.length(), NULL, NULL, NULL) != 0) {
        std::cerr << "sodium_hex2bin failed for " << filename << std::endl;
        return -1;
    }
    std::cout << "Successfully read and converted hex key from " << filename << std::endl;
    return 0;
}

// Helper to read the last line of a file
std::string read_last_line(const char* filename) {
    std::ifstream file(filename);
    if (!file) {
        std::cerr << "Error opening file to read last line: " << filename << std::endl;
        return "";
    }
    std::string last_line;
    std::string temp;
    while (std::getline(file, temp)) {
        if (!temp.empty()) {
            last_line = temp;
        }
    }
    return last_line;
}

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


// This function encapsulates your original crypto logic
std::vector<unsigned char> generate_secure_payload(const std::string& meter_data_str) {
    std::cout << "\n--- Starting Hybrid Cryptography Protocol ---\n";

    // ... (All key loading, KEM, DH, Sign, HKDF, and AEAD logic from your hybrid.c main function) ...
    // ... This logic is assumed to be here, but shortened for brevity in this example. ...
    // The key change is at the end, where instead of writing to a file, we return the payload.

    // --- AEAD Encryption using ACORN ---
    // (This is a simplified representation of your full crypto setup)
    unsigned char final_shared_secret[32];
    randombytes(final_shared_secret, sizeof(final_shared_secret)); // Placeholder for your HKDF result

    unsigned char acorn_key[KEY_SIZE];
    memcpy(acorn_key, final_shared_secret, KEY_SIZE);

    unsigned char acorn_nonce[NONCE_SIZE];
    randombytes(acorn_nonce, sizeof(acorn_nonce));

    size_t plaintext_len = meter_data_str.length();
    std::unique_ptr<unsigned char[]> message_buffer(new unsigned char[plaintext_len]);
    memcpy(message_buffer.get(), meter_data_str.c_str(), plaintext_len);

    unsigned char acorn_tag[TAG_SIZE];
    uint8_t acorn_state[STATE_SIZE];

    Initialize(acorn_state, acorn_key, acorn_nonce);
    ProcessPlaintext(acorn_state, message_buffer.get(), plaintext_len);
    Finalize(acorn_state, acorn_key);
    TagGeneration(acorn_state, acorn_tag);

    // The final payload is: NONCE || ENCRYPTED_DATA || TAG
    size_t payload_len = NONCE_SIZE + plaintext_len + TAG_SIZE;
    std::vector<unsigned char> secure_payload(payload_len);

    memcpy(secure_payload.data(), acorn_nonce, NONCE_SIZE);
    memcpy(secure_payload.data() + NONCE_SIZE, message_buffer.get(), plaintext_len);
    memcpy(secure_payload.data() + NONCE_SIZE + plaintext_len, acorn_tag, TAG_SIZE);

    std::cout << "--- Hybrid Cryptography Protocol Finished ---\n";
    print_hex("Final Secure Payload to be sent", secure_payload.data(), secure_payload.size());

    return secure_payload;
}


int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "USAGE: " << argv[0] << " <ip_address> <port>" << std::endl;
        return 1;
    }

    const char* ip_address = argv[1];
    int port = std::stoi(argv[2]);

    // Initialize Libsodium and Raccoon's RNG
    if (sodium_init() < 0) {
        std::cerr << "Libsodium couldn't be initialized!" << std::endl;
        return 1;
    }
    unsigned char entropy_input[48];
    for (int i=0; i<48; ++i) entropy_input[i] = i;
    nist_randombytes_init(entropy_input, (unsigned char *)"HybridSender", 256);
    std::cout << "Libsodium and RNG initialized." << std::endl;

    // 1. Read the smart meter data from the CSV file
    std::string meter_data = read_last_line("Meter #350012647.csv");
    if (meter_data.empty()) {
        std::cerr << "Failed to read meter data from CSV. Exiting." << std::endl;
        return 1;
    }
    std::cout << "Read meter data to be encrypted: \"" << meter_data << "\"" << std::endl;

    // 2. Generate the secure payload using your hybrid crypto logic
    std::vector<unsigned char> payload = generate_secure_payload(meter_data);
    if (payload.empty()) {
        std::cerr << "Failed to generate secure payload. Exiting." << std::endl;
        return 1;
    }

    // 3. Use C12Adapter to send the payload
    try {
        std::cout << "\n--- Initializing ANSI C12.22 Client ---\n";
        MProtocolC1222 protocol;
        MChannelSocket channel;

        protocol.SetChannel(&channel);
        protocol.GetChannel()->SetHost(ip_address);
        protocol.GetChannel()->SetPort(port);
        protocol.SetCalledApTitle("C1222_RECEIVER"); // Must match the receiver
        protocol.SetCallingApTitle("C1222_SENDER");

        std::cout << "Connecting to C12.22 receiver at " << ip_address << ":" << port << "..." << std::endl;
        protocol.Connect();
        std::cout << "C12.22 Connection successful." << std::endl;

        // In a real system, you'd write to a standard table. We'll use a
        // user-defined table ID (e.g., 65001) for our secure payload.
        int secure_table_id = 65001;
        MByteString data_to_send((const MByte*)payload.data(), payload.size());

        std::cout << "Writing encrypted payload to table " << secure_table_id << "..." << std::endl;
        protocol.Write(secure_table_id, data_to_send);
        std::cout << "Encrypted data successfully sent via ANSI C12.22." << std::endl;

        protocol.Disconnect();
        std::cout << "Disconnected." << std::endl;

    } catch (const MException& e) {
        std::cerr << "A C12.22 error occurred: " << e.GetWhat() << std::endl;
        return 1;
    }

    return 0;
}
