#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "include/ascon.h" // Include the main Ascon header

// Helper function to print hex data
void print_hex(const char* label, const uint8_t* data, uint64_t len) {
    printf("%s (%llu bytes): ", label, (unsigned long long)len);
    for (uint64_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    printf("--- Ascon-128 AEAD Encryption/Decryption Example ---\n\n");

    // 1. SETUP: Define key, nonce, data, and buffers
    // =================================================

    // Define a 128-bit (16-byte) secret key
    const uint8_t secret_key[ASCON_AEAD128_KEY_LEN] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    // Define a 128-bit (16-byte) nonce (must be unique for each use with the same key)
    const uint8_t nonce[ASCON_AEAD_NONCE_LEN] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    // Define some plaintext data to encrypt
    const uint8_t plaintext[] = "This is a secret message!";
    const uint64_t plaintext_len = sizeof(plaintext) - 1; // Exclude null terminator

    // Define some associated data (AD), which is authenticated but not encrypted
    const uint8_t associated_data[] = "Metadata";
    const uint64_t ad_len = sizeof(associated_data) - 1;

    // Buffers for the output
    // The ciphertext buffer must be large enough for the plaintext + the authentication tag
    uint8_t ciphertext[sizeof(plaintext) + ASCON_AEAD_TAG_LEN];
    uint64_t ciphertext_len = 0;

    uint8_t decrypted_text[sizeof(plaintext)];
    uint64_t decrypted_text_len = 0;

    print_hex("Secret Key", secret_key, ASCON_AEAD128_KEY_LEN);
    print_hex("Nonce", nonce, ASCON_AEAD_NONCE_LEN);
    print_hex("Plaintext", plaintext, plaintext_len);
    print_hex("Associated Data", associated_data, ad_len);
    printf("\n");

    // 2. ENCRYPTION
    // =================================================
    printf("Encrypting data...\n");
    

    int result = ascon_aead128_encrypt(
        ciphertext, &ciphertext_len,
        plaintext, plaintext_len,
        associated_data, ad_len,
        nonce, secret_key
    );

    if (result == 0) {
        printf("Encryption successful!\n");
        print_hex("Ciphertext", ciphertext, ciphertext_len);
        // The tag is the last 16 bytes of the ciphertext
        print_hex("Authentication Tag", ciphertext + plaintext_len, ASCON_AEAD_TAG_LEN);
    } else {
        fprintf(stderr, "Encryption failed!\n");
        return 1;
    }
    printf("\n");

    // 3. DECRYPTION
    // =================================================
    printf("Decrypting data...\n");

    // The decrypt function automatically verifies the authentication tag.
    result = ascon_aead128_decrypt(
        decrypted_text, &decrypted_text_len,
        ciphertext, ciphertext_len,
        associated_data, ad_len,
        nonce, secret_key
    );

    if (result == 0) {
        printf("SUCCESS: Decryption successful and authentication tag is valid!\n");
        print_hex("Decrypted Text", decrypted_text, decrypted_text_len);
    } else {
        fprintf(stderr, "ERROR: Decryption failed! The data may have been tampered with.\n");
        return 1;
    }
    printf("\n");

    // 4. FINAL VERIFICATION
    // =================================================
    if (plaintext_len == decrypted_text_len && memcmp(plaintext, decrypted_text, plaintext_len) == 0) {
        printf("✅ Verification successful: Original plaintext matches decrypted text.\n");
    } else {
        printf("❌ Verification failed: Mismatch between original and decrypted text.\n");
        return 1;
    }

    return 0;
}
