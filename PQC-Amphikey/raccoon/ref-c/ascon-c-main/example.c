#include <stdio.h>
#include <stdint.h>
#include <string.h>
// Change this line
#include "ascon.h"
#include "crypto_aead.h"
// To this line
#include "api.h"

// Helper function to print hex data
void print_hex(const char* label, const uint8_t* data, uint64_t len) {
    printf("%s (%llu bytes): ", label, (unsigned long long)len);
    for (uint64_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    printf("--- Ascon AEAD (SUPERCOP API) Example ---\n\n");

    // 1. SETUP
    const uint8_t secret_key[CRYPTO_KEYBYTES] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };
    const uint8_t nonce[CRYPTO_NPUBBYTES] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    const uint8_t plaintext[] = "This is a secret message!";
    const uint64_t plaintext_len = sizeof(plaintext) - 1;
    const uint8_t associated_data[] = "Authenticated Metadata";
    const uint64_t ad_len = sizeof(associated_data) - 1;
    
    uint8_t ciphertext[sizeof(plaintext) + CRYPTO_ABYTES];
    uint8_t decrypted_text[sizeof(plaintext)];

    // CORRECTED TYPE: Use unsigned long long to match the API
    unsigned long long ciphertext_len = 0;
    unsigned long long decrypted_text_len = 0;

    print_hex("Secret Key", secret_key, CRYPTO_KEYBYTES);
    print_hex("Nonce", nonce, CRYPTO_NPUBBYTES);
    print_hex("Plaintext", plaintext, plaintext_len);
    print_hex("Associated Data", associated_data, ad_len);
    printf("\n");

    // 2. ENCRYPTION
    printf("Encrypting data...\n");
    crypto_aead_encrypt(ciphertext, &ciphertext_len,
                        plaintext, plaintext_len,
                        associated_data, ad_len,
                        NULL, nonce, secret_key);
    print_hex("Ciphertext + Tag", ciphertext, ciphertext_len);
    printf("\n");

    // 3. DECRYPTION
    printf("Decrypting data...\n");
    int result = crypto_aead_decrypt(decrypted_text, &decrypted_text_len,
                                     NULL,
                                     ciphertext, ciphertext_len,
                                     associated_data, ad_len,
                                     nonce, secret_key);

    if (result == 0) {
        printf("SUCCESS: Decryption successful and tag is valid!\n");
        print_hex("Decrypted Text", decrypted_text, decrypted_text_len);
    } else {
        fprintf(stderr, "ERROR: Decryption failed! The data is not authentic.\n");
        return 1;
    }
    printf("\n");
    
    // 4. FINAL VERIFICATION
    if (plaintext_len == decrypted_text_len && memcmp(plaintext, decrypted_text, plaintext_len) == 0) {
        printf("✅ Verification successful: Original plaintext matches decrypted text.\n");
    } else {
        printf("❌ Verification failed: Mismatch between original and decrypted text.\n");
        return 1;
    }

    return 0;
}
