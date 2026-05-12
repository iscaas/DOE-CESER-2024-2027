// test_hkdf.c
#include <stdio.h>
#include <string.h>
#include <sodium.h> 

int main() {
    if (sodium_init() < 0) {
        fprintf(stderr, "Sodium init failed\n");
        return 1;
    }
    // Print runtime and compile-time version info for diagnostics
    printf("Sodium initialized.\n");
    printf("Runtime Library version: %s\n", sodium_version_string());
    printf("Compile-time SODIUM_LIBRARY_VERSION_MAJOR: %d\n", SODIUM_LIBRARY_VERSION_MAJOR);
    printf("Compile-time SODIUM_LIBRARY_VERSION_MINOR: %d\n", SODIUM_LIBRARY_VERSION_MINOR);
    printf("Compile-time SODIUM_VERSION_STRING: %s\n", SODIUM_VERSION_STRING);


    unsigned char out_key[32]; // Define a desired output key length, e.g., 32 bytes
    unsigned char ikm[] = "test_input_keying_material";
    unsigned char info[] = "test_context_specific_info"; // Can be NULL if not needed

    printf("Attempting HKDF...\n");
    // Using NULL for salt (and 0 length)
    // The out_key_len is specified by sizeof(out_key)
    if (crypto_kdf_hkdf_sha256(out_key, sizeof(out_key),
                               ikm, strlen((char *)ikm),
                               NULL, 0, 
                               info, strlen((char *)info)) != 0) {
        fprintf(stderr, "crypto_kdf_hkdf_sha256 failed\n");
        return 1;
    }

    printf("HKDF call succeeded. Derived key (first few bytes of %zu): ", sizeof(out_key));
    for(size_t i=0; i < sizeof(out_key) && i < 8; ++i) { 
        printf("%02x", out_key[i]);
    }
    printf("\n");

    return 0;
}
