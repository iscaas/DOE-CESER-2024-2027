#include <stdio.h>
#include <stdlib.h> // For exit()

// This should point to the main api.h for ml-kem-768
// The -I flag in gcc will help find it.
#include "api.h"

int main() {
    // Use the generic macros from api.h
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];

    printf("Generating ML-KEM-768 (Clean) key pair...\n");

    // Use the generic function name
    if (crypto_kem_keypair(pk, sk) != 0) {
        fprintf(stderr, "ERROR: Key pair generation failed.\n");
        return 1;
    }

    printf("Key pair generated successfully.\n");

    // Store public key
    // Ensure you use the generic CRYPTO_PUBLICKEYBYTES here too
    FILE *pk_file = fopen("mlkem768_clean.pk", "wb"); // Changed filename for clarity
    if (pk_file == NULL) {
        perror("ERROR: Could not open public key file for writing");
        return 1;
    }
    if (fwrite(pk, 1, CRYPTO_PUBLICKEYBYTES, pk_file) != CRYPTO_PUBLICKEYBYTES) {
        fprintf(stderr, "ERROR: Could not write complete public key to file.\n");
        fclose(pk_file);
        return 1;
    }
    fclose(pk_file);
    printf("Public key stored in mlkem768_clean.pk\n");

    // Store secret key
    // Ensure you use the generic CRYPTO_SECRETKEYBYTES here too
    FILE *sk_file = fopen("mlkem768_clean.sk", "wb"); // Changed filename for clarity
    if (sk_file == NULL) {
        perror("ERROR: Could not open secret key file for writing");
        return 1;
    }
    if (fwrite(sk, 1, CRYPTO_SECRETKEYBYTES, sk_file) != CRYPTO_SECRETKEYBYTES) {
        fprintf(stderr, "ERROR: Could not write complete secret key to file.\n");
        fclose(sk_file);
        return 1;
    }
    fclose(sk_file);
    printf("Secret key stored in mlkem768_clean.sk\n");

    printf("Done.\n");
    return 0;
}
