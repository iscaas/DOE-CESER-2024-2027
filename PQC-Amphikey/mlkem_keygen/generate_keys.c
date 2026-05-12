#include <stdio.h>
#include <stdlib.h> // For exit()

// This will include api.h from the .../ml-kem-768/clean/ directory
// due to the -I flag in your gcc command.
#include "api.h"

int main() {
    // Use the fully qualified names from the clean/api.h
    unsigned char pk[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES];

    printf("Generating ML-KEM-768 (Clean) key pair...\n");

    // Use the fully qualified function name
    if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk, sk) != 0) {
        fprintf(stderr, "ERROR: Key pair generation failed.\n");
        return 1;
    }

    printf("Key pair generated successfully.\n");

    // Store public key
    FILE *pk_file = fopen("mlkem768_clean.pk", "wb");
    if (pk_file == NULL) {
        perror("ERROR: Could not open public key file for writing");
        return 1;
    }
    if (fwrite(pk, 1, PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES, pk_file) != PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES) {
        fprintf(stderr, "ERROR: Could not write complete public key to file.\n");
        fclose(pk_file);
        return 1;
    }
    fclose(pk_file);
    printf("Public key stored in mlkem768_clean.pk\n");

    // Store secret key
    FILE *sk_file = fopen("mlkem768_clean.sk", "wb");
    if (sk_file == NULL) {
        perror("ERROR: Could not open secret key file for writing");
        return 1;
    }
    if (fwrite(sk, 1, PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES, sk_file) != PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES) {
        fprintf(stderr, "ERROR: Could not write complete secret key to file.\n");
        fclose(sk_file);
        return 1;
    }
    fclose(sk_file);
    printf("Secret key stored in mlkem768_clean.sk\n");

    printf("Done.\n");
    return 0;
}
