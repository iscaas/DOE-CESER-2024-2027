#include <oqs/kem.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <algorithm> <public key path> <private key path>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char* alg_name = argv[1];
    const char* pub_path = argv[2];
    const char* priv_path = argv[3];

    // Initialize KEM
    OQS_KEM* kem = OQS_KEM_new(alg_name);
    if (!kem) {
        fprintf(stderr, "Failed to initialize Kyber algorithm: %s\n", alg_name);
        return EXIT_FAILURE;
    }

    // Allocate memory for keys
    uint8_t* public_key = malloc(kem->length_public_key);
    uint8_t* private_key = malloc(kem->length_secret_key);
    if (!public_key || !private_key) {
        fprintf(stderr, "Memory allocation for keys failed.\n");
        OQS_KEM_free(kem);
        free(public_key);
        free(private_key);
        return EXIT_FAILURE;
    }

    // Generate keypair
    if (OQS_KEM_keypair(kem, public_key, private_key) != OQS_SUCCESS) {
        fprintf(stderr, "Keypair generation failed.\n");
        OQS_KEM_free(kem);
        free(public_key);
        free(private_key);
        return EXIT_FAILURE;
    }

    // Write public key
    FILE* pub_fp = fopen(pub_path, "wb");
    if (!pub_fp) {
        fprintf(stderr, "Failed to open public key file for writing: %s\n", pub_path);
        OQS_KEM_free(kem);
        free(public_key);
        free(private_key);
        return EXIT_FAILURE;
    }
    fwrite(public_key, 1, kem->length_public_key, pub_fp);
    fclose(pub_fp);

    // Write private key
    FILE* priv_fp = fopen(priv_path, "wb");
    if (!priv_fp) {
        fprintf(stderr, "Failed to open private key file for writing: %s\n", priv_path);
        OQS_KEM_free(kem);
        free(public_key);
        free(private_key);
        return EXIT_FAILURE;
    }
    fwrite(private_key, 1, kem->length_secret_key, priv_fp);
    fclose(priv_fp);

    // Cleanup
    OQS_KEM_free(kem);
    free(public_key);
    free(private_key);

    printf("✅ Kyber keys generated using %s\n", alg_name);
    printf("   📄 Public Key: %s\n", pub_path);
    printf("   🔒 Private Key: %s\n", priv_path);

    return EXIT_SUCCESS;
}
