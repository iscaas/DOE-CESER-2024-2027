#include <stdio.h>
#include <stdlib.h>
#include <oqs/oqs.h>

int main() {
    OQS_SIG *sig = OQS_SIG_new("falcon-512");
    if (sig == NULL) {
        fprintf(stderr, "Falcon not supported!\n");
        exit(EXIT_FAILURE);
    }

    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *secret_key = malloc(sig->length_secret_key);

    if (OQS_SIG_keypair(sig, public_key, secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "Key generation failed!\n");
        exit(EXIT_FAILURE);
    }

    FILE *pub = fopen("keys/falcon_public.key", "wb");
    FILE *priv = fopen("keys/falcon_private.key", "wb");
    fwrite(public_key, 1, sig->length_public_key, pub);
    fwrite(secret_key, 1, sig->length_secret_key, priv);
    fclose(pub);
    fclose(priv);

    OQS_SIG_free(sig);
    free(public_key);
    free(secret_key);

    printf("[Falcon] Keypair generated successfully\n");
    return 0;
}
