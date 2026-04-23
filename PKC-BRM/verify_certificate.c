#include "verify_certificate.h"
#include <openssl/evp.h>
#include <stdio.h>

int verify_certificate(X509 *cert, X509 *ca_cert)
{
    EVP_PKEY *ca_pub = X509_get_pubkey(ca_cert);
    if (!ca_pub) {
        fprintf(stderr, "Failed to extract CA public key\n");
        return 0;
    }
    int ok = X509_verify(cert, ca_pub);
    EVP_PKEY_free(ca_pub);
    return ok == 1;
}
