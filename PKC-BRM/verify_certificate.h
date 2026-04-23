#ifndef VERIFY_CERT_H
#define VERIFY_CERT_H

#include <openssl/x509.h>

int verify_certificate(X509 *cert, X509 *ca_cert);

#endif
