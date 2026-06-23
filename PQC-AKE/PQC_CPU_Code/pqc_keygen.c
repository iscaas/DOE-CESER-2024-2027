// pqc_keygen.c
// Generates toy CA + GSM + SGN Falcon-512 keypairs and toy certificates.
//
// Output files (created under ./keys):
//   ca_falcon_public.key
//   ca_falcon_private.key          (only needed for generation)
//   gsm_falcon_private.key
//   sgn_falcon_private.key
//   gsm_cert.bin                   (toy cert signed by CA)
//   sgn_cert.bin
//
// Build:
//   gcc -O2 pqc_keygen.c -loqs -lcrypto -o pqc_keygen
//
// Run:
//   ./pqc_keygen

#include <arpa/inet.h>
#include <errno.h>
#include <oqs/oqs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define KEY_DIR "./keys"

#define PATH_CA_PUB   KEY_DIR "/ca_falcon_public.key"
#define PATH_CA_PRIV  KEY_DIR "/ca_falcon_private.key"

#define PATH_GSM_PRIV KEY_DIR "/gsm_falcon_private.key"
#define PATH_SGN_PRIV KEY_DIR "/sgn_falcon_private.key"

#define PATH_GSM_CERT KEY_DIR "/gsm_cert.bin"
#define PATH_SGN_CERT KEY_DIR "/sgn_cert.bin"

static void die(const char *m) {
    perror(m);
    exit(1);
}

static int write_file(const char *path, const uint8_t *buf, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    if (len && fwrite(buf, 1, len, f) != len) { fclose(f); return -1; }
    fclose(f);
    return 0;
}

static int ensure_dir(const char *dir) {
    if (mkdir(dir, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

// Toy cert format:
//   [u32be id_len][id bytes]
//   [u32be pk_len][pk bytes]
//   [u32be sig_len][sig bytes]   where sig = Sign_CA(id||pk)
static int build_and_write_cert(const char *id,
                                const uint8_t *entity_pk, uint32_t entity_pk_len,
                                const OQS_SIG *falcon,
                                const uint8_t *ca_sk,
                                const char *out_path) {
    const uint32_t id_len = (uint32_t)strlen(id);

    // CA signs msg = id || pk
    const size_t msg_len = (size_t)id_len + (size_t)entity_pk_len;
    uint8_t *msg = (uint8_t *)malloc(msg_len);
    if (!msg) return -1;
    memcpy(msg, id, id_len);
    memcpy(msg + id_len, entity_pk, entity_pk_len);

    uint8_t *sig = (uint8_t *)malloc(falcon->length_signature);
    if (!sig) { free(msg); return -1; }

    size_t sig_len = 0;
    if (OQS_SIG_sign((OQS_SIG *)falcon, sig, &sig_len, msg, msg_len, ca_sk) != OQS_SUCCESS) {
        free(msg); free(sig);
        return -1;
    }
    free(msg);

    const size_t cert_len =
        4 + (size_t)id_len +
        4 + (size_t)entity_pk_len +
        4 + (size_t)sig_len;

    uint8_t *cert = (uint8_t *)malloc(cert_len);
    if (!cert) { free(sig); return -1; }

    uint8_t *p = cert;

    uint32_t be = htonl(id_len);
    memcpy(p, &be, 4); p += 4;
    memcpy(p, id, id_len); p += id_len;

    be = htonl(entity_pk_len);
    memcpy(p, &be, 4); p += 4;
    memcpy(p, entity_pk, entity_pk_len); p += entity_pk_len;

    be = htonl((uint32_t)sig_len);
    memcpy(p, &be, 4); p += 4;
    memcpy(p, sig, sig_len); p += sig_len;

    free(sig);

    if ((size_t)(p - cert) != cert_len) {
        free(cert);
        return -1;
    }

    int rc = write_file(out_path, cert, cert_len);
    free(cert);
    return rc;
}

int main(void) {
    if (ensure_dir(KEY_DIR) != 0) die("mkdir ./keys");

    OQS_SIG *falcon = OQS_SIG_new("falcon-512");
    if (!falcon) {
        fprintf(stderr, "OQS_SIG_new(falcon-512) failed\n");
        return 1;
    }

    // --- CA keypair ---
    uint8_t *ca_pk = (uint8_t *)malloc(falcon->length_public_key);
    uint8_t *ca_sk = (uint8_t *)malloc(falcon->length_secret_key);
    if (!ca_pk || !ca_sk) die("malloc ca");

    if (OQS_SIG_keypair(falcon, ca_pk, ca_sk) != OQS_SUCCESS) {
        fprintf(stderr, "CA keypair failed\n");
        return 1;
    }
    if (write_file(PATH_CA_PUB, ca_pk, falcon->length_public_key) != 0) die("write CA pub");
    if (write_file(PATH_CA_PRIV, ca_sk, falcon->length_secret_key) != 0) die("write CA priv");

    // --- GSM keypair ---
    uint8_t *gsm_pk = (uint8_t *)malloc(falcon->length_public_key);
    uint8_t *gsm_sk = (uint8_t *)malloc(falcon->length_secret_key);
    if (!gsm_pk || !gsm_sk) die("malloc gsm");

    if (OQS_SIG_keypair(falcon, gsm_pk, gsm_sk) != OQS_SUCCESS) {
        fprintf(stderr, "GSM keypair failed\n");
        return 1;
    }
    if (write_file(PATH_GSM_PRIV, gsm_sk, falcon->length_secret_key) != 0) die("write GSM sk");

    // --- SGN keypair ---
    uint8_t *sgn_pk = (uint8_t *)malloc(falcon->length_public_key);
    uint8_t *sgn_sk = (uint8_t *)malloc(falcon->length_secret_key);
    if (!sgn_pk || !sgn_sk) die("malloc sgn");

    if (OQS_SIG_keypair(falcon, sgn_pk, sgn_sk) != OQS_SUCCESS) {
        fprintf(stderr, "SGN keypair failed\n");
        return 1;
    }
    if (write_file(PATH_SGN_PRIV, sgn_sk, falcon->length_secret_key) != 0) die("write SGN sk");

    // --- Build toy certs (CA signs id||pk) ---
    if (build_and_write_cert("GSM-1", gsm_pk, (uint32_t)falcon->length_public_key, falcon, ca_sk, PATH_GSM_CERT) != 0)
        die("write GSM cert");
    if (build_and_write_cert("SGN-1", sgn_pk, (uint32_t)falcon->length_public_key, falcon, ca_sk, PATH_SGN_CERT) != 0)
        die("write SGN cert");

    printf("[keygen] Wrote keys/certs under %s\n", KEY_DIR);
    printf("  %s\n  %s\n  %s\n  %s\n  %s\n  %s\n",
           PATH_CA_PUB, PATH_CA_PRIV,
           PATH_GSM_PRIV, PATH_SGN_PRIV,
           PATH_GSM_CERT, PATH_SGN_CERT);

    free(ca_pk); free(ca_sk);
    free(gsm_pk); free(gsm_sk);
    free(sgn_pk); free(sgn_sk);
    OQS_SIG_free(falcon);
    return 0;
}