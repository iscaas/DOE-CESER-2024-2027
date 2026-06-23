// Build: gcc -O2 tools/pqc_init.c -loqs -o pqc-init
// Run:   ./pqc-init
// It will create ./keys/{ca_falcon_*.key, sgn_falcon_*.key, gsm_falcon_*.key, sgn_cert.bin, gsm_cert.bin}

#include <oqs/oqs.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DIR_KEYS "./keys"
#define ID_GSM   "GSM-1"
#define ID_SGN   "SGN-1"

static void die(const char *m) { perror(m); exit(EXIT_FAILURE); }

static void mkkeysdir(void) {
    if (mkdir(DIR_KEYS, 0700) != 0 && errno != EEXIST) die("mkdir ./keys");
}

static void write_file(const char *path, const uint8_t *buf, size_t len) {
    FILE *f = fopen(path, "wb"); if (!f) die(path);
    if (fwrite(buf, 1, len, f) != len) { fclose(f); die("fwrite"); }
    fclose(f);
    printf("[pqc-init] wrote %s (%zu bytes)\n", path, len);
}

static uint8_t *build_cert_blob(const char *id, const uint8_t *pk, uint32_t pk_len,
                                const uint8_t *ca_sk, OQS_SIG *falcon, size_t *out_len) {
    // CA signs msg = id || pk (no length fields)
    size_t id_len = strlen(id);
    size_t msg_len = id_len + pk_len;
    uint8_t *msg = (uint8_t *)malloc(msg_len);
    if (!msg) die("alloc msg");
    memcpy(msg, id, id_len);
    memcpy(msg + id_len, pk, pk_len);

    uint8_t *sig = (uint8_t *)malloc(falcon->length_signature);
    size_t sig_len = 0;
    if (OQS_SIG_sign(falcon, sig, &sig_len, msg, msg_len, ca_sk) != OQS_SUCCESS) {
        free(msg); free(sig); die("Falcon sign (CA)");
    }
    free(msg);

    // cert format: [u32 id_len][id][u32 pk_len][pk][u32 sig_len][sig]
    uint32_t be_id = htonl((uint32_t)id_len);
    uint32_t be_pk = htonl(pk_len);
    uint32_t be_sig = htonl((uint32_t)sig_len);
    *out_len = 4 + id_len + 4 + pk_len + 4 + sig_len;

    uint8_t *blob = (uint8_t *)malloc(*out_len);
    if (!blob) { free(sig); die("alloc cert"); }
    size_t off = 0;
    memcpy(blob + off, &be_id, 4); off += 4;
    memcpy(blob + off, id, id_len); off += id_len;
    memcpy(blob + off, &be_pk, 4); off += 4;
    memcpy(blob + off, pk, pk_len); off += pk_len;
    memcpy(blob + off, &be_sig, 4); off += 4;
    memcpy(blob + off, sig, sig_len); off += sig_len;
    free(sig);
    return blob;
}

int main(void) {
    printf("[pqc-init] Generating PQC CA, GSM, SGN keys and toy certificates...\n");

    mkkeysdir();

    // Falcon-512
    OQS_SIG *falcon = OQS_SIG_new("falcon-512");
    if (!falcon) die("OQS_SIG_new falcon-512");

    // --- CA keypair ---
    uint8_t *ca_pk = (uint8_t *)malloc(falcon->length_public_key);
    uint8_t *ca_sk = (uint8_t *)malloc(falcon->length_secret_key);
    if (!ca_pk || !ca_sk) die("alloc CA keys");
    if (OQS_SIG_keypair(falcon, ca_pk, ca_sk) != OQS_SUCCESS) die("CA keypair");

    write_file("./keys/ca_falcon_public.key",  ca_pk, falcon->length_public_key);
    write_file("./keys/ca_falcon_private.key", ca_sk, falcon->length_secret_key);

    // --- GSM subject keypair ---
    uint8_t *gsm_pk = (uint8_t *)malloc(falcon->length_public_key);
    uint8_t *gsm_sk = (uint8_t *)malloc(falcon->length_secret_key);
    if (!gsm_pk || !gsm_sk) die("alloc GSM keys");
    if (OQS_SIG_keypair(falcon, gsm_pk, gsm_sk) != OQS_SUCCESS) die("GSM keypair");

    write_file("./keys/gsm_falcon_public.key",  gsm_pk, falcon->length_public_key);
    write_file("./keys/gsm_falcon_private.key", gsm_sk, falcon->length_secret_key);

    // --- SGN subject keypair ---
    uint8_t *sgn_pk = (uint8_t *)malloc(falcon->length_public_key);
    uint8_t *sgn_sk = (uint8_t *)malloc(falcon->length_secret_key);
    if (!sgn_pk || !sgn_sk) die("alloc SGN keys");
    if (OQS_SIG_keypair(falcon, sgn_pk, sgn_sk) != OQS_SUCCESS) die("SGN keypair");

    write_file("./keys/sgn_falcon_public.key",  sgn_pk, falcon->length_public_key);
    write_file("./keys/sgn_falcon_private.key", sgn_sk, falcon->length_secret_key);

    // --- Build toy certs signed by CA: (id || pk) ---
    size_t cert_len = 0;
    uint8_t *gsm_cert = build_cert_blob(ID_GSM, gsm_pk, (uint32_t)falcon->length_public_key, ca_sk, falcon, &cert_len);
    write_file("./keys/gsm_cert.bin", gsm_cert, cert_len);
    free(gsm_cert);

    uint8_t *sgn_cert = build_cert_blob(ID_SGN, sgn_pk, (uint32_t)falcon->length_public_key, ca_sk, falcon, &cert_len);
    write_file("./keys/sgn_cert.bin", sgn_cert, cert_len);
    free(sgn_cert);

    // Clean up
    OQS_SIG_free(falcon);
    free(ca_pk); free(ca_sk);
    free(gsm_pk); /* gsm_sk kept on disk */ free(sgn_pk); /* sgn_sk kept on disk */
    printf("[pqc-init] Done.\n");
    printf("[pqc-init] Created files in ./keys:\n");
    printf("  ca_falcon_public.key\n  ca_falcon_private.key\n");
    printf("  gsm_falcon_public.key\n  gsm_falcon_private.key\n  gsm_cert.bin\n");
    printf("  sgn_falcon_public.key\n  sgn_falcon_private.key\n  sgn_cert.bin\n");
    return 0;
}

