// server.c — Ephemeral ECDHE + transcript signatures + HKDF + AES-CBC + HMAC
// TIMED VERSION: step-by-step compute timing, send/recv excluded
//
// Build:
//   gcc -O2 server.c -lssl -lcrypto -o server
//
// Notes:
// - Timing excludes all send/recv time by simply not timing those calls.
// - Also excludes file I/O / certificate loading from disk.
// - Keeps the wire protocol unchanged.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/crypto.h>

#define PORT 3000
#define BUF  4096

#ifndef LSEG_DEBUG
#define LSEG_DEBUG 0
#endif

/* ========================= TIMING HELPERS ========================= */
#if defined(CLOCK_THREAD_CPUTIME_ID)
#define LSEG_TIMING_CLOCK CLOCK_THREAD_CPUTIME_ID
#elif defined(CLOCK_PROCESS_CPUTIME_ID)
#define LSEG_TIMING_CLOCK CLOCK_PROCESS_CPUTIME_ID
#else
#define LSEG_TIMING_CLOCK CLOCK_MONOTONIC
#endif

static inline uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(LSEG_TIMING_CLOCK, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static inline double ns_to_us(uint64_t ns) {
    return (double)ns / 1000.0;
}

typedef struct {
    uint64_t step1_ns;
    uint64_t step2_ns;
    uint64_t step3_ns;
    uint64_t step4_ns;

    // Step 1
    uint64_t eph_keygen_ns;
    uint64_t pubkey_der_ns;
    uint64_t sig_server_ns;

    // Step 2
    uint64_t cli_pub_parse_ns;
    uint64_t ecdh_ns;
    uint64_t hkdf_ns;

    // Step 3
    uint64_t hmac_verify_ns;
    uint64_t decrypt_mrci_ns;
    uint64_t client_cert_parse_ns;
    uint64_t client_cert_verify_ns;
    uint64_t client_sigpub_extract_ns;
    uint64_t sig_client_verify_ns;

    // Step 4
    uint64_t rand_ksym_ns;
    uint64_t encrypt_yci_ns;
    uint64_t hmac_hy_ns;
} timings_t;

static void print_timings_server(const timings_t *t, int success) {
    uint64_t total_ns = t->step1_ns + t->step2_ns + t->step3_ns + t->step4_ns;

    printf("\n==================== SERVER TIMING ====================\n");
    printf("Status: %s\n", success ? "handshake complete" : "handshake aborted");
    printf("Compute-only timings (send/recv excluded)\n\n");

    printf("Step 1 (Server authenticated offer): %10.2f us\n", ns_to_us(t->step1_ns));
    printf("  - ECDHE keygen:                    %10.2f us\n", ns_to_us(t->eph_keygen_ns));
    printf("  - DER encode server eph pub:       %10.2f us\n", ns_to_us(t->pubkey_der_ns));
    printf("  - Sign alpha_TS:                   %10.2f us\n", ns_to_us(t->sig_server_ns));

    printf("\nStep 2 (Shared key derivation):       %10.2f us\n", ns_to_us(t->step2_ns));
    printf("  - Parse client eph pub:            %10.2f us\n", ns_to_us(t->cli_pub_parse_ns));
    printf("  - ECDH derive:                     %10.2f us\n", ns_to_us(t->ecdh_ns));
    printf("  - HKDF derive klocal:              %10.2f us\n", ns_to_us(t->hkdf_ns));

    printf("\nStep 3 (Client auth + validation):    %10.2f us\n", ns_to_us(t->step3_ns));
    printf("  - Verify hm (HMAC):                %10.2f us\n", ns_to_us(t->hmac_verify_ns));
    printf("  - AES decrypt m_rCi:               %10.2f us\n", ns_to_us(t->decrypt_mrci_ns));
    printf("  - Parse client cert:               %10.2f us\n", ns_to_us(t->client_cert_parse_ns));
    printf("  - Verify client cert:              %10.2f us\n", ns_to_us(t->client_cert_verify_ns));
    printf("  - Extract client verify key:       %10.2f us\n", ns_to_us(t->client_sigpub_extract_ns));
    printf("  - Verify alpha_TC:                 %10.2f us\n", ns_to_us(t->sig_client_verify_ns));

    printf("\nStep 4 (Server response generation):  %10.2f us\n", ns_to_us(t->step4_ns));
    printf("  - RAND_bytes(ksym):                %10.2f us\n", ns_to_us(t->rand_ksym_ns));
    printf("  - AES encrypt yCi:                 %10.2f us\n", ns_to_us(t->encrypt_yci_ns));
    printf("  - HMAC hy:                         %10.2f us\n", ns_to_us(t->hmac_hy_ns));

    printf("\nTOTAL server compute:                %10.2f us\n", ns_to_us(total_ns));
    printf("=======================================================\n\n");
}

/* ========================= Utility ========================= */

static void handle_error(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

static void print_hex(const char *label, const unsigned char *data, size_t len) {
#if LSEG_DEBUG
    if (label) printf("%s (%zu bytes): ", label, len);
    else       printf("(%zu bytes): ", len);
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
#else
    (void)label; (void)data; (void)len;
#endif
}

static int send_all(int fd, const void *buf, size_t len) {
    const unsigned char *p = (const unsigned char *)buf;
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, p + sent, len - sent, 0);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        if (n == 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static int recv_all(int fd, void *buf, size_t len) {
    unsigned char *p = (unsigned char *)buf;
    size_t recvd = 0;
    while (recvd < len) {
        ssize_t n = recv(fd, p + recvd, len - recvd, 0);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        if (n == 0) return -1;
        recvd += (size_t)n;
    }
    return 0;
}

// length-prefixed blob: [uint32_be length][payload]
static int send_blob(int fd, const unsigned char *data, uint32_t len) {
    uint32_t nlen = htonl(len);
    if (send_all(fd, &nlen, sizeof(nlen)) < 0) return -1;
    if (len > 0 && send_all(fd, data, len) < 0) return -1;
    return 0;
}

static int recv_blob(int fd, unsigned char **out, uint32_t *outlen) {
    uint32_t nlen = 0;
    if (recv_all(fd, &nlen, sizeof(nlen)) < 0) return -1;
    uint32_t len = ntohl(nlen);
    unsigned char *buf = NULL;
    if (len > 0) {
        buf = (unsigned char *)malloc(len);
        if (!buf) return -1;
        if (recv_all(fd, buf, len) < 0) { free(buf); return -1; }
    }
    *out = buf;
    *outlen = len;
    return 0;
}

/* ========================= Files / Certs ========================= */

static unsigned char *read_file(const char *path, size_t *len_out) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return NULL; }
    unsigned char *buf = (unsigned char *)malloc((size_t)sz);
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (n != (size_t)sz) { free(buf); return NULL; }
    *len_out = (size_t)sz;
    return buf;
}

static X509 *load_cert_pem(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    X509 *c = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);
    return c;
}

static EVP_PKEY *load_privkey_pem(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    EVP_PKEY *k = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    return k;
}

static int verify_cert_with_ca(X509 *cert, X509 *ca_cert) {
    int ok = 0;
    X509_STORE *store = X509_STORE_new();
    if (!store) return 0;
    if (X509_STORE_add_cert(store, ca_cert) != 1) goto out;
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (!ctx) goto out;
    if (X509_STORE_CTX_init(ctx, store, cert, NULL) != 1) {
        X509_STORE_CTX_free(ctx);
        goto out;
    }
    ok = X509_verify_cert(ctx) == 1;
    X509_STORE_CTX_free(ctx);
out:
    X509_STORE_free(store);
    return ok;
}

/* ========================= Ephemeral keys & ECDH/HKDF ========================= */

static EVP_PKEY *generate_ephemeral_ec_key(void) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) return NULL;
    if (EVP_PKEY_paramgen_init(pctx) <= 0) { EVP_PKEY_CTX_free(pctx); return NULL; }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }
    EVP_PKEY *params = NULL;
    if (EVP_PKEY_paramgen(pctx, &params) <= 0) { EVP_PKEY_CTX_free(pctx); return NULL; }

    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new(params, NULL);
    EVP_PKEY_free(params);
    if (!kctx) { EVP_PKEY_CTX_free(pctx); return NULL; }

    if (EVP_PKEY_keygen_init(kctx) <= 0) {
        EVP_PKEY_CTX_free(kctx);
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }
    if (EVP_PKEY_keygen(kctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(kctx);
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

static int pubkey_to_der(EVP_PKEY *pkey, unsigned char **der, int *der_len) {
    *der = NULL;
    *der_len = 0;

    int len = i2d_PUBKEY(pkey, NULL);
    if (len <= 0) return 0;

    *der = (unsigned char *)malloc((size_t)len);
    if (!*der) return 0;

    unsigned char *tmp = *der;
    int len2 = i2d_PUBKEY(pkey, &tmp);
    if (len2 != len) {
        free(*der);
        *der = NULL;
        return 0;
    }

    *der_len = len;
    return 1;
}

static EVP_PKEY *pubkey_from_der(const unsigned char *der, int der_len) {
    const unsigned char *p = der;
    return d2i_PUBKEY(NULL, &p, der_len);
}

static int ecdh_derive(EVP_PKEY *priv, EVP_PKEY *peer_pub, unsigned char **secret, size_t *secret_len) {
    *secret = NULL;
    *secret_len = 0;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv, NULL);
    if (!ctx) return 0;

    if (EVP_PKEY_derive_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); return 0; }
    if (EVP_PKEY_derive_set_peer(ctx, peer_pub) <= 0) { EVP_PKEY_CTX_free(ctx); return 0; }

    size_t len = 0;
    if (EVP_PKEY_derive(ctx, NULL, &len) <= 0) { EVP_PKEY_CTX_free(ctx); return 0; }

    unsigned char *buf = (unsigned char *)malloc(len);
    if (!buf) { EVP_PKEY_CTX_free(ctx); return 0; }

    if (EVP_PKEY_derive(ctx, buf, &len) <= 0) {
        free(buf);
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    EVP_PKEY_CTX_free(ctx);
    *secret = buf;
    *secret_len = len;
    return 1;
}

static int hkdf_sha256(const unsigned char *secret, size_t secret_len,
                       const unsigned char *salt, size_t salt_len,
                       const unsigned char *info, size_t info_len,
                       unsigned char *out, size_t out_len) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) return 0;

    int ok = 0;
    if (EVP_PKEY_derive_init(pctx) <= 0) goto done;
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) goto done;
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, (int)salt_len) <= 0) goto done;
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, (int)secret_len) <= 0) goto done;
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, (int)info_len) <= 0) goto done;
    if (EVP_PKEY_derive(pctx, out, &out_len) <= 0) goto done;
    ok = 1;

done:
    EVP_PKEY_CTX_free(pctx);
    return ok;
}

/* ========================= Sign / Verify transcript ========================= */

static int sign_bytes(const unsigned char *msg, size_t msg_len, EVP_PKEY *sign_key,
                      unsigned char **sig, size_t *sig_len) {
    *sig = NULL;
    *sig_len = 0;

    EVP_MD_CTX *m = EVP_MD_CTX_new();
    if (!m) return 0;

    int ok = 0;
    if (EVP_DigestSignInit(m, NULL, EVP_sha256(), NULL, sign_key) != 1) goto out;
    if (EVP_DigestSignUpdate(m, msg, msg_len) != 1) goto out;

    size_t need = 0;
    if (EVP_DigestSignFinal(m, NULL, &need) != 1 || need == 0) goto out;

    unsigned char *buf = (unsigned char *)malloc(need);
    if (!buf) goto out;

    if (EVP_DigestSignFinal(m, buf, &need) != 1) {
        free(buf);
        goto out;
    }

    *sig = buf;
    *sig_len = need;
    ok = 1;

out:
    EVP_MD_CTX_free(m);
    return ok;
}

static int verify_sig(const unsigned char *msg, size_t msg_len, EVP_PKEY *verify_key,
                      const unsigned char *sig, size_t sig_len) {
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    if (!m) return 0;

    int ok = 0;
    if (EVP_DigestVerifyInit(m, NULL, EVP_sha256(), NULL, verify_key) != 1) goto out;
    if (EVP_DigestVerifyUpdate(m, msg, msg_len) != 1) goto out;
    ok = (EVP_DigestVerifyFinal(m, sig, sig_len) == 1);

out:
    EVP_MD_CTX_free(m);
    return ok;
}

/* ========================= AES-256-CBC + HMAC ========================= */

static int aes256_cbc_encrypt(const unsigned char *key32,
                              const unsigned char *pt, int pt_len,
                              unsigned char **out, int *out_len) {
    *out = NULL;
    *out_len = 0;

    unsigned char iv[16];
    if (RAND_bytes(iv, sizeof(iv)) != 1) return 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    int ok = 0, len = 0, ct_len = 0;
    unsigned char *buf = (unsigned char *)malloc(16 + pt_len + 32);
    if (!buf) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    memcpy(buf, iv, 16);

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key32, iv) != 1) goto done;
    if (EVP_EncryptUpdate(ctx, buf + 16, &len, pt, pt_len) != 1) goto done;
    ct_len = len;
    if (EVP_EncryptFinal_ex(ctx, buf + 16 + len, &len) != 1) goto done;
    ct_len += len;

    *out = buf;
    *out_len = 16 + ct_len;
    buf = NULL;
    ok = 1;

done:
    if (buf) free(buf);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int aes256_cbc_decrypt(const unsigned char *key32,
                              const unsigned char *in, int in_len,
                              unsigned char **pt, int *pt_len) {
    *pt = NULL;
    *pt_len = 0;

    if (in_len < 16) return 0;

    const unsigned char *iv = in;
    const unsigned char *ct = in + 16;
    int ct_len = in_len - 16;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    int ok = 0, len = 0, out_len = 0;
    unsigned char *buf = (unsigned char *)malloc((size_t)ct_len);
    if (!buf) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key32, iv) != 1) goto done;
    if (EVP_DecryptUpdate(ctx, buf, &len, ct, ct_len) != 1) goto done;
    out_len = len;
    if (EVP_DecryptFinal_ex(ctx, buf + len, &len) != 1) goto done;
    out_len += len;

    *pt = buf;
    *pt_len = out_len;
    buf = NULL;
    ok = 1;

done:
    if (buf) free(buf);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int hmac_sha256(const unsigned char *key, size_t keylen,
                       const unsigned char *data, size_t datalen,
                       unsigned char out[EVP_MAX_MD_SIZE], unsigned int *outlen) {
    HMAC_CTX *c = HMAC_CTX_new();
    if (!c) return 0;

    int ok = 0;
    if (HMAC_Init_ex(c, key, (int)keylen, EVP_sha256(), NULL) != 1) goto done;
    if (HMAC_Update(c, data, datalen) != 1) goto done;
    if (HMAC_Final(c, out, outlen) != 1) goto done;
    ok = 1;

done:
    HMAC_CTX_free(c);
    return ok;
}

/* ========================= Main server flow ========================= */

int main(void) {
    OpenSSL_add_all_algorithms();

    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) handle_error("[Server] socket");

    int opt = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) handle_error("[Server] bind");
    if (listen(sfd, 10) < 0) handle_error("[Server] listen");

    printf("[Server] Listening on %d ...\n", PORT);

    for (;;) {
        int cfd = accept(sfd, NULL, NULL);
        if (cfd < 0) {
            perror("[Server] accept");
            continue;
        }

        printf("\n[Server] ==== New connection ====\n");

        timings_t tim;
        memset(&tim, 0, sizeof(tim));
        int handshake_ok = 0;
        uint64_t t0, dt;

        // Per-connection objects
        X509 *server_cert = NULL;
        X509 *ca_cert = NULL;
        X509 *client_cert = NULL;

        EVP_PKEY *server_sign_key = NULL;
        EVP_PKEY *srv_eph = NULL;
        EVP_PKEY *cli_eph_pub = NULL;
        EVP_PKEY *client_sig_pub = NULL;

        unsigned char *srv_pub_der = NULL;
        int srv_pub_der_len = 0;
        unsigned char *alpha_ts = NULL;
        size_t alpha_ts_len = 0;

        unsigned char *cert_pem = NULL;
        size_t cert_pem_len = 0;

        unsigned char *cli_pub_der = NULL;
        uint32_t cli_pub_der_len = 0;
        unsigned char *alpha_tc = NULL;
        uint32_t alpha_tc_len = 0;
        unsigned char *m_rci = NULL;
        uint32_t m_rci_len = 0;
        unsigned char *hm = NULL;
        uint32_t hm_len = 0;

        unsigned char *ecdh_secret = NULL;
        size_t ecdh_secret_len = 0;
        unsigned char *info = NULL;

        unsigned char klocal[32];
        memset(klocal, 0, sizeof(klocal));

        unsigned char hm_calc[EVP_MAX_MD_SIZE];
        unsigned int hm_calc_len = 0;

        unsigned char *pt = NULL;
        int pt_len = 0;

        unsigned char *client_cert_pem = NULL;
        uint32_t client_cert_pem_len = 0;

        unsigned char ri[16];
        memset(ri, 0, sizeof(ri));

        unsigned char ksym[32];
        memset(ksym, 0, sizeof(ksym));

        unsigned char *y_pt = NULL;
        int y_pt_len = 0;

        unsigned char *yCi = NULL;
        int yCi_len = 0;

        unsigned char hy[EVP_MAX_MD_SIZE];
        unsigned int hy_len = 0;

        unsigned char *sync = NULL;
        uint32_t sync_len = 0;

        // ---- Load long-term materials (not timed) ----
        server_cert = load_cert_pem("./certs/server_certificate.pem");
        ca_cert     = load_cert_pem("./certs/ca_certificate.pem");
        server_sign_key = load_privkey_pem("./keys/server_signing_private_key.pem");

        if (!server_cert || !ca_cert || !server_sign_key) {
            fprintf(stderr, "[Server] Failed to load certificate/keys\n");
            goto cleanup_conn;
        }

        /* =================== Step 1: Server authenticated offer =================== */

        t0 = now_ns();
        srv_eph = generate_ephemeral_ec_key();
        dt = now_ns() - t0;
        tim.eph_keygen_ns += dt;
        tim.step1_ns += dt;

        if (!srv_eph) {
            fprintf(stderr, "[Server] Ephemeral keygen failed\n");
            goto cleanup_conn;
        }

        t0 = now_ns();
        int der_ok = pubkey_to_der(srv_eph, &srv_pub_der, &srv_pub_der_len);
        dt = now_ns() - t0;
        tim.pubkey_der_ns += dt;
        tim.step1_ns += dt;

        if (!der_ok) {
            fprintf(stderr, "[Server] DER encode ephemeral pubkey failed\n");
            goto cleanup_conn;
        }
        print_hex("[Server] Ephemeral kpub,S (DER)", srv_pub_der, (size_t)srv_pub_der_len);

        t0 = now_ns();
        int sigs_ok = sign_bytes(srv_pub_der, (size_t)srv_pub_der_len, server_sign_key,
                                 &alpha_ts, &alpha_ts_len);
        dt = now_ns() - t0;
        tim.sig_server_ns += dt;
        tim.step1_ns += dt;

        if (!sigs_ok) {
            fprintf(stderr, "[Server] Signing alpha_TS failed\n");
            goto cleanup_conn;
        }
        print_hex("[Server] alpha_TS", alpha_ts, alpha_ts_len);

        // Read server cert PEM for sending (not timed)
        cert_pem = read_file("./certs/server_certificate.pem", &cert_pem_len);
        if (!cert_pem) {
            fprintf(stderr, "[Server] Could not read server_certificate.pem\n");
            goto cleanup_conn;
        }

        // Send Msg1 (not timed)
        if (send_blob(cfd, cert_pem, (uint32_t)cert_pem_len) < 0 ||
            send_blob(cfd, srv_pub_der, (uint32_t)srv_pub_der_len) < 0 ||
            send_blob(cfd, alpha_ts, (uint32_t)alpha_ts_len) < 0) {
            fprintf(stderr, "[Server] Sending Msg1 failed\n");
            goto cleanup_conn;
        }
        printf("[Server] Sent: CertS || kpub,S || alpha_TS\n");

        /* =================== Receive Msg2 (not timed) =================== */
        if (recv_blob(cfd, &cli_pub_der, &cli_pub_der_len) < 0 ||
            recv_blob(cfd, &alpha_tc, &alpha_tc_len) < 0 ||
            recv_blob(cfd, &m_rci, &m_rci_len) < 0 ||
            recv_blob(cfd, &hm, &hm_len) < 0) {
            fprintf(stderr, "[Server] Receiving Msg2 failed\n");
            goto cleanup_conn;
        }

        printf("[Server] Received Msg2 fields\n");
        print_hex("  kpub,Ci (DER)", cli_pub_der, cli_pub_der_len);
        print_hex("  alpha_TC", alpha_tc, alpha_tc_len);
        print_hex("  m_rCi (IV||CT)", m_rci, m_rci_len);
        print_hex("  hm", hm, hm_len);

        /* =================== Step 2: Shared key derivation =================== */

        t0 = now_ns();
        cli_eph_pub = pubkey_from_der(cli_pub_der, (int)cli_pub_der_len);
        dt = now_ns() - t0;
        tim.cli_pub_parse_ns += dt;
        tim.step2_ns += dt;

        if (!cli_eph_pub) {
            fprintf(stderr, "[Server] d2i kpub,Ci failed\n");
            goto cleanup_conn;
        }

        t0 = now_ns();
        int ecdh_ok = ecdh_derive(srv_eph, cli_eph_pub, &ecdh_secret, &ecdh_secret_len);
        dt = now_ns() - t0;
        tim.ecdh_ns += dt;
        tim.step2_ns += dt;

        if (!ecdh_ok) {
            fprintf(stderr, "[Server] ECDH derive failed\n");
            goto cleanup_conn;
        }
        print_hex("[Server] ECDH shared secret", ecdh_secret, ecdh_secret_len);

        const char *label = "Asfand-v3";
        size_t label_len = strlen(label);
        size_t info_len = label_len + (size_t)srv_pub_der_len + (size_t)cli_pub_der_len;

        info = (unsigned char *)malloc(info_len);
        if (!info) {
            fprintf(stderr, "[Server] malloc(info) failed\n");
            goto cleanup_conn;
        }

        memcpy(info, label, label_len);
        memcpy(info + label_len, srv_pub_der, (size_t)srv_pub_der_len);
        memcpy(info + label_len + (size_t)srv_pub_der_len, cli_pub_der, (size_t)cli_pub_der_len);

        t0 = now_ns();
        #include <openssl/sha.h>

        unsigned char zero_salt[SHA256_DIGEST_LENGTH] = {0};

        int hkdf_ok = hkdf_sha256(ecdh_secret, ecdh_secret_len,
                                  zero_salt, sizeof(zero_salt),
                                  info, info_len,
                                  klocal, sizeof(klocal));
        dt = now_ns() - t0;
        tim.hkdf_ns += dt;
        tim.step2_ns += dt;

        if (!hkdf_ok) {
            fprintf(stderr, "[Server] HKDF failed\n");
            goto cleanup_conn;
        }
        print_hex("[Server] klocal", klocal, sizeof(klocal));

        /* =================== Step 3: Client auth + request validation =================== */

        t0 = now_ns();
        int hm_ok = hmac_sha256(klocal, sizeof(klocal), m_rci, m_rci_len, hm_calc, &hm_calc_len);
        if (hm_ok) {
            hm_ok = (hm_len == hm_calc_len && CRYPTO_memcmp(hm, hm_calc, hm_len) == 0);
        }
        dt = now_ns() - t0;
        tim.hmac_verify_ns += dt;
        tim.step3_ns += dt;

        if (!hm_ok) {
            fprintf(stderr, "[Server] HMAC verification FAILED\n");
            goto cleanup_conn;
        }
        printf("[Server] hm verified OK\n");

        t0 = now_ns();
        int dec_ok = aes256_cbc_decrypt(klocal, m_rci, (int)m_rci_len, &pt, &pt_len);
        dt = now_ns() - t0;
        tim.decrypt_mrci_ns += dt;
        tim.step3_ns += dt;

        if (!dec_ok) {
            fprintf(stderr, "[Server] Decryption of m_rCi failed\n");
            goto cleanup_conn;
        }

        if (pt_len < 4 + 16) {
            fprintf(stderr, "[Server] m_rCi plaintext too short\n");
            goto cleanup_conn;
        }

        uint32_t cert_len_be = 0;
        memcpy(&cert_len_be, pt, 4);
        uint32_t cert_len = ntohl(cert_len_be);

        if ((int)(4 + cert_len + 16) != pt_len) {
            fprintf(stderr, "[Server] m_rCi layout mismatch\n");
            goto cleanup_conn;
        }

        client_cert_pem_len = cert_len;
        client_cert_pem = (unsigned char *)malloc(client_cert_pem_len);
        if (!client_cert_pem) {
            fprintf(stderr, "[Server] malloc(client_cert_pem) failed\n");
            goto cleanup_conn;
        }

        memcpy(client_cert_pem, pt + 4, client_cert_pem_len);
        memcpy(ri, pt + 4 + client_cert_pem_len, 16);

        printf("[Server] Extracted from m_rCi:\n");
        print_hex("  ri (nonce)", ri, sizeof(ri));

        t0 = now_ns();
        BIO *cb = BIO_new_mem_buf(client_cert_pem, (int)client_cert_pem_len);
        client_cert = cb ? PEM_read_bio_X509(cb, NULL, NULL, NULL) : NULL;
        if (cb) BIO_free(cb);
        dt = now_ns() - t0;
        tim.client_cert_parse_ns += dt;
        tim.step3_ns += dt;

        if (!client_cert) {
            fprintf(stderr, "[Server] Failed to parse client cert\n");
            goto cleanup_conn;
        }

        t0 = now_ns();
        int cert_ok = verify_cert_with_ca(client_cert, ca_cert);
        dt = now_ns() - t0;
        tim.client_cert_verify_ns += dt;
        tim.step3_ns += dt;

        if (!cert_ok) {
            fprintf(stderr, "[Server] Client certificate verification FAILED\n");
            goto cleanup_conn;
        }
        printf("[Server] Client certificate verified OK\n");

        t0 = now_ns();
        client_sig_pub = X509_get_pubkey(client_cert);
        dt = now_ns() - t0;
        tim.client_sigpub_extract_ns += dt;
        tim.step3_ns += dt;

        if (!client_sig_pub) {
            fprintf(stderr, "[Server] Extract client SIG pubkey failed\n");
            goto cleanup_conn;
        }

        t0 = now_ns();
        int sigc_ok = verify_sig(cli_pub_der, cli_pub_der_len, client_sig_pub, alpha_tc, alpha_tc_len);
        dt = now_ns() - t0;
        tim.sig_client_verify_ns += dt;
        tim.step3_ns += dt;

        if (!sigc_ok) {
            fprintf(stderr, "[Server] alpha_TC verification FAILED\n");
            goto cleanup_conn;
        }
        printf("[Server] alpha_TC verified OK\n");

        /* =================== Step 4: Server response generation =================== */

        t0 = now_ns();
        int rnd_ok = RAND_bytes(ksym, sizeof(ksym));
        dt = now_ns() - t0;
        tim.rand_ksym_ns += dt;
        tim.step4_ns += dt;

        if (rnd_ok != 1) {
            fprintf(stderr, "[Server] RAND_bytes(ksym) failed\n");
            goto cleanup_conn;
        }

        uint64_t lifetime_seconds = 3600;
        const char *IDS = "Server123";
        uint32_t ids_len = (uint32_t)strlen(IDS);

        unsigned char tbuf[8];
        uint64_t T = lifetime_seconds;
        for (int i = 7; i >= 0; --i) {
            tbuf[i] = (unsigned char)(T & 0xFF);
            T >>= 8;
        }

        uint32_t ids_be = htonl(ids_len);
        y_pt_len = 32 + 16 + 8 + 4 + (int)ids_len;
        y_pt = (unsigned char *)malloc((size_t)y_pt_len);
        if (!y_pt) {
            fprintf(stderr, "[Server] malloc(y_pt) failed\n");
            goto cleanup_conn;
        }

        int off = 0;
        memcpy(y_pt + off, ksym, 32); off += 32;
        memcpy(y_pt + off, ri, 16);   off += 16;
        memcpy(y_pt + off, tbuf, 8);  off += 8;
        memcpy(y_pt + off, &ids_be, 4); off += 4;
        memcpy(y_pt + off, IDS, ids_len); off += (int)ids_len;

        t0 = now_ns();
        int enc_ok = aes256_cbc_encrypt(klocal, y_pt, y_pt_len, &yCi, &yCi_len);
        dt = now_ns() - t0;
        tim.encrypt_yci_ns += dt;
        tim.step4_ns += dt;

        if (!enc_ok) {
            fprintf(stderr, "[Server] Encrypt yCi failed\n");
            goto cleanup_conn;
        }

        t0 = now_ns();
        int hy_ok = hmac_sha256(klocal, sizeof(klocal), yCi, (size_t)yCi_len, hy, &hy_len);
        dt = now_ns() - t0;
        tim.hmac_hy_ns += dt;
        tim.step4_ns += dt;

        if (!hy_ok) {
            fprintf(stderr, "[Server] HMAC hy failed\n");
            goto cleanup_conn;
        }

        print_hex("[Server] ksym", ksym, sizeof(ksym));
        printf("[Server] lifetime T = 3600 seconds; IDS = \"%s\"\n", IDS);
        print_hex("[Server] yCi (IV||CT)", yCi, (size_t)yCi_len);
        print_hex("[Server] hy", hy, (size_t)hy_len);

        // Send Msg3 (not timed)
        if (send_blob(cfd, yCi, (uint32_t)yCi_len) < 0 ||
            send_blob(cfd, hy, (uint32_t)hy_len) < 0) {
            fprintf(stderr, "[Server] Sending Msg3 failed\n");
            goto cleanup_conn;
        }
        printf("[Server] Sent: yCi || hy\n");

        // Receive SYNC (not timed)
        if (recv_blob(cfd, &sync, &sync_len) == 0) {
            printf("[Server] Received SYNC msg (%u bytes)\n", sync_len);
        }

        printf("[Server] Handshake complete. Ready to use ksym for T seconds.\n");
        handshake_ok = 1;

cleanup_conn:
        if (tim.step1_ns || tim.step2_ns || tim.step3_ns || tim.step4_ns) {
            print_timings_server(&tim, handshake_ok);
        }

        if (ecdh_secret) {
            OPENSSL_cleanse(ecdh_secret, ecdh_secret_len);
            free(ecdh_secret);
        }
        OPENSSL_cleanse(klocal, sizeof(klocal));
        OPENSSL_cleanse(ksym, sizeof(ksym));
        OPENSSL_cleanse(ri, sizeof(ri));

        if (sync) free(sync);
        if (yCi) free(yCi);
        if (y_pt) free(y_pt);
        if (client_cert_pem) free(client_cert_pem);
        if (pt) free(pt);
        if (info) free(info);
        if (hm) free(hm);
        if (m_rci) free(m_rci);
        if (alpha_tc) free(alpha_tc);
        if (cli_pub_der) free(cli_pub_der);
        if (cert_pem) free(cert_pem);
        if (alpha_ts) free(alpha_ts);
        if (srv_pub_der) free(srv_pub_der);

        if (client_sig_pub) EVP_PKEY_free(client_sig_pub);
        if (cli_eph_pub) EVP_PKEY_free(cli_eph_pub);
        if (srv_eph) EVP_PKEY_free(srv_eph);
        if (server_sign_key) EVP_PKEY_free(server_sign_key);

        if (client_cert) X509_free(client_cert);
        if (ca_cert) X509_free(ca_cert);
        if (server_cert) X509_free(server_cert);

        close(cfd);
    }

    close(sfd);
    return 0;
}