// client.c — Ephemeral ECDHE + transcript signatures + HKDF + AES-CBC + HMAC
// TIMED VERSION: step-by-step compute timing, send/recv excluded
//
// Receives:   CertS || kpub,S || alpha_TS
// Sends:      kpub,Ci || alpha_TC || m_rCi || hm
// Receives:   yCi || hy, verifies, checks ri and IDS, then sends "SYNC".
//
// Build:
//   gcc -O2 client.c -lssl -lcrypto -o client
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

#define SERVER_IP "127.0.0.1"
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

static inline uint64_t now_ns(void){
    struct timespec ts;
    clock_gettime(LSEG_TIMING_CLOCK, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static inline double ns_to_us(uint64_t ns){
    return (double)ns / 1000.0;
}

typedef struct {
    uint64_t step1_ns;
    uint64_t step2_ns;
    uint64_t step3_ns;
    uint64_t step4_ns;

    // Step 1
    uint64_t srv_cert_parse_ns;
    uint64_t srv_cert_verify_ns;
    uint64_t srv_sigpub_extract_ns;
    uint64_t alpha_ts_verify_ns;

    // Step 2
    uint64_t cli_eph_keygen_ns;
    uint64_t cli_pub_der_ns;
    uint64_t alpha_tc_sign_ns;
    uint64_t srv_eph_parse_ns;
    uint64_t ecdh_ns;
    uint64_t hkdf_ns;

    // Step 3
    uint64_t rand_ri_ns;
    uint64_t encrypt_mrci_ns;
    uint64_t hmac_hm_ns;

    // Step 4
    uint64_t hmac_hy_verify_ns;
    uint64_t decrypt_yci_ns;
    uint64_t parse_yci_ns;
    uint64_t nonce_check_ns;
} timings_t;

static void print_timings_client(const timings_t *t, int success){
    uint64_t total_ns = t->step1_ns + t->step2_ns + t->step3_ns + t->step4_ns;

    printf("\n==================== CLIENT TIMING ====================\n");
    printf("Status: %s\n", success ? "handshake complete" : "handshake aborted");
    printf("Compute-only timings (send/recv excluded)\n\n");

    printf("Step 1 (Verify server offer):      %10.2f us\n", ns_to_us(t->step1_ns));
    printf("  - Parse server cert:             %10.2f us\n", ns_to_us(t->srv_cert_parse_ns));
    printf("  - Verify server cert:            %10.2f us\n", ns_to_us(t->srv_cert_verify_ns));
    printf("  - Extract server verify key:     %10.2f us\n", ns_to_us(t->srv_sigpub_extract_ns));
    printf("  - Verify alpha_TS:               %10.2f us\n", ns_to_us(t->alpha_ts_verify_ns));

    printf("\nStep 2 (Client auth + klocal):      %10.2f us\n", ns_to_us(t->step2_ns));
    printf("  - Client ECDHE keygen:           %10.2f us\n", ns_to_us(t->cli_eph_keygen_ns));
    printf("  - DER encode client eph pub:     %10.2f us\n", ns_to_us(t->cli_pub_der_ns));
    printf("  - Sign alpha_TC:                 %10.2f us\n", ns_to_us(t->alpha_tc_sign_ns));
    printf("  - Parse server eph pub:          %10.2f us\n", ns_to_us(t->srv_eph_parse_ns));
    printf("  - ECDH derive:                   %10.2f us\n", ns_to_us(t->ecdh_ns));
    printf("  - HKDF derive klocal:            %10.2f us\n", ns_to_us(t->hkdf_ns));

    printf("\nStep 3 (Build client request):      %10.2f us\n", ns_to_us(t->step3_ns));
    printf("  - RAND_bytes(ri):                %10.2f us\n", ns_to_us(t->rand_ri_ns));
    printf("  - AES encrypt m_rCi:             %10.2f us\n", ns_to_us(t->encrypt_mrci_ns));
    printf("  - HMAC hm:                       %10.2f us\n", ns_to_us(t->hmac_hm_ns));

    printf("\nStep 4 (Verify server response):    %10.2f us\n", ns_to_us(t->step4_ns));
    printf("  - Verify hy (HMAC):              %10.2f us\n", ns_to_us(t->hmac_hy_verify_ns));
    printf("  - AES decrypt yCi:               %10.2f us\n", ns_to_us(t->decrypt_yci_ns));
    printf("  - Parse yCi fields:              %10.2f us\n", ns_to_us(t->parse_yci_ns));
    printf("  - Check nonce r'i == ri:         %10.2f us\n", ns_to_us(t->nonce_check_ns));

    printf("\nTOTAL client compute:              %10.2f us\n", ns_to_us(total_ns));
    printf("=======================================================\n\n");
}

/* ========================= Utility ========================= */

static void handle_error(const char *msg){
    perror(msg);
    exit(EXIT_FAILURE);
}

static void print_hex(const char *label, const unsigned char *data, size_t len){
#if LSEG_DEBUG
    if (label) printf("%s (%zu bytes): ", label, len);
    else       printf("(%zu bytes): ", len);
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
#else
    (void)label; (void)data; (void)len;
#endif
}

static int send_all(int fd, const void *buf, size_t len){
    const unsigned char *p = (const unsigned char*)buf;
    size_t sent = 0;
    while (sent < len){
        ssize_t n = send(fd, p + sent, len - sent, 0);
        if (n < 0){
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static int recv_all(int fd, void *buf, size_t len){
    unsigned char *p = (unsigned char*)buf;
    size_t recvd = 0;
    while (recvd < len){
        ssize_t n = recv(fd, p + recvd, len - recvd, 0);
        if (n < 0){
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        recvd += (size_t)n;
    }
    return 0;
}

static int send_blob(int fd, const unsigned char *data, uint32_t len){
    uint32_t nlen = htonl(len);
    if (send_all(fd, &nlen, sizeof(nlen)) < 0) return -1;
    if (len > 0 && send_all(fd, data, len) < 0) return -1;
    return 0;
}

static int recv_blob(int fd, unsigned char **out, uint32_t *outlen){
    uint32_t nlen = 0;
    if (recv_all(fd, &nlen, sizeof(nlen)) < 0) return -1;

    uint32_t len = ntohl(nlen);
    unsigned char *buf = NULL;

    if (len > 0){
        buf = (unsigned char*)malloc(len);
        if (!buf) return -1;
        if (recv_all(fd, buf, len) < 0){
            free(buf);
            return -1;
        }
    }

    *out = buf;
    *outlen = len;
    return 0;
}

/* ========================= Files / Certs ========================= */

static unsigned char *read_file(const char *path, size_t *len_out){
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (sz < 0){
        fclose(f);
        return NULL;
    }

    unsigned char *buf = (unsigned char*)malloc((size_t)sz);
    if (!buf){
        fclose(f);
        return NULL;
    }

    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);

    if (n != (size_t)sz){
        free(buf);
        return NULL;
    }

    *len_out = (size_t)sz;
    return buf;
}

static X509 *load_cert_pem(const char *path){
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    X509 *c = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);
    return c;
}

static EVP_PKEY *load_privkey_pem(const char *path){
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    EVP_PKEY *k = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    return k;
}

static int verify_cert_with_ca(X509 *cert, X509 *ca_cert){
    int ok = 0;

    X509_STORE *store = X509_STORE_new();
    if (!store) return 0;

    if (X509_STORE_add_cert(store, ca_cert) != 1){
        X509_STORE_free(store);
        return 0;
    }

    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (!ctx){
        X509_STORE_free(store);
        return 0;
    }

    if (X509_STORE_CTX_init(ctx, store, cert, NULL) != 1){
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);
        return 0;
    }

    ok = (X509_verify_cert(ctx) == 1);

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    return ok;
}

/* ========================= Ephemeral & KDF ========================= */

static EVP_PKEY *generate_ephemeral_ec_key(void){
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) return NULL;

    if (EVP_PKEY_paramgen_init(pctx) <= 0){
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0){
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    EVP_PKEY *params = NULL;
    if (EVP_PKEY_paramgen(pctx, &params) <= 0){
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new(params, NULL);
    EVP_PKEY_free(params);

    if (!kctx){
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    if (EVP_PKEY_keygen_init(kctx) <= 0){
        EVP_PKEY_CTX_free(kctx);
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    if (EVP_PKEY_keygen(kctx, &pkey) <= 0){
        EVP_PKEY_CTX_free(kctx);
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

static int pubkey_to_der(EVP_PKEY *pkey, unsigned char **der, int *der_len){
    *der = NULL;
    *der_len = 0;

    int len = i2d_PUBKEY(pkey, NULL);
    if (len <= 0) return 0;

    *der = (unsigned char*)malloc((size_t)len);
    if (!*der) return 0;

    unsigned char *tmp = *der;
    int len2 = i2d_PUBKEY(pkey, &tmp);
    if (len2 != len){
        free(*der);
        *der = NULL;
        return 0;
    }

    *der_len = len;
    return 1;
}

static EVP_PKEY *pubkey_from_der(const unsigned char *der, int der_len){
    const unsigned char *p = der;
    return d2i_PUBKEY(NULL, &p, der_len);
}

static int ecdh_derive(EVP_PKEY *priv, EVP_PKEY *peer_pub, unsigned char **secret, size_t *secret_len){
    *secret = NULL;
    *secret_len = 0;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv, NULL);
    if (!ctx) return 0;

    if (EVP_PKEY_derive_init(ctx) <= 0){
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (EVP_PKEY_derive_set_peer(ctx, peer_pub) <= 0){
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    size_t len = 0;
    if (EVP_PKEY_derive(ctx, NULL, &len) <= 0){
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    unsigned char *buf = (unsigned char*)malloc(len);
    if (!buf){
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (EVP_PKEY_derive(ctx, buf, &len) <= 0){
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
                       unsigned char *out, size_t out_len){
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

/* ========================= Sign / Verify ========================= */

static int sign_bytes(const unsigned char *msg, size_t msg_len, EVP_PKEY *sign_key,
                      unsigned char **sig, size_t *sig_len){
    *sig = NULL;
    *sig_len = 0;

    EVP_MD_CTX *m = EVP_MD_CTX_new();
    if (!m) return 0;

    int ok = 0;
    if (EVP_DigestSignInit(m, NULL, EVP_sha256(), NULL, sign_key) != 1) goto out;
    if (EVP_DigestSignUpdate(m, msg, msg_len) != 1) goto out;

    size_t need = 0;
    if (EVP_DigestSignFinal(m, NULL, &need) != 1 || need == 0) goto out;

    unsigned char *buf = (unsigned char*)malloc(need);
    if (!buf) goto out;

    if (EVP_DigestSignFinal(m, buf, &need) != 1){
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
                      const unsigned char *sig, size_t sig_len){
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

/* ========================= AES / HMAC ========================= */

static int aes256_cbc_encrypt(const unsigned char *key32,
                              const unsigned char *pt, int pt_len,
                              unsigned char **out, int *out_len){
    *out = NULL;
    *out_len = 0;

    unsigned char iv[16];
    if (RAND_bytes(iv, 16) != 1) return 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    unsigned char *buf = (unsigned char*)malloc((size_t)(16 + pt_len + 32));
    if (!buf){
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    memcpy(buf, iv, 16);

    int ok = 0, len = 0, ct_len = 0;
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
                              unsigned char **pt, int *pt_len){
    *pt = NULL;
    *pt_len = 0;

    if (in_len < 16) return 0;

    const unsigned char *iv = in;
    const unsigned char *ct = in + 16;
    int ct_len = in_len - 16;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    unsigned char *buf = (unsigned char*)malloc((size_t)ct_len);
    if (!buf){
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    int ok = 0, len = 0, out_len = 0;
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
                       unsigned char out[EVP_MAX_MD_SIZE], unsigned int *outlen){
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

/* ========================= Main client flow ========================= */

int main(void){
    OpenSSL_add_all_algorithms();

    timings_t tim;
    memset(&tim, 0, sizeof(tim));
    uint64_t t0, dt;
    int handshake_ok = 0;

    int fd = -1;

    X509 *ca_cert = NULL;
    X509 *srv_cert = NULL;

    EVP_PKEY *client_sign_key = NULL;
    EVP_PKEY *srv_sig_pub = NULL;
    EVP_PKEY *cli_eph = NULL;
    EVP_PKEY *srv_eph_pub = NULL;

    unsigned char *client_cert_pem = NULL;
    size_t client_cert_pem_len = 0;

    unsigned char *srv_cert_pem = NULL; uint32_t srv_cert_pem_len = 0;
    unsigned char *srv_pub_der  = NULL; uint32_t srv_pub_der_len  = 0;
    unsigned char *alpha_ts     = NULL; uint32_t alpha_ts_len     = 0;

    unsigned char *cli_pub_der = NULL; int cli_pub_der_len = 0;
    unsigned char *alpha_tc = NULL; size_t alpha_tc_len = 0;

    unsigned char *ecdh_secret = NULL; size_t ecdh_secret_len = 0;
    unsigned char *info = NULL;

    unsigned char *m_pt = NULL;
    unsigned char *m_rci = NULL; int m_rci_len = 0;

    unsigned char *yCi = NULL; uint32_t yCi_len = 0;
    unsigned char *hy  = NULL; uint32_t hy_len  = 0;
    unsigned char *y_pt = NULL; int y_pt_len = 0;

    char *IDS = NULL;

    unsigned char klocal[32]; memset(klocal, 0, sizeof(klocal));
    unsigned char ri[16];     memset(ri, 0, sizeof(ri));
    unsigned char ri2[16];    memset(ri2, 0, sizeof(ri2));
    unsigned char tbuf[8];    memset(tbuf, 0, sizeof(tbuf));
    unsigned char hm[EVP_MAX_MD_SIZE]; memset(hm, 0, sizeof(hm));
    unsigned char hy_calc[EVP_MAX_MD_SIZE]; memset(hy_calc, 0, sizeof(hy_calc));
    unsigned int hm_len = 0;
    unsigned int hy_calc_len = 0;
    unsigned char ksym[32]; memset(ksym, 0, sizeof(ksym));

    /* ---- Connect ---- */
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) handle_error("[Client] socket");

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        handle_error("[Client] connect");

    printf("[Client] Connected to %s:%d\n", SERVER_IP, PORT);

    /* ---- Load CA and client signing materials (not timed) ---- */
    ca_cert = load_cert_pem("./certs/ca_certificate.pem");
    client_sign_key = load_privkey_pem("./keys/client_signing_private_key.pem");
    client_cert_pem = read_file("./certs/client_certificate.pem", &client_cert_pem_len);

    if (!ca_cert || !client_sign_key || !client_cert_pem){
        fprintf(stderr, "[Client] Failed to load CA or client keys/cert\n");
        goto cleanup;
    }

    /* =================== Receive Msg1 (not timed) =================== */
    if (recv_blob(fd, &srv_cert_pem, &srv_cert_pem_len) < 0 ||
        recv_blob(fd, &srv_pub_der,  &srv_pub_der_len)  < 0 ||
        recv_blob(fd, &alpha_ts,     &alpha_ts_len)     < 0) {
        fprintf(stderr, "[Client] Receiving Msg1 failed\n");
        goto cleanup;
    }

    printf("[Client] Received: CertS || kpub,S || alpha_TS\n");
    print_hex("  kpub,S (DER)", srv_pub_der, srv_pub_der_len);
    print_hex("  alpha_TS", alpha_ts, alpha_ts_len);

    /* =================== Step 1: Verify server offer =================== */

    t0 = now_ns();
    BIO *b = BIO_new_mem_buf(srv_cert_pem, (int)srv_cert_pem_len);
    srv_cert = b ? PEM_read_bio_X509(b, NULL, NULL, NULL) : NULL;
    if (b) BIO_free(b);
    dt = now_ns() - t0;
    tim.srv_cert_parse_ns += dt;
    tim.step1_ns += dt;

    if (!srv_cert){
        fprintf(stderr, "[Client] Parse server cert failed\n");
        goto cleanup;
    }

    t0 = now_ns();
    int srv_cert_ok = verify_cert_with_ca(srv_cert, ca_cert);
    dt = now_ns() - t0;
    tim.srv_cert_verify_ns += dt;
    tim.step1_ns += dt;

    if (!srv_cert_ok){
        fprintf(stderr, "[Client] Server certificate verification FAILED\n");
        goto cleanup;
    }
    printf("[Client] Server certificate verified OK\n");

    t0 = now_ns();
    srv_sig_pub = X509_get_pubkey(srv_cert);
    dt = now_ns() - t0;
    tim.srv_sigpub_extract_ns += dt;
    tim.step1_ns += dt;

    if (!srv_sig_pub){
        fprintf(stderr, "[Client] Extract server SIG pubkey failed\n");
        goto cleanup;
    }

    t0 = now_ns();
    int alpha_ts_ok = verify_sig(srv_pub_der, srv_pub_der_len, srv_sig_pub, alpha_ts, alpha_ts_len);
    dt = now_ns() - t0;
    tim.alpha_ts_verify_ns += dt;
    tim.step1_ns += dt;

    if (!alpha_ts_ok){
        fprintf(stderr, "[Client] alpha_TS verification FAILED\n");
        goto cleanup;
    }
    printf("[Client] alpha_TS verified OK (server signed its ephemeral key)\n");

    /* =================== Step 2: Client auth + derive klocal =================== */

    t0 = now_ns();
    cli_eph = generate_ephemeral_ec_key();
    dt = now_ns() - t0;
    tim.cli_eph_keygen_ns += dt;
    tim.step2_ns += dt;

    if (!cli_eph){
        fprintf(stderr, "[Client] Ephemeral keygen failed\n");
        goto cleanup;
    }

    t0 = now_ns();
    int cli_der_ok = pubkey_to_der(cli_eph, &cli_pub_der, &cli_pub_der_len);
    dt = now_ns() - t0;
    tim.cli_pub_der_ns += dt;
    tim.step2_ns += dt;

    if (!cli_der_ok){
        fprintf(stderr, "[Client] DER encode kpub,Ci failed\n");
        goto cleanup;
    }
    print_hex("[Client] Ephemeral kpub,Ci (DER)", cli_pub_der, (size_t)cli_pub_der_len);

    t0 = now_ns();
    int alpha_tc_ok = sign_bytes(cli_pub_der, (size_t)cli_pub_der_len, client_sign_key, &alpha_tc, &alpha_tc_len);
    dt = now_ns() - t0;
    tim.alpha_tc_sign_ns += dt;
    tim.step2_ns += dt;

    if (!alpha_tc_ok){
        fprintf(stderr, "[Client] alpha_TC signing failed\n");
        goto cleanup;
    }
    print_hex("[Client] alpha_TC", alpha_tc, alpha_tc_len);

    t0 = now_ns();
    srv_eph_pub = pubkey_from_der(srv_pub_der, (int)srv_pub_der_len);
    dt = now_ns() - t0;
    tim.srv_eph_parse_ns += dt;
    tim.step2_ns += dt;

    if (!srv_eph_pub){
        fprintf(stderr, "[Client] d2i kpub,S failed\n");
        goto cleanup;
    }

    t0 = now_ns();
    int ecdh_ok = ecdh_derive(cli_eph, srv_eph_pub, &ecdh_secret, &ecdh_secret_len);
    dt = now_ns() - t0;
    tim.ecdh_ns += dt;
    tim.step2_ns += dt;

    if (!ecdh_ok){
        fprintf(stderr, "[Client] ECDH derive failed\n");
        goto cleanup;
    }
    print_hex("[Client] ECDH shared secret", ecdh_secret, ecdh_secret_len);

    const char *label = "Asfand-v3";
    size_t label_len = strlen(label);
    size_t info_len = label_len + (size_t)srv_pub_der_len + (size_t)cli_pub_der_len;

    info = (unsigned char*)malloc(info_len);
    if (!info){
        fprintf(stderr, "[Client] malloc(info) failed\n");
        goto cleanup;
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

    if (!hkdf_ok){
        fprintf(stderr, "[Client] HKDF failed\n");
        goto cleanup;
    }
    print_hex("[Client] klocal", klocal, sizeof(klocal));

    /* =================== Step 3: Build client request =================== */

    t0 = now_ns();
    int rnd_ok = RAND_bytes(ri, sizeof(ri));
    dt = now_ns() - t0;
    tim.rand_ri_ns += dt;
    tim.step3_ns += dt;

    if (rnd_ok != 1){
        fprintf(stderr, "[Client] RAND ri failed\n");
        goto cleanup;
    }
    print_hex("[Client] ri (nonce)", ri, sizeof(ri));

    uint32_t cert_len_be = htonl((uint32_t)client_cert_pem_len);
    int m_pt_len = 4 + (int)client_cert_pem_len + 16;

    m_pt = (unsigned char*)malloc((size_t)m_pt_len);
    if (!m_pt){
        fprintf(stderr, "[Client] malloc(m_pt) failed\n");
        goto cleanup;
    }

    memcpy(m_pt, &cert_len_be, 4);
    memcpy(m_pt + 4, client_cert_pem, client_cert_pem_len);
    memcpy(m_pt + 4 + client_cert_pem_len, ri, 16);

    t0 = now_ns();
    int enc_ok = aes256_cbc_encrypt(klocal, m_pt, m_pt_len, &m_rci, &m_rci_len);
    dt = now_ns() - t0;
    tim.encrypt_mrci_ns += dt;
    tim.step3_ns += dt;

    if (!enc_ok){
        fprintf(stderr, "[Client] Encrypt m_rCi failed\n");
        goto cleanup;
    }
    print_hex("[Client] m_rCi (IV||CT)", m_rci, (size_t)m_rci_len);

    t0 = now_ns();
    int hm_ok = hmac_sha256(klocal, sizeof(klocal), m_rci, (size_t)m_rci_len, hm, &hm_len);
    dt = now_ns() - t0;
    tim.hmac_hm_ns += dt;
    tim.step3_ns += dt;

    if (!hm_ok){
        fprintf(stderr, "[Client] HMAC hm failed\n");
        goto cleanup;
    }
    print_hex("[Client] hm", hm, (size_t)hm_len);

    /* ---- Send Msg2 (not timed) ---- */
    if (send_blob(fd, cli_pub_der, (uint32_t)cli_pub_der_len) < 0 ||
        send_blob(fd, alpha_tc,   (uint32_t)alpha_tc_len)   < 0 ||
        send_blob(fd, m_rci,      (uint32_t)m_rci_len)      < 0 ||
        send_blob(fd, hm,         (uint32_t)hm_len)         < 0) {
        fprintf(stderr, "[Client] Sending Msg2 failed\n");
        goto cleanup;
    }
    printf("[Client] Sent: kpub,Ci || alpha_TC || m_rCi || hm\n");

    /* ---- Receive Msg3 (not timed) ---- */
    if (recv_blob(fd, &yCi, &yCi_len) < 0 || recv_blob(fd, &hy, &hy_len) < 0){
        fprintf(stderr, "[Client] Receiving Msg3 failed\n");
        goto cleanup;
    }

    print_hex("[Client] yCi (IV||CT)", yCi, yCi_len);
    print_hex("[Client] hy", hy, hy_len);

    /* =================== Step 4: Verify server response =================== */

    t0 = now_ns();
    int hy_ok = hmac_sha256(klocal, sizeof(klocal), yCi, yCi_len, hy_calc, &hy_calc_len);
    if (hy_ok){
        hy_ok = (hy_len == hy_calc_len && CRYPTO_memcmp(hy, hy_calc, hy_len) == 0);
    }
    dt = now_ns() - t0;
    tim.hmac_hy_verify_ns += dt;
    tim.step4_ns += dt;

    if (!hy_ok){
        fprintf(stderr, "[Client] hy verification FAILED\n");
        goto cleanup;
    }
    printf("[Client] hy verified OK\n");

    t0 = now_ns();
    int ydec_ok = aes256_cbc_decrypt(klocal, yCi, (int)yCi_len, &y_pt, &y_pt_len);
    dt = now_ns() - t0;
    tim.decrypt_yci_ns += dt;
    tim.step4_ns += dt;

    if (!ydec_ok){
        fprintf(stderr, "[Client] yCi decrypt failed\n");
        goto cleanup;
    }

    if (y_pt_len < 32 + 16 + 8 + 4){
        fprintf(stderr, "[Client] yCi plaintext too short\n");
        goto cleanup;
    }

    t0 = now_ns();
    int off = 0;
    memcpy(ksym, y_pt + off, 32); off += 32;
    memcpy(ri2,  y_pt + off, 16); off += 16;
    memcpy(tbuf, y_pt + off, 8);  off += 8;

    uint32_t ids_be = 0;
    memcpy(&ids_be, y_pt + off, 4);
    off += 4;

    uint32_t ids_len = ntohl(ids_be);
    if (y_pt_len != off + (int)ids_len){
        fprintf(stderr, "[Client] yCi IDS length mismatch\n");
        goto cleanup;
    }

    IDS = (char*)malloc((size_t)ids_len + 1);
    if (!IDS){
        fprintf(stderr, "[Client] malloc(IDS) failed\n");
        goto cleanup;
    }

    memcpy(IDS, y_pt + off, ids_len);
    IDS[ids_len] = '\0';

    dt = now_ns() - t0;
    tim.parse_yci_ns += dt;
    tim.step4_ns += dt;

    print_hex("[Client] ksym", ksym, sizeof(ksym));
    print_hex("[Client] r'i (from server)", ri2, sizeof(ri2));
    printf("[Client] IDS = \"%s\"\n", IDS);

    t0 = now_ns();
    int nonce_ok = (CRYPTO_memcmp(ri, ri2, sizeof(ri)) == 0);
    dt = now_ns() - t0;
    tim.nonce_check_ns += dt;
    tim.step4_ns += dt;

    if (!nonce_ok){
        fprintf(stderr, "[Client] NONCE MISMATCH r'i != ri — abort\n");
        goto cleanup;
    }
    printf("[Client] Nonce verified OK\n");

    uint64_t T = 0;
    for (int i = 0; i < 8; i++){
        T = (T << 8) | tbuf[i];
    }
    printf("[Client] Lifetime T = %llu seconds; store ksym accordingly\n",
           (unsigned long long)T);

    /* ---- Send SYNC (not timed) ---- */
    const char *sync = "SYNC";
    (void)send_blob(fd, (const unsigned char*)sync, 4);
    printf("[Client] Sent SYNC — handshake complete.\n");

    handshake_ok = 1;

cleanup:
    if (tim.step1_ns || tim.step2_ns || tim.step3_ns || tim.step4_ns){
        print_timings_client(&tim, handshake_ok);
    }

    if (ecdh_secret){
        OPENSSL_cleanse(ecdh_secret, ecdh_secret_len);
        free(ecdh_secret);
    }

    OPENSSL_cleanse(klocal, sizeof(klocal));
    OPENSSL_cleanse(ri, sizeof(ri));
    OPENSSL_cleanse(ri2, sizeof(ri2));
    OPENSSL_cleanse(ksym, sizeof(ksym));
    OPENSSL_cleanse(hm, sizeof(hm));
    OPENSSL_cleanse(hy_calc, sizeof(hy_calc));

    if (IDS) free(IDS);
    if (y_pt) free(y_pt);
    if (hy) free(hy);
    if (yCi) free(yCi);
    if (m_rci) free(m_rci);
    if (m_pt) free(m_pt);
    if (info) free(info);
    if (alpha_tc) free(alpha_tc);
    if (cli_pub_der) free(cli_pub_der);
    if (alpha_ts) free(alpha_ts);
    if (srv_pub_der) free(srv_pub_der);
    if (srv_cert_pem) free(srv_cert_pem);
    if (client_cert_pem) free(client_cert_pem);

    if (srv_eph_pub) EVP_PKEY_free(srv_eph_pub);
    if (cli_eph) EVP_PKEY_free(cli_eph);
    if (srv_sig_pub) EVP_PKEY_free(srv_sig_pub);
    if (client_sign_key) EVP_PKEY_free(client_sign_key);

    if (srv_cert) X509_free(srv_cert);
    if (ca_cert) X509_free(ca_cert);

    if (fd >= 0) close(fd);

    return handshake_ok ? 0 : 1;
}