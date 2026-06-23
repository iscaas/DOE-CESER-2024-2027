// -----------------------------------------------------------------------------
// server.c  (GSM as TCP server, aligned to the paper)
// Protocol (Figure 3 / Section 3.2):
//   0) Receive: ID_SGN                      [initiation, no secrets]
//   1) Send:    CertGSM | sigma_GSM | pk_e
//   2) Receive: SGN response
//        - accepted in either order:
//          A) m_rSGN | h_m | ct | CertSGN | sigma_SGN   (Figure 3 label)
//          B) ct | CertSGN | sigma_SGN | m_rSGN | h_m   (§3.2.2 prose)
//   3) Send:    y_GSM | h_y
//   4) Send:    SYNC
//
// Crypto:
//   Kyber512 (KEM), Falcon-512 (SIG), SHA3-256 KDF,
//   AES-256-CBC + HMAC-SHA3-256
//
// Timing:
//   compute-only (crypto/local processing), send/recv excluded
//   unit: microseconds (us)
//
// Build:
//   gcc -O2 -Wall server.c -loqs -lcrypto -o server
// -----------------------------------------------------------------------------

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <oqs/oqs.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define PORT 3000
#define MAX_MSG 65536
#define NONCE_LEN 16
#define MAX_ID_LEN 256

#define PATH_CA_PUB   "./keys/ca_falcon_public.key"
#define PATH_GSM_PRIV "./keys/gsm_falcon_private.key"
#define PATH_GSM_CERT "./keys/gsm_cert.bin"

#define ID_GSM_STR       "GSM-1"
#define LIFETIME_SECONDS 3600U

// ---------------- timing (us) ----------------
static inline uint64_t now_us(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC_RAW, &t);
    return (uint64_t)t.tv_sec * 1000000ULL + (uint64_t)(t.tv_nsec / 1000ULL);
}

// ---------------- helpers ----------------
static void die(const char *msg) { perror(msg); exit(EXIT_FAILURE); }

static int send_all(int fd, const uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, 0);
        if (n <= 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static int recv_all(int fd, uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = recv(fd, buf + off, len - off, MSG_WAITALL);
        if (n <= 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

// length-prefixed I/O: [u32be len][bytes]
static int send_len_and_buf(int fd, const uint8_t *buf, uint32_t len) {
    uint32_t be = htonl(len);
    if (send_all(fd, (const uint8_t *)&be, 4) != 0) return -1;
    if (len == 0) return 0;
    return send_all(fd, buf, len);
}

static int recv_len_and_buf(int fd, uint8_t **out, uint32_t *out_len) {
    uint32_t be;
    if (recv_all(fd, (uint8_t *)&be, 4) != 0) return -1;
    uint32_t len = ntohl(be);
    if (len > MAX_MSG) return -1;
    uint8_t *buf = (uint8_t *)malloc(len ? len : 1);
    if (!buf) return -1;
    if (len > 0 && recv_all(fd, buf, len) != 0) {
        free(buf);
        return -1;
    }
    *out = buf;
    *out_len = len;
    return 0;
}

static int read_file(const char *path, uint8_t **out, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long L = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (L <= 0 || L > MAX_MSG) { fclose(f); return -1; }

    uint8_t *buf = (uint8_t *)malloc((size_t)L);
    if (!buf) { fclose(f); return -1; }

    if (fread(buf, 1, (size_t)L, f) != (size_t)L) {
        free(buf);
        fclose(f);
        return -1;
    }
    fclose(f);

    *out = buf;
    *out_len = (size_t)L;
    return 0;
}

// ---------------- SHA3 / HMAC(SHA3-256) ----------------
static int sha3_256(const uint8_t *in, size_t in_len, uint8_t out[32]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    if (EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL) != 1) { EVP_MD_CTX_free(ctx); return -1; }
    if (EVP_DigestUpdate(ctx, in, in_len) != 1)            { EVP_MD_CTX_free(ctx); return -1; }

    unsigned int olen = 0;
    if (EVP_DigestFinal_ex(ctx, out, &olen) != 1 || olen != 32) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    EVP_MD_CTX_free(ctx);
    return 0;
}

static int hmac_sha3_256(const uint8_t key[32], const uint8_t *data, size_t data_len,
                         uint8_t *out, unsigned int *out_len) {
    HMAC_CTX *h = HMAC_CTX_new();
    if (!h) return -1;
    if (HMAC_Init_ex(h, key, 32, EVP_sha3_256(), NULL) != 1) { HMAC_CTX_free(h); return -1; }
    if (HMAC_Update(h, data, data_len) != 1)                { HMAC_CTX_free(h); return -1; }
    if (HMAC_Final(h, out, out_len) != 1)                   { HMAC_CTX_free(h); return -1; }
    HMAC_CTX_free(h);
    return 0;
}

// ---------------- AES-256-CBC (PKCS#7) ----------------
static int aes256cbc_encrypt(const uint8_t *pt, int pt_len,
                             const uint8_t key[32], const uint8_t iv[16],
                             uint8_t *ct, int *ct_len_out) {
    int len = 0, ct_len = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) { EVP_CIPHER_CTX_free(ctx); return -1; }
    if (EVP_EncryptUpdate(ctx, ct, &len, pt, pt_len) != 1)              { EVP_CIPHER_CTX_free(ctx); return -1; }
    ct_len = len;
    if (EVP_EncryptFinal_ex(ctx, ct + len, &len) != 1)                  { EVP_CIPHER_CTX_free(ctx); return -1; }
    ct_len += len;

    EVP_CIPHER_CTX_free(ctx);
    *ct_len_out = ct_len;
    return 0;
}

static int aes256cbc_decrypt(const uint8_t *ct, int ct_len,
                             const uint8_t key[32], const uint8_t iv[16],
                             uint8_t *pt, int *pt_len_out) {
    int len = 0, pt_len = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) { EVP_CIPHER_CTX_free(ctx); return -1; }
    if (EVP_DecryptUpdate(ctx, pt, &len, ct, ct_len) != 1)              { EVP_CIPHER_CTX_free(ctx); return -1; }
    pt_len = len;
    if (EVP_DecryptFinal_ex(ctx, pt + len, &len) != 1)                  { EVP_CIPHER_CTX_free(ctx); return -1; }
    pt_len += len;

    EVP_CIPHER_CTX_free(ctx);
    *pt_len_out = pt_len;
    return 0;
}

// deterministic IV = first 16 bytes of SHA3-256(k_local || label)
static int derive_iv(const uint8_t k_local[32], const char *label, uint8_t iv[16]) {
    uint8_t buf[32 + 64];
    size_t L = strlen(label);
    if (L > 64) return -1;
    memcpy(buf, k_local, 32);
    memcpy(buf + 32, label, L);
    uint8_t h[32];
    if (sha3_256(buf, 32 + L, h) != 0) return -1;
    memcpy(iv, h, 16);
    return 0;
}

// ---------------- toy certificate ----------------
typedef struct {
    uint8_t *raw; size_t raw_len;
    char *id; uint32_t id_len;
    uint8_t *pk; uint32_t pk_len;
    uint8_t *ca_sig; uint32_t ca_sig_len;
} ToyCert;

static void cert_free(ToyCert *c) {
    if (!c) return;
    free(c->raw);
    memset(c, 0, sizeof(*c));
}

static int cert_parse_from_bytes(const uint8_t *buf, size_t len, ToyCert *c) {
    memset(c, 0, sizeof(*c));
    if (len < 12) return -1;

    c->raw = (uint8_t *)malloc(len);
    if (!c->raw) return -1;
    memcpy(c->raw, buf, len);
    c->raw_len = len;

    const uint8_t *p = c->raw;
    const uint8_t *end = c->raw + len;
    uint32_t be = 0;

    if (p + 4 > end) return -1;
    memcpy(&be, p, 4); p += 4;
    c->id_len = ntohl(be);
    if (p + c->id_len + 4 > end) return -1;
    c->id = (char *)p; p += c->id_len;

    memcpy(&be, p, 4); p += 4;
    c->pk_len = ntohl(be);
    if (p + c->pk_len + 4 > end) return -1;
    c->pk = (uint8_t *)p; p += c->pk_len;

    memcpy(&be, p, 4); p += 4;
    c->ca_sig_len = ntohl(be);
    if (p + c->ca_sig_len != end) return -1;
    c->ca_sig = (uint8_t *)p;

    return 0;
}

static int cert_verify_with_ca(OQS_SIG *falcon, const ToyCert *c, const uint8_t *ca_pub) {
    // CA signs msg = id || pk
    size_t msg_len = (size_t)c->id_len + (size_t)c->pk_len;
    uint8_t *msg = (uint8_t *)malloc(msg_len);
    if (!msg) return -1;

    memcpy(msg, c->id, c->id_len);
    memcpy(msg + c->id_len, c->pk, c->pk_len);

    int rc = OQS_SIG_verify(falcon, msg, msg_len, c->ca_sig, c->ca_sig_len, ca_pub);
    free(msg);
    return (rc == OQS_SUCCESS) ? 0 : -1;
}

// Accept either:
//   A) m_r | h_m | ct | CertSGN | sigma_SGN   (Figure 3 label)
//   B) ct | CertSGN | sigma_SGN | m_r | h_m   (§3.2.2 prose)
static int recv_sgn_response_flexible(
    int fd, const OQS_KEM *kem,
    uint8_t **m_r, uint32_t *m_r_len,
    uint8_t **h_m, uint32_t *h_m_len,
    uint8_t **ct, uint32_t *ct_len,
    uint8_t **cert_sgn_raw, uint32_t *cert_sgn_len,
    uint8_t **sigma_sgn, uint32_t *sigma_sgn_len,
    int *used_prose_order
) {
    uint8_t *first = NULL; uint32_t first_len = 0;
    if (recv_len_and_buf(fd, &first, &first_len) != 0) return -1;

    if (first_len == kem->length_ciphertext) {
        // prose order: ct | CertSGN | sigma_SGN | m_r | h_m
        *used_prose_order = 1;
        *ct = first; *ct_len = first_len;

        if (recv_len_and_buf(fd, cert_sgn_raw, cert_sgn_len) != 0) return -1;
        if (recv_len_and_buf(fd, sigma_sgn, sigma_sgn_len) != 0) return -1;
        if (recv_len_and_buf(fd, m_r, m_r_len) != 0) return -1;
        if (recv_len_and_buf(fd, h_m, h_m_len) != 0) return -1;
    } else {
        // figure order: m_r | h_m | ct | CertSGN | sigma_SGN
        *used_prose_order = 0;
        *m_r = first; *m_r_len = first_len;

        if (recv_len_and_buf(fd, h_m, h_m_len) != 0) return -1;
        if (recv_len_and_buf(fd, ct, ct_len) != 0) return -1;
        if (recv_len_and_buf(fd, cert_sgn_raw, cert_sgn_len) != 0) return -1;
        if (recv_len_and_buf(fd, sigma_sgn, sigma_sgn_len) != 0) return -1;
    }

    if (*ct_len != kem->length_ciphertext) return -1;
    if (*h_m_len != 32) return -1; // HMAC-SHA3-256
    return 0;
}

static int id_matches_cert(const uint8_t *id_blob, uint32_t id_blob_len, const ToyCert *cert_sgn) {
    if (id_blob_len != cert_sgn->id_len) return 0;
    return CRYPTO_memcmp(id_blob, cert_sgn->id, id_blob_len) == 0;
}

// ---------------- main ----------------
int main(void) {
    OQS_SIG *falcon = OQS_SIG_new("falcon-512");
    if (!falcon) { fprintf(stderr, "Falcon init failed\n"); return 1; }

    OQS_KEM *kem = OQS_KEM_new("Kyber512");
    if (!kem) { fprintf(stderr, "Kyber init failed\n"); OQS_SIG_free(falcon); return 1; }

    // Load long-term GSM materials once (not timed)
    uint8_t *ca_pub = NULL; size_t ca_pub_len = 0;
    if (read_file(PATH_CA_PUB, &ca_pub, &ca_pub_len) != 0 || ca_pub_len != falcon->length_public_key)
        die("load CA pub");

    uint8_t *gsm_priv = NULL; size_t gsm_priv_len = 0;
    if (read_file(PATH_GSM_PRIV, &gsm_priv, &gsm_priv_len) != 0 || gsm_priv_len != falcon->length_secret_key)
        die("load GSM priv");

    uint8_t *cert_gsm_raw = NULL; size_t cert_gsm_len = 0;
    if (read_file(PATH_GSM_CERT, &cert_gsm_raw, &cert_gsm_len) != 0)
        die("load GSM cert");

    ToyCert cert_gsm = {0};
    if (cert_parse_from_bytes(cert_gsm_raw, cert_gsm_len, &cert_gsm) != 0)
        die("parse GSM cert");

    // TCP server setup
    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) die("socket");

    int opt = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) die("bind");
    if (listen(sfd, 10) < 0) die("listen");

    printf("[GSM] TCP server listening on port %d ...\n", PORT);

    for (;;) {
        int cfd = accept(sfd, NULL, NULL);
        if (cfd < 0) {
            perror("accept");
            continue;
        }

        printf("\n[GSM] === New connection ===\n");

        // -------- per-connection timing (us) --------
        double us_step1 = 0, us_step2 = 0, us_step3 = 0, us_step4 = 0;

        double us_kyber_keypair = 0;
        double us_sign_gsm = 0;

        double us_parse_cert_sgn = 0;
        double us_verify_cert_sgn = 0;
        double us_verify_sig_sgn = 0;

        double us_decaps = 0;
        double us_kdf = 0;
        double us_verify_hmac_m = 0;
        double us_iv_mr = 0;
        double us_dec_mr = 0;

        double us_rand_ksym = 0;
        double us_iv_y = 0;
        double us_enc_y = 0;
        double us_hmac_y = 0;

        int ok_handshake = 0;

        // -------- per-connection objects --------
        uint8_t *id_sgn = NULL; uint32_t id_sgn_len = 0;
        uint8_t *pk_e = NULL, *sk_e = NULL, *sigma_gsm = NULL;
        size_t sigma_gsm_len = 0;

        uint8_t *m_r = NULL, *h_m = NULL, *ct = NULL, *cert_sgn_raw = NULL, *sigma_sgn = NULL;
        uint32_t m_r_len = 0, h_m_len = 0, ct_len = 0, cert_sgn_len = 0, sigma_sgn_len = 0;

        ToyCert cert_sgn = {0};

        uint8_t *ss = NULL;
        uint8_t k_local[32]; memset(k_local, 0, sizeof(k_local));
        uint8_t r_sgn[NONCE_LEN]; memset(r_sgn, 0, sizeof(r_sgn));
        int r_len = 0;

        uint8_t *y_pt = NULL, *y = NULL;
        int y_len = 0;

        int used_prose_order = 0;

        // ========== Phase 1(1): initiation SGN -> GSM : ID_SGN ==========
        // Not timed: network only. We keep it explicit because §3.2.1 includes it.
        if (recv_len_and_buf(cfd, &id_sgn, &id_sgn_len) != 0) {
            fprintf(stderr, "[GSM] recv ID_SGN failed\n");
            goto cleanup_conn;
        }
        if (id_sgn_len == 0 || id_sgn_len > MAX_ID_LEN) {
            fprintf(stderr, "[GSM] invalid ID_SGN length\n");
            goto cleanup_conn;
        }

        // ========== Phase 1(2): GSM challenge ==========
        pk_e = (uint8_t *)malloc(kem->length_public_key);
        sk_e = (uint8_t *)malloc(kem->length_secret_key);
        sigma_gsm = (uint8_t *)malloc(falcon->length_signature);
        if (!pk_e || !sk_e || !sigma_gsm) {
            fprintf(stderr, "[GSM] alloc pk_e/sk_e/sigma_gsm failed\n");
            goto cleanup_conn;
        }

        uint64_t t0 = now_us();
        if (OQS_KEM_keypair(kem, pk_e, sk_e) != OQS_SUCCESS) {
            fprintf(stderr, "[GSM] Kyber keypair failed\n");
            goto cleanup_conn;
        }
        us_kyber_keypair += (double)(now_us() - t0);

        size_t M_len = cert_gsm.raw_len + kem->length_public_key;
        uint8_t *M = (uint8_t *)malloc(M_len);
        if (!M) {
            fprintf(stderr, "[GSM] malloc M failed\n");
            goto cleanup_conn;
        }
        memcpy(M, cert_gsm.raw, cert_gsm.raw_len);
        memcpy(M + cert_gsm.raw_len, pk_e, kem->length_public_key);

        t0 = now_us();
        if (OQS_SIG_sign(falcon, sigma_gsm, &sigma_gsm_len, M, M_len, gsm_priv) != OQS_SUCCESS) {
            free(M);
            fprintf(stderr, "[GSM] Falcon sign sigma_GSM failed\n");
            goto cleanup_conn;
        }
        us_sign_gsm += (double)(now_us() - t0);
        free(M);

        // Send: CertGSM | sigma_GSM | pk_e
        if (send_len_and_buf(cfd, cert_gsm.raw, (uint32_t)cert_gsm.raw_len) != 0 ||
            send_len_and_buf(cfd, sigma_gsm, (uint32_t)sigma_gsm_len) != 0 ||
            send_len_and_buf(cfd, pk_e, (uint32_t)kem->length_public_key) != 0) {
            fprintf(stderr, "[GSM] send challenge failed\n");
            goto cleanup_conn;
        }

        us_step1 = us_kyber_keypair + us_sign_gsm;
        printf("[GSM] Step1 sent: CertGSM | sigma_GSM | pk_e\n");

        // ========== Phase 2(3): receive SGN response ==========
        if (recv_sgn_response_flexible(cfd, kem,
                                       &m_r, &m_r_len,
                                       &h_m, &h_m_len,
                                       &ct, &ct_len,
                                       &cert_sgn_raw, &cert_sgn_len,
                                       &sigma_sgn, &sigma_sgn_len,
                                       &used_prose_order) != 0) {
            fprintf(stderr, "[GSM] recv SGN response failed\n");
            goto cleanup_conn;
        }

        // ---------- SGN certificate + signature verification ----------
        t0 = now_us();
        if (cert_parse_from_bytes(cert_sgn_raw, cert_sgn_len, &cert_sgn) != 0) {
            fprintf(stderr, "[GSM] parse CertSGN failed\n");
            goto cleanup_conn;
        }
        us_parse_cert_sgn += (double)(now_us() - t0);

        // Optional but protocol-consistent: initiation ID must match certificate identity
        if (!id_matches_cert(id_sgn, id_sgn_len, &cert_sgn)) {
            fprintf(stderr, "[GSM] ID_SGN mismatch with CertSGN identity\n");
            goto cleanup_conn;
        }

        t0 = now_us();
        if (cert_verify_with_ca(falcon, &cert_sgn, ca_pub) != 0) {
            fprintf(stderr, "[GSM] verify CertSGN with CA failed\n");
            goto cleanup_conn;
        }
        us_verify_cert_sgn += (double)(now_us() - t0);

        // Verify sigma_SGN over (CertSGN || ct)
        size_t M2_len = cert_sgn.raw_len + ct_len;
        uint8_t *M2 = (uint8_t *)malloc(M2_len);
        if (!M2) {
            fprintf(stderr, "[GSM] malloc M2 failed\n");
            goto cleanup_conn;
        }
        memcpy(M2, cert_sgn.raw, cert_sgn.raw_len);
        memcpy(M2 + cert_sgn.raw_len, ct, ct_len);

        t0 = now_us();
        if (OQS_SIG_verify(falcon, M2, M2_len, sigma_sgn, sigma_sgn_len, cert_sgn.pk) != OQS_SUCCESS) {
            free(M2);
            fprintf(stderr, "[GSM] verify sigma_SGN failed\n");
            goto cleanup_conn;
        }
        us_verify_sig_sgn += (double)(now_us() - t0);
        free(M2);

        us_step2 = us_parse_cert_sgn + us_verify_cert_sgn + us_verify_sig_sgn;
        printf("[GSM] Step2 OK: verified CertSGN + sigma_SGN (%s order)\n",
               used_prose_order ? "prose" : "figure");

        // ========== Phase 2(4): decaps + k_local + verify/decrypt nonce ==========
        ss = (uint8_t *)malloc(kem->length_shared_secret);
        if (!ss) {
            fprintf(stderr, "[GSM] malloc ss failed\n");
            goto cleanup_conn;
        }

        t0 = now_us();
        if (OQS_KEM_decaps(kem, ss, ct, sk_e) != OQS_SUCCESS) {
            fprintf(stderr, "[GSM] decaps failed\n");
            goto cleanup_conn;
        }
        us_decaps += (double)(now_us() - t0);

        t0 = now_us();
        if (sha3_256(ss, kem->length_shared_secret, k_local) != 0) {
            fprintf(stderr, "[GSM] SHA3(ss') failed\n");
            goto cleanup_conn;
        }
        us_kdf += (double)(now_us() - t0);

        // securely erase ephemeral KEM secret immediately after decapsulation
        OPENSSL_cleanse(sk_e, kem->length_secret_key);
        free(sk_e);
        sk_e = NULL;

        OPENSSL_cleanse(ss, kem->length_shared_secret);
        free(ss);
        ss = NULL;

        // Verify h_m = HMAC_klocal(m_r)
        uint8_t calc_hm[EVP_MAX_MD_SIZE];
        unsigned int calc_hm_len = 0;
        t0 = now_us();
        if (hmac_sha3_256(k_local, m_r, m_r_len, calc_hm, &calc_hm_len) != 0) {
            fprintf(stderr, "[GSM] hmac(m_r) failed\n");
            goto cleanup_conn;
        }
        us_verify_hmac_m += (double)(now_us() - t0);

        if (calc_hm_len != h_m_len || CRYPTO_memcmp(calc_hm, h_m, h_m_len) != 0) {
            fprintf(stderr, "[GSM] h_m mismatch\n");
            goto cleanup_conn;
        }

        uint8_t iv_mr[16];
        t0 = now_us();
        if (derive_iv(k_local, "SGN->GSM|mr", iv_mr) != 0) {
            fprintf(stderr, "[GSM] derive iv mr failed\n");
            goto cleanup_conn;
        }
        us_iv_mr += (double)(now_us() - t0);

        t0 = now_us();
        if (aes256cbc_decrypt(m_r, (int)m_r_len, k_local, iv_mr, r_sgn, &r_len) != 0) {
            fprintf(stderr, "[GSM] decrypt m_r failed\n");
            goto cleanup_conn;
        }
        us_dec_mr += (double)(now_us() - t0);

        if (r_len != NONCE_LEN) {
            fprintf(stderr, "[GSM] unexpected r_SGN length\n");
            goto cleanup_conn;
        }

        us_step3 = us_decaps + us_kdf + us_verify_hmac_m + us_iv_mr + us_dec_mr;
        printf("[GSM] Step3 OK: decapsulated, derived k_local, verified/decrypted r_SGN\n");

        // ========== Phase 2(5) + (7): y_GSM | h_y, then SYNC ==========
        uint8_t K_sym[32];
        t0 = now_us();
        if (RAND_bytes(K_sym, sizeof(K_sym)) != 1) {
            fprintf(stderr, "[GSM] RAND K_sym failed\n");
            goto cleanup_conn;
        }
        us_rand_ksym += (double)(now_us() - t0);

        uint32_t T = LIFETIME_SECONDS;
        uint32_t T_be = htonl(T);
        const char *ID_GSM = ID_GSM_STR;
        uint32_t id_len = (uint32_t)strlen(ID_GSM);
        uint32_t id_be = htonl(id_len);

        size_t y_pt_len = 32 + NONCE_LEN + 4 + 4 + id_len;
        y_pt = (uint8_t *)malloc(y_pt_len);
        if (!y_pt) {
            fprintf(stderr, "[GSM] malloc y_pt failed\n");
            goto cleanup_conn;
        }

        size_t off = 0;
        memcpy(y_pt + off, K_sym, 32);         off += 32;
        memcpy(y_pt + off, r_sgn, NONCE_LEN);  off += NONCE_LEN;
        memcpy(y_pt + off, &T_be, 4);          off += 4;
        memcpy(y_pt + off, &id_be, 4);         off += 4;
        memcpy(y_pt + off, ID_GSM, id_len);    off += id_len;

        uint8_t iv_y[16];
        t0 = now_us();
        if (derive_iv(k_local, "GSM->SGN|y", iv_y) != 0) {
            fprintf(stderr, "[GSM] derive iv y failed\n");
            goto cleanup_conn;
        }
        us_iv_y += (double)(now_us() - t0);

        int y_cap = (int)(y_pt_len + 32);
        y = (uint8_t *)malloc((size_t)y_cap);
        if (!y) {
            fprintf(stderr, "[GSM] malloc y failed\n");
            goto cleanup_conn;
        }

        t0 = now_us();
        if (aes256cbc_encrypt(y_pt, (int)y_pt_len, k_local, iv_y, y, &y_len) != 0) {
            fprintf(stderr, "[GSM] encrypt y failed\n");
            goto cleanup_conn;
        }
        us_enc_y += (double)(now_us() - t0);

        uint8_t h_y[EVP_MAX_MD_SIZE];
        unsigned int h_y_len = 0;
        t0 = now_us();
        if (hmac_sha3_256(k_local, y, (size_t)y_len, h_y, &h_y_len) != 0) {
            fprintf(stderr, "[GSM] hmac(y) failed\n");
            goto cleanup_conn;
        }
        us_hmac_y += (double)(now_us() - t0);

        if (send_len_and_buf(cfd, y, (uint32_t)y_len) != 0 ||
            send_len_and_buf(cfd, h_y, (uint32_t)h_y_len) != 0) {
            fprintf(stderr, "[GSM] send y|h_y failed\n");
            goto cleanup_conn;
        }

        // Final protocol sync message
        static const uint8_t sync_msg[] = {'S','Y','N','C'};
        if (send_len_and_buf(cfd, sync_msg, (uint32_t)sizeof(sync_msg)) != 0) {
            fprintf(stderr, "[GSM] send SYNC failed\n");
            goto cleanup_conn;
        }

        us_step4 = us_rand_ksym + us_iv_y + us_enc_y + us_hmac_y;
        ok_handshake = 1;

    cleanup_conn:
        {
            double total_us = us_step1 + us_step2 + us_step3 + us_step4;
            double total_no_ca_us = total_us - us_verify_cert_sgn;

            printf("\n==================== GSM SERVER TIMING ====================\n");
            printf("Status: %s\n", ok_handshake ? "handshake complete" : "FAILED");
            printf("Compute-only timings (send/recv excluded), unit: us\n\n");

            printf("Step 1 (GSM challenge generation):    %.2f us\n", us_step1);
            printf("  - Kyber keypair (pk_e, sk_e):       %.2f us\n", us_kyber_keypair);
            printf("  - Falcon sign sigma_GSM:            %.2f us\n", us_sign_gsm);

            printf("\nStep 2 (Authenticate SGN):           %.2f us\n", us_step2);
            printf("  - Parse CertSGN:                    %.2f us\n", us_parse_cert_sgn);
            printf("  - Verify CertSGN (CA):              %.2f us\n", us_verify_cert_sgn);
            printf("  - Verify sigma_SGN:                 %.2f us\n", us_verify_sig_sgn);

            printf("\nStep 3 (Decaps + nonce verification): %.2f us\n", us_step3);
            printf("  - Kyber decaps:                     %.2f us\n", us_decaps);
            printf("  - KDF k_local=SHA3(ss'):            %.2f us\n", us_kdf);
            printf("  - Verify HMAC(m_r):                 %.2f us\n", us_verify_hmac_m);
            printf("  - Derive IV(m_r):                   %.2f us\n", us_iv_mr);
            printf("  - AES decrypt m_r:                  %.2f us\n", us_dec_mr);

            printf("\nStep 4 (Symmetric key sharing):       %.2f us\n", us_step4);
            printf("  - RAND K_sym:                       %.2f us\n", us_rand_ksym);
            printf("  - Derive IV(y):                     %.2f us\n", us_iv_y);
            printf("  - AES encrypt y_GSM:                %.2f us\n", us_enc_y);
            printf("  - HMAC(y_GSM):                      %.2f us\n", us_hmac_y);

            printf("\nTOTAL GSM compute (incl. CA verify):  %.2f us\n", total_us);
            printf("TOTAL GSM compute (excl. CA verify):  %.2f us\n", total_no_ca_us);
            printf("===========================================================\n\n");
        }

        // cleanup per-connection
        if (id_sgn) {
            OPENSSL_cleanse(id_sgn, id_sgn_len);
            free(id_sgn);
        }

        free(pk_e);
        if (sk_e) {
            OPENSSL_cleanse(sk_e, kem->length_secret_key);
            free(sk_e);
        }
        free(sigma_gsm);

        free(m_r);
        free(h_m);
        free(ct);
        free(cert_sgn_raw);
        free(sigma_sgn);
        cert_free(&cert_sgn);

        if (ss) {
            OPENSSL_cleanse(ss, kem->length_shared_secret);
            free(ss);
        }

        OPENSSL_cleanse(k_local, sizeof(k_local));
        OPENSSL_cleanse(r_sgn, sizeof(r_sgn));

        if (y_pt) {
            OPENSSL_cleanse(y_pt, y_pt_len);
            free(y_pt);
        }
        if (y) free(y);

        close(cfd);
    }

    // not normally reached
    cert_free(&cert_gsm);
    free(cert_gsm_raw);
    free(ca_pub);
    free(gsm_priv);
    OQS_SIG_free(falcon);
    OQS_KEM_free(kem);
    close(sfd);
    return 0;
}