// -----------------------------------------------------------------------------
// client.c  (SGN as TCP client, aligned to the paper)
// Protocol:
//   0) Send:    ID_SGN
//   1) Receive: CertGSM | sigma_GSM | pk_e
//   2) Send:    ct | CertSGN | sigma_SGN | m_rSGN | h_m   [§3.2.2 prose order]
//   3) Receive: y_GSM | h_y
//   4) Receive: SYNC
//
// Crypto:
//   Kyber512 (KEM), Falcon-512 (SIG), SHA3-256 KDF,
//   AES-256-CBC + HMAC-SHA3-256
//
// Timing:
//   compute-only (send/recv excluded), unit: microseconds (us)
//
// Build:
//   gcc -O2 -Wall client.c -loqs -lcrypto -o client
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

#define SERVER_IP "127.0.0.1"
#define PORT 3000
#define MAX_MSG 65536
#define NONCE_LEN 16

#define PATH_CA_PUB   "./keys/ca_falcon_public.key"
#define PATH_SGN_PRIV "./keys/sgn_falcon_private.key"
#define PATH_SGN_CERT "./keys/sgn_cert.bin"

#define EXPECTED_ID_GSM "GSM-1"

// ---------------- timing (us) ----------------
static inline uint64_t now_us(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC_RAW, &t);
    return (uint64_t)t.tv_sec * 1000000ULL + (uint64_t)(t.tv_nsec / 1000ULL);
}

// ---------------- helpers ----------------
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
    if (L <= 0 || L > MAX_MSG) {
        fclose(f);
        return -1;
    }

    uint8_t *buf = (uint8_t *)malloc((size_t)L);
    if (!buf) {
        fclose(f);
        return -1;
    }

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

// ---------------- Toy certificate ----------------
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

static int cert_load_from_file(const char *path, ToyCert *c) {
    uint8_t *buf = NULL;
    size_t len = 0;
    if (read_file(path, &buf, &len) != 0) return -1;
    int rc = cert_parse_from_bytes(buf, len, c);
    free(buf);
    return rc;
}

static int load_key_file(const char *path, uint8_t **out, size_t *out_len) {
    return read_file(path, out, out_len);
}

static int cert_verify_with_ca(const OQS_SIG *falcon, const ToyCert *c,
                               const uint8_t *ca_pub, size_t ca_pub_len) {
    (void)ca_pub_len;
    size_t msg_len = (size_t)c->id_len + (size_t)c->pk_len;
    uint8_t *msg = (uint8_t *)malloc(msg_len);
    if (!msg) return -1;

    memcpy(msg, c->id, c->id_len);
    memcpy(msg + c->id_len, c->pk, c->pk_len);

    int rc = OQS_SIG_verify(falcon, msg, msg_len, c->ca_sig, c->ca_sig_len, (uint8_t *)ca_pub);
    free(msg);
    return (rc == OQS_SUCCESS) ? 0 : -1;
}

// ---------------- client main logic ----------------
static int run_client(void) {
    int fd = -1;

    // timing accumulators (us; crypto/local only)
    double us_step1 = 0, us_step2 = 0, us_step3 = 0, us_step4 = 0;

    double us_parse_cert_gsm = 0;
    double us_verify_cert_gsm = 0;
    double us_verify_sigma_gsm = 0;

    double us_encaps = 0;
    double us_kdf = 0;

    double us_rand_nonce = 0;
    double us_iv_mr = 0;
    double us_enc_mr = 0;
    double us_hmac_mr = 0;
    double us_sign_sgn = 0;

    double us_verify_hy = 0;
    double us_iv_y = 0;
    double us_dec_y = 0;
    double us_parse_y = 0;

    int ok_handshake = 0;

    OQS_SIG *falcon = NULL;
    OQS_KEM *kem = NULL;

    uint8_t *ca_pub = NULL; size_t ca_pub_len = 0;
    uint8_t *sgn_priv = NULL; size_t sgn_priv_len = 0;
    ToyCert cert_sgn = {0};

    uint8_t *cert_gsm_raw = NULL, *sigma_gsm = NULL, *pk_e = NULL;
    uint32_t cert_gsm_len = 0, sigma_gsm_len = 0, pk_e_len = 0;
    ToyCert cert_gsm = {0};

    uint8_t *ct = NULL, *ss = NULL, *m_r = NULL, *sigma_sgn = NULL;
    size_t sigma_sgn_len = 0;
    int m_r_len = 0;

    uint8_t *M = NULL, *M2 = NULL;

    uint8_t k_local[32]; memset(k_local, 0, sizeof(k_local));
    uint8_t r[NONCE_LEN]; memset(r, 0, sizeof(r));

    uint8_t *y = NULL, *h_y = NULL, *y_pt = NULL, *sync = NULL;
    uint32_t y_len = 0, h_y_len = 0, sync_len = 0;

    char *id_gsm = NULL;

    uint64_t t0 = 0;

    // Connect
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); goto cleanup; }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, SERVER_IP, &addr.sin_addr) <= 0) { perror("inet_pton"); goto cleanup; }
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) { perror("connect"); goto cleanup; }

    printf("[SGN] Connected to %s:%d\n", SERVER_IP, PORT);

    // Init primitives
    falcon = OQS_SIG_new("falcon-512");
    kem = OQS_KEM_new("Kyber512");
    if (!falcon || !kem) {
        fprintf(stderr, "[SGN] OQS init failed\n");
        goto cleanup;
    }

    // Load CA pub & SGN signing key + cert (not timed)
    if (load_key_file(PATH_CA_PUB, &ca_pub, &ca_pub_len) != 0 ||
        ca_pub_len != falcon->length_public_key) {
        fprintf(stderr, "[SGN] load CA pub failed\n");
        goto cleanup;
    }

    if (load_key_file(PATH_SGN_PRIV, &sgn_priv, &sgn_priv_len) != 0 ||
        sgn_priv_len != falcon->length_secret_key) {
        fprintf(stderr, "[SGN] load SGN Falcon sk failed\n");
        goto cleanup;
    }

    if (cert_load_from_file(PATH_SGN_CERT, &cert_sgn) != 0) {
        fprintf(stderr, "[SGN] load SGN cert failed\n");
        goto cleanup;
    }

    // ---- Phase 1(1): send ID_SGN initiation (I/O excluded from timing) ----
    if (send_len_and_buf(fd, (const uint8_t *)cert_sgn.id, cert_sgn.id_len) != 0) {
        fprintf(stderr, "[SGN] send ID_SGN failed\n");
        goto cleanup;
    }

    // ---- Phase 1(2): receive CertGSM | sigma_GSM | pk_e (I/O excluded) ----
    if (recv_len_and_buf(fd, &cert_gsm_raw, &cert_gsm_len) != 0 ||
        recv_len_and_buf(fd, &sigma_gsm, &sigma_gsm_len) != 0 ||
        recv_len_and_buf(fd, &pk_e, &pk_e_len) != 0) {
        fprintf(stderr, "[SGN] receive GSM challenge failed\n");
        goto cleanup;
    }
    if (pk_e_len != kem->length_public_key) {
        fprintf(stderr, "[SGN] pk_e length mismatch\n");
        goto cleanup;
    }

    // ========== Step 1: verify CertGSM and sigma_GSM ==========
    t0 = now_us();
    if (cert_parse_from_bytes(cert_gsm_raw, cert_gsm_len, &cert_gsm) != 0) {
        fprintf(stderr, "[SGN] parse CertGSM failed\n");
        goto cleanup;
    }
    us_parse_cert_gsm += (double)(now_us() - t0);

    t0 = now_us();
    if (cert_verify_with_ca(falcon, &cert_gsm, ca_pub, ca_pub_len) != 0) {
        fprintf(stderr, "[SGN] CertGSM verify FAIL\n");
        goto cleanup;
    }
    us_verify_cert_gsm += (double)(now_us() - t0);

    M = (uint8_t *)malloc(cert_gsm.raw_len + pk_e_len);
    if (!M) {
        fprintf(stderr, "[SGN] malloc M failed\n");
        goto cleanup;
    }
    memcpy(M, cert_gsm.raw, cert_gsm.raw_len);
    memcpy(M + cert_gsm.raw_len, pk_e, pk_e_len);

    t0 = now_us();
    if (OQS_SIG_verify(falcon, M, cert_gsm.raw_len + pk_e_len,
                       sigma_gsm, sigma_gsm_len, cert_gsm.pk) != OQS_SUCCESS) {
        fprintf(stderr, "[SGN] sigma_GSM verify FAIL\n");
        goto cleanup;
    }
    us_verify_sigma_gsm += (double)(now_us() - t0);
    free(M); M = NULL;

    us_step1 = us_parse_cert_gsm + us_verify_cert_gsm + us_verify_sigma_gsm;
    printf("[SGN] Step1 OK: verified CertGSM + sigma_GSM\n");

    // ========== Step 2: Kyber encaps + k_local ==========
    ct = (uint8_t *)malloc(kem->length_ciphertext);
    ss = (uint8_t *)malloc(kem->length_shared_secret);
    if (!ct || !ss) {
        fprintf(stderr, "[SGN] alloc ct/ss failed\n");
        goto cleanup;
    }

    t0 = now_us();
    if (OQS_KEM_encaps(kem, ct, ss, pk_e) != OQS_SUCCESS) {
        fprintf(stderr, "[SGN] Kyber encaps failed\n");
        goto cleanup;
    }
    us_encaps += (double)(now_us() - t0);

    t0 = now_us();
    if (sha3_256(ss, kem->length_shared_secret, k_local) != 0) {
        fprintf(stderr, "[SGN] SHA3(ss) failed\n");
        goto cleanup;
    }
    us_kdf += (double)(now_us() - t0);

    OPENSSL_cleanse(ss, kem->length_shared_secret);
    free(ss); ss = NULL;

    us_step2 = us_encaps + us_kdf;
    printf("[SGN] Step2 OK: encaps + k_local derived\n");

    // ========== Step 3: build ct | CertSGN | sigma_SGN | m_r | h_m ==========
    t0 = now_us();
    if (RAND_bytes(r, sizeof(r)) != 1) {
        fprintf(stderr, "[SGN] RAND nonce failed\n");
        goto cleanup;
    }
    us_rand_nonce += (double)(now_us() - t0);

    uint8_t iv_mr[16];
    t0 = now_us();
    if (derive_iv(k_local, "SGN->GSM|mr", iv_mr) != 0) {
        fprintf(stderr, "[SGN] derive iv_mr failed\n");
        goto cleanup;
    }
    us_iv_mr += (double)(now_us() - t0);

    int m_r_cap = NONCE_LEN + 32;
    m_r = (uint8_t *)malloc((size_t)m_r_cap);
    if (!m_r) {
        fprintf(stderr, "[SGN] alloc m_r failed\n");
        goto cleanup;
    }

    t0 = now_us();
    if (aes256cbc_encrypt(r, (int)sizeof(r), k_local, iv_mr, m_r, &m_r_len) != 0) {
        fprintf(stderr, "[SGN] Encrypt m_r failed\n");
        goto cleanup;
    }
    us_enc_mr += (double)(now_us() - t0);

    uint8_t h_m[EVP_MAX_MD_SIZE];
    unsigned int h_m_len = 0;
    t0 = now_us();
    if (hmac_sha3_256(k_local, m_r, (size_t)m_r_len, h_m, &h_m_len) != 0) {
        fprintf(stderr, "[SGN] HMAC(m_r) failed\n");
        goto cleanup;
    }
    us_hmac_mr += (double)(now_us() - t0);

    M2 = (uint8_t *)malloc(cert_sgn.raw_len + kem->length_ciphertext);
    if (!M2) {
        fprintf(stderr, "[SGN] malloc M2 failed\n");
        goto cleanup;
    }
    memcpy(M2, cert_sgn.raw, cert_sgn.raw_len);
    memcpy(M2 + cert_sgn.raw_len, ct, kem->length_ciphertext);

    sigma_sgn = (uint8_t *)malloc(falcon->length_signature);
    if (!sigma_sgn) {
        fprintf(stderr, "[SGN] malloc sigma_sgn failed\n");
        goto cleanup;
    }

    t0 = now_us();
    if (OQS_SIG_sign(falcon, sigma_sgn, &sigma_sgn_len,
                     M2, cert_sgn.raw_len + kem->length_ciphertext, sgn_priv) != OQS_SUCCESS) {
        fprintf(stderr, "[SGN] Falcon sign sigma_SGN failed\n");
        goto cleanup;
    }
    us_sign_sgn += (double)(now_us() - t0);
    free(M2); M2 = NULL;

    // Send prose order from §3.2.2: ct | CertSGN | sigma_SGN | m_r | h_m
    if (send_len_and_buf(fd, ct, (uint32_t)kem->length_ciphertext) != 0 ||
        send_len_and_buf(fd, cert_sgn.raw, (uint32_t)cert_sgn.raw_len) != 0 ||
        send_len_and_buf(fd, sigma_sgn, (uint32_t)sigma_sgn_len) != 0 ||
        send_len_and_buf(fd, m_r, (uint32_t)m_r_len) != 0 ||
        send_len_and_buf(fd, h_m, (uint32_t)h_m_len) != 0) {
        fprintf(stderr, "[SGN] send SGN response failed\n");
        goto cleanup;
    }

    us_step3 = us_rand_nonce + us_iv_mr + us_enc_mr + us_hmac_mr + us_sign_sgn;
    printf("[SGN] Step3 sent: ct | CertSGN | sigma_SGN | m_r | h_m\n");

    // ========== Step 4: verify y_GSM, decrypt, check nonce+ID, receive SYNC ==========
    if (recv_len_and_buf(fd, &y, &y_len) != 0 ||
        recv_len_and_buf(fd, &h_y, &h_y_len) != 0) {
        fprintf(stderr, "[SGN] recv y_GSM | h_y failed\n");
        goto cleanup;
    }

    uint8_t calc_hy[EVP_MAX_MD_SIZE];
    unsigned int calc_hy_len = 0;
    t0 = now_us();
    if (hmac_sha3_256(k_local, y, y_len, calc_hy, &calc_hy_len) != 0) {
        fprintf(stderr, "[SGN] HMAC(y) failed\n");
        goto cleanup;
    }
    if (calc_hy_len != h_y_len || CRYPTO_memcmp(calc_hy, h_y, h_y_len) != 0) {
        fprintf(stderr, "[SGN] HMAC(y) verification FAIL\n");
        goto cleanup;
    }
    us_verify_hy += (double)(now_us() - t0);

    uint8_t iv_y[16];
    t0 = now_us();
    if (derive_iv(k_local, "GSM->SGN|y", iv_y) != 0) {
        fprintf(stderr, "[SGN] derive iv_y failed\n");
        goto cleanup;
    }
    us_iv_y += (double)(now_us() - t0);

    y_pt = (uint8_t *)malloc(y_len ? y_len : 1);
    if (!y_pt) {
        fprintf(stderr, "[SGN] malloc y_pt failed\n");
        goto cleanup;
    }

    int y_pt_len = 0;
    t0 = now_us();
    if (aes256cbc_decrypt(y, (int)y_len, k_local, iv_y, y_pt, &y_pt_len) != 0) {
        fprintf(stderr, "[SGN] Decrypt y failed\n");
        goto cleanup;
    }
    us_dec_y += (double)(now_us() - t0);

    t0 = now_us();
    if ((size_t)y_pt_len < 32 + NONCE_LEN + 4 + 4) {
        fprintf(stderr, "[SGN] y too short\n");
        goto cleanup;
    }

    size_t off = 0;
    uint8_t K_sym[32]; memcpy(K_sym, y_pt + off, 32); off += 32;
    uint8_t r_echo[NONCE_LEN]; memcpy(r_echo, y_pt + off, NONCE_LEN); off += NONCE_LEN;

    uint32_t T_be = 0; memcpy(&T_be, y_pt + off, 4); off += 4;
    uint32_t T = ntohl(T_be);

    uint32_t id_len_be = 0; memcpy(&id_len_be, y_pt + off, 4); off += 4;
    uint32_t id_len = ntohl(id_len_be);

    if (off + id_len != (size_t)y_pt_len) {
        fprintf(stderr, "[SGN] y id_len mismatch\n");
        goto cleanup;
    }

    id_gsm = (char *)malloc(id_len + 1);
    if (!id_gsm) {
        fprintf(stderr, "[SGN] malloc id_gsm failed\n");
        goto cleanup;
    }
    memcpy(id_gsm, y_pt + off, id_len);
    id_gsm[id_len] = '\0';

    if (CRYPTO_memcmp(r_echo, r, NONCE_LEN) != 0) {
        fprintf(stderr, "[SGN] Nonce mismatch\n");
        goto cleanup;
    }

    // Check against expected GSM identity and the identity from CertGSM
    if (strncmp(id_gsm, EXPECTED_ID_GSM, id_len) != 0 ||
        id_len != cert_gsm.id_len ||
        CRYPTO_memcmp(id_gsm, cert_gsm.id, id_len) != 0) {
        fprintf(stderr, "[SGN] ID_GSM mismatch\n");
        goto cleanup;
    }

    (void)K_sym;
    (void)T;
    us_parse_y += (double)(now_us() - t0);

    // Final SYNC (I/O excluded from timing)
    if (recv_len_and_buf(fd, &sync, &sync_len) != 0) {
        fprintf(stderr, "[SGN] recv SYNC failed\n");
        goto cleanup;
    }
    if (sync_len != 4 || memcmp(sync, "SYNC", 4) != 0) {
        fprintf(stderr, "[SGN] invalid SYNC\n");
        goto cleanup;
    }

    us_step4 = us_verify_hy + us_iv_y + us_dec_y + us_parse_y;
    ok_handshake = 1;

    // -------- summary --------
    {
        double total_us = us_step1 + us_step2 + us_step3 + us_step4;
        double total_no_ca_us = total_us - us_verify_cert_gsm;

        printf("\n==================== SGN CLIENT TIMING ====================\n");
        printf("Status: %s\n", ok_handshake ? "handshake complete" : "FAILED");
        printf("Compute-only timings (send/recv excluded), unit: us\n\n");

        printf("Step 1 (Verify GSM challenge):        %.2f us\n", us_step1);
        printf("  - Parse CertGSM:                    %.2f us\n", us_parse_cert_gsm);
        printf("  - Verify CertGSM (CA):              %.2f us\n", us_verify_cert_gsm);
        printf("  - Verify sigma_GSM:                 %.2f us\n", us_verify_sigma_gsm);

        printf("\nStep 2 (Encaps + KDF):                %.2f us\n", us_step2);
        printf("  - Kyber encaps:                     %.2f us\n", us_encaps);
        printf("  - KDF k_local=SHA3(ss):             %.2f us\n", us_kdf);

        printf("\nStep 3 (Build SGN response):          %.2f us\n", us_step3);
        printf("  - RAND nonce r_SGN:                 %.2f us\n", us_rand_nonce);
        printf("  - Derive IV(m_r):                   %.2f us\n", us_iv_mr);
        printf("  - AES encrypt m_rSGN:               %.2f us\n", us_enc_mr);
        printf("  - HMAC(m_rSGN):                     %.2f us\n", us_hmac_mr);
        printf("  - Falcon sign sigma_SGN:            %.2f us\n", us_sign_sgn);

        printf("\nStep 4 (Verify GSM reply):            %.2f us\n", us_step4);
        printf("  - Verify HMAC(y_GSM):               %.2f us\n", us_verify_hy);
        printf("  - Derive IV(y_GSM):                 %.2f us\n", us_iv_y);
        printf("  - AES decrypt y_GSM:                %.2f us\n", us_dec_y);
        printf("  - Parse/check nonce+ID:             %.2f us\n", us_parse_y);

        printf("\nTOTAL SGN compute (incl. CA verify):  %.2f us\n", total_us);
        printf("TOTAL SGN compute (excl. CA verify):  %.2f us\n", total_no_ca_us);
        printf("===========================================================\n\n");
    }

cleanup:
    if (fd >= 0) close(fd);

    if (M) free(M);
    if (M2) free(M2);

    if (ct) free(ct);
    if (ss) { OPENSSL_cleanse(ss, kem ? kem->length_shared_secret : 0); free(ss); }
    if (m_r) free(m_r);
    if (sigma_sgn) free(sigma_sgn);

    if (y) free(y);
    if (h_y) free(h_y);
    if (y_pt) free(y_pt);
    if (sync) free(sync);
    if (id_gsm) free(id_gsm);

    if (pk_e) free(pk_e);
    if (sigma_gsm) free(sigma_gsm);

    if (cert_gsm_raw) free(cert_gsm_raw);
    cert_free(&cert_gsm);

    if (ca_pub) free(ca_pub);
    if (sgn_priv) { OPENSSL_cleanse(sgn_priv, sgn_priv_len); free(sgn_priv); }

    cert_free(&cert_sgn);

    OPENSSL_cleanse(k_local, sizeof(k_local));
    OPENSSL_cleanse(r, sizeof(r));

    if (falcon) OQS_SIG_free(falcon);
    if (kem) OQS_KEM_free(kem);

    return ok_handshake ? 0 : 1;
}

int main(void) {
    printf("[SGN] Client starting, connecting to %s:%d ...\n", SERVER_IP, PORT);
    return run_client() == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}