
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <sodium.h>
/* ── Ascon-128 API constants (replaces api.h from the Ascon reference impl) ─ */
#define CRYPTO_KEYBYTES   16   /* 128-bit key                                 */
#define CRYPTO_NSECBYTES   0   /* no secret message number                    */
#define CRYPTO_NPUBBYTES  16   /* 128-bit public nonce                        */
#define CRYPTO_ABYTES     16   /* 128-bit authentication tag                  */
#define CRYPTO_NOOVERLAP   1
#define CRYPTO_ALGNAME    "ascon128"

int crypto_aead_encrypt(
    unsigned char *c, unsigned long long *clen,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *nsec,
    const unsigned char *npub,
    const unsigned char *k);

int crypto_aead_decrypt(
    unsigned char *m, unsigned long long *mlen,
    unsigned char *nsec,
    const unsigned char *c, unsigned long long clen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub,
    const unsigned char *k);

/* ── Configuration ──────────────────────────────────────────────────────── */
#define BENCH 1000

static const size_t SM_SIZES[] = { 21, 81, 127, 777, 2997, 4700 };
static const char *SM_LABELS[] = {
    "Low-1row ", "Med-1row ", "High-1row",
    "Low-batch", "Med-batch", "High-btch",
};
#define N_SIZES (sizeof(SM_SIZES)/sizeof(SM_SIZES[0]))

/* ── rdtsc ──────────────────────────────────────────────────────────────── */
#if defined(__i386__) || defined(__x86_64__)
static inline unsigned long long rdtsc(void) {
    unsigned int lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((unsigned long long)hi << 32) | lo;
}
#else
static inline unsigned long long rdtsc(void) { return 0; }
#endif

typedef struct {
    unsigned long long enc_ns, enc_cy, dec_ns, dec_cy;
} bench_result_t;

/* ── Helpers ────────────────────────────────────────────────────────────── */
static void ossl_err(const char *msg) {
    fprintf(stderr, "OpenSSL error in %s: ", msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

static void print_header(void) {
    printf("\n%-24s %9s %10s %10s %10s %10s %11s\n",
           "Cipher", "Payload",
           "Enc(ns)", "Enc(cyc)", "Dec(ns)", "Dec(cyc)", "Enc MB/s");
    printf("%-24s %9s %10s %10s %10s %10s %11s\n",
           "------------------------", "---------",
           "----------", "----------",
           "----------", "----------", "-----------");
}

static void print_row(const char *label, int actual,
                      size_t sz, int li, bench_result_t r) {
    double mbps = (r.enc_ns > 0) ? ((double)sz / (double)r.enc_ns) * 1000.0 : 0.0;
    printf("%-24s %9s %10llu %10llu %10llu %10llu %11.1f%s\n",
           label, SM_LABELS[li],
           r.enc_ns, r.enc_cy, r.dec_ns, r.dec_cy, mbps,
           actual ? " <-- ACTUAL" : "");
}

static void print_cbc_hmac_row(const char *label, int actual,
                                size_t sz, int li,
                                bench_result_t cbc, bench_result_t hmac) {
    unsigned long long enc = cbc.enc_ns + hmac.enc_ns;
    unsigned long long dec = cbc.dec_ns + hmac.dec_ns;
    unsigned long long ec = cbc.enc_cy + hmac.enc_cy;
    unsigned long long dc = cbc.dec_cy + hmac.dec_cy;
    double mbps = (enc > 0) ? ((double)sz / (double)enc) * 1000.0 : 0.0;
    printf("%-24s %9s %10llu %10llu %10llu %10llu %11.1f%s\n",
           label, SM_LABELS[li], enc, ec, dec, dc, mbps,
           actual ? " <-- ACTUAL" : "");
}

/* ── Serialization helpers ──────────────────────────────────────────────── */
static void write_f32(unsigned char *buf, float val) {
    uint32_t u;
    memcpy(&u, &val, sizeof(float));
    buf[0] = (u >> 24) & 0xFF;
    buf[1] = (u >> 16) & 0xFF;
    buf[2] = (u >> 8)  & 0xFF;
    buf[3] = u & 0xFF;
}

static size_t serialize_row(unsigned char *out, char **cells, int ncols) {
    size_t offset = 0;
    for (int i = 0; i < ncols; i++) {
        if (!cells[i]) continue;
        char *endptr;
        double val = strtod(cells[i], &endptr);
        if (*endptr == '\0') {
            float f = (float)val;
            write_f32(out + offset, f);
            offset += 4;
        } else {
            size_t len = strlen(cells[i]);
            if (len > 255) len = 255;
            out[offset++] = (unsigned char)len;
            memcpy(out + offset, cells[i], len);
            offset += len;
        }
    }
    return offset;
}

/* ── 20 real High rows (exactly as you provided) ────────────────────────── */
static const char *high_rows[20] = {
    "0.15,0.15,0,0.15,0,0,0,0,130.1,0,0,0,0,0,0,0,0,0,0,L0.99,0,0,90,15 Minutes,0.15,0,0,0,0,0,0,60.05,Forward,Forward,Forward",
    "0.15,0.15,0,0.15,0,0,0,0,129.9,0,0,0,0,0,0,0,0,0,0,0,0,0,90,15 Minutes,0.15,0,0,0,0,0,0,60.03,Forward,Forward,Forward",
    "0.15,0.15,0,0.15,0,0,0,0,130.2,0,0,0,0,0,0,0,0,0,0,L0.98,0,0,90,15 Minutes,0.15,0,0,0,0,0,0,60.04,Forward,Forward,Forward",
    "0.15,0.15,0,0.15,0,0,0,0,130.8,0,0,0,0,0,0,0,0,0,0,0,0,0,90,15 Minutes,0.15,0,0,0,0,0,0,60.05,Forward,Forward,Forward",
    "0.15,0.15,0,0.15,0,0,0,0,130.7,0,0,0.4,0,0,56,0,0,56,56,C0.99,0,0,90,15 Minutes,0.15,0,0,6,0,0,6,60.06,Forward,Forward,Forward",
    "0.15,0.15,0,0.15,0,0,0,0,130.8,0,0,0.4,0,0,50,0,0,50,50,C0.99,0,0,90,15 Minutes,0.16,0,0,6,0,0,6,60.04,Forward,Forward,Forward",
    "0.15,0.15,0,0.15,0,0,0,0,130.6,0,0,0.4,0,0,54,0,0,54,54,C0.99,0,0,90,15 Minutes,0.16,0,0,6,0,0,6,60.07,Forward,Forward,Forward",
    "0.16,0.16,0,0.16,0,0,0,0,130.7,0,0,0.2,0,0,42,0,0,42,42,C0.99,0,0,90,15 Minutes,0.16,0,0,6,0,0,6,60.05,Forward,Forward,Forward",
    "0.16,0.16,0,0.16,0,0,0,0,130.5,0,0,0.4,0,0,50,0,0,50,50,C0.99,0,0,90,15 Minutes,0.16,0,0,6,0,0,6,60.03,Forward,Forward,Forward",
    "0.16,0.16,0,0.16,0,0,0,0,130.5,0,0,0.4,0,0,52,0,0,52,52,C0.99,0,0,90,15 Minutes,0.16,0,0,6,0,0,6,60.02,Forward,Forward,Forward",
    "0.16,0.16,0,0.16,0,0,0,0,130.4,0,0,0.4,0,0,56,0,0,56,56,C0.99,0,0,90,15 Minutes,0.16,0,0,6,0,0,6,60.03,Forward,Forward,Forward",
    "0.16,0.16,0,0.16,0,0,0,0,130.4,0,0,0.4,0,0,52,0,0,52,52,C0.99,0,0,90,15 Minutes,0.16,0,0,6,0,0,6,60.04,Forward,Forward,Forward",
    "0.16,0.16,0,0.16,0,0,0,0,130.4,0,0,0.4,0,0,50,0,0,50,50,C0.99,0,0,90,15 Minutes,0.16,0,0,6,0,0,6,60.05,Forward,Forward,Forward",
    "0.16,0.16,0,0.16,0,0,0,0,130.4,0,0,0.4,0,0,50,0,0,50,50,C0.99,0,0,90,15 Minutes,0.16,0,0,6,0,0,6,60.08,Forward,Forward,Forward",
    "0.16,0.16,0,0.16,0,0,0,0,130.4,0,0,0.4,0,0,52,0,0,52,52,C0.99,0,0,90,15 Minutes,0.16,0,0,6,0,0,6,60.04,Forward,Forward,Forward",
    "0.16,0.16,0,0.16,0,0,0,0,131.8,0,0,0.4,0,0,50,0,0,50,50,C0.99,0,0,90,15 Minutes,0.16,0,0,6,0,0,6,60.06,Forward,Forward,Forward",
    "0.16,0.16,0,0.16,0,0,0,0,132.8,0,0,0.4,0,0,52,0,0,52,52,C0.99,0,0,90,15 Minutes,0.17,0,0,6,0,0,6,60.05,Forward,Forward,Forward",
    "0.16,0.16,0,0.16,0,0,0,0,132.2,0,0,0.4,0,0,54,0,0,54,54,C0.99,0,0,90,15 Minutes,0.17,0,0,6,0,0,6,60.06,Forward,Forward,Forward",
    "0.17,0.17,0,0.17,0,0,0,0,131.9,0,0,0.4,0,0,56,0,0,56,56,C0.99,0,0,90,15 Minutes,0.17,0,0,6,0,0,6,60.02,Forward,Forward,Forward",
    "0.17,0.17,0,0.17,0,0,0,0,131.9,0,0,0.4,0,0,52,0,0,52,52,C0.99,0,0,90,15 Minutes,0.17,0,0,6,0,0,6,60.02,Forward,Forward,Forward"
};

/* ── Real unique buffer from 20 High rows ───────────────────────────────── */
static void fill_smart_meter(unsigned char *buf, size_t len) {
    static unsigned char big_buffer[8192];
    static size_t big_len = 0;

    if (big_len == 0) {
        size_t pos = 0;
        for (int r = 0; r < 20; r++) {
            char *row_copy = strdup(high_rows[r]);
            char *cells[40] = {0};
            int ncols = 0;
            char *token = strtok(row_copy, ",");
            while (token && ncols < 40) {
                cells[ncols++] = token;
                token = strtok(NULL, ",");
            }
            size_t row_bytes = serialize_row(big_buffer + pos, cells, ncols);
            pos += row_bytes;
            free(row_copy);
        }
        big_len = pos;
    }

    size_t copy_len = (len < big_len) ? len : big_len;
    memcpy(buf, big_buffer, copy_len);
    if (len > big_len) memset(buf + big_len, 0, len - big_len);
}

static void verify_smart_meter(const unsigned char *pt, size_t max_sz) {
    printf("\n── Smart-meter plaintext verification ──────────────────────────────────\n");
    printf(" Source : Smart_meter_data.xlsx — 20 unique High-priority rows\n");
    printf(" Using full 20 distinct rows — no repetition\n");
    printf(" First 48 bytes (hex):\n ");
    for (size_t i = 0; i < 48 && i < max_sz; i++) {
        printf("%02x", pt[i]);
        if ((i+1) % 16 == 0) printf("\n ");
        else if ((i+1) % 4 == 0) printf(" ");
    }
    printf("\n All %zu B plaintext built from real 20 High rows.\n", max_sz);
    printf("────────────────────────────────────────────────────────────────────────\n");
}

/* ── FULL Benchmark functions (all five + HMAC) ─────────────────────────── */
static bench_result_t bench_aes128cbc(size_t mlen, const unsigned char *pt,
                                      const unsigned char *key16,
                                      const unsigned char *iv16) {
    bench_result_t r = {0};
    struct timespec ts, te; unsigned long long sc, ec;
    unsigned char *ct = malloc(mlen + 16);
    unsigned char *pt2 = malloc(mlen + 16);
    unsigned long long tn = 0, tc = 0;
    for (int i = 0; i < BENCH; i++) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) ossl_err("AES-128-CBC enc");
        EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key16, iv16);
        int o1 = 0, o2 = 0;
        clock_gettime(CLOCK_MONOTONIC, &ts); sc = rdtsc();
        EVP_EncryptUpdate(ctx, ct, &o1, pt, (int)mlen);
        EVP_EncryptFinal_ex(ctx, ct + o1, &o2);
        ec = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &te);
        tn += (te.tv_sec-ts.tv_sec)*1000000000LL+(te.tv_nsec-ts.tv_nsec);
        if (ec > sc) tc += ec - sc;
        EVP_CIPHER_CTX_free(ctx);
    }
    r.enc_ns = tn/BENCH; r.enc_cy = tc/BENCH;
    EVP_CIPHER_CTX *c0 = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(c0, EVP_aes_128_cbc(), NULL, key16, iv16);
    int o1=0,o2=0;
    EVP_EncryptUpdate(c0,ct,&o1,pt,(int)mlen);
    EVP_EncryptFinal_ex(c0,ct+o1,&o2);
    size_t ctl=(size_t)(o1+o2); EVP_CIPHER_CTX_free(c0);
    tn=0; tc=0;
    for (int i = 0; i < BENCH; i++) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) ossl_err("AES-128-CBC dec");
        EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key16, iv16);
        int d1=0,d2=0;
        clock_gettime(CLOCK_MONOTONIC, &ts); sc = rdtsc();
        EVP_DecryptUpdate(ctx,pt2,&d1,ct,(int)ctl);
        EVP_DecryptFinal_ex(ctx,pt2+d1,&d2);
        ec = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &te);
        tn += (te.tv_sec-ts.tv_sec)*1000000000LL+(te.tv_nsec-ts.tv_nsec);
        if (ec > sc) tc += ec - sc;
        EVP_CIPHER_CTX_free(ctx);
    }
    r.dec_ns = tn/BENCH; r.dec_cy = tc/BENCH;
    free(ct); free(pt2); return r;
}

static bench_result_t bench_aes256cbc(size_t mlen, const unsigned char *pt,
                                      const unsigned char *key32,
                                      const unsigned char *iv16) {
    bench_result_t r = {0};
    struct timespec ts, te; unsigned long long sc, ec;
    unsigned char *ct = malloc(mlen + 16);
    unsigned char *pt2 = malloc(mlen + 16);
    unsigned long long tn = 0, tc = 0;
    for (int i = 0; i < BENCH; i++) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) ossl_err("AES-256-CBC enc");
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key32, iv16);
        int o1=0,o2=0;
        clock_gettime(CLOCK_MONOTONIC, &ts); sc = rdtsc();
        EVP_EncryptUpdate(ctx,ct,&o1,pt,(int)mlen);
        EVP_EncryptFinal_ex(ctx,ct+o1,&o2);
        ec = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &te);
        tn += (te.tv_sec-ts.tv_sec)*1000000000LL+(te.tv_nsec-ts.tv_nsec);
        if (ec > sc) tc += ec - sc;
        EVP_CIPHER_CTX_free(ctx);
    }
    r.enc_ns = tn/BENCH; r.enc_cy = tc/BENCH;
    EVP_CIPHER_CTX *c0 = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(c0, EVP_aes_256_cbc(), NULL, key32, iv16);
    int o1=0,o2=0;
    EVP_EncryptUpdate(c0,ct,&o1,pt,(int)mlen);
    EVP_EncryptFinal_ex(c0,ct+o1,&o2);
    size_t ctl=(size_t)(o1+o2); EVP_CIPHER_CTX_free(c0);
    tn=0; tc=0;
    for (int i = 0; i < BENCH; i++) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) ossl_err("AES-256-CBC dec");
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key32, iv16);
        int d1=0,d2=0;
        clock_gettime(CLOCK_MONOTONIC, &ts); sc = rdtsc();
        EVP_DecryptUpdate(ctx,pt2,&d1,ct,(int)ctl);
        EVP_DecryptFinal_ex(ctx,pt2+d1,&d2);
        ec = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &te);
        tn += (te.tv_sec-ts.tv_sec)*1000000000LL+(te.tv_nsec-ts.tv_nsec);
        if (ec > sc) tc += ec - sc;
        EVP_CIPHER_CTX_free(ctx);
    }
    r.dec_ns = tn/BENCH; r.dec_cy = tc/BENCH;
    free(ct); free(pt2); return r;
}

static bench_result_t bench_aes128gcm(size_t mlen, const unsigned char *pt,
                                      const unsigned char *key16,
                                      const unsigned char *iv12) {
    bench_result_t r = {0};
    struct timespec ts, te; unsigned long long sc, ec;
    unsigned char *ct = malloc(mlen + 16);
    unsigned char *pt2 = malloc(mlen);
    unsigned char tag[16];
    unsigned long long tn = 0, tc = 0;
    for (int i = 0; i < BENCH; i++) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
        EVP_EncryptInit_ex(ctx, NULL, NULL, key16, iv12);
        int outl = 0;
        clock_gettime(CLOCK_MONOTONIC, &ts); sc = rdtsc();
        EVP_EncryptUpdate(ctx, ct, &outl, pt, (int)mlen);
        EVP_EncryptFinal_ex(ctx, ct + outl, &outl);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
        ec = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &te);
        tn += (te.tv_sec-ts.tv_sec)*1000000000LL+(te.tv_nsec-ts.tv_nsec);
        if (ec > sc) tc += ec - sc;
        EVP_CIPHER_CTX_free(ctx);
    }
    r.enc_ns = tn/BENCH; r.enc_cy = tc/BENCH;
    EVP_CIPHER_CTX *c0 = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(c0, EVP_aes_128_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(c0, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_EncryptInit_ex(c0, NULL, NULL, key16, iv12);
    int o1=0;
    EVP_EncryptUpdate(c0,ct,&o1,pt,(int)mlen);
    EVP_EncryptFinal_ex(c0,ct+o1,&o1);
    EVP_CIPHER_CTX_ctrl(c0,EVP_CTRL_GCM_GET_TAG,16,tag);
    EVP_CIPHER_CTX_free(c0);
    tn=0; tc=0;
    for (int i = 0; i < BENCH; i++) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
        EVP_DecryptInit_ex(ctx, NULL, NULL, key16, iv12);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
        int dl=0, dl2=0;
        clock_gettime(CLOCK_MONOTONIC, &ts); sc = rdtsc();
        EVP_DecryptUpdate(ctx, pt2, &dl, ct, (int)mlen);
        EVP_DecryptFinal_ex(ctx, pt2+dl, &dl2);
        ec = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &te);
        tn += (te.tv_sec-ts.tv_sec)*1000000000LL+(te.tv_nsec-ts.tv_nsec);
        if (ec > sc) tc += ec - sc;
        EVP_CIPHER_CTX_free(ctx);
    }
    r.dec_ns = tn/BENCH; r.dec_cy = tc/BENCH;
    free(ct); free(pt2); return r;
}

static bench_result_t bench_ascon128(size_t mlen, const unsigned char *pt,
                                     const unsigned char *key16,
                                     const unsigned char *nonce16) {
    bench_result_t r = {0};
    struct timespec ts, te; unsigned long long sc, ec;
    unsigned char *ct = malloc(mlen + 16);
    unsigned char *pt2 = malloc(mlen + 16);
    unsigned long long ctlen, ptlen;
    unsigned long long tn = 0, tc = 0;
    for (int i = 0; i < BENCH; i++) {
        clock_gettime(CLOCK_MONOTONIC, &ts); sc = rdtsc();
        crypto_aead_encrypt(ct, &ctlen, pt, (unsigned long long)mlen,
                            NULL, 0, NULL, nonce16, key16);
        ec = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &te);
        tn += (te.tv_sec-ts.tv_sec)*1000000000LL+(te.tv_nsec-ts.tv_nsec);
        if (ec > sc) tc += ec - sc;
    }
    r.enc_ns = tn/BENCH; r.enc_cy = tc/BENCH;
    crypto_aead_encrypt(ct, &ctlen, pt, (unsigned long long)mlen,
                        NULL, 0, NULL, nonce16, key16);
    tn=0; tc=0;
    for (int i = 0; i < BENCH; i++) {
        clock_gettime(CLOCK_MONOTONIC, &ts); sc = rdtsc();
        crypto_aead_decrypt(pt2, &ptlen, NULL, ct, ctlen,
                            NULL, 0, nonce16, key16);
        ec = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &te);
        tn += (te.tv_sec-ts.tv_sec)*1000000000LL+(te.tv_nsec-ts.tv_nsec);
        if (ec > sc) tc += ec - sc;
    }
    r.dec_ns = tn/BENCH; r.dec_cy = tc/BENCH;
    (void)ptlen; free(ct); free(pt2); return r;
}

static bench_result_t bench_chacha20poly1305(size_t mlen,
                                              const unsigned char *pt,
                                              const unsigned char *key32,
                                              const unsigned char *nonce12) {
    bench_result_t r = {0};
    struct timespec ts, te; unsigned long long sc, ec;
    size_t ctlen = mlen + crypto_aead_chacha20poly1305_ietf_ABYTES;
    unsigned char *ct = malloc(ctlen);
    unsigned char *pt2 = malloc(mlen);
    unsigned long long clen; unsigned long long tl;
    unsigned long long tn = 0, tc = 0;
    for (int i = 0; i < BENCH; i++) {
        clock_gettime(CLOCK_MONOTONIC, &ts); sc = rdtsc();
        crypto_aead_chacha20poly1305_ietf_encrypt(
            ct, &clen, pt, (unsigned long long)mlen,
            NULL, 0, NULL, nonce12, key32);
        ec = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &te);
        tn += (te.tv_sec-ts.tv_sec)*1000000000LL+(te.tv_nsec-ts.tv_nsec);
        if (ec > sc) tc += ec - sc;
    }
    r.enc_ns = tn/BENCH; r.enc_cy = tc/BENCH;
    crypto_aead_chacha20poly1305_ietf_encrypt(
        ct, &clen, pt, (unsigned long long)mlen,
        NULL, 0, NULL, nonce12, key32);
    tn=0; tc=0;
    for (int i = 0; i < BENCH; i++) {
        clock_gettime(CLOCK_MONOTONIC, &ts); sc = rdtsc();
        crypto_aead_chacha20poly1305_ietf_decrypt(
            pt2, &tl, NULL, ct, clen, NULL, 0, nonce12, key32);
        ec = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &te);
        tn += (te.tv_sec-ts.tv_sec)*1000000000LL+(te.tv_nsec-ts.tv_nsec);
        if (ec > sc) tc += ec - sc;
    }
    r.dec_ns = tn/BENCH; r.dec_cy = tc/BENCH;
    (void)tl; free(ct); free(pt2); return r;
}

static bench_result_t bench_hmacsha256(size_t mlen, const unsigned char *pt,
                                       const unsigned char *key,
                                       size_t keylen) {
    bench_result_t r = {0};
    struct timespec ts, te; unsigned long long sc, ec, tn=0, tc=0;
    unsigned char k32[32]={0};
    memcpy(k32, key, keylen < 32 ? keylen : 32);
    unsigned char tag[32], tag_ref[32];
    for (int i = 0; i < BENCH; i++) {
        clock_gettime(CLOCK_MONOTONIC, &ts); sc = rdtsc();
        crypto_auth_hmacsha256(tag, pt, mlen, k32);
        ec = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &te);
        tn += (te.tv_sec-ts.tv_sec)*1000000000LL+(te.tv_nsec-ts.tv_nsec);
        if (ec > sc) tc += ec - sc;
    }
    r.enc_ns = tn/BENCH; r.enc_cy = tc/BENCH;
    crypto_auth_hmacsha256(tag_ref, pt, mlen, k32);
    tn=0; tc=0;
    for (int i = 0; i < BENCH; i++) {
        unsigned char tag2[32];
        clock_gettime(CLOCK_MONOTONIC, &ts); sc = rdtsc();
        crypto_auth_hmacsha256(tag2, pt, mlen, k32);
        sodium_memcmp(tag2, tag_ref, 32);
        ec = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &te);
        tn += (te.tv_sec-ts.tv_sec)*1000000000LL+(te.tv_nsec-ts.tv_nsec);
        if (ec > sc) tc += ec - sc;
    }
    r.dec_ns = tn/BENCH; r.dec_cy = tc/BENCH;
    return r;
}

/* ── run_all_ciphers ────────────────────────────────────────────────────── */
static void run_all_ciphers(int actual_cipher,
                             const unsigned char *pt,
                             const unsigned char *key16,
                             const unsigned char *key32,
                             const unsigned char *iv16,
                             const unsigned char *iv12,
                             const unsigned char *n16,
                             const unsigned char *n12) {
    print_header();
    for (size_t s = 0; s < N_SIZES; s++) {
        size_t sz = SM_SIZES[s]; int li = (int)s;
        { bench_result_t cbc = bench_aes128cbc(sz, pt, key16, iv16);
          bench_result_t hmac = bench_hmacsha256(sz, pt, key16, 16);
          print_cbc_hmac_row("AES-128-CBC+HMAC", actual_cipher==1, sz, li, cbc, hmac); }
        { bench_result_t cbc = bench_aes256cbc(sz, pt, key32, iv16);
          bench_result_t hmac = bench_hmacsha256(sz, pt, key32, 32);
          print_cbc_hmac_row("AES-256-CBC+HMAC", actual_cipher==2, sz, li, cbc, hmac); }
        { bench_result_t r = bench_aes128gcm(sz, pt, key16, iv12);
          print_row("AES-128-GCM", actual_cipher==3, sz, li, r); }
        { bench_result_t r = bench_ascon128(sz, pt, key16, n16);
          print_row("Ascon-128", actual_cipher==4, sz, li, r); }
        { bench_result_t r = bench_chacha20poly1305(sz, pt, key32, n12);
          print_row("ChaCha20-Poly1305", actual_cipher==5, sz, li, r); }
        printf("\n");
    }
}

/* ── main ───────────────────────────────────────────────────────────────── */
int main(void) {
    if (sodium_init() < 0) { fprintf(stderr,"libsodium init failed\n"); return 1; }
    OpenSSL_add_all_algorithms();

    printf("=== Deliverable 4.1 — Crypto Benchmark (%d iters per cell) ===\n", BENCH);
#if defined(__aarch64__)
    printf("Platform: ARM64 (Raspberry Pi / aarch64)\n");
#elif defined(__arm__)
    printf("Platform: ARM32 (Raspberry Pi / armv7)\n");
#elif defined(__x86_64__)
    printf("Platform: x86-64 server/workstation\n");
#else
    printf("Platform: Unknown\n");
#endif

    unsigned char key16[16], key32[32], iv16[16], iv12[12], n16[16], n12[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(key16, sizeof(key16));
    randombytes_buf(key32, sizeof(key32));
    randombytes_buf(iv16, sizeof(iv16));
    randombytes_buf(iv12, sizeof(iv12));
    randombytes_buf(n16, sizeof(n16));
    randombytes_buf(n12, sizeof(n12));

    size_t max_sz = SM_SIZES[N_SIZES - 1];
    unsigned char *pt = malloc(max_sz);
    fill_smart_meter(pt, max_sz);
    verify_smart_meter(pt, max_sz);

    /* Run all protocols */
    printf("\n┌─────────────────────────────────────────────────────────────────────────────┐\n");
    printf("│ PKC-1 (Del. 2.1) │ AES-256-CBC + HMAC-SHA256 (ksh=32 B) │\n");
    printf("└─────────────────────────────────────────────────────────────────────────────┘\n");
    run_all_ciphers(2, pt, key16, key32, iv16, iv12, n16, n12);

    printf("\n┌─────────────────────────────────────────────────────────────────────────────┐\n");
    printf("│ PKC-2 / LSEG (Del. 2.1) │ Ascon-128a (ksh=16 B) │\n");
    printf("└─────────────────────────────────────────────────────────────────────────────┘\n");
    run_all_ciphers(4, pt, key16, key32, iv16, iv12, n16, n12);

    printf("\n┌─────────────────────────────────────────────────────────────────────────────┐\n");
    printf("│ PQC-1 (Del. 2.2) │ AES-128-CBC + HMAC-SHA256 (ksh=16 B) │\n");
    printf("└─────────────────────────────────────────────────────────────────────────────┘\n");
    run_all_ciphers(1, pt, key16, key32, iv16, iv12, n16, n12);

    printf("\n┌─────────────────────────────────────────────────────────────────────────────┐\n");
    printf("│ PQC-2 Authenticated Mode (Del. 2.2, AmphiKey) │ Ascon-128 AEAD │\n");
    printf("│ ksh = 32 B HKDF; Ascon key = ksh[0:16] │\n");
    printf("└─────────────────────────────────────────────────────────────────────────────┘\n");
    run_all_ciphers(4, pt, key16, key32, iv16, iv12, n16, n12);

    printf("\n┌─────────────────────────────────────────────────────────────────────────────┐\n");
    printf("│ PQC-2 Deniable Mode (Del. 2.2, AmphiKey) │ Ascon-128 AEAD │\n");
    printf("│ ksh = 32 B HKDF; Ascon key = ksh[0:16] │\n");
    printf("└─────────────────────────────────────────────────────────────────────────────┘\n");
    run_all_ciphers(4, pt, key16, key32, iv16, iv12, n16, n12);

    printf("\nDone. Full 20 unique High-priority rows from Smart_meter_data.xlsx used (no repetition).\n");
    free(pt);
    return 0;
}
