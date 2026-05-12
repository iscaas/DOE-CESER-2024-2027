/*
 * AmphiKey Authenticated Mode — Server (Initiator + Decapsulator)
 * COMPLETE with keygen benchmarks (Table II) + all Step 1 / Step 3
 * per-operation benchmarks (Table I, PQC 2 rows).
 *
 * Step 1: ML-KEM.Gen + DHKEM.Gen + Raccoon.Sign(SHs)   [server]
 * Step 3: Raccoon.Verify(sigc) + ML-KEM.Dec + DHKEM.Dec + HKDF(ksh) [server]
 * Post:   Ascon-128 AEAD encrypt                    [server]
 *
 * Workflow:
 *   1. ./auth_server        → saves server_hello.bin, server_sigs.sig
 *   2. ./auth_client        → saves client_encap_c.bin, client_sigc.sig
 *   3. ./auth_server        → reads client files, verifies, derives ksh
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include <sodium.h>
#include "api_mlkem.h"
#include "api_raccoon.h"
/* Ascon-128 NIST LWCA one-shot API */
#include "api.h"
int crypto_aead_encrypt(unsigned char *c,  unsigned long long *clen,
                        const unsigned char *m,   unsigned long long mlen,
                        const unsigned char *ad,  unsigned long long adlen,
                        const unsigned char *nsec,
                        const unsigned char *npub,
                        const unsigned char *k);

extern void nist_randombytes_init(unsigned char *entropy,
                                  unsigned char *pers, int strength);
extern void randombytes(unsigned char *x, unsigned long long xlen);

void PQCLEAN_randombytes(unsigned char *buf, size_t n) {
    randombytes(buf, (unsigned long long)n);
}

/* ── AmphiKey constants ───────────────────────────────────────────────── */
#define AMPHIKEY_MODE_AUTHENTICATED ((unsigned char)0x01)
#define AMPHIKEY_DHKEM_INFO         "AmphiKey-DHKEM-v1"

/* ── ML-KEM-768 sizes ─────────────────────────────────────────────────── */
#ifndef PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES
#define PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES  1184
#endif
#ifndef PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES
#define PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES  2400
#endif
#ifndef PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES 1088
#endif
#ifndef PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES
#define PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES           32
#endif

#define C_TOTAL_BYTES (PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES + 32)
#define SHS_BYTES     (PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES + 32 + 1)

/* ── Benchmarking helpers ─────────────────────────────────────────────── */
#define BENCH_ITERS 1000

#if defined(__i386__) || defined(__x86_64__)
static inline unsigned long long rdtsc(void) {
    unsigned int lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((unsigned long long)hi << 32) | lo;
}
#else
static inline unsigned long long rdtsc(void) { return 0; }
#endif

static void bench_print(const char *label, unsigned long long ns,
                        unsigned long long cy) {
    printf("  Time   : %10llu ns  (%8.3f µs)\n", ns, ns / 1000.0);
    printf("  Cycles : %10llu\n", cy);
    (void)label;
}

/* ── I/O helpers ──────────────────────────────────────────────────────── */
static void print_hex(const char *lbl, const unsigned char *d, size_t n) {
    printf("%s (%zu B): ", lbl, n);
    for (size_t i = 0; i < n; i++) printf("%02x", d[i]);
    printf("\n");
}
static int write_bin(const char *fn, const unsigned char *d, size_t n) {
    FILE *fp = fopen(fn, "wb");
    if (!fp) { perror(fn); return -1; }
    fwrite(d, 1, n, fp); fclose(fp);
    printf("  Wrote %zu bytes → %s\n", n, fn);
    return 0;
}
static int read_bin(const char *fn, unsigned char *buf, size_t n, size_t *got) {
    FILE *fp = fopen(fn, "rb");
    if (!fp) { perror(fn); return -1; }
    *got = fread(buf, 1, n, fp); fclose(fp);
    printf("  Read  %zu bytes ← %s\n", *got, fn);
    return (*got == n) ? 0 : -1;
}
static int read_hex(const char *fn, unsigned char *buf, size_t n, size_t *got) {
    FILE *fp = fopen(fn, "r");
    if (!fp) { perror(fn); return -1; }
    char *hex = malloc(n * 2 + 4);
    if (!hex) { fclose(fp); return -1; }
    if (!fgets(hex, (int)(n*2+4), fp)) { free(hex); fclose(fp); return -1; }
    fclose(fp);
    hex[strcspn(hex, "\r\n")] = 0;
    if (sodium_hex2bin(buf, n, hex, strlen(hex), NULL, got, NULL) != 0) {
        free(hex); return -1;
    }
    free(hex);
    printf("  Read  %zu bytes ← %s (hex)\n", *got, fn);
    return 0;
}

/* ── HKDF-SHA256 ──────────────────────────────────────────────────────── */
static int hkdf_extract(unsigned char *prk,
                        const unsigned char *salt, size_t salt_len,
                        const unsigned char *ikm,  size_t ikm_len) {
    unsigned char zero[crypto_auth_hmacsha256_KEYBYTES] = {0};
    const unsigned char *key = (salt && salt_len) ? salt : zero;
    return crypto_auth_hmacsha256(prk, ikm, ikm_len, key);
}
static int hkdf_expand(unsigned char *okm, size_t okm_len,
                       const unsigned char *prk,  size_t prk_len,
                       const unsigned char *info, size_t info_len) {
    if (okm_len > 255*32) return -1;
    unsigned char T[32] = {0};
    size_t T_len = 0, off = 0, N = (okm_len + 31) / 32;
    crypto_auth_hmacsha256_state st;
    for (unsigned char i = 1; (size_t)i <= N; i++) {
        crypto_auth_hmacsha256_init(&st, prk, prk_len);
        if (T_len)    crypto_auth_hmacsha256_update(&st, T, T_len);
        if (info_len) crypto_auth_hmacsha256_update(&st, info, info_len);
        crypto_auth_hmacsha256_update(&st, &i, 1);
        crypto_auth_hmacsha256_final(&st, T);
        T_len = 32;
        size_t cp = (off + 32 > okm_len) ? okm_len - off : 32;
        memcpy(okm + off, T, cp);
        off += cp;
    }
    sodium_memzero(T, 32);
    return 0;
}

/* DHKEM(X25519) Decapsulation */
static int dhkem_decap(unsigned char k2[32],
                       const unsigned char c2[32],
                       const unsigned char sk_recv[32],
                       const unsigned char pk_recv[32]) {
    unsigned char dh[32], ikm[96], prk[32];
    if (crypto_scalarmult(dh, sk_recv, c2) != 0) return -1;
    memcpy(ikm,    dh,      32);
    memcpy(ikm+32, c2,      32);
    memcpy(ikm+64, pk_recv, 32);
    hkdf_extract(prk, NULL, 0, ikm, 96);
    hkdf_expand(k2, 32, prk, 32,
                (const unsigned char*)AMPHIKEY_DHKEM_INFO,
                strlen(AMPHIKEY_DHKEM_INFO));
    sodium_memzero(dh, 32);
    sodium_memzero(ikm, 96);
    sodium_memzero(prk, 32);
    return 0;
}

/* ── Main ─────────────────────────────────────────────────────────────── */
int main(void) {
    printf("=== AmphiKey Authenticated Mode — Server (auth_server) ===\n\n");

    unsigned char entropy[48];
    for (int i = 0; i < 48; i++) entropy[i] = (unsigned char)i;
    nist_randombytes_init(entropy, (unsigned char*)"AmphiKey-Server", 256);
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n"); return 1;
    }

    struct timespec ts, te;
    unsigned long long sc, ec, tot_ns, tot_cy;
    size_t got;

    /* ── Detect which step we are in ────────────────────────────────────
     * Step 1: client_encap_c.bin does NOT exist → generate keys, sign SHs
     * Step 3: client_encap_c.bin DOES exist     → load keys, decapsulate
     * ─────────────────────────────────────────────────────────────────── */
    int is_step3 = 0;
    { FILE *f = fopen("client_encap_c.bin", "rb"); if (f) { is_step3=1; fclose(f); } }
    printf("Mode: %s\n\n", is_step3
        ? "Step 3 — client files found, running decapsulation"
        : "Step 1 — no client files, running Server Hello + keygen benchmarks");

    unsigned char sks1_mlkem[PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES];
    unsigned char pks1_mlkem[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    unsigned char sks2_x25519[32], pks2_x25519[32];

    if (is_step3) {
        /* ── Load keys saved during Step 1 — never regenerate ── */
        printf("Loading Step 1 server keys from disk...\n");
        if (read_bin("server_mlkem_sk.key", sks1_mlkem, sizeof(sks1_mlkem), &got) != 0) {
            fprintf(stderr, "server_mlkem_sk.key missing — run Step 1 first\n"); return 1;
        }
        if (read_bin("server_mlkem_pk.key", pks1_mlkem, sizeof(pks1_mlkem), &got) != 0) {
            fprintf(stderr, "server_mlkem_pk.key missing\n"); return 1;
        }
        /* Load X25519 sk */
        {
            char hex[65]; size_t g;
            FILE *f = fopen("server_x25519_sk.hex", "r");
            if (!f) { fprintf(stderr, "server_x25519_sk.hex missing\n"); return 1; }
            if (!fgets(hex, sizeof(hex), f)) { fclose(f); return 1; }
            fclose(f); hex[strcspn(hex, "\r\n")] = 0;
            sodium_hex2bin(sks2_x25519, 32, hex, strlen(hex), NULL, &g, NULL);
        }
        /* Load X25519 pk */
        {
            char hex[65]; size_t g;
            FILE *f = fopen("server_x25519_pk.hex", "r");
            if (!f) { fprintf(stderr, "server_x25519_pk.hex missing\n"); return 1; }
            if (!fgets(hex, sizeof(hex), f)) { fclose(f); return 1; }
            fclose(f); hex[strcspn(hex, "\r\n")] = 0;
            sodium_hex2bin(pks2_x25519, 32, hex, strlen(hex), NULL, &g, NULL);
        }
        printf("  Keys loaded (ML-KEM sk/pk, X25519 sk/pk)\n\n");
    } else {
        /* ════════════════════════════════════════════════════════════════
         * TABLE II — KEY GENERATION BENCHMARKS (Step 1 only)
         * ════════════════════════════════════════════════════════════════ */
        printf("══════════════════════════════════════════════════════\n");
        printf("TABLE II — Key Generation Benchmarks (%d iterations)\n",
               BENCH_ITERS);
        printf("══════════════════════════════════════════════════════\n\n");

        /* ── ML-KEM-768 KeyGen ── */
        printf("[ ML-KEM-768 KeyGen ]\n");
        unsigned char tmp_pk[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
        unsigned char tmp_sk[PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES];
        tot_ns = 0; tot_cy = 0;
        for (int i = 0; i < BENCH_ITERS; i++) {
            clock_gettime(CLOCK_MONOTONIC, &ts); sc = rdtsc();
            PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(tmp_pk, tmp_sk);
            ec = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &te);
            tot_ns += (te.tv_sec-ts.tv_sec)*1000000000LL+(te.tv_nsec-ts.tv_nsec);
            if (ec > sc) tot_cy += ec - sc;
        }
        bench_print("ML-KEM-768 KeyGen", tot_ns/BENCH_ITERS, tot_cy/BENCH_ITERS);
        memcpy(sks1_mlkem, tmp_sk, sizeof(sks1_mlkem));
        memcpy(pks1_mlkem, tmp_pk, sizeof(pks1_mlkem));
        write_bin("server_mlkem_sk.key", sks1_mlkem, sizeof(sks1_mlkem));
        write_bin("server_mlkem_pk.key", pks1_mlkem, sizeof(pks1_mlkem));

        /* ── X25519 / DHKEM KeyGen ── */
        printf("\n[ X25519-DHKEM KeyGen ]\n");
        tot_ns = 0; tot_cy = 0;
        for (int i = 0; i < BENCH_ITERS; i++) {
            unsigned char sk_tmp[32], pk_tmp[32];
            clock_gettime(CLOCK_MONOTONIC, &ts); sc = rdtsc();
            randombytes_buf(sk_tmp, 32);
            crypto_scalarmult_base(pk_tmp, sk_tmp);
            ec = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &te);
            tot_ns += (te.tv_sec-ts.tv_sec)*1000000000LL+(te.tv_nsec-ts.tv_nsec);
            if (ec > sc) tot_cy += ec - sc;
            if (i == BENCH_ITERS-1) {
                memcpy(sks2_x25519, sk_tmp, 32);
                memcpy(pks2_x25519, pk_tmp, 32);
            }
        }
        bench_print("X25519-DHKEM KeyGen", tot_ns/BENCH_ITERS, tot_cy/BENCH_ITERS);
        {
            char hex_sk[65], hex_pk[65];
            sodium_bin2hex(hex_sk, 65, sks2_x25519, 32);
            sodium_bin2hex(hex_pk, 65, pks2_x25519, 32);
            FILE *f = fopen("server_x25519_sk.hex", "w");
            if (f) { fprintf(f, "%s\n", hex_sk); fclose(f);
                     printf("  Wrote 32 bytes → server_x25519_sk.hex (hex)\n"); }
            f = fopen("server_x25519_pk.hex", "w");
            if (f) { fprintf(f, "%s\n", hex_pk); fclose(f);
                     printf("  Wrote 32 bytes → server_x25519_pk.hex (hex)\n"); }
        }
    }

    /* ── Raccoon DSA KeyGen ── */
    unsigned char sks_rac[CRYPTO_SECRETKEYBYTES];
    unsigned char pks_rac[CRYPTO_PUBLICKEYBYTES];

    if (is_step3) {
        /* Load long-term Raccoon keys saved in Step 1 */
        if (read_bin("server_raccoon_sk.key", sks_rac, sizeof(sks_rac), &got) != 0) {
            fprintf(stderr, "server_raccoon_sk.key missing\n"); return 1;
        }
        if (read_bin("server_raccoon_pk.key", pks_rac, sizeof(pks_rac), &got) != 0) {
            fprintf(stderr, "server_raccoon_pk.key missing\n"); return 1;
        }
        printf("  Raccoon long-term keys loaded.\n\n");
    } else {
        printf("\n[ Raccoon DSA KeyGen (long-term; amortized) ]\n");
        int rac_loaded = 0;
        {
            FILE *f = fopen("server_raccoon_sk.key", "rb");
            if (f) {
                fread(sks_rac, 1, sizeof(sks_rac), f); fclose(f);
                f = fopen("server_raccoon_pk.key", "rb");
                if (f) { fread(pks_rac, 1, sizeof(pks_rac), f); fclose(f);
                          rac_loaded = 1;
                          printf("  (loaded existing long-term Raccoon keys)\n"); }
            }
        }
        tot_ns = 0; tot_cy = 0;
        unsigned char rac_pk_tmp[CRYPTO_PUBLICKEYBYTES];
        unsigned char rac_sk_tmp[CRYPTO_SECRETKEYBYTES];
        for (int i = 0; i < BENCH_ITERS; i++) {
            clock_gettime(CLOCK_MONOTONIC, &ts); sc = rdtsc();
            crypto_sign_keypair(rac_pk_tmp, rac_sk_tmp);
            ec = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &te);
            tot_ns += (te.tv_sec-ts.tv_sec)*1000000000LL+(te.tv_nsec-ts.tv_nsec);
            if (ec > sc) tot_cy += ec - sc;
        }
        bench_print("Raccoon DSA KeyGen", tot_ns/BENCH_ITERS, tot_cy/BENCH_ITERS);
        if (!rac_loaded) {
            memcpy(sks_rac, rac_sk_tmp, sizeof(sks_rac));
            memcpy(pks_rac, rac_pk_tmp, sizeof(pks_rac));
            write_bin("server_raccoon_sk.key", sks_rac, sizeof(sks_rac));
            write_bin("server_raccoon_pk.key", pks_rac, sizeof(pks_rac));
        }
    }

    /* ════════════════════════════════════════════════════════════════════
     * TABLE I — STEP 1: SERVER HELLO (Sign SHs with Raccoon)
     * ════════════════════════════════════════════════════════════════════ */
    unsigned char mode = AMPHIKEY_MODE_AUTHENTICATED;
    unsigned char SHs[SHS_BYTES];
    unsigned char sigs[CRYPTO_BYTES];

    if (!is_step3) {
        printf("\n══════════════════════════════════════════════════════\n");
        printf("TABLE I Step 1 — Server Hello: Raccoon.Sign(SHs)\n");
        printf("══════════════════════════════════════════════════════\n\n");

        memcpy(SHs,                         pks1_mlkem,  sizeof(pks1_mlkem));
        memcpy(SHs + sizeof(pks1_mlkem),    pks2_x25519, 32);
        SHs[sizeof(pks1_mlkem) + 32] = mode;

        printf("[ Raccoon.Sign(SHs) ]\n");
        unsigned char sm_buf[CRYPTO_BYTES + SHS_BYTES];
        unsigned long long smlen;
        tot_ns = 0; tot_cy = 0;
        for (int i = 0; i < BENCH_ITERS; i++) {
            clock_gettime(CLOCK_MONOTONIC, &ts); sc = rdtsc();
            if (crypto_sign(sm_buf, &smlen, SHs, sizeof(SHs), sks_rac) != 0) {
                fprintf(stderr, "Raccoon sign failed\n"); return 1;
            }
            ec = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &te);
            tot_ns += (te.tv_sec-ts.tv_sec)*1000000000LL+(te.tv_nsec-ts.tv_nsec);
            if (ec > sc) tot_cy += ec - sc;
        }
        memcpy(sigs, sm_buf, CRYPTO_BYTES);
        bench_print("Raccoon.Sign(SHs)", tot_ns/BENCH_ITERS, tot_cy/BENCH_ITERS);
        printf("\n  Step 1 total (KeyGen amortized + Sign):\n");
        printf("  MLKEM.Gen + DHKEM.Gen benchmarked above (Table II)\n");

        write_bin("server_hello.bin",      SHs,     sizeof(SHs));
        write_bin("server_sigs.sig",       sigs,    CRYPTO_BYTES);
        write_bin("server_raccoon_pk.key", pks_rac, sizeof(pks_rac));
        printf("\n  → Server Hello saved. Run ./auth_client now.\n\n");
        return 0;   /* Step 1 complete — user runs auth_client next */
    }

    /* ════════════════════════════════════════════════════════════════════
     * TABLE I — STEP 3: SERVER DECAPSULATION
     * ════════════════════════════════════════════════════════════════════ */
    printf("══════════════════════════════════════════════════════\n");
    printf("TABLE I Step 3 — Server Decapsulation\n");
    printf("══════════════════════════════════════════════════════\n\n");

    /* Reload SHs and sigs so verify uses the correct server hello */
    if (read_bin("server_hello.bin", SHs, sizeof(SHs), &got) != 0) {
        fprintf(stderr, "server_hello.bin missing\n"); return 1;
    }
    if (read_bin("server_sigs.sig",  sigs, CRYPTO_BYTES, &got) != 0) return 1;

    unsigned char c[C_TOTAL_BYTES];
    unsigned char sigc[CRYPTO_BYTES];
    unsigned char pkc_rac[CRYPTO_PUBLICKEYBYTES];

    if (read_bin("client_encap_c.bin",   c,       sizeof(c),       &got) != 0) return 1;
    if (read_bin("client_sigc.sig",      sigc,    CRYPTO_BYTES,    &got) != 0) return 1;
    if (read_bin("client_raccoon_pk.key",pkc_rac, sizeof(pkc_rac), &got) != 0)
        return 1;

    /* ── Raccoon.Verify(sigc) ── */
    printf("[ Raccoon.Verify(sigc) ]\n");
    size_t mv_len = sizeof(c) + sizeof(SHs);
    unsigned char *mv = malloc(mv_len);
    memcpy(mv,          c,   sizeof(c));
    memcpy(mv+sizeof(c), SHs, sizeof(SHs));
    size_t sm_ver_len = CRYPTO_BYTES + mv_len;
    unsigned char *sm_ver = malloc(sm_ver_len);
    memcpy(sm_ver,             sigc, CRYPTO_BYTES);
    memcpy(sm_ver+CRYPTO_BYTES, mv,  mv_len);
    free(mv);

    tot_ns = 0; tot_cy = 0;
    unsigned char *m_open = malloc(mv_len + 1);
    unsigned long long m_open_len;
    int vr = 0;
    for (int i = 0; i < BENCH_ITERS; i++) {
        clock_gettime(CLOCK_MONOTONIC, &ts); sc = rdtsc();
        vr = crypto_sign_open(m_open, &m_open_len, sm_ver, sm_ver_len, pkc_rac);
        ec = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &te);
        tot_ns += (te.tv_sec-ts.tv_sec)*1000000000LL+(te.tv_nsec-ts.tv_nsec);
        if (ec > sc) tot_cy += ec - sc;
    }
    free(sm_ver); free(m_open);
    if (vr != 0) { fprintf(stderr, "ABORT: sigc verification FAILED\n"); return 1; }
    printf("  sigc VERIFIED.\n");
    bench_print("Raccoon.Verify(sigc)", tot_ns/BENCH_ITERS, tot_cy/BENCH_ITERS);

    /* ── ML-KEM Decapsulation ── */
    printf("\n[ ML-KEM-768 Decapsulation ]\n");
    const unsigned char *c1 = c;
    const unsigned char *c2 = c + PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    unsigned char k1[PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES];
    tot_ns = 0; tot_cy = 0;
    for (int i = 0; i < BENCH_ITERS; i++) {
        clock_gettime(CLOCK_MONOTONIC, &ts); sc = rdtsc();
        if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(k1, c1, sks1_mlkem) != 0) {
            fprintf(stderr, "ML-KEM decap failed\n"); return 1;
        }
        ec = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &te);
        tot_ns += (te.tv_sec-ts.tv_sec)*1000000000LL+(te.tv_nsec-ts.tv_nsec);
        if (ec > sc) tot_cy += ec - sc;
    }
    bench_print("ML-KEM-768 Dec", tot_ns/BENCH_ITERS, tot_cy/BENCH_ITERS);
    print_hex("  k1", k1, sizeof(k1));

    /* ── DHKEM Decapsulation ── */
    printf("\n[ DHKEM(X25519) Decapsulation ]\n");
    unsigned char k2[32];
    tot_ns = 0; tot_cy = 0;
    for (int i = 0; i < BENCH_ITERS; i++) {
        clock_gettime(CLOCK_MONOTONIC, &ts); sc = rdtsc();
        if (dhkem_decap(k2, c2, sks2_x25519, pks2_x25519) != 0) {
            fprintf(stderr, "DHKEM decap failed\n"); return 1;
        }
        ec = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &te);
        tot_ns += (te.tv_sec-ts.tv_sec)*1000000000LL+(te.tv_nsec-ts.tv_nsec);
        if (ec > sc) tot_cy += ec - sc;
    }
    bench_print("DHKEM(X25519) Dec", tot_ns/BENCH_ITERS, tot_cy/BENCH_ITERS);
    print_hex("  k2", k2, sizeof(k2));

    /* ── HKDF ksh derivation ── */
    printf("\n[ HKDF ksh Derivation (Step 3) ]\n");
    size_t ikm_len = sizeof(k1)+sizeof(k2)+sizeof(c)+
                     CRYPTO_BYTES+CRYPTO_BYTES+
                     CRYPTO_PUBLICKEYBYTES*2+1;
    unsigned char *ikm = malloc(ikm_len);
    unsigned char *p = ikm;
    memcpy(p, k1,      sizeof(k1));          p += sizeof(k1);
    memcpy(p, k2,      sizeof(k2));          p += sizeof(k2);
    memcpy(p, c,       sizeof(c));           p += sizeof(c);
    memcpy(p, sigs,    CRYPTO_BYTES);        p += CRYPTO_BYTES;
    memcpy(p, sigc,    CRYPTO_BYTES);        p += CRYPTO_BYTES;
    memcpy(p, pks_rac, CRYPTO_PUBLICKEYBYTES); p += CRYPTO_PUBLICKEYBYTES;
    memcpy(p, pkc_rac, CRYPTO_PUBLICKEYBYTES); p += CRYPTO_PUBLICKEYBYTES;
    *p = mode;

    unsigned char ksh[32];
    tot_ns = 0; tot_cy = 0;
    for (int i = 0; i < BENCH_ITERS; i++) {
        unsigned char prk[32];
        clock_gettime(CLOCK_MONOTONIC, &ts); sc = rdtsc();
        hkdf_extract(prk, NULL, 0, ikm, ikm_len);
        hkdf_expand(ksh, 32, prk, 32,
                    (const unsigned char*)"ksh", 3);
        ec = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &te);
        tot_ns += (te.tv_sec-ts.tv_sec)*1000000000LL+(te.tv_nsec-ts.tv_nsec);
        if (ec > sc) tot_cy += ec - sc;
    }
    free(ikm);
    bench_print("HKDF ksh", tot_ns/BENCH_ITERS, tot_cy/BENCH_ITERS);
    print_hex("  ksh", ksh, sizeof(ksh));

    /* ── Post-handshake AEAD: Ascon-128 Encrypt ── */
    printf("\n[ Ascon-128 AEAD Encrypt (post-handshake response) ]\n");
    unsigned char ascon_key[16];
    memcpy(ascon_key, ksh, 16);
    unsigned char anonce[16];
    randombytes(anonce, sizeof(anonce));
    const char *resp = "AmphiKey Auth Mode: session established.";
    size_t resp_len = strlen(resp);

    /* ct buffer: plaintext + 16-byte Ascon tag appended automatically */
    unsigned char *ct = malloc(resp_len + 16);
    unsigned long long ct_actual_len = 0;

    tot_ns = 0; tot_cy = 0;
    for (int i = 0; i < BENCH_ITERS; i++) {
        unsigned long long tmp_len = 0;
        clock_gettime(CLOCK_MONOTONIC, &ts); sc = rdtsc();
        crypto_aead_encrypt(ct, &tmp_len,
                            (const unsigned char*)resp, resp_len,
                            NULL, 0, NULL,
                            anonce, ascon_key);
        ec = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &te);
        tot_ns += (te.tv_sec-ts.tv_sec)*1000000000LL+(te.tv_nsec-ts.tv_nsec);
        if (ec > sc) tot_cy += ec - sc;
        ct_actual_len = tmp_len;
    }
    bench_print("Ascon-128 AEAD Enc", tot_ns/BENCH_ITERS, tot_cy/BENCH_ITERS);

    write_bin("server_response_nonce.bin", anonce, sizeof(anonce));
    write_bin("server_response_ct.bin",   ct,     (size_t)ct_actual_len);
    sodium_memzero(ascon_key, sizeof(ascon_key));
    free(ct);

    /* ── Summary ── */
    printf("\n══════════════════════════════════════════════════════\n");
    printf("Auth Mode payload sizes:\n");
    printf("  c (c1+c2)        : %d bytes\n",  C_TOTAL_BYTES);
    printf("  sigc (Raccoon)   : %d bytes\n",  CRYPTO_BYTES);
    printf("  pkc_rac (Raccoon): %d bytes\n",  CRYPTO_PUBLICKEYBYTES);
    printf("  TOTAL M2         : %d bytes\n",
           C_TOTAL_BYTES + CRYPTO_BYTES + CRYPTO_PUBLICKEYBYTES);
    printf("  SHs (Server Hello): %d bytes\n", SHS_BYTES);
    printf("  sigs (Raccoon)   : %d bytes\n",  CRYPTO_BYTES);
    printf("  TOTAL M1         : %d bytes\n",
           SHS_BYTES + CRYPTO_BYTES + CRYPTO_PUBLICKEYBYTES);
    printf("══════════════════════════════════════════════════════\n");
    printf("PROTOCOL SUCCESS: Auth Mode server complete.\n\n");

    sodium_memzero(sks1_mlkem, sizeof(sks1_mlkem));
    sodium_memzero(sks2_x25519, sizeof(sks2_x25519));
    sodium_memzero(sks_rac, sizeof(sks_rac));
    sodium_memzero(k1, sizeof(k1));
    sodium_memzero(k2, sizeof(k2));
    sodium_memzero(ksh, sizeof(ksh));
    return 0;
}
