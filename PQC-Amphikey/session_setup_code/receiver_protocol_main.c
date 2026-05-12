/*
 * AmphiKey Authenticated Mode — Client (Responder + Encapsulator)
 * COMPLETE with 1000-iteration benchmark loops on all client-side ops:
 *   Raccoon.Verify(sigs)  — Table I Step 2
 *   ML-KEM.Enc            — Table I Step 2
 *   DHKEM.Enc             — Table I Step 2
 *   Raccoon.Sign(sigc)    — Table I Step 2
 *   HKDF(ksh)             — Table I Step 2
 *   Ascon-128 AEAD Dec    — Table I Post-handshake (client)
 *
 * Prerequisite: run ./auth_server first to generate:
 *   server_hello.bin, server_sigs.sig, server_raccoon_pk.key
 * Client long-term Raccoon keys generated here if absent:
 *   client_raccoon_sk.key, client_raccoon_pk.key
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
int crypto_aead_decrypt(unsigned char *m,  unsigned long long *mlen,
                        unsigned char *nsec,
                        const unsigned char *c,   unsigned long long clen,
                        const unsigned char *ad,  unsigned long long adlen,
                        const unsigned char *npub,
                        const unsigned char *k);

extern void nist_randombytes_init(unsigned char *entropy,
                                  unsigned char *pers, int strength);
extern void randombytes(unsigned char *x, unsigned long long xlen);

void PQCLEAN_randombytes(unsigned char *buf, size_t n) {
    randombytes(buf, (unsigned long long)n);
}

#define AMPHIKEY_MODE_AUTHENTICATED ((unsigned char)0x01)
#define AMPHIKEY_DHKEM_INFO         "AmphiKey-DHKEM-v1"

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
    printf("  Time   : %10llu ns  (%8.3f µs)\n", ns, ns/1000.0);
    printf("  Cycles : %10llu\n", cy);
    (void)label;
}

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
    size_t T_len = 0, off = 0, N = (okm_len+31)/32;
    crypto_auth_hmacsha256_state st;
    for (unsigned char i = 1; (size_t)i <= N; i++) {
        crypto_auth_hmacsha256_init(&st, prk, prk_len);
        if (T_len)    crypto_auth_hmacsha256_update(&st, T, T_len);
        if (info_len) crypto_auth_hmacsha256_update(&st, info, info_len);
        crypto_auth_hmacsha256_update(&st, &i, 1);
        crypto_auth_hmacsha256_final(&st, T);
        T_len = 32;
        size_t cp = (off+32 > okm_len) ? okm_len-off : 32;
        memcpy(okm+off, T, cp); off += cp;
    }
    sodium_memzero(T, 32);
    return 0;
}

/* DHKEM(X25519) Encapsulation */
static int dhkem_encap(unsigned char c2[32], unsigned char k2[32],
                       const unsigned char pk_recv[32]) {
    unsigned char sk_eph[32], pk_eph[32], dh[32], ikm[96], prk[32];
    randombytes_buf(sk_eph, 32);
    crypto_scalarmult_base(pk_eph, sk_eph);
    if (crypto_scalarmult(dh, sk_eph, pk_recv) != 0) {
        sodium_memzero(sk_eph, 32); return -1;
    }
    memcpy(ikm,    dh,      32);
    memcpy(ikm+32, pk_eph,  32);
    memcpy(ikm+64, pk_recv, 32);
    hkdf_extract(prk, NULL, 0, ikm, 96);
    hkdf_expand(k2, 32, prk, 32,
                (const unsigned char*)AMPHIKEY_DHKEM_INFO,
                strlen(AMPHIKEY_DHKEM_INFO));
    memcpy(c2, pk_eph, 32);
    sodium_memzero(sk_eph, 32);
    sodium_memzero(dh, 32);
    sodium_memzero(ikm, 96);
    sodium_memzero(prk, 32);
    return 0;
}

/* ── Main ─────────────────────────────────────────────────────────────── */
int main(void) {
    printf("=== AmphiKey Authenticated Mode — Client (auth_client) ===\n\n");

    unsigned char entropy[48];
    for (int i = 0; i < 48; i++) entropy[i] = (unsigned char)('C' + i);
    nist_randombytes_init(entropy, (unsigned char*)"AmphiKey-Client", 256);
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n"); return 1;
    }
    /* ── Post-handshake-only mode ─────────────────────────────────────────
     * If server_response_nonce.bin AND client_ksh.bin both exist, just
     * decrypt the server response — do NOT re-run Step 2 (would overwrite
     * client_ksh.bin with a new ksh that won't match the server's ct).
     * ──────────────────────────────────────────────────────────────────── */
    {
        FILE *fn = fopen("server_response_nonce.bin", "rb");
        FILE *fk = fopen("client_ksh.bin", "rb");
        if (fn && fk) {
            fclose(fn); fclose(fk);
            printf("\n══════════════════════════════════════════════════════\n");
            printf("TABLE I Post-handshake — Ascon-128 AEAD Decrypt (client)\n");
            printf("══════════════════════════════════════════════════════\n\n");
            printf("[ Ascon-128 AEAD Decrypt ]\n");
            unsigned char ksh_ph[32]; size_t got_ph;
            if (read_bin("client_ksh.bin", ksh_ph, 32, &got_ph) != 0) return 1;
            unsigned char resp_nonce_ph[16];
            if (read_bin("server_response_nonce.bin", resp_nonce_ph, 16, &got_ph) != 0) return 1;
            FILE *fp = fopen("server_response_ct.bin", "rb");
            if (fp) {
                unsigned char ct_in[512]; size_t ct_sz = fread(ct_in, 1, sizeof(ct_in), fp); fclose(fp);
                if (ct_sz > 16) {
                    unsigned char ak[16]; memcpy(ak, ksh_ph, 16);
                    struct timespec ts2, te2; unsigned long long sc2, ec2, tn=0, tc=0;
                    for (int i = 0; i < BENCH_ITERS; i++) {
                        unsigned char pt_tmp[512]; unsigned long long pl=0;
                        clock_gettime(CLOCK_MONOTONIC,&ts2); sc2=rdtsc();
                        crypto_aead_decrypt(pt_tmp,&pl,NULL,ct_in,(unsigned long long)ct_sz,NULL,0,resp_nonce_ph,ak);
                        ec2=rdtsc(); clock_gettime(CLOCK_MONOTONIC,&te2);
                        tn+=(te2.tv_sec-ts2.tv_sec)*1000000000LL+(te2.tv_nsec-ts2.tv_nsec);
                        if(ec2>sc2) tc+=ec2-sc2;
                    }
                    printf("  Time   : %10llu ns  (%8.3f \xc2\xb5s)\n", tn/BENCH_ITERS, (double)(tn/BENCH_ITERS)/1000.0);
                    printf("  Cycles : %10llu\n", tc/BENCH_ITERS);
                    unsigned char pt_out[512]; unsigned long long pl2=0;
                    int ret = crypto_aead_decrypt(pt_out,&pl2,NULL,ct_in,(unsigned long long)ct_sz,NULL,0,resp_nonce_ph,ak);
                    if (ret==0) { pt_out[pl2]='\0'; printf("  \xe2\x9c\x93 Ascon-128 verified. Server: %s\n",(char*)pt_out); }
                    else fprintf(stderr,"  Ascon-128 AEAD tag FAILED\n");
                    sodium_memzero(ak,16);
                }
            }
            printf("\nPROTOCOL SUCCESS: post-handshake decrypt complete.\n\n");
            return 0;
        }
        if (fn) fclose(fn);
        if (fk) fclose(fk);
    }

    struct timespec ts, te;
    unsigned long long sc, ec, tot_ns, tot_cy;
    size_t got;

    /* ── Load Server Hello materials ── */
    printf("Loading Server Hello materials...\n");
    unsigned char SHs[SHS_BYTES];
    unsigned char sigs[CRYPTO_BYTES];
    unsigned char pks_rac[CRYPTO_PUBLICKEYBYTES];

    if (read_bin("server_hello.bin",    SHs,  sizeof(SHs), &got)) {
        fprintf(stderr, "server_hello.bin missing — run ./auth_server first\n");
        return 1;
    }
    if (read_bin("server_sigs.sig",     sigs, CRYPTO_BYTES, &got)) return 1;
    if (read_bin("server_raccoon_pk.key", pks_rac, sizeof(pks_rac), &got)) return 1;

    unsigned char pks1_mlkem[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    unsigned char pks2_x25519[32];
    unsigned char mode_rcvd;
    memcpy(pks1_mlkem,  SHs,                   sizeof(pks1_mlkem));
    memcpy(pks2_x25519, SHs+sizeof(pks1_mlkem), 32);
    mode_rcvd = SHs[sizeof(pks1_mlkem)+32];
    printf("  MODE = 0x%02x (expected 0x01 = Authenticated)\n\n", mode_rcvd);
    if (mode_rcvd != AMPHIKEY_MODE_AUTHENTICATED) {
        fprintf(stderr, "MODE mismatch — downgrade attack or wrong mode.\n");
        return 1;
    }

    /* ── Load or generate client Raccoon keys ── */
    printf("Loading client Raccoon keys...\n");
    unsigned char skc_rac[CRYPTO_SECRETKEYBYTES];
    unsigned char pkc_rac[CRYPTO_PUBLICKEYBYTES];
    {
        FILE *f = fopen("client_raccoon_sk.key", "rb");
        if (f) {
            fread(skc_rac, 1, sizeof(skc_rac), f); fclose(f);
            f = fopen("client_raccoon_pk.key", "rb");
            if (f) { fread(pkc_rac, 1, sizeof(pkc_rac), f); fclose(f);
                     printf("  (loaded existing client Raccoon keys)\n"); }
            else {
                /* pk file missing — recompute from sk */
                printf("  (client_raccoon_pk.key missing — regenerating pk)\n");
                crypto_sign_keypair(pkc_rac, skc_rac);  /* fresh pair */
                write_bin("client_raccoon_sk.key", skc_rac, sizeof(skc_rac));
                write_bin("client_raccoon_pk.key", pkc_rac, sizeof(pkc_rac));
            }
        } else {
            printf("  (generating new client Raccoon keys...)\n");
            crypto_sign_keypair(pkc_rac, skc_rac);
            write_bin("client_raccoon_sk.key", skc_rac, sizeof(skc_rac));
            write_bin("client_raccoon_pk.key", pkc_rac, sizeof(pkc_rac));
        }
    }
    printf("\n");

    /* ════════════════════════════════════════════════════════════════════
     * TABLE I — STEP 2 CLIENT BENCHMARKS
     * ════════════════════════════════════════════════════════════════════ */
    printf("══════════════════════════════════════════════════════\n");
    printf("TABLE I Step 2 — Client Benchmarks (%d iterations)\n",
           BENCH_ITERS);
    printf("══════════════════════════════════════════════════════\n\n");

    /* ── Raccoon.Verify(sigs) ── */
    printf("[ Raccoon.Verify(sigs) ]\n");
    size_t sm_len = CRYPTO_BYTES + sizeof(SHs);
    unsigned char *sm = malloc(sm_len);
    memcpy(sm,             sigs, CRYPTO_BYTES);
    memcpy(sm+CRYPTO_BYTES, SHs, sizeof(SHs));
    unsigned char *m_open = malloc(sizeof(SHs)+1);
    unsigned long long m_open_len;
    tot_ns = 0; tot_cy = 0;
    int vr = 0;
    for (int i = 0; i < BENCH_ITERS; i++) {
        clock_gettime(CLOCK_MONOTONIC, &ts); sc = rdtsc();
        vr = crypto_sign_open(m_open, &m_open_len, sm, sm_len, pks_rac);
        ec = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &te);
        tot_ns += (te.tv_sec-ts.tv_sec)*1000000000LL+(te.tv_nsec-ts.tv_nsec);
        if (ec > sc) tot_cy += ec - sc;
    }
    free(sm); free(m_open);
    if (vr != 0) { fprintf(stderr, "ABORT: sigs FAILED\n"); return 1; }
    printf("  sigs VERIFIED — server identity confirmed.\n");
    bench_print("Raccoon.Verify(sigs)", tot_ns/BENCH_ITERS, tot_cy/BENCH_ITERS);

    /* ── ML-KEM Encapsulation ── */
    printf("\n[ ML-KEM-768 Encapsulation ]\n");
    unsigned char c1[PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    unsigned char k1[PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES];
    tot_ns = 0; tot_cy = 0;
    for (int i = 0; i < BENCH_ITERS; i++) {
        clock_gettime(CLOCK_MONOTONIC, &ts); sc = rdtsc();
        if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(c1, k1, pks1_mlkem) != 0) {
            fprintf(stderr, "ML-KEM encap failed\n"); return 1;
        }
        ec = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &te);
        tot_ns += (te.tv_sec-ts.tv_sec)*1000000000LL+(te.tv_nsec-ts.tv_nsec);
        if (ec > sc) tot_cy += ec - sc;
    }
    bench_print("ML-KEM-768 Enc", tot_ns/BENCH_ITERS, tot_cy/BENCH_ITERS);
    print_hex("  k1", k1, sizeof(k1));

    /* ── DHKEM Encapsulation ── */
    printf("\n[ DHKEM(X25519) Encapsulation ]\n");
    unsigned char c2[32], k2[32];
    tot_ns = 0; tot_cy = 0;
    for (int i = 0; i < BENCH_ITERS; i++) {
        clock_gettime(CLOCK_MONOTONIC, &ts); sc = rdtsc();
        if (dhkem_encap(c2, k2, pks2_x25519) != 0) {
            fprintf(stderr, "DHKEM encap failed\n"); return 1;
        }
        ec = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &te);
        tot_ns += (te.tv_sec-ts.tv_sec)*1000000000LL+(te.tv_nsec-ts.tv_nsec);
        if (ec > sc) tot_cy += ec - sc;
    }
    bench_print("DHKEM(X25519) Enc", tot_ns/BENCH_ITERS, tot_cy/BENCH_ITERS);
    print_hex("  k2", k2, sizeof(k2));

    /* c = c1 ‖ c2 */
    unsigned char c[C_TOTAL_BYTES];
    memcpy(c,          c1, sizeof(c1));
    memcpy(c+sizeof(c1), c2, 32);

    /* ── Raccoon.Sign(sigc) ── */
    printf("\n[ Raccoon.Sign(sigc) — signing c ‖ SHs ]\n");
    size_t msg_len = sizeof(c) + sizeof(SHs);
    unsigned char *msg = malloc(msg_len);
    memcpy(msg,          c,   sizeof(c));
    memcpy(msg+sizeof(c), SHs, sizeof(SHs));
    size_t sm_buf_sz = CRYPTO_BYTES + msg_len;
    unsigned char *sm_buf = malloc(sm_buf_sz);
    unsigned long long smlen;
    unsigned char sigc[CRYPTO_BYTES];

    tot_ns = 0; tot_cy = 0;
    for (int i = 0; i < BENCH_ITERS; i++) {
        clock_gettime(CLOCK_MONOTONIC, &ts); sc = rdtsc();
        if (crypto_sign(sm_buf, &smlen, msg, msg_len, skc_rac) != 0) {
            fprintf(stderr, "Raccoon sign (sigc) failed\n"); return 1;
        }
        ec = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &te);
        tot_ns += (te.tv_sec-ts.tv_sec)*1000000000LL+(te.tv_nsec-ts.tv_nsec);
        if (ec > sc) tot_cy += ec - sc;
    }
    memcpy(sigc, sm_buf, CRYPTO_BYTES);
    free(msg); free(sm_buf);
    bench_print("Raccoon.Sign(sigc)", tot_ns/BENCH_ITERS, tot_cy/BENCH_ITERS);

    /* ── HKDF ksh Derivation ── */
    printf("\n[ HKDF ksh Derivation (Step 2) ]\n");
    unsigned char mode = AMPHIKEY_MODE_AUTHENTICATED;
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

    /* ── Save encapsulation output for server ── */
    printf("\nSaving encapsulation output for ./auth_server Step 3...\n");
    write_bin("client_encap_c.bin",      c,       sizeof(c));
    write_bin("client_sigc.sig",         sigc,    CRYPTO_BYTES);
    write_bin("client_raccoon_pk.key",   pkc_rac, sizeof(pkc_rac));
    write_bin("client_ksh.bin",          ksh,     sizeof(ksh));
    /* Save ksh so post-handshake decrypt uses the matching session key */
    write_bin("client_ksh.bin",          ksh,     sizeof(ksh));

    /* ── Post-handshake: decrypt server's AEAD response ── */
    printf("\n══════════════════════════════════════════════════════\n");
    printf("TABLE I Post-handshake — Ascon-128 AEAD Decrypt (client)\n");
    printf("══════════════════════════════════════════════════════\n\n");
    printf("[ Ascon-128 AEAD Decrypt ]\n");

    /* Load ksh from disk — must match the ksh server used to encrypt */
    unsigned char ksh_saved[32];
    size_t got2;
    if (read_bin("client_ksh.bin", ksh_saved, sizeof(ksh_saved), &got2) != 0) {
        fprintf(stderr, "client_ksh.bin missing\n"); return 1;
    }

    unsigned char resp_nonce[16];
    if (read_bin("server_response_nonce.bin", resp_nonce,
                 sizeof(resp_nonce), &got2) != 0) {
        printf("  server_response_nonce.bin not found;\n");
        printf("  run ./auth_server Step 3 first to generate the response.\n");
    } else {
        FILE *fp = fopen("server_response_ct.bin", "rb");
        if (fp) {
            unsigned char ct_in[512];

            size_t ct_sz = fread(ct_in, 1, sizeof(ct_in), fp);
            fclose(fp);
            if (ct_sz > 16) {  /* must be longer than Ascon tag (16 B) */
                unsigned char ascon_key[16];
                memcpy(ascon_key, ksh_saved, 16);

                /* Benchmark 1000 iterations */
                tot_ns = 0; tot_cy = 0;
                for (int i = 0; i < BENCH_ITERS; i++) {
                    unsigned char pt_tmp[512];
                    unsigned long long pt_tmp_len = 0;
                    clock_gettime(CLOCK_MONOTONIC, &ts); sc = rdtsc();
                    crypto_aead_decrypt(pt_tmp, &pt_tmp_len,
                                        NULL,
                                        ct_in, (unsigned long long)ct_sz,
                                        NULL, 0,
                                        resp_nonce, ascon_key);
                    ec = rdtsc(); clock_gettime(CLOCK_MONOTONIC, &te);
                    tot_ns += (te.tv_sec-ts.tv_sec)*1000000000LL+
                              (te.tv_nsec-ts.tv_nsec);
                    if (ec > sc) tot_cy += ec - sc;
                }
                bench_print("Ascon-128 AEAD Dec",
                            tot_ns/BENCH_ITERS, tot_cy/BENCH_ITERS);

                /* Final decrypt + authenticated tag verify */
                unsigned char pt_out[512];
                unsigned long long pt_out_len = 0;
                int ret = crypto_aead_decrypt(pt_out, &pt_out_len,
                                              NULL,
                                              ct_in, (unsigned long long)ct_sz,
                                              NULL, 0,
                                              resp_nonce, ascon_key);
                if (ret == 0) {
                    pt_out[pt_out_len] = '\0';
                    printf("  ✓ Ascon-128 tag verified. Server response: %s\n",
                           (char*)pt_out);
                } else {
                    fprintf(stderr, "  Ascon-128 AEAD tag verification FAILED\n");
                }
                sodium_memzero(ascon_key, sizeof(ascon_key));
            }
        }
    }

    /* ── Payload size summary ── */
    printf("\n══════════════════════════════════════════════════════\n");
    printf("Auth Mode client → server payload:\n");
    printf("  c = c1(%d) + c2(32)  : %d bytes\n",
           PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES, C_TOTAL_BYTES);
    printf("  sigc (Raccoon)       : %d bytes\n",  CRYPTO_BYTES);
    printf("  pkc_rac              : %d bytes\n",  CRYPTO_PUBLICKEYBYTES);
    printf("  TOTAL M2             : %d bytes\n",
           C_TOTAL_BYTES + CRYPTO_BYTES + CRYPTO_PUBLICKEYBYTES);
    printf("══════════════════════════════════════════════════════\n");
    printf("PROTOCOL SUCCESS: Auth Mode client complete.\n\n");

    sodium_memzero(skc_rac, sizeof(skc_rac));
    sodium_memzero(k1, sizeof(k1));
    sodium_memzero(k2, sizeof(k2));
    sodium_memzero(ksh, sizeof(ksh));
    return 0;
}
