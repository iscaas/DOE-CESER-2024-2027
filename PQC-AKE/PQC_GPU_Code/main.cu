// main_gpu_handshake.cu  — microsecond timings, explicit a(...), and CA check (test vectors)

#ifdef N
#  undef N
#endif
#ifdef LOGN
#  undef LOGN
#endif
#ifdef FALCON_N
#  pragma push_macro("FALCON_N")
#endif
#ifdef FALCON_LOGN
#  pragma push_macro("FALCON_LOGN")
#endif

#include <cuda.h>
#include <cuda_runtime.h>
#include <cuda_fp16.h>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <chrono>

#ifndef FALCON_N
#  define FALCON_N 512
#endif
#ifndef FALCON_LOGN
#  define FALCON_LOGN 9
#endif

#define N     FALCON_N
#define LOGN  FALCON_LOGN

#ifdef FALCON_N
#  pragma pop_macro("FALCON_N")
#endif
#ifdef FALCON_LOGN
#  pragma pop_macro("FALCON_LOGN")
#endif

#include "include/cuda_kernel.cuh"
#include "include/params.h"
#include "include/tmp_constants.h"
#include "include/poly.h"
#include "include/keygeneration.cuh"
#include "include/incdpa.cuh"
#include "include/test_vector.cuh"

#ifndef AES_BLOCK_SIZE
#define AES_BLOCK_SIZE 16
#endif

#ifndef MLEN
#define MLEN 33
#endif

#ifndef HAVE_M_TV
static const uint8_t m_tv[MLEN] = {
    216, 28, 77, 141, 115, 79, 203, 251, 234, 222, 61, 63, 138,
    3, 159, 170, 42, 44, 153, 87, 232, 53, 173, 85, 178, 46, 117,
    191, 87, 187, 85, 106, 200
};
#endif

// Simple fixed “certificate bodies” for transcript binding (toy/test-vector only)
static const uint8_t CERT_GSM[64] = {
  0x47,0x53,0x4d,0x2d,0x31,0x01,0x02,0x03,0x04,0x05,0x10,0x11,0x12,0x13,0x14,0x15,
  0x21,0x22,0x23,0x24,0x25,0xAA,0xBB,0xCC,0xDD,0xEE,0x30,0x31,0x32,0x33,0x34,0x35,
  0x40,0x41,0x42,0x43,0x44,0x99,0x77,0x55,0x22,0x11,0x66,0x77,0x88,0x99,0xAB,0xCD,
  0xDE,0xEF,0xF0,0x0F,0x5A,0x5B,0x5C,0x5D,0x90,0x91,0x92,0x93,0x94,0x95,0xA0,0xA1
};
static const uint8_t CERT_SGN[64] = {
  0x53,0x47,0x4E,0x2D,0x31,0x55,0x44,0x33,0x22,0x11,0x20,0x21,0x22,0x23,0x24,0x25,
  0x31,0x32,0x33,0x34,0x35,0xBA,0xDB,0xEE,0xF0,0x0F,0x60,0x61,0x62,0x63,0x64,0x65,
  0x70,0x71,0x72,0x73,0x74,0x19,0x27,0x35,0x42,0x51,0x16,0x27,0x38,0x49,0x5A,0x6B,
  0x7C,0x8D,0x9E,0xAF,0x5E,0x5D,0x5C,0x5B,0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xB0,0xB1
};

static constexpr size_t HMAC_TAG_LEN = 32;
static constexpr size_t AES_KEY_LEN  = 32;
static constexpr size_t IV_LEN       = 16;
static constexpr size_t NONCE_LEN    = 16;

#ifndef KYBER_FAKE_SS
#define KYBER_FAKE_SS 1
#endif

static void print_hex(const char* label, const uint8_t* buf, size_t len) {
    if (label && *label) std::printf("%s (hex): ", label);
    for (size_t i = 0; i < len; ++i) std::printf("%02x", buf[i]);
    std::printf("\n");
}

static bool hmac_sha256_bytes(const uint8_t* key, size_t key_len,
                              const uint8_t* data, size_t data_len,
                              uint8_t out_tag[HMAC_TAG_LEN]) {
    unsigned int out_len = 0;
    HMAC_CTX* ctx = HMAC_CTX_new();
    if (!ctx) return false;
    bool ok = HMAC_Init_ex(ctx, key, (int)key_len, EVP_sha256(), nullptr) == 1
           && HMAC_Update(ctx, data, data_len) == 1
           && HMAC_Final(ctx, out_tag, &out_len) == 1
           && out_len == HMAC_TAG_LEN;
    HMAC_CTX_free(ctx);
    return ok;
}

static bool verify_hmac_tag(const uint8_t* key, size_t key_len,
                            const uint8_t* data, size_t data_len,
                            const uint8_t tag[HMAC_TAG_LEN]) {
    uint8_t calc[HMAC_TAG_LEN];
    if (!hmac_sha256_bytes(key, key_len, data, data_len, calc)) return false;
    return CRYPTO_memcmp(calc, tag, HMAC_TAG_LEN) == 0;
}

static int aes256_cbc_encrypt(const uint8_t key[AES_KEY_LEN], const uint8_t iv[IV_LEN],
                              const uint8_t* pt, int pt_len, uint8_t* ct, int ct_cap) {
    int len = 0, tot = 0;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) { EVP_CIPHER_CTX_free(ctx); return -1; }
    if (EVP_EncryptUpdate(ctx, ct, &len, pt, pt_len) != 1) { EVP_CIPHER_CTX_free(ctx); return -1; }
    tot = len;
    if (tot + AES_BLOCK_SIZE > ct_cap) { EVP_CIPHER_CTX_free(ctx); return -1; }
    if (EVP_EncryptFinal_ex(ctx, ct + tot, &len) != 1) { EVP_CIPHER_CTX_free(ctx); return -1; }
    tot += len;
    EVP_CIPHER_CTX_free(ctx);
    return tot;
}

static int aes256_cbc_decrypt(const uint8_t key[AES_KEY_LEN], const uint8_t iv[IV_LEN],
                              const uint8_t* ct, int ct_len, uint8_t* pt, int pt_cap) {
    int len = 0, tot = 0;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) { EVP_CIPHER_CTX_free(ctx); return -1; }
    if (pt_cap < ct_len + AES_BLOCK_SIZE) { EVP_CIPHER_CTX_free(ctx); return -1; }
    if (EVP_DecryptUpdate(ctx, pt, &len, ct, ct_len) != 1) { EVP_CIPHER_CTX_free(ctx); return -1; }
    tot = len;
    if (EVP_DecryptFinal_ex(ctx, pt + tot, &len) != 1) { EVP_CIPHER_CTX_free(ctx); return -1; }
    tot += len;
    EVP_CIPHER_CTX_free(ctx);
    return tot;
}

static bool sha3_256_bytes(const uint8_t* in, size_t in_len, uint8_t out32[32]) {
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    if (!md) return false;
    bool ok = EVP_DigestInit_ex(md, EVP_sha3_256(), nullptr) == 1
           && EVP_DigestUpdate(md, in, in_len) == 1
           && EVP_DigestFinal_ex(md, out32, nullptr) == 1;
    EVP_MD_CTX_free(md);
    return ok;
}

template <typename T>
static void halloc(T** p, size_t count) {
    if (cudaMallocHost((void**)p, count * sizeof(T)) != cudaSuccess) {
        std::fprintf(stderr, "cudaMallocHost failed\n");
        std::exit(EXIT_FAILURE);
    }
}

static void gpu_sync_or_die(const char* where) {
    cudaError_t err = cudaDeviceSynchronize();
    if (err != cudaSuccess) {
        std::fprintf(stderr, "CUDA error after %s: %s\n", where, cudaGetErrorString(err));
        std::exit(EXIT_FAILURE);
    }
}

// --- microseconds timing ---
static inline double us_since(std::chrono::high_resolution_clock::time_point t0,
                              std::chrono::high_resolution_clock::time_point t1) {
    return std::chrono::duration<double, std::micro>(t1 - t0).count();
}

// Build SHA3-256(prefix || variable_per_batch) into MLEN bytes
static void fill_digest_messages(uint8_t* dst_h_m1, const uint8_t* prefix, size_t prefix_len,
                                 const uint8_t* varbuf, size_t var_len_per_batch) {
    for (int b = 0; b < BATCH; ++b) {
        uint8_t tmp[64 + KYBER_INDCPA_PUBLICKEYBYTES];
        size_t off = 0;
        std::memcpy(tmp + off, prefix, prefix_len); off += prefix_len;
        std::memcpy(tmp + off, varbuf + b * var_len_per_batch, var_len_per_batch); off += var_len_per_batch;
        uint8_t dig[32];
        if (!sha3_256_bytes(tmp, off, dig)) { std::fprintf(stderr, "SHA3 transcript\n"); std::exit(EXIT_FAILURE); }
        uint8_t* mslot = dst_h_m1 + b * MLEN;
        std::memset(mslot, 0, MLEN);
        std::memcpy(mslot, dig, (MLEN < 32 ? MLEN : 32));
    }
}

// Build SHA3-256(prefix) only (for CA signing cert bodies)
static void fill_digest_prefix_only(uint8_t* dst_h_m1, const uint8_t* prefix, size_t prefix_len) {
    for (int b = 0; b < BATCH; ++b) {
        uint8_t dig[32];
        if (!sha3_256_bytes(prefix, prefix_len, dig)) { std::fprintf(stderr, "SHA3 prefix\n"); std::exit(EXIT_FAILURE); }
        uint8_t* mslot = dst_h_m1 + b * MLEN;
        std::memset(mslot, 0, MLEN);
        std::memcpy(mslot, dig, (MLEN < 32 ? MLEN : 32));
    }
}

int main() {
    using clock = std::chrono::high_resolution_clock;
    auto t_total0 = clock::now();

    // Timing accumulators in microseconds
    double t_ca_gsm_sign=0, t_ca_gsm_ver=0, t_ca_sgn_sign=0, t_ca_sgn_ver=0;
    double t_sig1=0, t_ver1=0, t_kyber_enc=0, t_kdf_sgn=0, t_hmac_ck=0;
    double t_kyber_dec=0, t_kdf_sgs=0, t_hmac_ck_ver=0;
    double t_rand_r=0, t_aes_mr_enc=0, t_hmac_mr=0, t_hmac_mr_ver=0, t_aes_mr_dec=0, t_sig2=0, t_ver2=0;
    double t_rand_k=0, t_rand_iv_mr=0, t_rand_iv_y=0;
    double t_aes_y_enc=0, t_hmac_y=0, t_hmac_y_ver=0, t_aes_y_dec=0;

    std::printf("[GPU Harness] Start (BATCH=%d)\n", BATCH);

    // Pinned host buffers
    uint8_t *h_sm, *h_m1, *h_m2;
    uint8_t *h_sm2, *h_m2_sgn;
    uint8_t *c_k, *msg_k, *pk_k, *coins;
    uint8_t *msg1;
    uint8_t *c_y;
    uint8_t *kr_enc, *kr_dec;

    // CA buffers (test-vector signing for cert bodies)
    uint8_t *h_sm_ca, *h_m_ca, *h_m_ca_ver;

    halloc(&h_sm,   (MLEN + CRYPTO_BYTES) * BATCH);
    halloc(&h_m1,   MLEN * BATCH);
    halloc(&h_m2,   MLEN * BATCH);
    halloc(&h_sm2,  (MLEN + CRYPTO_BYTES) * BATCH);
    halloc(&h_m2_sgn, MLEN * BATCH);

    halloc(&c_k,    KYBER_INDCPA_BYTES * BATCH);
    halloc(&msg_k,  KYBER_INDCPA_MSGBYTES * BATCH);
    halloc(&pk_k,   KYBER_INDCPA_PUBLICKEYBYTES * BATCH);
    halloc(&coins,  KYBER_SYMBYTES * BATCH);
    halloc(&msg1,   KYBER_INDCPA_MSGBYTES * BATCH);

    halloc(&c_y,    (4096 + IV_LEN) * BATCH);

    halloc(&kr_enc, KYBER_SSBYTES * BATCH);
    halloc(&kr_dec, KYBER_SSBYTES * BATCH);

    // CA buffers
    halloc(&h_sm_ca,   (MLEN + CRYPTO_BYTES) * BATCH);
    halloc(&h_m_ca,    MLEN * BATCH);
    halloc(&h_m_ca_ver,MLEN * BATCH);

    // Seed message buffer with test vector
    for (int j = 0; j < BATCH; ++j)
        for (int i = 0; i < MLEN; ++i)
            h_m1[j*MLEN + i] = m_tv[i];

#ifdef AESGPU
    for (int i=0;i<BATCH;i++) for (int j=0;j<KYBER_INDCPA_PUBLICKEYBYTES;j++) pk_k[i*KYBER_INDCPA_PUBLICKEYBYTES + j] = tmp_pk_aes[j];
    for (int i=0;i<BATCH;i++) for (int j=0;j<KYBER_INDCPA_MSGBYTES;j++)      msg_k[i*KYBER_INDCPA_MSGBYTES + j]       = tmp_msg_aes[j];
#else
    for (int i=0;i<BATCH;i++) for (int j=0;j<KYBER_INDCPA_PUBLICKEYBYTES;j++) pk_k[i*KYBER_INDCPA_PUBLICKEYBYTES + j] = tmp_pk[j];
    for (int i=0;i<BATCH;i++) for (int j=0;j<KYBER_INDCPA_MSGBYTES;j++)      msg_k[i*KYBER_INDCPA_MSGBYTES + j]       = tmp_msg_aes[j];
#endif
    for (int i=0;i<BATCH;i++) for (int j=0;j<KYBER_SYMBYTES;j++)             coins[i*KYBER_SYMBYTES + j]               = tmp_coins[j];

    // ------------------------------------------------------------------
    // [CA] Simulated CA verification using test vectors (GPU sign/verify)
    // ------------------------------------------------------------------
    std::printf("[CA] Test-vector CA check: Verify(pk_CA, CertGSM) and Verify(pk_CA, CertSGN)\n");

    // a_CA(GSM) = SHA3-256(CERT_GSM)
    fill_digest_prefix_only(h_m_ca, CERT_GSM, sizeof(CERT_GSM));
    print_hex("[CA] a_CA(GSM) = SHA3-256(CERT_GSM)", h_m_ca, 32);

    { // CA sign/verify (GSM cert body)
        auto t0 = clock::now();
        crypto_sign(h_sm_ca, h_m_ca);
        gpu_sync_or_die("CA sign (GSM)");
        auto t1 = clock::now();
        t_ca_gsm_sign += us_since(t0,t1);

        auto t2 = clock::now();
        crypto_ver(h_sm_ca, h_m_ca, h_m_ca_ver);
        gpu_sync_or_die("CA verify (GSM)");
        auto t3 = clock::now();
        t_ca_gsm_ver += us_since(t2,t3);

        if (!check_signatures(h_m_ca, h_m_ca_ver)) {
            std::fprintf(stderr, "[CA] Verify(pk_CA, CertGSM) failed\n");
            return EXIT_FAILURE;
        }
    }

    // a_CA(SGN) = SHA3-256(CERT_SGN)
    fill_digest_prefix_only(h_m_ca, CERT_SGN, sizeof(CERT_SGN));
    print_hex("[CA] a_CA(SGN) = SHA3-256(CERT_SGN)", h_m_ca, 32);

    { // CA sign/verify (SGN cert body)
        auto t0 = clock::now();
        crypto_sign(h_sm_ca, h_m_ca);
        gpu_sync_or_die("CA sign (SGN)");
        auto t1 = clock::now();
        t_ca_sgn_sign += us_since(t0,t1);

        auto t2 = clock::now();
        crypto_ver(h_sm_ca, h_m_ca, h_m_ca_ver);
        gpu_sync_or_die("CA verify (SGN)");
        auto t3 = clock::now();
        t_ca_sgn_ver += us_since(t2,t3);

        if (!check_signatures(h_m_ca, h_m_ca_ver)) {
            std::fprintf(stderr, "[CA] Verify(pk_CA, CertSGN) failed\n");
            return EXIT_FAILURE;
        }
    }
    std::printf("[CA] OK (test-vector CA)\n");

    // -------------------------------------------------------------
    // [1] σ_GSM over SHA3-256(CERT_GSM || pk_e) — sign + verify
    // -------------------------------------------------------------
    std::printf("[1] Falcon: GSM signs (CertGSM||pk_e), SGN verifies\n");

    // Print a_GSM for slot 0 (BATCH>=1)
    {
        uint8_t tmp[sizeof(CERT_GSM) + KYBER_INDCPA_PUBLICKEYBYTES];
        size_t off = 0;
        std::memcpy(tmp + off, CERT_GSM, sizeof(CERT_GSM)); off += sizeof(CERT_GSM);
        std::memcpy(tmp + off, pk_k, KYBER_INDCPA_PUBLICKEYBYTES);
        uint8_t a_gsm[32];
        sha3_256_bytes(tmp, off + KYBER_INDCPA_PUBLICKEYBYTES, a_gsm);
        print_hex("[GSM] a_GSM = SHA3-256(CERT_GSM||pk_e)", a_gsm, 32);
    }

    fill_digest_messages(h_m1, CERT_GSM, sizeof(CERT_GSM),
                         pk_k, KYBER_INDCPA_PUBLICKEYBYTES);

    {
        auto t0 = clock::now();
        crypto_sign(h_sm, h_m1);
        gpu_sync_or_die("Falcon sign #1");
        auto t1 = clock::now();
        t_sig1 += us_since(t0,t1);
        std::printf("[TIMING] Falcon sign #1: %.1f us\n", us_since(t0,t1));
    }
    {
        auto t0 = clock::now();
        crypto_ver(h_sm, h_m1, h_m2);
        gpu_sync_or_die("Falcon verify #1");
        auto t1 = clock::now();
        t_ver1 += us_since(t0,t1);
        std::printf("[TIMING] Falcon verify #1: %.1f us\n", us_since(t0,t1));
    }
    if (!check_signatures(h_m1, h_m2)) { std::fprintf(stderr, "[1] Falcon verify failed\n"); return EXIT_FAILURE; }
    std::printf("[1] OK\n");

    // -------------------------------------------------------------------
    // [2] Kyber: encaps/decaps; KDF from msg_k; HMAC(c_k)
    // -------------------------------------------------------------------
    std::printf("[2] Kyber: SGN encaps, SGS decaps; derive k_local; HMAC(c_k)\n");
    {
        auto t0 = clock::now();
        indcpa_enc_gpu(c_k, msg_k, pk_k, coins);
        gpu_sync_or_die("Kyber enc");
        auto t1 = clock::now();
        t_kyber_enc += us_since(t0,t1);
    }

    uint8_t ss_enc[32];
    {
        auto t0 = clock::now();
        if (!sha3_256_bytes(msg_k, KYBER_INDCPA_MSGBYTES, ss_enc)) { std::fprintf(stderr, "[2] SHA3-256(msg_k)\n"); return EXIT_FAILURE; }
        uint8_t k_local_enc[AES_KEY_LEN];
        if (!sha3_256_bytes(ss_enc, sizeof ss_enc, k_local_enc)) { std::fprintf(stderr, "[2] SHA3-256(ss_enc)\n"); return EXIT_FAILURE; }
        auto t1 = clock::now();
        t_kdf_sgn += us_since(t0,t1);
        print_hex("[SGN] ss=SHA3-256(m)", ss_enc, sizeof ss_enc);
        print_hex("[SGN] k_local", k_local_enc, AES_KEY_LEN);

        // HMAC(c_k)
        uint8_t tag_ck[HMAC_TAG_LEN];
        auto t2 = clock::now();
        if (!hmac_sha256_bytes(k_local_enc, AES_KEY_LEN, c_k, KYBER_INDCPA_BYTES, tag_ck)) { std::fprintf(stderr, "[2] HMAC(c_k) @SGN\n"); return EXIT_FAILURE; }
        auto t3 = clock::now();
        t_hmac_ck += us_since(t2,t3);
        print_hex("[SGN] HMAC(c_k)", tag_ck, HMAC_TAG_LEN);

        // --- Print a_SGN once ct is available ---
        {
            uint8_t tmp2[sizeof(CERT_SGN) + KYBER_INDCPA_BYTES];
            size_t off2 = 0;
            std::memcpy(tmp2 + off2, CERT_SGN, sizeof(CERT_SGN)); off2 += sizeof(CERT_SGN);
            std::memcpy(tmp2 + off2, c_k, KYBER_INDCPA_BYTES);
            uint8_t a_sgn[32];
            sha3_256_bytes(tmp2, off2 + KYBER_INDCPA_BYTES, a_sgn);
            print_hex("[SGN] a_SGN = SHA3-256(CERT_SGN||ct)", a_sgn, 32);
        }

        // Decaps
        auto t4 = clock::now();
        indcpa_dec_gpu(c_k, msg1, kr_dec);
        gpu_sync_or_die("Kyber dec");
        auto t5 = clock::now();
        t_kyber_dec += us_since(t4,t5);

        // SGS KDF
        uint8_t ss_dec[32];
    #if KYBER_FAKE_SS
        const uint8_t* m_src = msg_k;
    #else
        const uint8_t* m_src = msg1;
    #endif
        auto t6 = clock::now();
        if (!sha3_256_bytes(m_src, KYBER_INDCPA_MSGBYTES, ss_dec)) { std::fprintf(stderr, "[2] SHA3-256(m_src)\n"); return EXIT_FAILURE; }
        uint8_t k_local_dec[AES_KEY_LEN];
        if (!sha3_256_bytes(ss_dec, sizeof ss_dec, k_local_dec)) { std::fprintf(stderr, "[2] SHA3-256(ss_dec)\n"); return EXIT_FAILURE; }
        auto t7 = clock::now();
        t_kdf_sgs += us_since(t6,t7);
        print_hex("[SGS] ss=SHA3-256(m')", ss_dec, sizeof ss_dec);
        print_hex("[SGS] k_local", k_local_dec, AES_KEY_LEN);

        // Verify HMAC(c_k)
        auto t8 = clock::now();
        bool ok = verify_hmac_tag(k_local_dec, AES_KEY_LEN, c_k, KYBER_INDCPA_BYTES, tag_ck);
        auto t9 = clock::now();
        t_hmac_ck_ver += us_since(t8,t9);
        if (!ok) { std::fprintf(stderr, "[2] HMAC(c_k) verify @SGS failed\n"); return EXIT_FAILURE; }
        std::printf("[2] OK\n");

        // -------------------------------------------------------------------
        // [2b] SGN challenge m_rSGN + σ_SGN; SGS verifies
        // -------------------------------------------------------------------
        std::printf("[2b] SGN challenge + signature; SGS verifies\n");

        uint8_t r_SGN[NONCE_LEN];
        auto t10 = clock::now();
        if (RAND_bytes(r_SGN, sizeof r_SGN) != 1) { std::fprintf(stderr, "[2b] RAND r_SGN\n"); return EXIT_FAILURE; }
        auto t11 = clock::now();
        t_rand_r += us_since(t10,t11);
        print_hex("[SGN] r_SGN", r_SGN, sizeof r_SGN);

        uint8_t iv2[IV_LEN];
        auto t12 = clock::now();
        if (RAND_bytes(iv2, sizeof iv2) != 1) { std::fprintf(stderr, "[2b] RAND iv2\n"); return EXIT_FAILURE; }
        auto t13 = clock::now();
        t_rand_iv_mr += us_since(t12,t13);

        uint8_t mr_ct[128];
        auto t14 = clock::now();
        int mr_ct_len = aes256_cbc_encrypt(k_local_enc, iv2, r_SGN, (int)sizeof r_SGN, mr_ct, (int)sizeof mr_ct);
        auto t15 = clock::now();
        t_aes_mr_enc += us_since(t14,t15);
        if (mr_ct_len <= 0) { std::fprintf(stderr, "[2b] AES enc r_SGN\n"); return EXIT_FAILURE; }

        uint8_t mr_wire[IV_LEN + 128];
        std::memcpy(mr_wire, iv2, IV_LEN);
        std::memcpy(mr_wire + IV_LEN, mr_ct, mr_ct_len);
        const int mr_wire_len = IV_LEN + mr_ct_len;
        print_hex("[SGN] m_rSGN (iv||ct)", mr_wire, mr_wire_len);

        uint8_t hm2[HMAC_TAG_LEN];
        auto t16 = clock::now();
        if (!hmac_sha256_bytes(k_local_enc, AES_KEY_LEN, mr_wire, mr_wire_len, hm2)) { std::fprintf(stderr, "[2b] HMAC(m_rSGN) @SGN\n"); return EXIT_FAILURE; }
        auto t17 = clock::now();
        t_hmac_mr += us_since(t16,t17);
        print_hex("[SGN] HMAC(m_rSGN)", hm2, HMAC_TAG_LEN);

        // σ_SGN over (CERT_SGN || ct): fill digests and sign/verify on GPU
        fill_digest_messages(h_m1, CERT_SGN, sizeof(CERT_SGN),
                             c_k, KYBER_INDCPA_BYTES);

        {
            auto tx0 = clock::now();
            crypto_sign(h_sm2, h_m1);
            gpu_sync_or_die("Falcon sign #2");
            auto tx1 = clock::now();
            t_sig2 += us_since(tx0,tx1);
            std::printf("[TIMING] Falcon sign #2: %.1f us\n", us_since(tx0,tx1));
        }

        auto t18 = clock::now();
        bool ok2 = verify_hmac_tag(k_local_dec, AES_KEY_LEN, mr_wire, mr_wire_len, hm2);
        auto t19 = clock::now();
        t_hmac_mr_ver += us_since(t18,t19);
        if (!ok2) { std::fprintf(stderr, "[2b] HMAC(m_rSGN) verify @SGS failed\n"); return EXIT_FAILURE; }
        std::printf("[2b] OK: HMAC(m_rSGN)\n");

        uint8_t r_buf[64], r_SGN_rx[NONCE_LEN];
        auto t20 = clock::now();
        int r_pt_len = aes256_cbc_decrypt(k_local_dec, mr_wire, mr_wire + IV_LEN, mr_wire_len - IV_LEN,
                                          r_buf, (int)sizeof r_buf);
        auto t21 = clock::now();
        t_aes_mr_dec += us_since(t20,t21);
        if (r_pt_len != (int)sizeof r_SGN_rx) { std::fprintf(stderr, "[2b] AES dec r_SGN @SGS\n"); return EXIT_FAILURE; }
        std::memcpy(r_SGN_rx, r_buf, sizeof r_SGN_rx);
        print_hex("[SGS] r_SGN'", r_SGN_rx, sizeof r_SGN_rx);
        if (CRYPTO_memcmp(r_SGN_rx, r_SGN, sizeof r_SGN) != 0) {
            std::fprintf(stderr, "[2b] r_SGN mismatch\n");
            return EXIT_FAILURE;
        }

        {
            auto ty0 = clock::now();
            crypto_ver(h_sm2, h_m1, h_m2_sgn);
            gpu_sync_or_die("Falcon verify #2");
            auto ty1 = clock::now();
            t_ver2 += us_since(ty0,ty1);
            std::printf("[TIMING] Falcon verify #2: %.1f us\n", us_since(ty0,ty1));
        }
        if (!check_signatures(h_m1, h_m2_sgn)) { std::fprintf(stderr, "[2b] Falcon verify (SGN->SGS) failed\n"); return EXIT_FAILURE; }
        std::printf("[2b] OK\n");

        // -------------------------------------------------------------------
        // [3/4] SGS builds y = Enc_{k_local}(K_sym || r_SGN || T || ID) and HMACs
        // -------------------------------------------------------------------
        std::printf("[3/4] SGS sends y (AES-256-CBC + HMAC over IV||CT)\n");

        uint8_t K_sym[32];
        auto tz0 = clock::now();
        if (RAND_bytes(K_sym, sizeof K_sym) != 1) { std::fprintf(stderr, "[3/4] RAND K_sym\n"); return EXIT_FAILURE; }
        auto tz1 = clock::now();
        t_rand_k += us_since(tz0,tz1);
        print_hex("[SGS] K_sym", K_sym, sizeof K_sym);

        // Echo r_SGN in y
        print_hex("[SGS] Echo r_SGN in y", r_SGN, sizeof r_SGN);

        time_t now_ts = std::time(nullptr);
        const char* id_str = "Server123";
        const size_t id_len = std::strlen(id_str);

        uint8_t y_plain[1024];
        size_t  y_plain_len = 0;
        std::memcpy(y_plain + y_plain_len, K_sym, sizeof K_sym); y_plain_len += sizeof K_sym;
        std::memcpy(y_plain + y_plain_len, r_SGN, sizeof r_SGN); y_plain_len += sizeof r_SGN;
        std::memcpy(y_plain + y_plain_len, &now_ts, sizeof(now_ts));   y_plain_len += sizeof(now_ts);
        std::memcpy(y_plain + y_plain_len, id_str, id_len);            y_plain_len += id_len;

        uint8_t iv[IV_LEN];
    #ifdef CBC_ZERO_IV
        std::memset(iv, 0, sizeof iv);
    #else
        auto tz4 = clock::now();
        if (RAND_bytes(iv, sizeof iv) != 1) { std::fprintf(stderr, "[3/4] RAND iv\n"); return EXIT_FAILURE; }
        auto tz5 = clock::now();
        t_rand_iv_y += us_since(tz4,tz5);
    #endif

        auto tz6 = clock::now();
        int y_ct_len = aes256_cbc_encrypt(k_local_dec, iv, y_plain, (int)y_plain_len, c_y, 4096);
        auto tz7 = clock::now();
        t_aes_y_enc += us_since(tz6,tz7);
        if (y_ct_len <= 0) { std::fprintf(stderr, "[3/4] AES enc y\n"); return EXIT_FAILURE; }

        std::memmove(c_y + IV_LEN, c_y, y_ct_len);
        std::memcpy(c_y, iv, IV_LEN);
        const int y_wire_len = IV_LEN + y_ct_len;
        print_hex("[SGS] y (iv||ct)", c_y, y_wire_len);

        uint8_t tag_y[HMAC_TAG_LEN];
        auto tz8 = clock::now();
        if (!hmac_sha256_bytes(k_local_dec, AES_KEY_LEN, c_y, (size_t)y_wire_len, tag_y)) { std::fprintf(stderr, "[3/4] HMAC(y) @SGS\n"); return EXIT_FAILURE; }
        auto tz9 = clock::now();
        t_hmac_y += us_since(tz8,tz9);
        print_hex("[SGS] HMAC(y)", tag_y, HMAC_TAG_LEN);

        auto ta0 = clock::now();
        bool oky = verify_hmac_tag(k_local_enc, AES_KEY_LEN, c_y, (size_t)y_wire_len, tag_y);
        auto ta1 = clock::now();
        t_hmac_y_ver += us_since(ta0,ta1);
        if (!oky) { std::fprintf(stderr, "[SGN] HMAC(y) verify failed\n"); return EXIT_FAILURE; }
        std::printf("[SGN] OK: HMAC(y)\n");

        const uint8_t* iv_rx = c_y;
        const uint8_t* ct_rx = c_y + IV_LEN;
        const int      ct_rx_len = y_wire_len - IV_LEN;

        uint8_t y_dec[2048];
        auto ta2 = clock::now();
        int y_pt_len = aes256_cbc_decrypt(k_local_enc, iv_rx, ct_rx, ct_rx_len, y_dec, (int)sizeof(y_dec));
        auto ta3 = clock::now();
        t_aes_y_dec += us_since(ta2,ta3);
        if (y_pt_len <= 0) { std::fprintf(stderr, "[SGN] AES dec y\n"); return EXIT_FAILURE; }

        size_t off = 0;
        uint8_t  K_sym_rx[32];
        uint8_t  nonce_rx[NONCE_LEN];
        time_t   T_rx;
        std::memcpy(K_sym_rx, y_dec + off, sizeof(K_sym_rx)); off += sizeof(K_sym_rx);
        std::memcpy(nonce_rx,  y_dec + off, sizeof(nonce_rx)); off += sizeof(nonce_rx);
        std::memcpy(&T_rx,     y_dec + off, sizeof(T_rx));     off += sizeof(T_rx);
        const char* id_rx = (const char*)(y_dec + off);
        size_t id_rx_len = (size_t)y_pt_len - off;

        print_hex("[SGN] K_sym'", K_sym_rx, sizeof K_sym_rx);
        print_hex("[SGN] r_SGN' (from y)", nonce_rx, sizeof nonce_rx);
        std::printf("[SGN] Time: %s", std::ctime(&T_rx));
        std::printf("[SGN] ID: %.*s\n", (int)id_rx_len, id_rx);

        if (CRYPTO_memcmp(nonce_rx, r_SGN, NONCE_LEN) != 0) { std::fprintf(stderr, "[SGN] r_SGN echo mismatch\n"); return EXIT_FAILURE; }
        if ((id_rx_len != std::strlen(id_str)) || std::memcmp(id_str, id_rx, id_rx_len) != 0) { std::fprintf(stderr, "[SGN] ID mismatch\n"); return EXIT_FAILURE; }

        OPENSSL_cleanse(K_sym, sizeof K_sym);
    } // step 2..4 block

    auto t_total1 = clock::now();

    // ----- Timing Summary (us) -----
    std::printf("\n[GPU Harness] Timing Summary (us)\n");
    std::printf("  CA sign (GSM cert body):           %.1f\n", t_ca_gsm_sign);
    std::printf("  CA verify (GSM):                    %.1f\n", t_ca_gsm_ver);
    std::printf("  CA sign (SGN cert body):           %.1f\n", t_ca_sgn_sign);
    std::printf("  CA verify (SGN):                    %.1f\n", t_ca_sgn_ver);
    std::printf("  Falcon sign #1 (σ_GSM):             %.1f\n", t_sig1);
    std::printf("  Falcon verify #1:                    %.1f\n", t_ver1);
    std::printf("  Kyber encaps (GPU):                  %.1f\n", t_kyber_enc);
    std::printf("  k_local @SGN (SHA3):                 %.1f\n", t_kdf_sgn);
    std::printf("  HMAC(c_k) @SGN:                      %.1f\n", t_hmac_ck);
    std::printf("  Kyber decaps (GPU):                  %.1f\n", t_kyber_dec);
    std::printf("  KDF k_local @SGS (SHA3):             %.1f\n", t_kdf_sgs);
    std::printf("  Verify HMAC(c_k) @SGS:               %.1f\n", t_hmac_ck_ver);
    std::printf("  RAND r_SGN:                          %.1f\n", t_rand_r);
    std::printf("  RAND iv (m_rSGN):                    %.1f\n", t_rand_iv_mr);
    std::printf("  AES-256-CBC enc m_rSGN:              %.1f\n", t_aes_mr_enc);
    std::printf("  HMAC(m_rSGN) @SGN:                   %.1f\n", t_hmac_mr);
    std::printf("  Verify HMAC(m_rSGN) @SGS:            %.1f\n", t_hmac_mr_ver);
    std::printf("  AES-256-CBC dec m_rSGN:              %.1f\n", t_aes_mr_dec);
    std::printf("  Falcon sign #2 (σ_SGN):              %.1f\n", t_sig2);
    std::printf("  Falcon verify #2:                    %.1f\n", t_ver2);
    std::printf("  RAND K_sym:                          %.1f\n", t_rand_k);
    std::printf("  RAND iv (y):                         %.1f\n", t_rand_iv_y);
    std::printf("  AES-256-CBC enc y:                   %.1f\n", t_aes_y_enc);
    std::printf("  HMAC(y) @SGS:                        %.1f\n", t_hmac_y);
    std::printf("  Verify HMAC(y) @SGN:                 %.1f\n", t_hmac_y_ver);
    std::printf("  AES-256-CBC dec y:                   %.1f\n", t_aes_y_dec);
    std::printf("  TOTAL (end-to-end, no I/O):          %.1f\n\n", us_since(t_total0, t_total1));

    //--------------------------------------------------------------------------//

    // ---- Per-role totals (us) ----
    double sgn_total_us =
          t_ver1 + t_kyber_enc + t_kdf_sgn + t_sig2 +
          t_rand_r + t_rand_iv_mr + t_aes_mr_enc + t_hmac_mr +
          t_hmac_y_ver + t_aes_y_dec;

    double gsm_total_us =
          t_sig1 + t_kyber_dec + t_kdf_sgs + t_hmac_ck_ver +
          t_hmac_mr_ver + t_aes_mr_dec + t_ver2 +
          t_rand_k + t_rand_iv_y + t_aes_y_enc + t_hmac_y;

    double ca_total_us = t_ca_gsm_sign + t_ca_gsm_ver + t_ca_sgn_sign + t_ca_sgn_ver;

    std::printf("[GPU Harness] Per-role Totals (us)\n");
    std::printf("  SGN-side total:                      %.1f\n", sgn_total_us);
    std::printf("  GSM-side total:                      %.1f\n", gsm_total_us);
    std::printf("  CA (offline) total:                  %.1f\n\n", ca_total_us);


    // Cleanup
    cudaFreeHost(h_sm);    cudaFreeHost(h_m1);    cudaFreeHost(h_m2);
    cudaFreeHost(h_sm2);   cudaFreeHost(h_m2_sgn);
    cudaFreeHost(c_k);     cudaFreeHost(msg_k);   cudaFreeHost(pk_k); cudaFreeHost(coins);
    cudaFreeHost(msg1);    cudaFreeHost(c_y);     cudaFreeHost(kr_enc); cudaFreeHost(kr_dec);
    cudaFreeHost(h_sm_ca); cudaFreeHost(h_m_ca);  cudaFreeHost(h_m_ca_ver);
    return 0;
}
