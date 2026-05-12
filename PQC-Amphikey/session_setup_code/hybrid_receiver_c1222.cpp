/*
 * AmphiKey Deniable Mode + ANSI C12.22 — Receiver (Server/SCADA)
 
 * AEAD: Ascon-128 (NIST LWCA standard).
 *   API: crypto_aead_encrypt / crypto_aead_decrypt  (aead.c)
 *   Key: 16 B  |  Nonce: 16 B  |  Tag: 16 B (appended to ciphertext)
 *
 * Per-operation execution timing on every crypto step.
 *
 * USAGE: ./receiver_c1222 <port>
 */

#include <MCORE/MCOREExtern.h>
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <stdexcept>
#include <cstring>
#include <time.h>

extern "C" {
    #include <sodium.h>
    #include "api_mlkem.h"
    /* Ascon-128 NIST LWCA one-shot API */
    #include "api.h"
    int crypto_aead_decrypt(unsigned char *m,  unsigned long long *mlen,
                            unsigned char *nsec,
                            const unsigned char *c,   unsigned long long clen,
                            const unsigned char *ad,  unsigned long long adlen,
                            const unsigned char *npub,
                            const unsigned char *k);
    void nist_randombytes_init(unsigned char *entropy_input,
                               unsigned char *personalization_string,
                               int security_strength);
    void randombytes(unsigned char *x, unsigned long long xlen);
}

#include <MCOM/ChannelSocket.h>
#include <MCOM/MCOMExceptions.h>

extern "C" void PQCLEAN_randombytes(unsigned char *buf, size_t nbytes) {
    randombytes(buf, static_cast<unsigned long long>(nbytes));
}

/* ── Timing ──────────────────────────────────────────────────────────── */
#if defined(__i386__) || defined(__x86_64__)
static inline unsigned long long rdtsc_cpp() {
    unsigned int lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((unsigned long long)hi << 32) | lo;
}
#else
static inline unsigned long long rdtsc_cpp() { return 0; }
#endif

static long long total_crypto_ns = 0;

struct TimerAcc {
    struct timespec t0; unsigned long long c0;
    void start() { clock_gettime(CLOCK_MONOTONIC, &t0); c0 = rdtsc_cpp(); }
    void stop(const std::string& label) {
        unsigned long long c1 = rdtsc_cpp();
        struct timespec t1; clock_gettime(CLOCK_MONOTONIC, &t1);
        long long ns = (t1.tv_sec-t0.tv_sec)*1000000000LL+(t1.tv_nsec-t0.tv_nsec);
        unsigned long long cy = (c1 > c0) ? c1-c0 : 0;
        std::cout << "  [TIME] " << std::left << std::setw(32) << label
                  << std::right << std::setw(8) << ns/1000 << " µs"
                  << "  (" << cy << " cycles)\n";
        total_crypto_ns += ns;
    }
};

/* ── AmphiKey constants ──────────────────────────────────────────────── */
#define AMPHIKEY_MODE_DENIABLE   ((unsigned char)0x00)
#define AMPHIKEY_DHKEM_INFO      "AmphiKey-DHKEM-v1"
#define AMPHIKEY_KAUTH_INFO      "auth"
#define NONCE_RS_BYTES           16
#define SERVER_HELLO_BYTES       (1184 + 32 + NONCE_RS_BYTES + 1)

/* Ascon-128 fixed sizes (NIST LWCA — always 16 bytes each) */
#define ASCON_KEY_BYTES   16
#define ASCON_NONCE_BYTES 16
#define ASCON_TAG_BYTES   16

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

/* ── HKDF-SHA256 ─────────────────────────────────────────────────────── */
static void hkdf_extract(unsigned char *prk,
                         const unsigned char *ikm, size_t ikm_len) {
    unsigned char zero[crypto_auth_hmacsha256_KEYBYTES] = {0};
    crypto_auth_hmacsha256(prk, ikm, ikm_len, zero);
}
static void hkdf_expand(unsigned char *okm, size_t okm_len,
                        const unsigned char *prk, size_t prk_len,
                        const unsigned char *info, size_t info_len) {
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
}

static int dhkem_decap(unsigned char k2[32],
                       const unsigned char c2[32],
                       const unsigned char sk_recv[32],
                       const unsigned char pk_recv[32]) {
    unsigned char dh[32], ikm[96], prk[32];
    if (crypto_scalarmult(dh, sk_recv, c2) != 0) return -1;
    memcpy(ikm,    dh,      32);
    memcpy(ikm+32, c2,      32);
    memcpy(ikm+64, pk_recv, 32);
    hkdf_extract(prk, ikm, 96);
    hkdf_expand(k2, 32, prk, 32,
                reinterpret_cast<const unsigned char*>(AMPHIKEY_DHKEM_INFO),
                strlen(AMPHIKEY_DHKEM_INFO));
    sodium_memzero(dh,32); sodium_memzero(ikm,96); sodium_memzero(prk,32);
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────── */
int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "USAGE: " << argv[0] << " <port>\n"; return 1;
    }
    if (sodium_init() < 0) { std::cerr << "Libsodium failed\n"; return 1; }

    try {
        TimerAcc T;

        /* ── Step 1A: Ephemeral KEM KeyGen ── */
        std::cout << "── Step 1A: Ephemeral KEM KeyGen ─────────────────────\n";
        unsigned char skr1_mlkem[PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES];
        unsigned char pkr1_mlkem[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
        T.start();
        PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pkr1_mlkem, skr1_mlkem);
        T.stop("ML-KEM-768 KeyGen");

        unsigned char skr2_x25519[32], pkr2_x25519[32];
        T.start();
        randombytes_buf(skr2_x25519, 32);
        crypto_scalarmult_base(pkr2_x25519, skr2_x25519);
        T.stop("X25519-DHKEM KeyGen");

        unsigned char rs[NONCE_RS_BYTES];
        T.start();
        randombytes_buf(rs, NONCE_RS_BYTES);
        T.stop("Session nonce rs");
        std::cout << "\n";

        /* ── TCP listen + accept ── */
        MChannelSocket channel;
        channel.SetAutoAnswer(true);
        channel.SetAutoAnswerPort(static_cast<unsigned>(std::stoi(argv[1])));
        std::cout << "Listening on port " << argv[1] << "...\n";
        T.start(); channel.Connect(); T.stop("TCP Accept (blocking)");
        std::cout << "  Client connected.\n\n";

        /* ── Step 1B: Send Server Hello ── */
        std::cout << "── Step 1B: Send Server Hello ────────────────────────\n";
        MByteString hello;
        hello.reserve(SERVER_HELLO_BYTES);
        hello.append(reinterpret_cast<const char*>(pkr1_mlkem),  1184);
        hello.append(reinterpret_cast<const char*>(pkr2_x25519),   32);
        hello.append(reinterpret_cast<const char*>(rs), NONCE_RS_BYTES);
        hello.push_back(static_cast<char>(AMPHIKEY_MODE_DENIABLE));
        T.start(); channel.WriteBytes(hello); T.stop("Network: Send Server Hello");
        std::cout << "  pkr1(1184) + pkr2(32) + rs(16) + MODE(1) = "
                  << SERVER_HELLO_BYTES << " bytes\n\n";

        /* ── Step 3A: Receive client frame ── */
        std::cout << "── Step 3A: Receive Client Frame ─────────────────────\n";
        /* Header: c(1120) + hmac_tag(32) + ascon_nonce(16) + ct_len(4) */
        const size_t HDR = C_TOTAL_BYTES + 32 + ASCON_NONCE_BYTES + 4;
        T.start();
        MByteString hdr = channel.ReadBytes(HDR);
        T.stop("Network: Recv Frame Header");

        const unsigned char *hp =
            reinterpret_cast<const unsigned char*>(hdr.data());
        unsigned char c[C_TOTAL_BYTES];
        unsigned char hmac_tag[32];
        unsigned char ascon_nonce[ASCON_NONCE_BYTES];
        memcpy(c,          hp,                          C_TOTAL_BYTES);
        memcpy(hmac_tag,   hp+C_TOTAL_BYTES,            32);
        memcpy(ascon_nonce,hp+C_TOTAL_BYTES+32,         ASCON_NONCE_BYTES);
        uint32_t ct_len =
            ((unsigned char)hp[C_TOTAL_BYTES+32+ASCON_NONCE_BYTES+0]<<24) |
            ((unsigned char)hp[C_TOTAL_BYTES+32+ASCON_NONCE_BYTES+1]<<16) |
            ((unsigned char)hp[C_TOTAL_BYTES+32+ASCON_NONCE_BYTES+2]<<8)  |
            ((unsigned char)hp[C_TOTAL_BYTES+32+ASCON_NONCE_BYTES+3]);

        T.start();
        MByteString ct_raw = channel.ReadBytes(ct_len);
        T.stop("Network: Recv Ciphertext");
        std::cout << "  c(1120)+hmac_tag(32)+nonce(16)+len(4)+ct("
                  << ct_len << ") = " << (HDR+ct_len) << " bytes\n\n";

        /* ── Step 3B: ML-KEM-768 Decapsulation ── */
        std::cout << "── Step 3B: ML-KEM-768 Decapsulation ────────────────\n";
        const unsigned char *c1 = c;
        const unsigned char *c2 = c + PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES;
        unsigned char k1[PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES];
        T.start();
        if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(k1, c1, skr1_mlkem) != 0) {
            std::cerr << "ABORT: ML-KEM decap failed\n"; return 1;
        }
        T.stop("ML-KEM-768 Dec");
        std::cout << "\n";

        /* ── Step 3C: DHKEM(X25519) Decapsulation ── */
        std::cout << "── Step 3C: DHKEM(X25519) Decapsulation ─────────────\n";
        unsigned char k2[32];
        T.start();
        if (dhkem_decap(k2, c2, skr2_x25519, pkr2_x25519) != 0) {
            std::cerr << "ABORT: DHKEM decap failed\n"; return 1;
        }
        T.stop("DHKEM(X25519) Dec");
        std::cout << "\n";

        /* ── Step 3D: kauth + HMAC Verify ── */
        std::cout << "── Step 3D: kauth Derivation + HMAC Verify ──────────\n";
        unsigned char kauth[32];
        T.start();
        {
            unsigned char ikm[32+32+NONCE_RS_BYTES], prk[32];
            memcpy(ikm,    k1, 32);
            memcpy(ikm+32, k2, 32);
            memcpy(ikm+64, rs, NONCE_RS_BYTES);
            hkdf_extract(prk, ikm, sizeof(ikm));
            hkdf_expand(kauth, 32, prk, 32,
                reinterpret_cast<const unsigned char*>(AMPHIKEY_KAUTH_INFO),
                strlen(AMPHIKEY_KAUTH_INFO));
        }
        T.stop("HKDF kauth");

        unsigned char mode = AMPHIKEY_MODE_DENIABLE;
        size_t tmsg_len = C_TOTAL_BYTES + NONCE_RS_BYTES + 1;
        std::vector<unsigned char> tmsg(tmsg_len);
        memcpy(tmsg.data(),               c,  C_TOTAL_BYTES);
        memcpy(tmsg.data()+C_TOTAL_BYTES, rs, NONCE_RS_BYTES);
        tmsg[C_TOTAL_BYTES+NONCE_RS_BYTES] = mode;
        unsigned char tag_comp[crypto_auth_hmacsha256_BYTES];
        T.start();
        crypto_auth_hmacsha256(tag_comp, tmsg.data(), tmsg_len, kauth);
        T.stop("HMAC-SHA256 Verify");
        if (sodium_memcmp(tag_comp, hmac_tag, 32) != 0) {
            std::cerr << "PROTOCOL ABORT: HMAC tag FAILED\n"; return 1;
        }
        std::cout << "  ✓ HMAC tag VERIFIED\n\n";

        /* ── Step 3E: HKDF ksh ── */
        std::cout << "── Step 3E: HKDF ksh Derivation ─────────────────────\n";
        unsigned char ksh[32];
        T.start();
        {
            size_t ikm_len = 32+32+C_TOTAL_BYTES+NONCE_RS_BYTES+1184+32+1;
            std::vector<unsigned char> ikm(ikm_len);
            unsigned char *p = ikm.data();
            memcpy(p,k1,32);           p+=32;
            memcpy(p,k2,32);           p+=32;
            memcpy(p,c,C_TOTAL_BYTES); p+=C_TOTAL_BYTES;
            memcpy(p,rs,NONCE_RS_BYTES); p+=NONCE_RS_BYTES;
            memcpy(p,pkr1_mlkem,1184); p+=1184;
            memcpy(p,pkr2_x25519,32);  p+=32;
            *p = mode;
            unsigned char prk[32];
            hkdf_extract(prk, ikm.data(), ikm_len);
            hkdf_expand(ksh, 32, prk, 32,
                reinterpret_cast<const unsigned char*>("ksh"), 3);
        }
        T.stop("HKDF ksh");
        std::cout << "\n";

        /* ── Step 3F: Ascon-128 AEAD Decrypt ── */
        std::cout << "── Step 3F: Ascon-128 AEAD Decrypt ──────────────────\n";
        unsigned char ascon_key[ASCON_KEY_BYTES];
        memcpy(ascon_key, ksh, ASCON_KEY_BYTES);

        /* ct_raw = ciphertext ‖ 16-byte Ascon tag */
        std::vector<unsigned char> pt(ct_len);  /* output at most ct_len bytes */
        unsigned long long pt_actual_len = 0;
        const unsigned char *ct_ptr =
            reinterpret_cast<const unsigned char*>(ct_raw.data());

        T.start();
        int dec_ret = crypto_aead_decrypt(
            pt.data(), &pt_actual_len,
            nullptr,                     /* nsec unused */
            ct_ptr, ct_len,              /* ciphertext with appended tag */
            nullptr, 0,                  /* no additional data */
            ascon_nonce, ascon_key);
        T.stop("Ascon-128 AEAD Dec");

        if (dec_ret != 0) {
            std::cerr << "ABORT: Ascon-128 AEAD decryption/authentication FAILED\n";
            return 1;
        }
        std::cout << "  ✓ Ascon-128 AEAD tag VERIFIED\n\n";

        /* ── Print recovered meter data ── */
        std::string recovered(reinterpret_cast<const char*>(pt.data()), pt_actual_len);
        std::cout << "════════════════════════════════════════════════════════\n";
        std::cout << ">>> AMPHIKEY DENIABLE MODE: DECRYPTION SUCCESSFUL <<<\n";
        std::cout << "Recovered meter data (" << pt_actual_len << " bytes):\n";
        std::cout << recovered << "\n";
        std::cout << "════════════════════════════════════════════════════════\n\n";

        /* ── Wire frame summary ── */
        std::cout << "Wire frame:\n"
                  << "  Server Hello (sent):    " << SERVER_HELLO_BYTES << " bytes\n"
                  << "  Client frame (received): " << (HDR+ct_len) << " bytes\n"
                  << "    c(1120) + hmac_tag(32) + ascon_nonce(16) + len(4)"
                  << " + ascon_ct+tag(" << ct_len << ")\n\n";

        /* ── Timing summary ── */
        std::cout << "══════════════════════════════════════════════════════\n";
        std::cout << "RECEIVER TIMING SUMMARY (single run)\n";
        std::cout << "══════════════════════════════════════════════════════\n";
        std::cout << "  Total measured time: " << total_crypto_ns/1000 << " µs\n";
        std::cout << "  (For 1000-iter averages, run ./deny_receiver_bench)\n";
        std::cout << "══════════════════════════════════════════════════════\n";

        channel.Disconnect();
        sodium_memzero(skr1_mlkem,sizeof(skr1_mlkem));
        sodium_memzero(skr2_x25519,32);
        sodium_memzero(k1,32); sodium_memzero(k2,32);
        sodium_memzero(kauth,32); sodium_memzero(ksh,32);
        sodium_memzero(ascon_key,sizeof(ascon_key));
    }
    catch (const MException& e) {
        std::cerr << "MCOM error: " << e.AsString() << "\n"; return 1;
    }
    catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n"; return 1;
    }
    return 0;
}
