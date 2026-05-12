/*
 * AmphiKey Deniable Mode + ANSI C12.22 — Sender (Client/Smart Meter)
 
 * AEAD: Ascon-128 (NIST LWCA standard).
 *   API: crypto_aead_encrypt / crypto_aead_decrypt  (aead.c)
 *   Key: 16 B  |  Nonce: 16 B  |  Tag: 16 B (appended to ciphertext)
 *
 * Per-operation execution timing on every crypto step.
 *
 * USAGE: ./sender_c1222 <ip_address> <port>
 */

#include <MCORE/MCOREExtern.h>
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <fstream>
#include <stdexcept>
#include <cstring>
#include <time.h>

extern "C" {
    #include <sodium.h>
    #include "api_mlkem.h"
    /* Ascon-128 NIST LWCA one-shot API */
    #include "api.h"          /* CRYPTO_KEYBYTES=16, CRYPTO_NPUBBYTES=16, CRYPTO_ABYTES=16 */
    int crypto_aead_encrypt(unsigned char *c,  unsigned long long *clen,
                            const unsigned char *m,   unsigned long long mlen,
                            const unsigned char *ad,  unsigned long long adlen,
                            const unsigned char *nsec,
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
#define SERVER_HELLO_BYTES       (1184 + 32 + NONCE_RS_BYTES + 1)  /* 1233 */

/* Ascon-128 fixed sizes (NIST LWCA — always 16 bytes each) */
#define ASCON_KEY_BYTES   16
#define ASCON_NONCE_BYTES 16
#define ASCON_TAG_BYTES   16

#ifndef PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES
#define PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES  1184
#endif
#ifndef PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES 1088
#endif
#ifndef PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES
#define PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES           32
#endif

/* ── HKDF-SHA256 (libsodium) ─────────────────────────────────────────── */
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

static int dhkem_encap(unsigned char c2[32], unsigned char k2[32],
                       const unsigned char pkr[32]) {
    unsigned char sk_eph[32], pk_eph[32], dh[32], ikm[96], prk[32];
    randombytes_buf(sk_eph, 32);
    crypto_scalarmult_base(pk_eph, sk_eph);
    if (crypto_scalarmult(dh, sk_eph, pkr) != 0) {
        sodium_memzero(sk_eph, 32); return -1;
    }
    memcpy(ikm,    dh,     32);
    memcpy(ikm+32, pk_eph, 32);
    memcpy(ikm+64, pkr,    32);
    hkdf_extract(prk, ikm, 96);
    hkdf_expand(k2, 32, prk, 32,
                reinterpret_cast<const unsigned char*>(AMPHIKEY_DHKEM_INFO),
                strlen(AMPHIKEY_DHKEM_INFO));
    memcpy(c2, pk_eph, 32);
    sodium_memzero(sk_eph,32); sodium_memzero(dh,32);
    sodium_memzero(ikm,96);    sodium_memzero(prk,32);
    return 0;
}

static std::string read_last_line(const char *filename) {
    std::ifstream file(filename);
    if (!file) return "";
    std::string line, last;
    while (std::getline(file, line))
        if (!line.empty()) last = line;
    return last;
}

/* ─────────────────────────────────────────────────────────────────────── */
int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "USAGE: " << argv[0] << " <ip_address> <port>\n";
        return 1;
    }
    if (sodium_init() < 0) { std::cerr << "Libsodium failed\n"; return 1; }

    std::string meter_data = read_last_line("/home/kazi/CPE_code/Smart_meter_data.csv");
    if (meter_data.empty()) { std::cerr << "Failed to read meter data\n"; return 1; }
    std::cout << "Meter data (" << meter_data.size() << " bytes): "
              << meter_data.substr(0, 60) << "...\n\n";

    try {
        TimerAcc T;

        /* ── TCP connect ── */
        MChannelSocket channel;
        channel.SetPeerAddress(argv[1]);
        channel.SetPeerPort(static_cast<unsigned>(std::stoi(argv[2])));
        std::cout << "Connecting to " << argv[1] << ":" << argv[2] << "...\n";
        T.start(); channel.Connect(); T.stop("TCP Connect");
        std::cout << "\n";

        /* ── Step 0: Receive Server Hello ── */
        std::cout << "── Step 0: Receive Server Hello ──────────────────────\n";
        T.start();
        MByteString hello_raw = channel.ReadBytes(SERVER_HELLO_BYTES);
        T.stop("Network: Recv Server Hello");

        const unsigned char *hp =
            reinterpret_cast<const unsigned char*>(hello_raw.data());
        unsigned char pkr1_mlkem[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
        unsigned char pkr2_x25519[32], rs[NONCE_RS_BYTES];
        unsigned char mode_rcvd;
        memcpy(pkr1_mlkem,  hp,                         1184);
        memcpy(pkr2_x25519, hp+1184,                    32);
        memcpy(rs,           hp+1184+32,                 NONCE_RS_BYTES);
        mode_rcvd =          hp[1184+32+NONCE_RS_BYTES];
        std::cout << "  MODE=0x" << std::hex << (int)mode_rcvd
                  << std::dec << " (Deniable=0x00)\n\n";
        if (mode_rcvd != AMPHIKEY_MODE_DENIABLE) {
            std::cerr << "MODE mismatch — aborting\n"; return 1;
        }

        /* ── Step 2A: ML-KEM-768 Encapsulation ── */
        std::cout << "── Step 2A: ML-KEM-768 Encapsulation ────────────────\n";
        unsigned char c1[PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES];
        unsigned char k1[PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES];
        T.start();
        if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(c1, k1, pkr1_mlkem) != 0) {
            std::cerr << "ML-KEM encap failed\n"; return 1;
        }
        T.stop("ML-KEM-768 Enc");
        std::cout << "\n";

        /* ── Step 2B: DHKEM(X25519) Encapsulation ── */
        std::cout << "── Step 2B: DHKEM(X25519) Encapsulation ─────────────\n";
        unsigned char c2[32], k2[32];
        T.start();
        if (dhkem_encap(c2, k2, pkr2_x25519) != 0) {
            std::cerr << "DHKEM encap failed\n"; return 1;
        }
        T.stop("DHKEM(X25519) Enc");
        std::cout << "\n";

        /* c = c1 ‖ c2 */
        const size_t c_len = sizeof(c1) + 32;
        unsigned char c[PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES + 32];
        memcpy(c,          c1, sizeof(c1));
        memcpy(c+sizeof(c1), c2, 32);

        /* ── Step 2C: HKDF kauth ── */
        std::cout << "── Step 2C: HKDF kauth Derivation ───────────────────\n";
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
        std::cout << "\n";

        /* ── Step 2D: HMAC-SHA256 tag ── */
        std::cout << "── Step 2D: HMAC-SHA256 Tag Generation ──────────────\n";
        unsigned char mode = AMPHIKEY_MODE_DENIABLE;
        size_t tmsg_len = c_len + NONCE_RS_BYTES + 1;
        std::vector<unsigned char> tmsg(tmsg_len);
        memcpy(tmsg.data(),          c,   c_len);
        memcpy(tmsg.data()+c_len,    rs,  NONCE_RS_BYTES);
        tmsg[c_len+NONCE_RS_BYTES] = mode;
        unsigned char tag[crypto_auth_hmacsha256_BYTES];
        T.start();
        crypto_auth_hmacsha256(tag, tmsg.data(), tmsg_len, kauth);
        T.stop("HMAC-SHA256 tag");
        std::cout << "\n";

        /* ── Step 2E: HKDF ksh ── */
        std::cout << "── Step 2E: HKDF ksh Derivation ─────────────────────\n";
        unsigned char ksh[32];
        T.start();
        {
            size_t ikm_len = 32+32+c_len+NONCE_RS_BYTES+1184+32+1;
            std::vector<unsigned char> ikm(ikm_len);
            unsigned char *p = ikm.data();
            memcpy(p,k1,32);          p+=32;
            memcpy(p,k2,32);          p+=32;
            memcpy(p,c,c_len);        p+=c_len;
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

        /* ── Step 2F: Ascon-128 AEAD Encrypt ── */
        std::cout << "── Step 2F: Ascon-128 AEAD Encrypt ──────────────────\n";
        unsigned char ascon_key[ASCON_KEY_BYTES];
        unsigned char ascon_nonce[ASCON_NONCE_BYTES];
        memcpy(ascon_key, ksh, ASCON_KEY_BYTES);
        randombytes(ascon_nonce, ASCON_NONCE_BYTES);

        /* crypto_aead_encrypt appends CRYPTO_ABYTES (16B) tag to ciphertext */
        size_t pt_len = meter_data.size();
        std::vector<unsigned char> ct(pt_len + ASCON_TAG_BYTES);
        unsigned long long ct_actual_len = 0;

        T.start();
        if (crypto_aead_encrypt(
                ct.data(), &ct_actual_len,
                reinterpret_cast<const unsigned char*>(meter_data.data()), pt_len,
                nullptr, 0,   /* no additional data */
                nullptr,      /* nsec unused */
                ascon_nonce, ascon_key) != 0) {
            std::cerr << "Ascon-128 encrypt failed\n"; return 1;
        }
        T.stop("Ascon-128 AEAD Enc");
        std::cout << "  Plaintext: " << pt_len << " B  →  Ciphertext+tag: "
                  << ct_actual_len << " B  (tag=" << ASCON_TAG_BYTES << " B)\n\n";

        /* ── Step 3: Build and send wire frame ── */
        std::cout << "── Step 3: Send AmphiKey Frame ───────────────────────\n";
        /*
         * Wire frame:
         *   c      (1120 B) — ML-KEM + DHKEM ciphertexts
         *   tag    (  32 B) — HMAC-SHA256 authentication tag
         *   nonce  (  16 B) — Ascon-128 nonce
         *   ct_len (   4 B) — big-endian uint32 length of ciphertext+tag
         *   ct+tag (ct_actual_len B) — Ascon ciphertext with tag appended
         */
        uint32_t ct_len_be = static_cast<uint32_t>(ct_actual_len);
        MByteString frame;
        frame.reserve(c_len + 32 + ASCON_NONCE_BYTES + 4 + ct_actual_len);
        frame.append(reinterpret_cast<const char*>(c),           c_len);
        frame.append(reinterpret_cast<const char*>(tag),         32);
        frame.append(reinterpret_cast<const char*>(ascon_nonce), ASCON_NONCE_BYTES);
        char len_buf[4];
        len_buf[0]=(ct_len_be>>24)&0xFF; len_buf[1]=(ct_len_be>>16)&0xFF;
        len_buf[2]=(ct_len_be>>8)&0xFF;  len_buf[3]=(ct_len_be)&0xFF;
        frame.append(len_buf, 4);
        frame.append(reinterpret_cast<const char*>(ct.data()), ct_actual_len);

        T.start(); channel.WriteBytes(frame); T.stop("Network: Send Frame");

        std::cout << "\n  Frame composition:\n"
                  << "    c (ML-KEM+DHKEM):     " << c_len         << " bytes\n"
                  << "    HMAC tag:              32 bytes\n"
                  << "    Ascon nonce:           " << ASCON_NONCE_BYTES << " bytes\n"
                  << "    ct+tag (Ascon-128):    " << ct_actual_len << " bytes\n"
                  << "    TOTAL:                 " << frame.size()  << " bytes\n\n";

        /* ── Summary ── */
        std::cout << "══════════════════════════════════════════════════════\n";
        std::cout << "SENDER TIMING SUMMARY (single run)\n";
        std::cout << "══════════════════════════════════════════════════════\n";
        std::cout << "  Total measured time: " << total_crypto_ns/1000 << " µs\n";
        std::cout << "  (For 1000-iter averages, run ./deny_sender_bench)\n";
        std::cout << "══════════════════════════════════════════════════════\n";

        channel.Disconnect();
        sodium_memzero(k1,32); sodium_memzero(k2,32);
        sodium_memzero(kauth,32); sodium_memzero(ksh,32);
        sodium_memzero(ascon_key, sizeof(ascon_key));
    }
    catch (const MException& e) {
        std::cerr << "MCOM error: " << e.AsString() << "\n"; return 1;
    }
    catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n"; return 1;
    }
    return 0;
}
