// server.c — updated protocol implementation (drop-in)
// Build:  gcc server.c ascon.c verify_certificate.c -lcrypto -lssl -o server
// Requires:
//   ./certs/ca_certificate.pem
//   ./certs/server_certificate.pem      (Ed25519 cert)
//   ./keys/server_sign_ed25519_priv.pem (Ed25519 signing key)
//   ./keys/server_x25519_priv.pem       (static X25519, PKCS#8 PEM)
// Wire messages use [len32 | bytes] framing for each field.
// AEAD: ASCON-128a with 16-byte nonce; we send nonce||ciphertext||tag (as 3 framed blobs).

#include "verify_certificate.h"
#include "ascon.h"

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/bn.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include <stdint.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define PORT 3000
#define BUF  4096

#define TAG_LEN    16
#define NONCE_LEN  16
#define FRESH_WINDOW_SEC 300  // accept timestamps within ±300 s (wider for testing)

#define CA_CERT_PATH      "./certs/ca_certificate.pem"
#define SERVER_CERT_PATH  "./certs/server_certificate.pem"
#define SERVER_SIGN_KEY   "./keys/server_sign_ed25519_priv.pem"   // Ed25519 (sign m2)
#define SERVER_X25519_KEY "./keys/server_x25519_priv.pem"         // static X25519

/* ------------------------ util ---------------------------------- */

static uint64_t htonll(uint64_t v) {
    return ((uint64_t)htonl((uint32_t)(v >> 32)) << 32) | htonl((uint32_t)v);
}
static uint64_t ntohll(uint64_t v) {
    return ((uint64_t)ntohl((uint32_t)(v >> 32)) << 32) | ntohl((uint32_t)v);
}

// fresh check in unsigned domain (avoids sign issues on some platforms)
static int ts_fresh_u64(uint64_t t_client) {
    uint64_t now = (uint64_t)time(NULL);
    uint64_t diff = (now >= t_client) ? (now - t_client) : (t_client - now);
    return diff <= (uint64_t)FRESH_WINDOW_SEC;
}

static int send_all(int fd, const void *buf, size_t len){
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, (const char*)buf + off, len - off, 0);
        if (n <= 0) return 0;
        off += (size_t)n;
    }
    return 1;
}

static int recv_all(int fd, void *buf, size_t len){
    size_t off = 0;
    while (off < len) {
        ssize_t n = recv(fd, (char*)buf + off, len - off, 0);
        if (n <= 0) return 0;
        off += (size_t)n;
    }
    return 1;
}

static int send_blob(int fd, const unsigned char *p, uint32_t len){
    uint32_t n = htonl(len);
    return send_all(fd, &n, 4) && (len ? send_all(fd, p, len) : 1);
}

static int recv_blob(int fd, unsigned char **out, uint32_t *outlen){
    uint32_t n;
    if (!recv_all(fd, &n, 4)) return 0;
    *outlen = ntohl(n);
    *out    = NULL;
    if (*outlen) {
        *out = (unsigned char*)malloc(*outlen);
        if (!*out) return 0;
        if (!recv_all(fd, *out, *outlen)) {
            free(*out); *out = NULL; return 0;
        }
    }
    return 1;
}

static void print_hex(const char *lab, const unsigned char *d, size_t l){
    printf("%s (%zu bytes): ", lab, l);
    for (size_t i=0;i<l;i++) printf("%02X", d[i]);
    printf("\n");
}

static int hkdf_sha256(const unsigned char *ikm, size_t ikm_len,
                       const unsigned char *info, size_t info_len,
                       unsigned char *okm, size_t okm_len){
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) return 0;
    int ok = EVP_PKEY_derive_init(pctx) > 0 &&
             EVP_PKEY_CTX_set_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND) > 0 &&
             EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) > 0 &&
             EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, ikm_len) > 0 &&
             EVP_PKEY_CTX_add1_hkdf_info(pctx, info, info_len) > 0 &&
             EVP_PKEY_derive(pctx, okm, &okm_len) > 0;
    EVP_PKEY_CTX_free(pctx);
    return ok;
}

static void secure_bzero(void *p, size_t n){
    if (p && n) OPENSSL_cleanse(p, n);
}

/* ------------------------ load keys/certs ------------------------ */

static X509* load_cert_pem(const char *path){
    FILE *f = fopen(path, "r"); if (!f) { perror(path); return NULL; }
    X509 *c = PEM_read_X509(f, NULL, NULL, NULL); fclose(f); return c;
}
static EVP_PKEY* load_privkey_pem(const char *path){
    FILE *f = fopen(path, "r"); if (!f) { perror(path); return NULL; }
    EVP_PKEY *k = PEM_read_PrivateKey(f, NULL, NULL, NULL); fclose(f); return k;
}

/* ------------------------ Ed25519 sign/verify -------------------- */

static int ed25519_verify(X509 *cert_pub, const unsigned char *msg, size_t msglen,
                          const unsigned char *sig, size_t siglen){
    EVP_PKEY *pk = X509_get_pubkey(cert_pub);
    if (!pk) return 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pk) > 0 &&
             EVP_DigestVerify(ctx, sig, siglen, msg, msglen) == 1;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pk);
    return ok;
}

static int ed25519_sign(EVP_PKEY *sk, const unsigned char *msg, size_t msglen,
                        unsigned char *sig, size_t *siglen){
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = EVP_DigestSignInit(ctx, NULL, NULL, NULL, sk) > 0 &&
             EVP_DigestSign(ctx, sig, siglen, msg, msglen) > 0;
    EVP_MD_CTX_free(ctx);
    return ok;
}

/* ------------------------ Montgomery→Edwards reprojection -------- */

static int mont_x_to_ed_y(const unsigned char *x32, unsigned char *y32){
    int ok = 0;
    BIGNUM *x = BN_bin2bn(x32, 32, NULL);
    BN_CTX *c = BN_CTX_new();
    BIGNUM *one = BN_new(), *p = BN_new(), *xm1 = BN_new(), *xp1 = BN_new(), *y = BN_new();

    if (!x || !c || !one || !p || !xm1 || !xp1 || !y) goto done;
    BN_one(one);                    // p = 2^255 - 19
    BN_set_bit(p, 255); BN_sub_word(p, 19);
    BN_mod_sub(xm1, x, one, p, c);
    BN_mod_add(xp1, x, one, p, c);
    if (!BN_mod_inverse(xp1, xp1, p, c)) goto done;
    BN_mod_mul(y, xm1, xp1, p, c);
    if (BN_bn2binpad(y, y32, 32) < 0) goto done;
    ok = 1;
done:
    BN_free(x); BN_free(one); BN_free(p); BN_free(xm1); BN_free(xp1); BN_free(y); BN_CTX_free(c);
    return ok;
}

/* ------------------------ ASCON helpers -------------------------- */

static int ascon_aead_encrypt(const unsigned char key[16],
                              const unsigned char *pt, size_t pt_len,
                              unsigned char out_nonce[NONCE_LEN],
                              unsigned char *out_ct, unsigned char out_tag[TAG_LEN]){
    if (!RAND_bytes(out_nonce, NONCE_LEN)) return 0;
    // no AAD
    return ascon_aead128_encrypt(key, out_nonce, pt, out_ct, out_tag, pt_len) == 0;
}
static int ascon_aead_decrypt(const unsigned char key[16],
                              const unsigned char in_nonce[NONCE_LEN],
                              const unsigned char *ct, size_t ct_len,
                              const unsigned char in_tag[TAG_LEN],
                              unsigned char *out_pt){
    return ascon_decrypt(key, in_nonce, ct, out_pt, in_tag, ct_len) == 0;
}

/* ======================== SERVER MAIN FLOW ======================= */

int main(void){
    clock_t start_time, end_time;
    double time_spent;
    /* ---- load CA + server cert + server Ed25519 signing key ---- */
    X509     *ca       = load_cert_pem(CA_CERT_PATH);
    X509     *srv_cert = load_cert_pem(SERVER_CERT_PATH);
    EVP_PKEY *srv_sign = load_privkey_pem(SERVER_SIGN_KEY);
    if (!ca || !srv_cert || !srv_sign) { fprintf(stderr,"[fatal] load cert/key\n"); return 1; }

    /* ---- load server static X25519 key ---- */
    EVP_PKEY *srv_x_priv = load_privkey_pem(SERVER_X25519_KEY);
    unsigned char srv_x_pub[32]; size_t srv_x_pub_len = sizeof(srv_x_pub);
    if (!srv_x_priv || EVP_PKEY_get_raw_public_key(srv_x_priv, srv_x_pub, &srv_x_pub_len) <= 0){
        fprintf(stderr,"[fatal] load server X25519 keypair\n"); return 1;
    }

    /* ---- socket listen ---- */
    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET; addr.sin_port = htons(PORT); addr.sin_addr.s_addr = INADDR_ANY;
    bind(sfd, (struct sockaddr*)&addr, sizeof(addr));
    listen(sfd, 1);
    printf("[Server] listening on %d…\n", PORT);

    int cfd = accept(sfd, NULL, NULL);
    if (cfd < 0) { perror("accept"); return 1; }

    /* =================== Phase 1: Mutual Authentication =================== */
    // m1: { Cert_c(DER), T_c(8), Sig_c, X25519_pub_c(32) } — each as framed blob
    unsigned char *cert_c_der = NULL, *sig_c = NULL, *x25519_pub_c = NULL, *tbuf = NULL;
    uint32_t cert_c_len=0, sig_c_len=0, x25519_pub_c_len=0, tlen=0;

    if (!recv_blob(cfd, &cert_c_der, &cert_c_len))                                  { fprintf(stderr,"recv Cert_c\n"); goto fatal; }
    if (!recv_blob(cfd, &tbuf, &tlen) || tlen != 8)                                 { fprintf(stderr,"recv T_c\n"); goto fatal; }
    if (!recv_blob(cfd, &sig_c, &sig_c_len))                                        { fprintf(stderr,"recv Sig_c\n"); goto fatal; }
    if (!recv_blob(cfd, &x25519_pub_c, &x25519_pub_c_len) || x25519_pub_c_len != 32){ fprintf(stderr,"recv X25519_pub_c\n"); goto fatal; }

    const unsigned char *pp = cert_c_der;
    X509 *cert_c = d2i_X509(NULL, &pp, cert_c_len);
    if (!cert_c || !verify_certificate(cert_c, ca)) { fprintf(stderr,"[auth] client cert chain failed\n"); goto fatal; }

    // Parse T_c as big-endian 64-bit epoch
    uint64_t Tc_net = 0;
    memcpy(&Tc_net, tbuf, 8);
    uint64_t Tc = ntohll(Tc_net);

    // Debug print (helps diagnose any time drift)
    printf("[auth] T_c(client)=%llu now=%llu\n",
           (unsigned long long)Tc, (unsigned long long)time(NULL));

    if (!ts_fresh_u64(Tc)) { fprintf(stderr,"[auth] stale timestamp\n"); goto fatal; }

    // Verify Sig_c over (DER(Cert_c) || T_c_bytes)
    unsigned char *msg1 = (unsigned char*)malloc(cert_c_len + 8);
    memcpy(msg1, cert_c_der, cert_c_len);
    memcpy(msg1 + cert_c_len, tbuf, 8);
    if (!ed25519_verify(cert_c, msg1, cert_c_len + 8, sig_c, sig_c_len)) {
        fprintf(stderr,"[auth] Sig_c verify failed\n"); goto fatal;
    }
    printf("[auth] client verified\n");

    // m2: { Cert_s(DER), T_s(8), Sig_s, X25519_pub_s(32) }
    unsigned char *srv_der = NULL; int srv_der_len = i2d_X509(srv_cert, &srv_der);
    if (srv_der_len <= 0) { fprintf(stderr,"i2d_X509 server\n"); goto fatal; }

    uint64_t Ts     = (uint64_t)time(NULL);
    uint64_t Ts_net = htonll(Ts);
    unsigned char t2[8]; memcpy(t2, &Ts_net, 8);

    unsigned char *msg2 = (unsigned char*)malloc(srv_der_len + 8);
    memcpy(msg2, srv_der, srv_der_len);
    memcpy(msg2 + srv_der_len, t2, 8);

    unsigned char sig_s[64]; size_t sig_s_len = sizeof(sig_s);
    if (!ed25519_sign(srv_sign, msg2, srv_der_len + 8, sig_s, &sig_s_len)) {
        fprintf(stderr,"sign m2\n"); goto fatal;
    }

    if (!send_blob(cfd, srv_der, (uint32_t)srv_der_len) ||
        !send_blob(cfd, t2, 8) ||
        !send_blob(cfd, sig_s, (uint32_t)sig_s_len) ||
        !send_blob(cfd, srv_x_pub, 32)) {
        fprintf(stderr,"send m2\n"); goto fatal;
    }
    OPENSSL_free(srv_der); free(msg2);

    /* =================== Phase 2: Static Key Derivation =================== */
    EVP_PKEY *cli_x_pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, x25519_pub_c, 32);
    EVP_PKEY_CTX *dctx  = EVP_PKEY_CTX_new(srv_x_priv, NULL);
    unsigned char kx[32]; size_t kx_len = sizeof(kx);
    if (!dctx || EVP_PKEY_derive_init(dctx) <= 0 ||
        EVP_PKEY_derive_set_peer(dctx, cli_x_pub) <= 0 ||
        EVP_PKEY_derive(dctx, kx, &kx_len) <= 0) {
        fprintf(stderr,"ECDH static\n"); goto fatal;
    }
    print_hex("[k_x] static", kx, 32);

    unsigned char ky[32];
    if (!mont_x_to_ed_y(kx, ky)) { fprintf(stderr,"reprojection failed\n"); goto fatal; }
    print_hex("[k_y] reprojection", ky, 32);

    unsigned char root_key[64];
    memcpy(root_key,     kx, 32);
    memcpy(root_key + 32,ky, 32);

    unsigned char k_init[16];
    if (!hkdf_sha256(root_key, sizeof(root_key),
                     (const unsigned char*)"kinit", 5, k_init, sizeof(k_init))) {
        fprintf(stderr,"HKDF k_init\n"); goto fatal;
    }
    print_hex("[k_init]", k_init, sizeof(k_init));

    secure_bzero(kx, sizeof(kx));
    secure_bzero(ky, sizeof(ky));
    secure_bzero(root_key, sizeof(root_key));
    if (dctx) EVP_PKEY_CTX_free(dctx);

    /* =================== Ephemeral Key Derivation (encrypted) ============ */
    // Generate ephemeral server keypair
    EVP_PKEY_CTX *gctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *srv_eph = NULL;
    EVP_PKEY_keygen_init(gctx);
    EVP_PKEY_keygen(gctx, &srv_eph);
   

    if (gctx) EVP_PKEY_CTX_free(gctx);

    unsigned char srv_eph_pub[32]; size_t srv_eph_pub_len = 32;
    EVP_PKEY_get_raw_public_key(srv_eph, srv_eph_pub, &srv_eph_pub_len);

    // E2 = Enc_{k_init}(k_pub_s,eph)
    unsigned char e2_nonce[NONCE_LEN], e2_ct[32], e2_tag[TAG_LEN];
    start_time = clock();
    if (!ascon_aead_encrypt(k_init, srv_eph_pub, 32, e2_nonce, e2_ct, e2_tag)) {
        fprintf(stderr,"AEAD send E2\n"); goto fatal;
    }
    end_time = clock();
    time_spent += (double)((end_time - start_time)*1000000) / CLOCKS_PER_SEC;
    if (!send_blob(cfd, e2_nonce, NONCE_LEN) ||
        !send_blob(cfd, e2_ct,    32)         ||
        !send_blob(cfd, e2_tag,   TAG_LEN)) {
        fprintf(stderr,"send E2\n"); goto fatal;
    }

    // Receive E1 = Enc_{k_init}(k_pub_c,eph)
    unsigned char *e1_nonce=NULL,*e1_ct=NULL,*e1_tag=NULL; uint32_t n1=0,c1=0,t1=0;
    if (!recv_blob(cfd, &e1_nonce, &n1) || n1 != NONCE_LEN) { fprintf(stderr,"recv E1 nonce\n"); goto fatal; }
    if (!recv_blob(cfd, &e1_ct,    &c1) || c1 != 32)        { fprintf(stderr,"recv E1 ct\n");    goto fatal; }
    if (!recv_blob(cfd, &e1_tag,   &t1) || t1 != TAG_LEN)   { fprintf(stderr,"recv E1 tag\n");   goto fatal; }

    unsigned char cli_eph_pub[32];
    //start_time = clock();

    if (!ascon_aead_decrypt(k_init, e1_nonce, e1_ct, 32, e1_tag, cli_eph_pub)) {
        fprintf(stderr,"AEAD decrypt E1\n"); goto fatal;
    }
    //end_time = clock();
   // time_spent += (double)((end_time - start_time)*1000000) / CLOCKS_PER_SEC;
    print_hex("[eph pub]_client", cli_eph_pub, 32);

    // Derive k_eph
     //start_time = clock();
    EVP_PKEY *cli_eph = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, cli_eph_pub, 32);
    EVP_PKEY_CTX *edctx = EVP_PKEY_CTX_new(srv_eph, NULL);
    unsigned char k_eph[32]; size_t k_eph_len = 32;
    if (!edctx || EVP_PKEY_derive_init(edctx) <= 0 ||
        EVP_PKEY_derive_set_peer(edctx, cli_eph) <= 0 ||
        EVP_PKEY_derive(edctx, k_eph, &k_eph_len) <= 0) {
        fprintf(stderr,"ECDHE eph\n"); goto fatal;
    }
    //print_hex("[k_eph] derived", k_eph, 32);
    if (edctx) EVP_PKEY_CTX_free(edctx);

    unsigned char k_eph_aead[16];
    if (!hkdf_sha256(k_eph, 32, (const unsigned char*)"keph", 4, k_eph_aead, 16)) {
        fprintf(stderr,"HKDF keph->aead\n"); goto fatal;
    }
    secure_bzero(k_eph, 32);

    // Erase ephemeral private key
    EVP_PKEY_free(srv_eph); srv_eph = NULL;
    //end_time = clock();
    //time_spent += (double)((end_time - start_time)*1000000) / CLOCKS_PER_SEC;
    //printf("Empheral Key  Phase: %.2lf µs\n", time_spent);

    /* =================== Key Exchange (C1/C2 under k_eph) ================= */
    // Receive C1 = Enc_{k_eph}(n_r)
    unsigned char *c1_nonce=NULL,*c1_ct=NULL,*c1_tag=NULL; uint32_t cn=0, cc=0, ct=0;
    if (!recv_blob(cfd, &c1_nonce, &cn) || cn != NONCE_LEN) { fprintf(stderr,"recv C1 nonce\n"); goto fatal; }
    if (!recv_blob(cfd, &c1_ct,    &cc) || cc != 16)        { fprintf(stderr,"recv C1 ct\n");    goto fatal; }
    if (!recv_blob(cfd, &c1_tag,   &ct) || ct != TAG_LEN)   { fprintf(stderr,"recv C1 tag\n");   goto fatal; }

    unsigned char n_r[16];
    if (!ascon_aead_decrypt(k_eph_aead, c1_nonce, c1_ct, 16, c1_tag, n_r)) {
        fprintf(stderr,"C1 decrypt fail\n"); goto fatal;
    }
    //print_hex("[n_r] client nonce", n_r, 16);

    // Generate k_sym (128-bit)
    unsigned char k_sym[16];
    if (!RAND_bytes(k_sym, sizeof(k_sym))) { fprintf(stderr,"RAND k_sym\n"); goto fatal; }
    //print_hex("[k_sym] generated", k_sym, 16);

    // --- NEW: compute h = SHA-256(k_sym ⊕ n_r) -----------------------------
    unsigned char xored[16];
    for (int i = 0; i < 16; i++) xored[i] = k_sym[i] ^ n_r[i];

    unsigned char h[32];
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    start_time = clock();
    if (!mdctx ||
        !EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) ||
        !EVP_DigestUpdate(mdctx, xored, sizeof(xored)) ||
        !EVP_DigestFinal_ex(mdctx, h, NULL)) {
        fprintf(stderr,"hash(k_sym ⊕ n_r) failed\n"); 
        if (mdctx) EVP_MD_CTX_free(mdctx);
        goto fatal;
    }
    end_time = clock();
    time_spent += (double)((end_time - start_time)*1000000) / CLOCKS_PER_SEC;
    printf("Hash: %.2lf µs\n", time_spent);
    EVP_MD_CTX_free(mdctx);
   // print_hex("[h] SHA-256(k_sym ⊕ n_r)", h, sizeof(h));

    // Encrypt k_sym under k_eph and send C2 plus h
    unsigned char c2_nonce[NONCE_LEN], c2_ct[16], c2_tag[TAG_LEN];
    if (!ascon_aead_encrypt(k_eph_aead, k_sym, 16, c2_nonce, c2_ct, c2_tag)) {
        fprintf(stderr,"C2 encrypt\n"); goto fatal;
    }
    if (!send_blob(cfd, c2_nonce, NONCE_LEN) ||
        !send_blob(cfd, c2_ct,    16)        ||
        !send_blob(cfd, c2_tag,   TAG_LEN)   ||
        !send_blob(cfd, h,        32)) {
        fprintf(stderr,"send C2 || h\n"); goto fatal;
    }

    
    printf("[OK] session established. k_sym stored for application traffic.\n");


    /* ---- cleanup ---- */
    secure_bzero(k_init,     sizeof(k_init));
    secure_bzero(k_eph_aead, sizeof(k_eph_aead));
    // (k_sym would normally be retained for application data)

    close(cfd); close(sfd);
    X509_free(ca); X509_free(srv_cert); EVP_PKEY_free(srv_sign); EVP_PKEY_free(srv_x_priv);
    X509_free(cert_c); EVP_PKEY_free(cli_x_pub); EVP_PKEY_free(cli_eph);
    free(cert_c_der); free(sig_c); free(x25519_pub_c); free(tbuf);
    free(e1_nonce); free(e1_ct); free(e1_tag);
    free(c1_nonce); free(c1_ct); free(c1_tag);
    free(msg1);
    return 0;

fatal:
    if (cfd >= 0) close(cfd);
    if (sfd >= 0) close(sfd);
    return 1;
}
