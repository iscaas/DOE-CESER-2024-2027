// client.c — updated protocol client (drop-in)
// Build:  gcc client.c ascon.c verify_certificate.c -lssl -lcrypto -o client
// Requires:
//   ./certs/ca_certificate.pem
//   ./certs/client_certificate.pem         (Ed25519 cert)
//   ./keys/client_sign_ed25519_priv.pem    (Ed25519 signing key)
//   ./keys/client_x25519_priv.pem          (static X25519, PKCS#8 PEM)
// Wire messages use [len32 | bytes] framing for each field.
// AEAD: ASCON-128a with 16-byte nonce; we send/receive as 3 framed blobs (nonce, ct, tag).

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

#define SERVER_IP "127.0.0.1"
#define PORT 3000
#define BUF  4096

#define TAG_LEN    16
#define NONCE_LEN  16

#define CA_CERT_PATH          "./certs/ca_certificate.pem"
#define CLIENT_CERT_PATH      "./certs/client_certificate.pem"
#define CLIENT_SIGN_KEY       "./keys/client_sign_ed25519_priv.pem"  // Ed25519 signer
#define CLIENT_X25519_KEY     "./keys/client_x25519_priv.pem"        // static X25519

/* ------------------------ util / IO ---------------------------------- */

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
        if (!recv_all(fd, *out, *outlen)) { free(*out); *out = NULL; return 0; }
    }
    return 1;
}
static void print_hex(const char *lab, const unsigned char *d, size_t l){
    printf("%s (%zu): ", lab, l);
    for (size_t i=0;i<l;i++) printf("%02X", d[i]);
    printf("\n");
}

/* ------------------------ 64-bit network order helpers --------------- */

static uint64_t htonll(uint64_t v){
    return ((uint64_t)htonl((uint32_t)(v>>32))<<32) | htonl((uint32_t)v);
}
static uint64_t ntohll(uint64_t v){
    return ((uint64_t)ntohl((uint32_t)(v>>32))<<32) | ntohl((uint32_t)v);
}

/* ------------------------ HKDF -------------------------------------- */

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

/* ------------------------ load cert/keys ---------------------------- */

static X509* load_cert_pem(const char *path){
    FILE *f = fopen(path, "r"); if (!f) { perror(path); return NULL; }
    X509 *c = PEM_read_X509(f, NULL, NULL, NULL); fclose(f); return c;
}
static EVP_PKEY* load_privkey_pem(const char *path){
    FILE *f = fopen(path, "r"); if (!f) { perror(path); return NULL; }
    EVP_PKEY *k = PEM_read_PrivateKey(f, NULL, NULL, NULL); fclose(f); return k;
}

/* ------------------------ Ed25519 sign/verify ----------------------- */

static int ed25519_sign(EVP_PKEY *sk, const unsigned char *msg, size_t msglen,
                        unsigned char *sig, size_t *siglen){
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = EVP_DigestSignInit(ctx, NULL, NULL, NULL, sk) > 0 &&
             EVP_DigestSign(ctx, sig, siglen, msg, msglen) > 0;
    EVP_MD_CTX_free(ctx);
    return ok;
}
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

/* ------------------------ reprojection y=(x-1)/(x+1) mod p --------- */

static int mont_x_to_ed_y(const unsigned char *x32, unsigned char *y32){
    int ok=0;
    BIGNUM *x = BN_bin2bn(x32, 32, NULL);
    BN_CTX *c = BN_CTX_new();
    BIGNUM *one=BN_new(), *p=BN_new(), *xm1=BN_new(), *xp1=BN_new(), *y=BN_new();
    if(!x||!c||!one||!p||!xm1||!xp1||!y) goto done;
    BN_one(one);
    BN_set_bit(p,255); BN_sub_word(p,19);                 // p = 2^255 - 19
    BN_mod_sub(xm1,x,one,p,c);
    BN_mod_add(xp1,x,one,p,c);
    if(!BN_mod_inverse(xp1,xp1,p,c)) goto done;
    BN_mod_mul(y,xm1,xp1,p,c);
    if(BN_bn2binpad(y,y32,32)<0) goto done;
    ok=1;
done:
    BN_free(x); BN_free(one); BN_free(p); BN_free(xm1); BN_free(xp1); BN_free(y); BN_CTX_free(c);
    return ok;
}

/* ------------------------ ASCON wrappers --------------------------- */

static int ascon_aead_encrypt(const unsigned char key[16],
                              const unsigned char *pt, size_t pt_len,
                              unsigned char out_nonce[NONCE_LEN],
                              unsigned char *out_ct, unsigned char out_tag[TAG_LEN]){
    if (!RAND_bytes(out_nonce, NONCE_LEN)) return 0;
    return ascon_aead128_encrypt(key, out_nonce, pt, out_ct, out_tag, pt_len) == 0;
}
static int ascon_aead_decrypt(const unsigned char key[16],
                              const unsigned char in_nonce[NONCE_LEN],
                              const unsigned char *ct, size_t ct_len,
                              const unsigned char in_tag[TAG_LEN],
                              unsigned char *out_pt){
    return ascon_decrypt(key, in_nonce, ct, out_pt, in_tag, ct_len) == 0;
}

/* ======================== CLIENT MAIN FLOW ======================== */

int main(void){
    clock_t start_time, end_time;
    double time_spent;
    /* Load CA, client cert, Ed25519 signing key, and static X25519 */
    X509     *ca         = load_cert_pem(CA_CERT_PATH);
    X509     *cli_cert   = load_cert_pem(CLIENT_CERT_PATH);
    EVP_PKEY *cli_sign   = load_privkey_pem(CLIENT_SIGN_KEY);
    EVP_PKEY *cli_x_priv = load_privkey_pem(CLIENT_X25519_KEY);
    if (!ca || !cli_cert || !cli_sign || !cli_x_priv) { fprintf(stderr,"[fatal] load cert/key\n"); return 1; }

    unsigned char cli_x_pub[32]; size_t cli_x_pub_len = sizeof(cli_x_pub);
    if (EVP_PKEY_get_raw_public_key(cli_x_priv, cli_x_pub, &cli_x_pub_len) <= 0) {
        fprintf(stderr,"[fatal] extract client static X25519 pub\n"); return 1;
    }

    /* Connect */
  int fd=socket(AF_INET,SOCK_STREAM,0);
  struct sockaddr_in addr={0}; addr.sin_family=AF_INET; addr.sin_port=htons(PORT);
  inet_pton(AF_INET, SERVER_IP, &addr.sin_addr); if(connect(fd,(struct sockaddr*)&addr,sizeof(addr))<0){ perror("connect"); return 1; }

    /* =================== Phase 1: Mutual Authentication =================== */
    // m1: Cert_c(DER), T_c(8), Sig_c(Ed25519 on DER||T_c), X25519_pub_c(32) — all framed blobs
    unsigned char *cli_der = NULL; int cli_der_len = i2d_X509(cli_cert, &cli_der);
    if (cli_der_len <= 0) { fprintf(stderr,"i2d_X509 client\n"); return 1; }

    uint64_t Tc     = (uint64_t)time(NULL);
    uint64_t Tc_net = htonll(Tc);
    unsigned char tbuf[8]; memcpy(tbuf, &Tc_net, 8);

    unsigned char *msg1 = (unsigned char*)malloc(cli_der_len + 8);
    memcpy(msg1,            cli_der,      cli_der_len);
    memcpy(msg1 + cli_der_len, tbuf, 8);

    unsigned char sig_c[64]; size_t sig_c_len = sizeof(sig_c);
    if (!ed25519_sign(cli_sign, msg1, (size_t)cli_der_len + 8, sig_c, &sig_c_len)) {
        fprintf(stderr,"sign m1\n"); return 1;
    }

    if (!send_blob(fd, cli_der,        (uint32_t)cli_der_len) ||
        !send_blob(fd, tbuf,           8)                     ||
        !send_blob(fd, sig_c,          (uint32_t)sig_c_len)   ||
        !send_blob(fd, cli_x_pub,      32)) {
        fprintf(stderr,"send m1\n"); return 1;
    }
    OPENSSL_free(cli_der); free(msg1);

    // m2: { Cert_s(DER), T_s(8), Sig_s(Ed25519 on DER||T_s), X25519_pub_s(32) }
    unsigned char *srv_der=NULL, *t2=NULL, *sig_s=NULL, *srv_x_pub=NULL;
    uint32_t srv_der_len=0, t2_len=0, sig_s_len=0, srv_x_pub_len=0;

    if (!recv_blob(fd,&srv_der,&srv_der_len) ||
        !recv_blob(fd,&t2,&t2_len) || t2_len != 8 ||
        !recv_blob(fd,&sig_s,&sig_s_len) ||
        !recv_blob(fd,&srv_x_pub,&srv_x_pub_len) || srv_x_pub_len != 32) {
        fprintf(stderr,"recv m2\n"); return 1;
    }

    const unsigned char *pp = srv_der;
    X509 *srv_cert = d2i_X509(NULL, &pp, srv_der_len);
    if (!srv_cert || !verify_certificate(srv_cert, ca)) {
        fprintf(stderr,"[auth] server cert chain failed\n"); return 1;
    }

    unsigned char *msg2 = (unsigned char*)malloc(srv_der_len + 8);
    memcpy(msg2,            srv_der, srv_der_len);
    memcpy(msg2 + srv_der_len, t2, 8);
    if (!ed25519_verify(srv_cert, msg2, srv_der_len + 8, sig_s, sig_s_len)) {
        fprintf(stderr,"[auth] Sig_s verify failed\n"); return 1;
    }
    free(msg2);
    printf("[auth] server verified\n");

    /* =================== Phase 2: Static Key Derivation =================== */
    EVP_PKEY *srv_x_pubkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, srv_x_pub, 32);
    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(cli_x_priv, NULL);
    unsigned char kx[32]; size_t kx_len = 32;

    if (!dctx || EVP_PKEY_derive_init(dctx) <= 0 ||
        EVP_PKEY_derive_set_peer(dctx, srv_x_pubkey) <= 0 ||
        EVP_PKEY_derive(dctx, kx, &kx_len) <= 0) {
        fprintf(stderr,"ECDH static\n"); return 1;
    }
    print_hex("[k_x] static", kx, 32);

    unsigned char ky[32];
    if (!mont_x_to_ed_y(kx, ky)) { fprintf(stderr,"reprojection failed\n"); return 1; }
    print_hex("[k_y] reprojection", ky, 32);

    unsigned char root_key[64];
    memcpy(root_key,     kx, 32);
    memcpy(root_key + 32,ky, 32);

    unsigned char k_init[16];
    if (!hkdf_sha256(root_key, sizeof(root_key),
                     (const unsigned char*)"kinit", 5, k_init, sizeof(k_init))) {
        fprintf(stderr,"HKDF k_init\n"); return 1;
    }
    print_hex("[k_init]", k_init, sizeof(k_init));

    OPENSSL_cleanse(kx, sizeof(kx));
    OPENSSL_cleanse(ky, sizeof(ky));
    OPENSSL_cleanse(root_key, sizeof(root_key));
    if (dctx) EVP_PKEY_CTX_free(dctx);

    /* =================== Ephemeral Key Derivation (encrypted) ============ */
    // Receive E2 = Enc_{k_init}(srv_eph_pub)
    unsigned char *e2_nonce=NULL,*e2_ct=NULL,*e2_tag=NULL; uint32_t n2=0,c2=0,tg2=0;
    if (!recv_blob(fd, &e2_nonce, &n2) || n2 != NONCE_LEN) { fprintf(stderr,"recv E2 nonce\n"); return 1; }
    if (!recv_blob(fd, &e2_ct,    &c2) || c2 != 32)        { fprintf(stderr,"recv E2 ct\n");    return 1; }
    if (!recv_blob(fd, &e2_tag,   &tg2)|| tg2 != TAG_LEN)  { fprintf(stderr,"recv E2 tag\n");   return 1; }

    unsigned char srv_eph_pub[32];
     //start_time = clock();
    if (!ascon_aead_decrypt(k_init, e2_nonce, e2_ct, 32, e2_tag, srv_eph_pub)) {
        fprintf(stderr,"E2 decrypt\n"); return 1;
    }
    // end_time = clock();
    //time_spent += (double)((end_time - start_time)*1000000) / CLOCKS_PER_SEC;
    //print_hex("[eph pub]_server", srv_eph_pub, 32);
    // Generate client ephemeral and send E1 = Enc_{k_init}(cli_eph_pub)
        start_time = clock();
    EVP_PKEY_CTX *gctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *cli_eph = NULL;
    EVP_PKEY_keygen_init(gctx);
    end_time = clock();
    time_spent += (double)((end_time - start_time)*1000000) / CLOCKS_PER_SEC;
    EVP_PKEY_keygen(gctx, &cli_eph);
    
    if (gctx) EVP_PKEY_CTX_free(gctx);

    unsigned char cli_eph_pub[32]; size_t cli_eph_pub_len = 32;
    EVP_PKEY_get_raw_public_key(cli_eph, cli_eph_pub, &cli_eph_pub_len);
    
    unsigned char e1_nonce[NONCE_LEN], e1_ct[32], e1_tag[TAG_LEN];
   // start_time = clock();
    if (!ascon_aead_encrypt(k_init, cli_eph_pub, 32, e1_nonce, e1_ct, e1_tag)) {
        fprintf(stderr,"E1 encrypt\n"); return 1;
    }
   // end_time = clock();
    //time_spent += (double)((end_time - start_time)*1000000) / CLOCKS_PER_SEC;
    if (!send_blob(fd, e1_nonce, NONCE_LEN) ||
        !send_blob(fd, e1_ct,    32)        ||
        !send_blob(fd, e1_tag,   TAG_LEN)) {
        fprintf(stderr,"send E1\n"); return 1;
    }
    // Derive k_eph
   // start_time = clock();

    EVP_PKEY *srv_eph = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, srv_eph_pub, 32);
    EVP_PKEY_CTX *edctx = EVP_PKEY_CTX_new(cli_eph, NULL);
    unsigned char k_eph[32]; size_t k_eph_len = 32;

    if (!edctx || EVP_PKEY_derive_init(edctx) <= 0 ||
        EVP_PKEY_derive_set_peer(edctx, srv_eph) <= 0 ||
        EVP_PKEY_derive(edctx, k_eph, &k_eph_len) <= 0) {
        fprintf(stderr,"ECDHE eph\n"); return 1;
    }
    //print_hex("[k_eph] derived", k_eph, 32);
    if (edctx) EVP_PKEY_CTX_free(edctx);

    unsigned char k_eph_aead[16];
    if (!hkdf_sha256(k_eph, 32, (const unsigned char*)"keph", 4, k_eph_aead, 16)) {
        fprintf(stderr,"HKDF keph->aead\n"); return 1;
    }
    OPENSSL_cleanse(k_eph, 32);

    // Erase ephemeral private key
    EVP_PKEY_free(srv_eph); srv_eph = NULL;

    EVP_PKEY_free(cli_eph); EVP_PKEY_free(srv_eph);
     //  end_time = clock();
  // time_spent += (double)((end_time - start_time)*1000000) / CLOCKS_PER_SEC;
  // printf("Empheral Key Exchange Phase: %.2lf µs\n", time_spent);

    /* =================== Key Exchange (C1/C2 under k_eph) ================= */
    // Send C1 = Enc_{k_eph}(n_r)
    unsigned char n_r[16];
    if (!RAND_bytes(n_r, sizeof(n_r))) { fprintf(stderr,"RAND n_r\n"); return 1; }
    print_hex("[n_r] client", n_r, 16);

    unsigned char c1_nonce[NONCE_LEN], c1_ct[16], c1_tag[TAG_LEN];
    if (!ascon_aead_encrypt(k_eph_aead, n_r, 16, c1_nonce, c1_ct, c1_tag)) {
        fprintf(stderr,"C1 encrypt\n"); return 1;
    }
    if (!send_blob(fd, c1_nonce, NONCE_LEN) ||
        !send_blob(fd, c1_ct,    16)        ||
        !send_blob(fd, c1_tag,   TAG_LEN)) {
        fprintf(stderr,"send C1\n"); return 1;
    }

    /* ---- Receive C2 = Enc_{k_eph}(k_sym) and h = SHA-256(k_sym ⊕ n_r) ---- */
    unsigned char *c2_nonce=NULL,*c2_ct2=NULL,*c2_tag=NULL,*h=NULL;
    uint32_t nn=0, cc=0, tt=0, hl=0;

    if (!recv_blob(fd, &c2_nonce, &nn) || nn != NONCE_LEN) { fprintf(stderr,"recv C2 nonce\n"); return 1; }
    if (!recv_blob(fd, &c2_ct2,   &cc) || cc != 16)        { fprintf(stderr,"recv C2 ct\n");    return 1; }
    if (!recv_blob(fd, &c2_tag,   &tt) || tt != TAG_LEN)   { fprintf(stderr,"recv C2 tag\n");   return 1; }
    if (!recv_blob(fd, &h,        &hl) || hl != 32)        { fprintf(stderr,"recv h\n");        return 1; }

    unsigned char k_sym[16];
    if (!ascon_aead_decrypt(k_eph_aead, c2_nonce, c2_ct2, 16, c2_tag, k_sym)) {
        fprintf(stderr,"C2 decrypt fail\n"); return 1;
    }
    print_hex("[k_sym] established", k_sym, 16);

    /* ---- Verify: h' = SHA-256(k_sym ⊕ n_r) ---- */
    unsigned char xored[16];
    for (int i = 0; i < 16; i++) xored[i] = k_sym[i] ^ n_r[i];

    unsigned char hprime[32];
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    start_time = clock();
    if (!mdctx ||
        !EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) ||
        !EVP_DigestUpdate(mdctx, xored, sizeof(xored)) ||
        !EVP_DigestFinal_ex(mdctx, hprime, NULL)) {
        fprintf(stderr,"hash(k_sym ⊕ n_r) failed\n");
        if (mdctx) EVP_MD_CTX_free(mdctx);
        return 1;
    }
    end_time = clock();
    time_spent += (double)((end_time - start_time)*1000000) / CLOCKS_PER_SEC;
    printf("Hash: %.2lf µs\n", time_spent);
    EVP_MD_CTX_free(mdctx);

    if (memcmp(hprime, h, 32) != 0) {
        print_hex("[h]   received", h, 32);
        print_hex("[h'] computed", hprime, 32);
        fprintf(stderr,"[verify] h mismatch! aborting\n");
        free(h);
        return 1;
    }
    print_hex("[h]   received", h, 32);
    print_hex("[h'] computed", hprime, 32);
    printf("[verify] h == h' ✓\n");
    free(h);

    printf("[OK] session established. k_sym ready for application data.\n");


    /* ---- cleanup (retain k_sym as needed for your application) ---- */
    close(fd);
    X509_free(ca); X509_free(cli_cert); X509_free(srv_cert);
    EVP_PKEY_free(cli_sign); EVP_PKEY_free(cli_x_priv);
    EVP_PKEY_free(srv_x_pubkey);
    free(srv_der); free(t2); free(sig_s); free(srv_x_pub);
    free(e2_nonce); free(e2_ct); free(e2_tag);
    free(c2_nonce); free(c2_ct2); free(c2_tag);
    return 0;
}
