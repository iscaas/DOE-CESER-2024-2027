#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sodium.h>
#include "api_mlkem.h"
#include "api.h"
int crypto_aead_encrypt(unsigned char*,unsigned long long*,const unsigned char*,unsigned long long,const unsigned char*,unsigned long long,const unsigned char*,const unsigned char*,const unsigned char*);

#define BENCH 1000
#if defined(__i386__)||defined(__x86_64__)
static inline unsigned long long rdtsc(void){unsigned int lo,hi;__asm__ __volatile__("rdtsc":"=a"(lo),"=d"(hi));return((unsigned long long)hi<<32)|lo;}
#else
static inline unsigned long long rdtsc(void){return 0;}
#endif

void PQCLEAN_randombytes(unsigned char*buf,size_t n){randombytes_buf(buf,(unsigned long long)n);}

static void hkdf_extract(unsigned char*prk,const unsigned char*ikm,size_t ilen){
    unsigned char zero[32];memset(zero,0,32);
    crypto_auth_hmacsha256(prk,ikm,ilen,zero);}
static void hkdf_expand1(unsigned char*okm,const unsigned char*prk,const char*info){
    crypto_auth_hmacsha256_state st; unsigned char ctr=1;
    crypto_auth_hmacsha256_init(&st,prk,32);
    crypto_auth_hmacsha256_update(&st,(const unsigned char*)info,strlen(info));
    crypto_auth_hmacsha256_update(&st,&ctr,1);
    crypto_auth_hmacsha256_final(&st,okm);}

int main(void){
    if(sodium_init()<0){fprintf(stderr,"libsodium failed\n");return 1;}
    printf("=== AmphiKey Deniable Mode — Sender Bench (%d iters) ===\n\n",BENCH);

    struct timespec ts,te; unsigned long long sc,ec,tn,tc;

    /* Generate fresh ephemeral receiver keys (SCADA side) */
    unsigned char skr_x[32],pkr_x[32];
    randombytes_buf(skr_x,32); crypto_scalarmult_base(pkr_x,skr_x);
    unsigned char skr_ml[PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES];
    unsigned char pkr_ml[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pkr_ml,skr_ml);
    unsigned char rs[16]; randombytes_buf(rs,16);

    /* Save for receiver bench */
    FILE*f;
    f=fopen("bench_skr_x25519.bin","wb");fwrite(skr_x,1,32,f);fclose(f);
    f=fopen("bench_pkr_x25519.bin","wb");fwrite(pkr_x,1,32,f);fclose(f);
    f=fopen("bench_skr_mlkem.bin","wb");fwrite(skr_ml,1,sizeof(skr_ml),f);fclose(f);
    f=fopen("bench_pkr_mlkem.bin","wb");fwrite(pkr_ml,1,sizeof(pkr_ml),f);fclose(f);
    f=fopen("bench_rs.bin","wb");fwrite(rs,1,16,f);fclose(f);

    /* --- AKEM1: X25519 Encapsulation --- */
    printf("--- Benchmarking AKEM1 (X25519) Encapsulation ---\n");
    unsigned char c2[32],k2[32]; tn=0;tc=0;
    for(int i=0;i<BENCH;i++){
        unsigned char sk_e[32],pk_e[32],dh[32],ikm[96],prk[32];
        randombytes_buf(sk_e,32); crypto_scalarmult_base(pk_e,sk_e);
        clock_gettime(CLOCK_MONOTONIC,&ts);sc=rdtsc();
        crypto_scalarmult(dh,sk_e,pkr_x);
        memcpy(ikm,dh,32);memcpy(ikm+32,pk_e,32);memcpy(ikm+64,pkr_x,32);
        hkdf_extract(prk,ikm,96);
        hkdf_expand1(k2,prk,"AmphiKey-DHKEM-v1");
        memcpy(c2,pk_e,32);
        ec=rdtsc();clock_gettime(CLOCK_MONOTONIC,&te);
        tn+=(te.tv_sec-ts.tv_sec)*1000000000LL+(te.tv_nsec-ts.tv_nsec);
        if(ec>sc)tc+=ec-sc;
    }
    printf("Average Time:   %llu ns\nAverage Cycles: %llu\n------------------------------------\n",tn/BENCH,tc/BENCH);

    /* --- AKEM2: ML-KEM Encapsulation --- */
    printf("\n--- Benchmarking AKEM2 (ML-KEM-768) Encapsulation ---\n");
    unsigned char c1[PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES],k1[32];
    tn=0;tc=0;
    for(int i=0;i<BENCH;i++){
        clock_gettime(CLOCK_MONOTONIC,&ts);sc=rdtsc();
        PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(c1,k1,pkr_ml);
        ec=rdtsc();clock_gettime(CLOCK_MONOTONIC,&te);
        tn+=(te.tv_sec-ts.tv_sec)*1000000000LL+(te.tv_nsec-ts.tv_nsec);
        if(ec>sc)tc+=ec-sc;
    }
    printf("Average Time:   %llu ns\nAverage Cycles: %llu\n------------------------------------\n",tn/BENCH,tc/BENCH);

    /* --- kauth Derivation --- */
    printf("\n--- Benchmarking kauth Derivation (HKDF-SHA256) ---\n");
    unsigned char kauth[32]; tn=0;tc=0;
    for(int i=0;i<BENCH;i++){
        unsigned char ikm[80],prk[32];
        memcpy(ikm,k1,32);memcpy(ikm+32,k2,32);memcpy(ikm+64,rs,16);
        clock_gettime(CLOCK_MONOTONIC,&ts);sc=rdtsc();
        hkdf_extract(prk,ikm,80);
        hkdf_expand1(kauth,prk,"auth");
        ec=rdtsc();clock_gettime(CLOCK_MONOTONIC,&te);
        tn+=(te.tv_sec-ts.tv_sec)*1000000000LL+(te.tv_nsec-ts.tv_nsec);
        if(ec>sc)tc+=ec-sc;
    }
    printf("Average Time:   %llu ns\nAverage Cycles: %llu\n------------------------------------\n",tn/BENCH,tc/BENCH);

    /* --- HMAC Tag --- */
    printf("\n--- Benchmarking HMAC-SHA256 Tag ---\n");
    size_t c_len=sizeof(c1)+32;
    unsigned char c[PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES+32];
    memcpy(c,c1,sizeof(c1));memcpy(c+sizeof(c1),c2,32);
    unsigned char tag[32]; tn=0;tc=0;
    for(int i=0;i<BENCH;i++){
        unsigned char tmsg[sizeof(c)+17];
        memcpy(tmsg,c,c_len);memcpy(tmsg+c_len,rs,16);tmsg[c_len+16]=0x00;
        clock_gettime(CLOCK_MONOTONIC,&ts);sc=rdtsc();
        crypto_auth_hmacsha256(tag,tmsg,c_len+17,kauth);
        ec=rdtsc();clock_gettime(CLOCK_MONOTONIC,&te);
        tn+=(te.tv_sec-ts.tv_sec)*1000000000LL+(te.tv_nsec-ts.tv_nsec);
        if(ec>sc)tc+=ec-sc;
    }
    printf("Average Time:   %llu ns\nAverage Cycles: %llu\n------------------------------------\n",tn/BENCH,tc/BENCH);

    /* Save wire data for receiver bench */
    f=fopen("bench_c.bin","wb");fwrite(c,1,c_len,f);fclose(f);
    f=fopen("bench_tag.bin","wb");fwrite(tag,1,32,f);fclose(f);

    /* --- ksh Derivation --- */
    printf("\n--- Benchmarking ksh Derivation (HKDF-SHA256) ---\n");
    unsigned char ksh[32]; tn=0;tc=0;
    for(int i=0;i<BENCH;i++){
        size_t ilen=32+32+c_len+16+sizeof(pkr_ml)+32+1;
        unsigned char*ikm=(unsigned char*)malloc(ilen),prk[32];
        unsigned char*p=ikm;
        memcpy(p,k1,32);p+=32;memcpy(p,k2,32);p+=32;
        memcpy(p,c,c_len);p+=c_len;memcpy(p,rs,16);p+=16;
        memcpy(p,pkr_ml,sizeof(pkr_ml));p+=sizeof(pkr_ml);
        memcpy(p,pkr_x,32);p+=32;*p=0x00;
        clock_gettime(CLOCK_MONOTONIC,&ts);sc=rdtsc();
        hkdf_extract(prk,ikm,ilen);hkdf_expand1(ksh,prk,"ksh");
        ec=rdtsc();clock_gettime(CLOCK_MONOTONIC,&te);
        tn+=(te.tv_sec-ts.tv_sec)*1000000000LL+(te.tv_nsec-ts.tv_nsec);
        if(ec>sc)tc+=ec-sc;
        free(ikm);
    }
    printf("Average Time:   %llu ns\nAverage Cycles: %llu\n------------------------------------\n",tn/BENCH,tc/BENCH);

    /* --- Ascon-128 AEAD Encrypt --- */
    printf("\n--- Benchmarking Ascon-128 AEAD Encrypt ---\n");
    const char*meter="0.18,0.18,0,0.18,0,0,0,0,131.8,0,0,0.4,0,0,54,0,0,54,54,C0.99,0,0,90,15 Minutes,0.18,0,0,6,0,0,6,60.03,Forward,Forward,Forward";
    size_t mlen=strlen(meter);
    unsigned char ak[16],an[16];memcpy(ak,ksh,16);randombytes_buf(an,16);
    unsigned char*ct=(unsigned char*)malloc(mlen+16);unsigned long long clen=0;
    tn=0;tc=0;
    for(int i=0;i<BENCH;i++){
        unsigned long long tl=0;
        clock_gettime(CLOCK_MONOTONIC,&ts);sc=rdtsc();
        crypto_aead_encrypt(ct,&tl,(const unsigned char*)meter,mlen,NULL,0,NULL,an,ak);
        ec=rdtsc();clock_gettime(CLOCK_MONOTONIC,&te);
        tn+=(te.tv_sec-ts.tv_sec)*1000000000LL+(te.tv_nsec-ts.tv_nsec);
        if(ec>sc)tc+=ec-sc;clen=tl;
    }
    printf("  Plaintext: %zu B -> Ciphertext+tag: %llu B\n",mlen,clen);
    printf("Average Time:   %llu ns\nAverage Cycles: %llu\n------------------------------------\n",tn/BENCH,tc/BENCH);
    free(ct);
    printf("\nDone. Saved bench_c.bin, bench_tag.bin, bench_rs.bin, bench_*r_*.bin for receiver bench.\n");
    return 0;
}
