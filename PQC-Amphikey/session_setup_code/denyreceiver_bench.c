#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sodium.h>
#include "api_mlkem.h"
#include "api.h"
int crypto_aead_encrypt(unsigned char*,unsigned long long*,const unsigned char*,unsigned long long,const unsigned char*,unsigned long long,const unsigned char*,const unsigned char*,const unsigned char*);
int crypto_aead_decrypt(unsigned char*,unsigned long long*,unsigned char*,const unsigned char*,unsigned long long,const unsigned char*,unsigned long long,const unsigned char*,const unsigned char*);

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
    crypto_auth_hmacsha256_state st;unsigned char ctr=1;
    crypto_auth_hmacsha256_init(&st,prk,32);
    crypto_auth_hmacsha256_update(&st,(const unsigned char*)info,strlen(info));
    crypto_auth_hmacsha256_update(&st,&ctr,1);
    crypto_auth_hmacsha256_final(&st,okm);}

static int load(const char*fn,unsigned char*buf,size_t n){
    FILE*f=fopen(fn,"rb");if(!f){fprintf(stderr,"%s: not found\n",fn);return -1;}
    fread(buf,1,n,f);fclose(f);return 0;}

int main(void){
    if(sodium_init()<0){fprintf(stderr,"libsodium failed\n");return 1;}
    printf("=== AmphiKey Deniable Mode — Receiver Bench (%d iters) ===\n\n",BENCH);
    printf("NOTE: Run ./deny_sender_bench first to generate bench_*.bin files.\n\n");

    struct timespec ts,te;unsigned long long sc,ec,tn,tc;

    /* Load receiver secret keys (written by deny_sender_bench) */
    unsigned char skr_x[32],pkr_x[32];
    unsigned char skr_ml[PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES];
    unsigned char pkr_ml[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    unsigned char rs[16];
    size_t c_data_len=PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES+32;
    unsigned char*c=(unsigned char*)malloc(c_data_len);
    unsigned char tag[32];
    if(load("bench_skr_x25519.bin",skr_x,32)||
       load("bench_pkr_x25519.bin",pkr_x,32)||
       load("bench_skr_mlkem.bin",skr_ml,sizeof(skr_ml))||
       load("bench_pkr_mlkem.bin",pkr_ml,sizeof(pkr_ml))||
       load("bench_rs.bin",rs,16)||
       load("bench_c.bin",c,c_data_len)||
       load("bench_tag.bin",tag,32)){
        fprintf(stderr,"Run ./deny_sender_bench first!\n");free(c);return 1;}
    printf("All bench files loaded.\n\n");

    unsigned char*c1=c;
    unsigned char*c2=c+PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES;

    /* --- AKEM1: X25519 Decapsulation --- */
    printf("--- Benchmarking AKEM1 (X25519) Decapsulation ---\n");
    unsigned char k2[32]; tn=0;tc=0;
    for(int i=0;i<BENCH;i++){
        unsigned char dh[32],ikm[96],prk[32];
        clock_gettime(CLOCK_MONOTONIC,&ts);sc=rdtsc();
        crypto_scalarmult(dh,skr_x,c2);
        memcpy(ikm,dh,32);memcpy(ikm+32,c2,32);memcpy(ikm+64,pkr_x,32);
        hkdf_extract(prk,ikm,96);hkdf_expand1(k2,prk,"AmphiKey-DHKEM-v1");
        ec=rdtsc();clock_gettime(CLOCK_MONOTONIC,&te);
        tn+=(te.tv_sec-ts.tv_sec)*1000000000LL+(te.tv_nsec-ts.tv_nsec);
        if(ec>sc)tc+=ec-sc;
    }
    printf("Average Time:   %llu ns\nAverage Cycles: %llu\n------------------------------------\n",tn/BENCH,tc/BENCH);

    /* --- AKEM2: ML-KEM Decapsulation --- */
    printf("\n--- Benchmarking AKEM2 (ML-KEM-768) Decapsulation ---\n");
    unsigned char k1[32]; tn=0;tc=0;
    for(int i=0;i<BENCH;i++){
        clock_gettime(CLOCK_MONOTONIC,&ts);sc=rdtsc();
        PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(k1,c1,skr_ml);
        ec=rdtsc();clock_gettime(CLOCK_MONOTONIC,&te);
        tn+=(te.tv_sec-ts.tv_sec)*1000000000LL+(te.tv_nsec-ts.tv_nsec);
        if(ec>sc)tc+=ec-sc;
    }
    printf("Average Time:   %llu ns\nAverage Cycles: %llu\n------------------------------------\n",tn/BENCH,tc/BENCH);

    /* --- kauth Derivation + HMAC Verify --- */
    printf("\n--- Benchmarking kauth Derivation + HMAC-SHA256 Verify ---\n");
    unsigned char kauth[32]; tn=0;tc=0;
    for(int i=0;i<BENCH;i++){
        unsigned char ikm[80],prk[32];
        memcpy(ikm,k1,32);memcpy(ikm+32,k2,32);memcpy(ikm+64,rs,16);
        clock_gettime(CLOCK_MONOTONIC,&ts);sc=rdtsc();
        hkdf_extract(prk,ikm,80);hkdf_expand1(kauth,prk,"auth");
        unsigned char computed[32];
        unsigned char tmsg[c_data_len+17];
        memcpy(tmsg,c,c_data_len);memcpy(tmsg+c_data_len,rs,16);tmsg[c_data_len+16]=0x00;
        crypto_auth_hmacsha256(computed,tmsg,c_data_len+17,kauth);
        ec=rdtsc();clock_gettime(CLOCK_MONOTONIC,&te);
        tn+=(te.tv_sec-ts.tv_sec)*1000000000LL+(te.tv_nsec-ts.tv_nsec);
        if(ec>sc)tc+=ec-sc;
    }
    /* Final verify check */
    unsigned char ikm_v[80],prk_v[32],computed_v[32];
    memcpy(ikm_v,k1,32);memcpy(ikm_v+32,k2,32);memcpy(ikm_v+64,rs,16);
    hkdf_extract(prk_v,ikm_v,80);hkdf_expand1(kauth,prk_v,"auth");
    unsigned char tmsg_v[c_data_len+17];
    memcpy(tmsg_v,c,c_data_len);memcpy(tmsg_v+c_data_len,rs,16);tmsg_v[c_data_len+16]=0x00;
    crypto_auth_hmacsha256(computed_v,tmsg_v,c_data_len+17,kauth);
    if(sodium_memcmp(computed_v,tag,32)!=0){fprintf(stderr,"TAG MISMATCH\n");free(c);return 1;}
    printf("TAG VERIFIED.\n");
    printf("Average Time:   %llu ns\nAverage Cycles: %llu\n------------------------------------\n",tn/BENCH,tc/BENCH);

    /* --- ksh Derivation --- */
    printf("\n--- Benchmarking ksh Derivation (HKDF-SHA256) ---\n");
    unsigned char ksh[32]; tn=0;tc=0;
    for(int i=0;i<BENCH;i++){
        size_t ilen=32+32+c_data_len+16+sizeof(pkr_ml)+32+1;
        unsigned char*ikm=(unsigned char*)malloc(ilen),prk[32];
        unsigned char*p=ikm;
        memcpy(p,k1,32);p+=32;memcpy(p,k2,32);p+=32;
        memcpy(p,c,c_data_len);p+=c_data_len;memcpy(p,rs,16);p+=16;
        memcpy(p,pkr_ml,sizeof(pkr_ml));p+=sizeof(pkr_ml);
        memcpy(p,pkr_x,32);p+=32;*p=0x00;
        clock_gettime(CLOCK_MONOTONIC,&ts);sc=rdtsc();
        hkdf_extract(prk,ikm,ilen);hkdf_expand1(ksh,prk,"ksh");
        ec=rdtsc();clock_gettime(CLOCK_MONOTONIC,&te);
        tn+=(te.tv_sec-ts.tv_sec)*1000000000LL+(te.tv_nsec-ts.tv_nsec);
        if(ec>sc)tc+=ec-sc;free(ikm);
    }
    printf("Average Time:   %llu ns\nAverage Cycles: %llu\n------------------------------------\n",tn/BENCH,tc/BENCH);

    /* --- Ascon-128 AEAD Decrypt --- */
    printf("\n--- Benchmarking Ascon-128 AEAD Decrypt ---\n");
    const char*meter="0.18,0.18,0,0.18,0,0,0,0,131.8,0,0,0.4,0,0,54,0,0,54,54,C0.99,0,0,90,15 Minutes,0.18,0,0,6,0,0,6,60.03,Forward,Forward,Forward";
    size_t mlen=strlen(meter);
    unsigned char ak[16],an[16];memcpy(ak,ksh,16);randombytes_buf(an,16);
    unsigned char*ct=(unsigned char*)malloc(mlen+16);unsigned long long clen=0;
    crypto_aead_encrypt(ct,&clen,(const unsigned char*)meter,mlen,NULL,0,NULL,an,ak);
    unsigned char*pt=(unsigned char*)malloc(mlen+1);unsigned long long plen=0;
    tn=0;tc=0;
    for(int i=0;i<BENCH;i++){
        unsigned long long tl=0;
        clock_gettime(CLOCK_MONOTONIC,&ts);sc=rdtsc();
        crypto_aead_decrypt(pt,&tl,NULL,ct,clen,NULL,0,an,ak);
        ec=rdtsc();clock_gettime(CLOCK_MONOTONIC,&te);
        tn+=(te.tv_sec-ts.tv_sec)*1000000000LL+(te.tv_nsec-ts.tv_nsec);
        if(ec>sc)tc+=ec-sc;plen=tl;
    }
    pt[plen]='\0';
    printf("  Ciphertext+tag: %llu B -> Plaintext: %llu B\n",clen,plen);
    printf("Average Time:   %llu ns\nAverage Cycles: %llu\n------------------------------------\n",tn/BENCH,tc/BENCH);
    free(ct);free(pt);free(c);
    return 0;
}
