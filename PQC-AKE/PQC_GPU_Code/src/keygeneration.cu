#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <cuda.h>
#include <cuda_runtime.h>

#include "../include/params.h"
#include "../include/keygeneration.cuh"
#include "../include/sha2.cuh"

#define ROTL32(S0, S1, r) ( ((uint32_t)(r) < 32U) ? ( ((uint32_t)(S0) << (uint32_t)(r)) | ((uint32_t)(S1) >> (32U - (uint32_t)(r))) ) \
                                                  : ( ((uint32_t)(S1) << ((uint32_t)(r) - 32U)) | ((uint32_t)(S0) >> (32U - ((uint32_t)(r) - 32U))) ) )

static const uint32_t RC[48] = {
    0x00000000,0x00000001,0x00000000,0x00008082,0x80000000,0x0000808a,0x80000000,0x80008000,
    0x00000000,0x0000808b,0x00000000,0x80000001,0x80000000,0x80008081,0x80000000,0x00008009,
    0x00000000,0x0000008a,0x00000000,0x00000088,0x00000000,0x80008009,0x00000000,0x8000000a,
    0x00000000,0x8000808b,0x80000000,0x0000008b,0x80000000,0x00008089,0x80000000,0x00008003,
    0x80000000,0x00008002,0x80000000,0x00000080,0x00000000,0x0000800a,0x80000000,0x8000000a,
    0x80000000,0x80008081,0x80000000,0x00008080,0x00000000,0x80000001,0x80000000,0x80008008
};

static const uint32_t RhoRotCnst[24] = {
    1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44
};

static const uint32_t RhoYIndex[24] = {
    0,2,1,2,3,3,0,1,3,1,4,4,0,3,4,3,2,2,0,4,2,4,1,1
};

static const uint32_t PIXIndex[24] = {
    3,1,4,2,1,4,2,0,3,2,0,3,1,4,3,1,4,2,0,4,2,0,3,1
};

void ComputeSHA3_256(uint32_t *S)
{
    uint32_t sIndex = 0, index = 0, index1 = 0, x = 0, y = 0;
    uint32_t temp = 0, round = 0;
    uint32_t C[10], D[10];

    for (index = 0; index < 50; index += 2) {
        index1 = S[index];
        temp   = S[index+1];
        S[index]   = (temp << 24) | ((temp & 0x0000FF00) << 8) | ((temp & 0x00FF0000) >> 8) | (temp >> 24);
        S[index+1] = (index1 << 24) | ((index1 & 0x0000FF00) << 8) | ((index1 & 0x00FF0000) >> 8) | (index1 >> 24);
    }

    for (round = 0; round < 48; round += 2) {
        C[0]=S[0];  C[1]=S[1];  C[2]=S[2];  C[3]=S[3];  C[4]=S[4];
        C[5]=S[5];  C[6]=S[6];  C[7]=S[7];  C[8]=S[8];  C[9]=S[9];
        C[0]^=S[10];C[1]^=S[11];C[2]^=S[12];C[3]^=S[13];C[4]^=S[14];
        C[5]^=S[15];C[6]^=S[16];C[7]^=S[17];C[8]^=S[18];C[9]^=S[19];
        C[0]^=S[20];C[1]^=S[21];C[2]^=S[22];C[3]^=S[23];C[4]^=S[24];
        C[5]^=S[25];C[6]^=S[26];C[7]^=S[27];C[8]^=S[28];C[9]^=S[29];
        C[0]^=S[30];C[1]^=S[31];C[2]^=S[32];C[3]^=S[33];C[4]^=S[34];
        C[5]^=S[35];C[6]^=S[36];C[7]^=S[37];C[8]^=S[38];C[9]^=S[39];
        C[0]^=S[40];C[1]^=S[41];C[2]^=S[42];C[3]^=S[43];C[4]^=S[44];
        C[5]^=S[45];C[6]^=S[46];C[7]^=S[47];C[8]^=S[48];C[9]^=S[49];

        D[0] = (C[2] << 1) | ((C[3] & 0x80000000U) >> 31);
        D[1] = (C[3] << 1) | ((C[2] & 0x80000000U) >> 31);
        D[2] = (C[4] << 1) | ((C[5] & 0x80000000U) >> 31);
        D[3] = (C[5] << 1) | ((C[4] & 0x80000000U) >> 31);
        D[4] = (C[6] << 1) | ((C[7] & 0x80000000U) >> 31);
        D[5] = (C[7] << 1) | ((C[6] & 0x80000000U) >> 31);
        D[6] = (C[8] << 1) | ((C[9] & 0x80000000U) >> 31);
        D[7] = (C[9] << 1) | ((C[8] & 0x80000000U) >> 31);
        D[8] = (C[0] << 1) | ((C[1] & 0x80000000U) >> 31);
        D[9] = (C[1] << 1) | ((C[0] & 0x80000000U) >> 31);

        D[2]^=C[0]; D[3]^=C[1]; D[4]^=C[2]; D[5]^=C[3]; D[6]^=C[4];
        D[7]^=C[5]; D[8]^=C[6]; D[9]^=C[7]; D[0]^=C[8]; D[1]^=C[9];

        index1 = 0;
        for (index = 0; index < 50; index += 10) {
            S[index+0]^=D[index1+0]; S[index+1]^=D[index1+1]; S[index+2]^=D[index1+2]; S[index+3]^=D[index1+3]; S[index+4]^=D[index1+4];
            S[index+5]^=D[index1+5]; S[index+6]^=D[index1+6]; S[index+7]^=D[index1+7]; S[index+8]^=D[index1+8]; S[index+9]^=D[index1+9];
        }

        y = 1;
        for (index = 0; index < 24; index += 4) {
            x = y; y = RhoYIndex[index];   sIndex = ((x + y*5U) << 1);
            temp = S[sIndex]; index1 = S[sIndex+1]; x = RhoRotCnst[index];
            S[sIndex] = ROTL32(temp, index1, x); S[sIndex+1] = ROTL32(index1, temp, x);

            x = y; y = RhoYIndex[index+1]; sIndex = ((x + y*5U) << 1);
            temp = S[sIndex]; index1 = S[sIndex+1]; x = RhoRotCnst[index+1];
            S[sIndex] = ROTL32(temp, index1, x); S[sIndex+1] = ROTL32(index1, temp, x);

            x = y; y = RhoYIndex[index+2]; sIndex = ((x + y*5U) << 1);
            temp = S[sIndex]; index1 = S[sIndex+1]; x = RhoRotCnst[index+2];
            S[sIndex] = ROTL32(temp, index1, x); S[sIndex+1] = ROTL32(index1, temp, x);

            x = y; y = RhoYIndex[index+3]; sIndex = ((x + y*5U) << 1);
            temp = S[sIndex]; index1 = S[sIndex+1]; x = RhoRotCnst[index+3];
            S[sIndex] = ROTL32(temp, index1, x); S[sIndex+1] = ROTL32(index1, temp, x);
        }

        temp = S[6]; index1 = S[7];
        S[6]=S[36]; S[7]=S[37]; S[36]=S[34]; S[37]=S[35]; S[34]=S[22]; S[35]=S[23];
        S[22]=S[14]; S[23]=S[15]; S[14]=S[20]; S[15]=S[21]; S[20]=S[2];  S[21]=S[3];
        S[2]=S[12];  S[3]=S[13];  S[12]=S[18]; S[13]=S[19]; S[18]=S[44]; S[19]=S[45];
        S[44]=S[28]; S[45]=S[29]; S[28]=S[40]; S[29]=S[41]; S[40]=S[4];  S[41]=S[5];
        S[4]=S[24];  S[5]=S[25];  S[24]=S[26]; S[25]=S[27]; S[26]=S[38]; S[27]=S[39];
        S[38]=S[46]; S[39]=S[47]; S[46]=S[30]; S[47]=S[31]; S[30]=S[8];  S[31]=S[9];
        S[8]=S[48];  S[9]=S[49];  S[48]=S[42]; S[49]=S[43]; S[42]=S[16]; S[43]=S[17];
        S[16]=S[32]; S[17]=S[33]; S[32]=S[10]; S[33]=S[11]; S[10]=temp;  S[11]=index1;

        temp=S[0]; index=S[2]; x=S[1]; y=S[3];
        S[0]^=(S[2]^0xFFFFFFFFU)&S[4];  S[1]^=(S[3]^0xFFFFFFFFU)&S[5];
        S[2]^=(S[4]^0xFFFFFFFFU)&S[6];  S[3]^=(S[5]^0xFFFFFFFFU)&S[7];
        S[4]^=(S[6]^0xFFFFFFFFU)&S[8];  S[5]^=(S[7]^0xFFFFFFFFU)&S[9];
        S[6]^=(S[8]^0xFFFFFFFFU)&temp;  S[7]^=(S[9]^0xFFFFFFFFU)&x;
        S[8]^=(temp^0xFFFFFFFFU)&index; S[9]^=(x^0xFFFFFFFFU)&y;

        temp=S[10]; index=S[12]; x=S[11]; y=S[13];
        S[10]^=(S[12]^0xFFFFFFFFU)&S[14]; S[11]^=(S[13]^0xFFFFFFFFU)&S[15];
        S[12]^=(S[14]^0xFFFFFFFFU)&S[16]; S[13]^=(S[15]^0xFFFFFFFFU)&S[17];
        S[14]^=(S[16]^0xFFFFFFFFU)&S[18]; S[15]^=(S[17]^0xFFFFFFFFU)&S[19];
        S[16]^=(S[18]^0xFFFFFFFFU)&temp;  S[17]^=(S[19]^0xFFFFFFFFU)&x;
        S[18]^=(temp^0xFFFFFFFFU)&index;  S[19]^=(x^0xFFFFFFFFU)&y;

        temp=S[20]; index=S[22]; x=S[21]; y=S[23];
        S[20]^=(S[22]^0xFFFFFFFFU)&S[24]; S[21]^=(S[23]^0xFFFFFFFFU)&S[25];
        S[22]^=(S[24]^0xFFFFFFFFU)&S[26]; S[23]^=(S[25]^0xFFFFFFFFU)&S[27];
        S[24]^=(S[26]^0xFFFFFFFFU)&S[28]; S[25]^=(S[27]^0xFFFFFFFFU)&S[29];
        S[26]^=(S[28]^0xFFFFFFFFU)&temp;  S[27]^=(S[29]^0xFFFFFFFFU)&x;
        S[28]^=(temp^0xFFFFFFFFU)&index;  S[29]^=(x^0xFFFFFFFFU)&y;

        temp=S[30]; index=S[32]; x=S[31]; y=S[33];
        S[30]^=(S[32]^0xFFFFFFFFU)&S[34]; S[31]^=(S[33]^0xFFFFFFFFU)&S[35];
        S[32]^=(S[34]^0xFFFFFFFFU)&S[36]; S[33]^=(S[35]^0xFFFFFFFFU)&S[37];
        S[34]^=(S[36]^0xFFFFFFFFU)&S[38]; S[35]^=(S[37]^0xFFFFFFFFU)&S[39];
        S[36]^=(S[38]^0xFFFFFFFFU)&temp;  S[37]^=(S[39]^0xFFFFFFFFU)&x;
        S[38]^=(temp^0xFFFFFFFFU)&index;  S[39]^=(x^0xFFFFFFFFU)&y;

        temp=S[40]; index=S[42]; x=S[41]; y=S[43];
        S[40]^=(S[42]^0xFFFFFFFFU)&S[44]; S[41]^=(S[43]^0xFFFFFFFFU)&S[45];
        S[42]^=(S[44]^0xFFFFFFFFU)&S[46]; S[43]^=(S[45]^0xFFFFFFFFU)&S[47];
        S[44]^=(S[46]^0xFFFFFFFFU)&S[48]; S[45]^=(S[47]^0xFFFFFFFFU)&S[49];
        S[46]^=(S[48]^0xFFFFFFFFU)&temp;  S[47]^=(S[49]^0xFFFFFFFFU)&x;
        S[48]^=(temp^0xFFFFFFFFU)&index;  S[49]^=(x^0xFFFFFFFFU)&y;

        S[0]^=RC[round]; S[1]^=RC[round+1];
    }
}

void geenratekeyHMAC(uint8_t *pk_k, uint8_t *sk_k, uint8_t *keylocal)
{
    uint8_t *sharedSecret, *check;
    cudaMalloc((void**)&sharedSecret, BATCH*KYBER_INDCPA_PUBLICKEYBYTES);
    cudaMallocHost((void**)&check, BATCH*KYBER_INDCPA_PUBLICKEYBYTES);

    scalar_multiplication<<<BATCH, KYBER_INDCPA_PUBLICKEYBYTES>>>(pk_k, sharedSecret, sk_k);
    sha256_gpu<<<BATCH, 1>>>(sharedSecret, keylocal, KYBER_INDCPA_PUBLICKEYBYTES);
}

void HMAC(uint8_t *inputMsg, int noOfInput, uint8_t *Key, uint8_t *macDigest)
{
    uint32_t S0[50] = {0}, S1[50] = {0};
    uint32_t A, B, C, D, r = 34;
    int index = 0;

    A = Key[0] ^ 0x36363636U; B = Key[1] ^ 0x36363636U; C = Key[2] ^ 0x36363636U; D = Key[3] ^ 0x36363636U;
    S0[0]=A; S0[1]=B; S0[2]=C; S0[3]=D;
    for (index = 4; index <= 33; ++index) S0[index] = 0x36363636U;

    ComputeSHA3_256(S0);

    for (index = 0; index < noOfInput; index += 2) {
        A = inputMsg[index];
        B = inputMsg[index + 1];
        S0[index]   ^= (B << 24) | ((B & 0x0000FF00U) << 8) | ((B & 0x00FF0000U) >> 8) | (B >> 24);
        S0[index+1] ^= (A << 24) | ((A & 0x0000FF00U) << 8) | ((A & 0x00FF0000U) >> 8) | (A >> 24);
    }
    S0[index+1] ^= 0x01000000U;
    S0[r-1]     ^= 0x80000000U;

    ComputeSHA3_256(S0);

    A = Key[0] ^ 0x5C5C5C5CU; B = Key[1] ^ 0x5C5C5C5CU; C = Key[2] ^ 0x5C5C5C5CU; D = Key[3] ^ 0x5C5C5C5CU;
    S1[0]=A; S1[1]=B; S1[2]=C; S1[3]=D;
    for (index = 4; index <= 33; ++index) S1[index] = 0x5C5C5C5CU;

    ComputeSHA3_256(S1);

    S1[0]^=S0[0]; S1[1]^=S0[1]; S1[2]^=S0[2]; S1[3]^=S0[3];
    S1[4]^=S0[4]; S1[5]^=S0[5]; S1[6]^=S0[6]; S1[7]^=S0[7];
    S1[8]^=0x00000001U; S1[r-1]^=0x80000000U;

    ComputeSHA3_256(S1);

    macDigest[0]= (uint8_t)S1[0]; macDigest[1]= (uint8_t)S1[1]; macDigest[2]= (uint8_t)S1[2]; macDigest[3]= (uint8_t)S1[3];
    macDigest[4]= (uint8_t)S1[4]; macDigest[5]= (uint8_t)S1[5]; macDigest[6]= (uint8_t)S1[6]; macDigest[7]= (uint8_t)S1[7];
}

void concatenate_HMAC(uint8_t *output, uint8_t *hmac)
{
    for (int i = 0; i < 8; i++) output[i + KYBER_INDCPA_BYTES] = hmac[i];
}

int check_HMAC(uint8_t *h_m1, uint8_t *h_m2)
{
    for (int j = 0; j < BATCH; j++) {
        for (int i = 0; i < 8; i++) {
            if (h_m1[j*8 + i] != h_m2[j*8 + i]) {
                printf("Error: HMAC not verified.\n");
                return 0;
            }
        }
    }
    printf("HMAC verified.\n");
    return 1;
}

void geenrateSymKey(uint8_t *keySym)
{
    uint8_t *sharedSecret, *check, *generatingPoint, *randomNumber;

    cudaMalloc((void**)&sharedSecret,     BATCH*KYBER_INDCPA_PUBLICKEYBYTES);
    cudaMalloc((void**)&generatingPoint,  BATCH*KYBER_INDCPA_PUBLICKEYBYTES);
    cudaMalloc((void**)&randomNumber,     BATCH*KYBER_INDCPA_PUBLICKEYBYTES);
    cudaMallocHost((void**)&check,        BATCH*KYBER_INDCPA_PUBLICKEYBYTES);

    srand((unsigned)time(NULL));
    for (int i = 0; i < (int)KYBER_INDCPA_PUBLICKEYBYTES; i++) check[i] = (uint8_t)(rand() % KYBER_N);

    cudaMemcpy(generatingPoint, check, BATCH*KYBER_SSBYTES, cudaMemcpyHostToDevice);
    cudaMemcpy(randomNumber,    check, BATCH*KYBER_SSBYTES, cudaMemcpyHostToDevice);

    scalar_multiplication<<<BATCH, KYBER_INDCPA_PUBLICKEYBYTES>>>(generatingPoint, sharedSecret, randomNumber);
    sha256_gpu<<<BATCH, 1>>>(sharedSecret, keySym, KYBER_INDCPA_PUBLICKEYBYTES);
}
