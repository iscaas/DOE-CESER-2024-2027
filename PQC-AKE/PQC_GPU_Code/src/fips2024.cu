#include "../include/fips2024.cuh"
#include "../include/params.h"

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72
#define MODN(X) ((X) & (KYBER_N-1))
#define h1 (1 << (SABER_EQ - SABER_EP - 1))
#define h2 ((1 << (SABER_EP - 2)) - (1 << (SABER_EP - SABER_ET - 1)) + (1 << (SABER_EQ - SABER_EP - 1)))

#define R64(a,b,c) (((a) << (b)) ^ ((a) >> (c)))
#define NROUNDS 24
#define ROL(a, off) (((a) << (off)) ^ ((a) >> (64 - (off))))

__constant__ uint64_t rc[5][NROUNDS] = {
    { 0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL,
      0x8000000080008000ULL, 0x000000000000808BULL, 0x0000000080000001ULL,
      0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008AULL,
      0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
      0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL,
      0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
      0x000000000000800AULL, 0x800000008000000AULL, 0x8000000080008081ULL,
      0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL },
    { 0ULL }, { 0ULL }, { 0ULL }, { 0ULL }
};

__constant__ int ro[25][2] = {
  { 0,64 }, { 44,20 }, { 43,21 }, { 21,43 }, { 14,50 },
  { 1,63 }, { 6,58 },  { 25,39 }, { 8,56 },  { 18,46 },
  { 62,2 }, { 55,9 },  { 39,25 }, { 41,23 }, { 2,62 },
  { 28,36 },{ 20,44 }, { 3,61 },  { 45,19 }, { 61,3 },
  { 27,37 },{ 36,28 }, { 10,54 }, { 15,49 }, { 56,8 }
};

__constant__ int a[25] = {
  0,6,12,18,24, 1,7,13,19,20, 2,8,14,15,21, 3,9,10,16,22, 4,5,11,17,23
};

__constant__ int b[25] = {
  0,1,2,3,4, 1,2,3,4,0, 2,3,4,0,1, 3,4,0,1,2, 4,0,1,2,3
};

__constant__ int c[25][3] = {
  {0,1,2},{1,2,3},{2,3,4},{3,4,0},{4,0,1},
  {5,6,7},{6,7,8},{7,8,9},{8,9,5},{9,5,6},
  {10,11,12},{11,12,13},{12,13,14},{13,14,10},{14,10,11},
  {15,16,17},{16,17,18},{17,18,19},{18,19,15},{19,15,16},
  {20,21,22},{21,22,23},{22,23,24},{23,24,20},{24,20,21}
};

__constant__ int d[25] = {
  0,1,2,3,4, 10,11,12,13,14, 20,21,22,23,24, 5,6,7,8,9, 15,16,17,18,19
};

__device__ __forceinline__ uint64_t load64(const uint8_t *x)
{
  uint64_t r = 0;
  #pragma unroll
  for (int i = 0; i < 8; ++i) r |= (uint64_t)x[i] << (8 * i);
  return r;
}

__device__ __forceinline__ void store64(uint8_t *x, uint64_t u)
{
  #pragma unroll
  for (int i = 0; i < 8; ++i) { x[i] = (uint8_t)u; u >>= 8; }
}

__constant__ const uint64_t KeccakF_RoundConstants[NROUNDS] = {
  0x0000000000000001ULL,0x0000000000008082ULL,0x800000000000808aULL,0x8000000080008000ULL,
  0x000000000000808bULL,0x0000000080000001ULL,0x8000000080008081ULL,0x8000000000008009ULL,
  0x000000000000008aULL,0x0000000000000088ULL,0x0000000080008009ULL,0x000000008000000aULL,
  0x000000008000808bULL,0x800000000000008bULL,0x8000000000008089ULL,0x8000000000008003ULL,
  0x8000000000008002ULL,0x8000000000000080ULL,0x000000000000800aULL,0x800000008000000aULL,
  0x8000000080008081ULL,0x8000000000008080ULL,0x0000000080000001ULL,0x8000000080008008ULL
};

__device__ void KeccakF1600_StatePermute(uint64_t *state)
{
  int round;
  uint64_t Aba,Abe,Abi,Abo,Abu,Aga,Age,Agi,Ago,Agu,Aka,Ake,Aki,Ako,Aku,Ama,Ame,Ami,Amo,Amu,Asa,Ase,Asi,Aso,Asu;
  uint64_t BCa,BCe,BCi,BCo,BCu,Da,De,Di,Do,Du,Eba,Ebe,Ebi,Ebo,Ebu,Ega,Ege,Egi,Ego,Egu,Eka,Eke,Eki,Eko,Eku,Ema,Eme,Emi,Emo,Emu,Esa,Ese,Esi,Eso,Esu;

  Aba=state[0]; Abe=state[1]; Abi=state[2]; Abo=state[3]; Abu=state[4];
  Aga=state[5]; Age=state[6]; Agi=state[7]; Ago=state[8]; Agu=state[9];
  Aka=state[10];Ake=state[11];Aki=state[12];Ako=state[13];Aku=state[14];
  Ama=state[15];Ame=state[16];Ami=state[17];Amo=state[18];Amu=state[19];
  Asa=state[20];Ase=state[21];Asi=state[22];Aso=state[23];Asu=state[24];

  for (round = 0; round < NROUNDS; round += 2) {
    BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
    BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;
    BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
    BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
    BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

    Da = BCu ^ ROL(BCe, 1);
    De = BCa ^ ROL(BCi, 1);
    Di = BCe ^ ROL(BCo, 1);
    Do = BCi ^ ROL(BCu, 1);
    Du = BCo ^ ROL(BCa, 1);

    Aba ^= Da;  BCa = Aba;
    Age ^= De;  BCe = ROL(Age, 44);
    Aki ^= Di;  BCi = ROL(Aki, 43);
    Amo ^= Do;  BCo = ROL(Amo, 21);
    Asu ^= Du;  BCu = ROL(Asu, 14);
    Eba = BCa ^ ((~BCe) & BCi);
    Eba ^= KeccakF_RoundConstants[round];
    Ebe = BCe ^ ((~BCi) & BCo);
    Ebi = BCi ^ ((~BCo) & BCu);
    Ebo = BCo ^ ((~BCu) & BCa);
    Ebu = BCu ^ ((~BCa) & BCe);

    Abo ^= Do;  BCa = ROL(Abo, 28);
    Agu ^= Du;  BCe = ROL(Agu, 20);
    Aka ^= Da;  BCi = ROL(Aka, 3);
    Ame ^= De;  BCo = ROL(Ame, 45);
    Asi ^= Di;  BCu = ROL(Asi, 61);
    Ega = BCa ^ ((~BCe) & BCi);
    Ege = BCe ^ ((~BCi) & BCo);
    Egi = BCi ^ ((~BCo) & BCu);
    Ego = BCo ^ ((~BCu) & BCa);
    Egu = BCu ^ ((~BCa) & BCe);

    Abe ^= De;  BCa = ROL(Abe, 1);
    Agi ^= Di;  BCe = ROL(Agi, 6);
    Ako ^= Do;  BCi = ROL(Ako, 25);
    Amu ^= Du;  BCo = ROL(Amu, 8);
    Asa ^= Da;  BCu = ROL(Asa, 18);
    Eka = BCa ^ ((~BCe) & BCi);
    Eke = BCe ^ ((~BCi) & BCo);
    Eki = BCi ^ ((~BCo) & BCu);
    Eko = BCo ^ ((~BCu) & BCa);
    Eku = BCu ^ ((~BCa) & BCe);

    Abu ^= Du;  BCa = ROL(Abu, 27);
    Aga ^= Da;  BCe = ROL(Aga, 36);
    Ake ^= De;  BCi = ROL(Ake, 10);
    Ami ^= Di;  BCo = ROL(Ami, 15);
    Aso ^= Do;  BCu = ROL(Aso, 56);
    Ema = BCa ^ ((~BCe) & BCi);
    Eme = BCe ^ ((~BCi) & BCo);
    Emi = BCi ^ ((~BCo) & BCu);
    Emo = BCo ^ ((~BCu) & BCa);
    Emu = BCu ^ ((~BCa) & BCe);

    Abi ^= Di;  BCa = ROL(Abi, 62);
    Ago ^= Do;  BCe = ROL(Ago, 55);
    Aku ^= Du;  BCi = ROL(Aku, 39);
    Ama ^= Da;  BCo = ROL(Ama, 41);
    Ase ^= De;  BCu = ROL(Ase, 2);
    Esa = BCa ^ ((~BCe) & BCi);
    Ese = BCe ^ ((~BCi) & BCo);
    Esi = BCi ^ ((~BCo) & BCu);
    Eso = BCo ^ ((~BCu) & BCa);
    Esu = BCu ^ ((~BCa) & BCe);

    BCa = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
    BCe = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
    BCi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
    BCo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
    BCu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

    Da = BCu ^ ROL(BCe, 1);
    De = BCa ^ ROL(BCi, 1);
    Di = BCe ^ ROL(BCo, 1);
    Do = BCi ^ ROL(BCu, 1);
    Du = BCo ^ ROL(BCa, 1);

    Eba ^= Da;  BCa = Eba;
    Ege ^= De;  BCe = ROL(Ege, 44);
    Eki ^= Di;  BCi = ROL(Eki, 43);
    Emo ^= Do;  BCo = ROL(Emo, 21);
    Esu ^= Du;  BCu = ROL(Esu, 14);
    Aba = BCa ^ ((~BCe) & BCi);
    Aba ^= KeccakF_RoundConstants[round+1];
    Abe = BCe ^ ((~BCi) & BCo);
    Abi = BCi ^ ((~BCo) & BCu);
    Abo = BCo ^ ((~BCu) & BCa);
    Abu = BCu ^ ((~BCa) & BCe);

    Ebo ^= Do;  BCa = ROL(Ebo, 28);
    Egu ^= Du;  BCe = ROL(Egu, 20);
    Eka ^= Da;  BCi = ROL(Eka, 3);
    Eme ^= De;  BCo = ROL(Eme, 45);
    Esi ^= Di;  BCu = ROL(Esi, 61);
    Aga = BCa ^ ((~BCe) & BCi);
    Age = BCe ^ ((~BCi) & BCo);
    Agi = BCi ^ ((~BCo) & BCu);
    Ago = BCo ^ ((~BCu) & BCa);
    Agu = BCu ^ ((~BCa) & BCe);

    Ebe ^= De;  BCa = ROL(Ebe, 1);
    Egi ^= Di;  BCe = ROL(Egi, 6);
    Eko ^= Do;  BCi = ROL(Eko, 25);
    Emu ^= Du;  BCo = ROL(Emu, 8);
    Esa ^= Da;  BCu = ROL(Esa, 18);
    Aka = BCa ^ ((~BCe) & BCi);
    Ake = BCe ^ ((~BCi) & BCo);
    Aki = BCi ^ ((~BCo) & BCu);
    Ako = BCo ^ ((~BCu) & BCa);
    Aku = BCu ^ ((~BCa) & BCe);

    Ebu ^= Du;  BCa = ROL(Ebu, 27);
    Ega ^= Da;  BCe = ROL(Ega, 36);
    Eke ^= De;  BCi = ROL(Eke, 10);
    Emi ^= Di;  BCo = ROL(Emi, 15);
    Eso ^= Do;  BCu = ROL(Eso, 56);
    Ama = BCa ^ ((~BCe) & BCi);
    Ame = BCe ^ ((~BCi) & BCo);
    Ami = BCi ^ ((~BCo) & BCu);
    Amo = BCo ^ ((~BCu) & BCa);
    Amu = BCu ^ ((~BCa) & BCe);

    Ebi ^= Di;  BCa = ROL(Ebi, 62);
    Ego ^= Do;  BCe = ROL(Ego, 55);
    Eku ^= Du;  BCi = ROL(Eku, 39);
    Ema ^= Da;  BCo = ROL(Ema, 41);
    Ese ^= De;  BCu = ROL(Ese, 2);
    Asa = BCa ^ ((~BCe) & BCi);
    Ase = BCe ^ ((~BCi) & BCo);
    Asi = BCi ^ ((~BCo) & BCu);
    Aso = BCo ^ ((~BCu) & BCa);
    Asu = BCu ^ ((~BCa) & BCe);
  }

  state[0]=Aba; state[1]=Abe; state[2]=Abi; state[3]=Abo; state[4]=Abu;
  state[5]=Aga; state[6]=Age; state[7]=Agi; state[8]=Ago; state[9]=Agu;
  state[10]=Aka; state[11]=Ake; state[12]=Aki; state[13]=Ako; state[14]=Aku;
  state[15]=Ama; state[16]=Ame; state[17]=Ami; state[18]=Amo; state[19]=Amu;
  state[20]=Asa; state[21]=Ase; state[22]=Asi; state[23]=Aso; state[24]=Asu;
}

__device__ void keccak_absorb(uint64_t *s, unsigned int r, const uint8_t *m, unsigned long long mlen, uint8_t p)
{
  unsigned long long i;
  uint8_t t[200];

  while (mlen >= r) {
    for (i = 0; i < r/8; ++i) s[i] ^= load64(m + 8*i);
    KeccakF1600_StatePermute(s);
    mlen -= r; m += r;
  }

  for (i = 0; i < r; ++i) t[i] = 0;
  for (i = 0; i < mlen; ++i) t[i] = m[i];
  t[i] = p;
  t[r - 1] |= 128U;
  for (i = 0; i < r/8; ++i) s[i] ^= load64(t + 8*i);
}

__device__ void keccak_squeezeblocks(uint8_t *h, unsigned long long nblocks, uint64_t *s, unsigned int r)
{
  while (nblocks > 0) {
    KeccakF1600_StatePermute(s);
    for (unsigned int i = 0; i < (r >> 3); i++) store64(h + 8*i, s[i]);
    h += r; nblocks--;
  }
}

__device__ void shake128(uint8_t *out, unsigned long long outlen, const uint8_t *in, unsigned long long inlen)
{
  uint64_t s[25]; uint8_t t[SHAKE128_RATE]; unsigned long long nblocks = outlen / SHAKE128_RATE; size_t i;
  for (i = 0; i < 25; ++i) s[i] = 0;
  keccak_absorb(s, SHAKE128_RATE, in, inlen, 0x1F);
  keccak_squeezeblocks(out, nblocks, s, SHAKE128_RATE);
  out += nblocks * SHAKE128_RATE; outlen -= nblocks * SHAKE128_RATE;
  if (outlen) { keccak_squeezeblocks(t, 1, s, SHAKE128_RATE); for (i = 0; i < outlen; i++) out[i] = t[i]; }
}

__global__ void shake128_gpu(uint8_t *out, const uint8_t *in, size_t inlen, uint32_t outlen, uint32_t out_stride)
{
  uint32_t tid = threadIdx.x, bid = blockIdx.x;
  uint8_t p = 0x1F; uint32_t r = SHAKE128_RATE;
  __shared__ uint64_t A[25], Csh[25], Dsh[25], d_data[25];
  __shared__ uint8_t t[200];
  uint32_t i, count = 0;
  uint32_t nblocks = outlen / SHAKE128_RATE;
  outlen -= nblocks * SHAKE128_RATE;

  for (i = 0; i < 8; ++i) if (tid < 25) t[i*25 + tid] = 0;
  if (tid < 25) { A[tid] = 0; Csh[tid] = 0; Dsh[tid] = 0; d_data[tid] = 0; }

  while (inlen >= r) {
    if (tid < 17) d_data[tid] ^= load64(in + bid*KYBER_PUBLICKEYBYTES + 8*tid + count*r);
    if (tid < 25) {
      A[tid] = d_data[tid];
      for (int rr = 0; rr < NROUNDS; ++rr) {
        Csh[tid] = A[tid%5] ^ A[(tid%5)+5] ^ A[(tid%5)+10] ^ A[(tid%5)+15] ^ A[(tid%5)+20];
        Dsh[tid] = Csh[b[20 + (tid%5)]] ^ R64(Csh[b[5 + (tid%5)]], 1, 63);
        Csh[tid] = R64(A[a[tid]] ^ Dsh[b[tid]], ro[tid][0], ro[tid][1]);
        A[d[tid]] = Csh[c[tid][0]] ^ ((~Csh[c[tid][1]]) & Csh[c[tid][2]]);
        A[tid] ^= rc[(tid == 0) ? 0 : 1][rr];
      }
      d_data[tid] = A[tid];
    }
    inlen -= r; count++;
  }

  if (tid == 0) { t[inlen] = p; t[r - 1] |= 128U; }
  __syncthreads();

  uint32_t repeat = (uint32_t)(inlen / blockDim.x) + 1U;
  for (i = 0; i < repeat; i++) {
    if (tid < inlen) t[i*blockDim.x + tid] = in[i*blockDim.x + tid + count*r];
    inlen = (inlen > blockDim.x) ? (inlen - blockDim.x) : 0;
    __syncthreads();
  }

  if (tid < 21) d_data[tid] ^= load64(t + 8*tid);

  if (tid < 25) { A[tid] = 0; Csh[tid] = 0; Dsh[tid] = 0; }
  count = 0;

  while (nblocks > 0) {
    if (tid < 25) {
      A[tid] = d_data[tid];
      for (int rr = 0; rr < NROUNDS; ++rr) {
        Csh[tid] = A[tid%5] ^ A[(tid%5)+5] ^ A[(tid%5)+10] ^ A[(tid%5)+15] ^ A[(tid%5)+20];
        Dsh[tid] = Csh[b[20 + (tid%5)]] ^ R64(Csh[b[5 + (tid%5)]], 1, 63);
        Csh[tid] = R64(A[a[tid]] ^ Dsh[b[tid]], ro[tid][0], ro[tid][1]);
        A[d[tid]] = Csh[c[tid][0]] ^ ((~Csh[c[tid][1]]) & Csh[c[tid][2]]);
        A[tid] ^= rc[(tid == 0) ? 0 : 1][rr];
      }
      d_data[tid] = A[tid];
      store64(out + bid*out_stride + count*r + 8*tid, d_data[tid]);
    }
    count++; nblocks--;
  }

  if (outlen) {
    if (tid < 25) {
      A[tid] = d_data[tid];
      for (int rr = 0; rr < NROUNDS; ++rr) {
        Csh[tid] = A[tid%5] ^ A[(tid%5)+5] ^ A[(tid%5)+10] ^ A[(tid%5)+15] ^ A[(tid%5)+20];
        Dsh[tid] = Csh[b[20 + (tid%5)]] ^ R64(Csh[b[5 + (tid%5)]], 1, 63);
        Csh[tid] = R64(A[a[tid]] ^ Dsh[b[tid]], ro[tid][0], ro[tid][1]);
        A[d[tid]] = Csh[c[tid][0]] ^ ((~Csh[c[tid][1]]) & Csh[c[tid][2]]);
        A[tid] ^= rc[(tid == 0) ? 0 : 1][rr];
      }
      d_data[tid] = A[tid];
    }
    if (tid < outlen/8U) store64(out + bid*out_stride + count*r + 8*tid, d_data[tid]);
  }
  __syncthreads();
}

__global__ void sha3_256_gpu(uint8_t *output, uint8_t *input, unsigned long long inlen, uint32_t in_stride, uint32_t out_stride)
{
  uint64_t s[25]; uint8_t t[SHA3_256_RATE]; size_t i; uint32_t tid = threadIdx.x;
  for (i = 0; i < 25; ++i) s[i] = 0;
  keccak_absorb(s, SHA3_256_RATE, input + tid*in_stride, inlen, 0x06);
  keccak_squeezeblocks(t, 1, s, SHA3_256_RATE);
  for (i = 0; i < 32; i++) output[i + tid*out_stride] = t[i];
  __syncthreads();
}

__global__ void sha3_512_gpu(uint8_t *output, uint8_t *input, unsigned long long inlen)
{
  uint64_t s[25]; uint8_t t[SHA3_512_RATE]; size_t i; uint32_t tid = threadIdx.x;
  for (i = 0; i < 25; ++i) s[i] = 0;
  keccak_absorb(s, SHA3_512_RATE, input + tid*64U, inlen, 0x06);
  keccak_squeezeblocks(t, 1, s, SHA3_512_RATE);
  for (i = 0; i < 64; i++) output[i + tid*64U] = t[i];
  __syncthreads();
}

__device__ uint64_t load_littleendian(const uint8_t *x, int bytes)
{
  uint64_t r = x[0];
  for (int i = 1; i < bytes; i++) r |= (uint64_t)x[i] << (8 * i);
  return r;
}
