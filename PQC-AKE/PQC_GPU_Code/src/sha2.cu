#include <stdint.h>
#include <stddef.h>
#include <cuda_runtime.h>

#include "../include/params.h"

// Alias used below (matches your original)
#define blocks crypto_hashblocks_sha256

// ---------- SHA-256 ----------

__constant__ __device__ uint8_t kSha256IV[32] = {
  0x6a,0x09,0xe6,0x67, 0xbb,0x67,0xae,0x85, 0x3c,0x6e,0xf3,0x72, 0xa5,0x4f,0xf5,0x3a,
  0x51,0x0e,0x52,0x7f, 0x9b,0x05,0x68,0x8c, 0x1f,0x83,0xd9,0xab, 0x5b,0xe0,0xcd,0x19,
};

__device__ __forceinline__ uint32_t load_bigendian(const uint8_t *x) {
  return (uint32_t)x[3]
       | ((uint32_t)x[2] << 8)
       | ((uint32_t)x[1] << 16)
       | ((uint32_t)x[0] << 24);
}

__device__ __forceinline__ void store_bigendian(uint8_t *x, uint32_t u) {
  x[3] = (uint8_t)u; u >>= 8;
  x[2] = (uint8_t)u; u >>= 8;
  x[1] = (uint8_t)u; u >>= 8;
  x[0] = (uint8_t)u;
}

#define SHR(x,c)  ((x) >> (c))
#define ROTR(x,c) (((x) >> (c)) | ((x) << (32 - (c))))

#define Ch(x,y,z)    (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x,y,z)   (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sigma0(x)    (ROTR((x), 2) ^ ROTR((x),13) ^ ROTR((x),22))
#define Sigma1(x)    (ROTR((x), 6) ^ ROTR((x),11) ^ ROTR((x),25))
#define sigma0(x)    (ROTR((x), 7) ^ ROTR((x),18) ^ SHR((x), 3))
#define sigma1(x)    (ROTR((x),17) ^ ROTR((x),19) ^ SHR((x),10))

#define M(w0,w14,w9,w1) do { (w0) = sigma1((w14)) + (w9) + sigma0((w1)) + (w0); } while(0)

#define EXPAND \
  M(w0 ,w14,w9 ,w1 ); \
  M(w1 ,w15,w10,w2 ); \
  M(w2 ,w0 ,w11,w3 ); \
  M(w3 ,w1 ,w12,w4 ); \
  M(w4 ,w2 ,w13,w5 ); \
  M(w5 ,w3 ,w14,w6 ); \
  M(w6 ,w4 ,w15,w7 ); \
  M(w7 ,w5 ,w0 ,w8 ); \
  M(w8 ,w6 ,w1 ,w9 ); \
  M(w9 ,w7 ,w2 ,w10); \
  M(w10,w8 ,w3 ,w11); \
  M(w11,w9 ,w4 ,w12); \
  M(w12,w10,w5 ,w13); \
  M(w13,w11,w6 ,w14); \
  M(w14,w12,w7 ,w15); \
  M(w15,w13,w8 ,w0 )

// IMPORTANT: this macro is a do/while block; each use MUST end with a semicolon.
#define F(w,k) do {                  \
  T1 = h + Sigma1(e) + Ch(e,f,g) + (uint32_t)(k) + (w); \
  T2 = Sigma0(a) + Maj(a,b,c);       \
  h = g; g = f; f = e;               \
  e = d + T1;                        \
  d = c; c = b; b = a;               \
  a = T1 + T2;                       \
} while(0)

__device__ int crypto_hashblocks_sha256(uint8_t *statebytes, const uint8_t *in, size_t inlen)
{
  uint32_t state[8];
  uint32_t a,b,c,d,e,f,g,h,T1,T2;

  a = load_bigendian(statebytes +  0); state[0] = a;
  b = load_bigendian(statebytes +  4); state[1] = b;
  c = load_bigendian(statebytes +  8); state[2] = c;
  d = load_bigendian(statebytes + 12); state[3] = d;
  e = load_bigendian(statebytes + 16); state[4] = e;
  f = load_bigendian(statebytes + 20); state[5] = f;
  g = load_bigendian(statebytes + 24); state[6] = g;
  h = load_bigendian(statebytes + 28); state[7] = h;

  while (inlen >= 64) {
    uint32_t w0  = load_bigendian(in +  0);
    uint32_t w1  = load_bigendian(in +  4);
    uint32_t w2  = load_bigendian(in +  8);
    uint32_t w3  = load_bigendian(in + 12);
    uint32_t w4  = load_bigendian(in + 16);
    uint32_t w5  = load_bigendian(in + 20);
    uint32_t w6  = load_bigendian(in + 24);
    uint32_t w7  = load_bigendian(in + 28);
    uint32_t w8  = load_bigendian(in + 32);
    uint32_t w9  = load_bigendian(in + 36);
    uint32_t w10 = load_bigendian(in + 40);
    uint32_t w11 = load_bigendian(in + 44);
    uint32_t w12 = load_bigendian(in + 48);
    uint32_t w13 = load_bigendian(in + 52);
    uint32_t w14 = load_bigendian(in + 56);
    uint32_t w15 = load_bigendian(in + 60);

    F(w0 , 0x428a2f98U);
    F(w1 , 0x71374491U);
    F(w2 , 0xb5c0fbcfU);
    F(w3 , 0xe9b5dba5U);
    F(w4 , 0x3956c25bU);
    F(w5 , 0x59f111f1U);
    F(w6 , 0x923f82a4U);
    F(w7 , 0xab1c5ed5U);
    F(w8 , 0xd807aa98U);
    F(w9 , 0x12835b01U);
    F(w10, 0x243185beU);
    F(w11, 0x550c7dc3U);
    F(w12, 0x72be5d74U);
    F(w13, 0x80deb1feU);
    F(w14, 0x9bdc06a7U);
    F(w15, 0xc19bf174U);

    EXPAND;

    F(w0 , 0xe49b69c1U);
    F(w1 , 0xefbe4786U);
    F(w2 , 0x0fc19dc6U);
    F(w3 , 0x240ca1ccU);
    F(w4 , 0x2de92c6fU);
    F(w5 , 0x4a7484aaU);
    F(w6 , 0x5cb0a9dcU);
    F(w7 , 0x76f988daU);
    F(w8 , 0x983e5152U);
    F(w9 , 0xa831c66dU);
    F(w10, 0xb00327c8U);
    F(w11, 0xbf597fc7U);
    F(w12, 0xc6e00bf3U);
    F(w13, 0xd5a79147U);
    F(w14, 0x06ca6351U);
    F(w15, 0x14292967U);

    EXPAND;

    F(w0 , 0x27b70a85U);
    F(w1 , 0x2e1b2138U);
    F(w2 , 0x4d2c6dfcU);
    F(w3 , 0x53380d13U);
    F(w4 , 0x650a7354U);
    F(w5 , 0x766a0abbU);
    F(w6 , 0x81c2c92eU);
    F(w7 , 0x92722c85U);
    F(w8 , 0xa2bfe8a1U);
    F(w9 , 0xa81a664bU);
    F(w10, 0xc24b8b70U);
    F(w11, 0xc76c51a3U);
    F(w12, 0xd192e819U);
    F(w13, 0xd6990624U);
    F(w14, 0xf40e3585U);
    F(w15, 0x106aa070U);

    EXPAND;

    F(w0 , 0x19a4c116U);
    F(w1 , 0x1e376c08U);
    F(w2 , 0x2748774cU);
    F(w3 , 0x34b0bcb5U);
    F(w4 , 0x391c0cb3U);
    F(w5 , 0x4ed8aa4aU);
    F(w6 , 0x5b9cca4fU);
    F(w7 , 0x682e6ff3U);
    F(w8 , 0x748f82eeU);
    F(w9 , 0x78a5636fU);
    F(w10, 0x84c87814U);
    F(w11, 0x8cc70208U);
    F(w12, 0x90befffaU);
    F(w13, 0xa4506cebU);
    F(w14, 0xbef9a3f7U);
    F(w15, 0xc67178f2U);

    a += state[0]; b += state[1]; c += state[2]; d += state[3];
    e += state[4]; f += state[5]; g += state[6]; h += state[7];

    state[0] = a; state[1] = b; state[2] = c; state[3] = d;
    state[4] = e; state[5] = f; state[6] = g; state[7] = h;

    in    += 64;
    inlen -= 64;
  }

  store_bigendian(statebytes +  0, state[0]);
  store_bigendian(statebytes +  4, state[1]);
  store_bigendian(statebytes +  8, state[2]);
  store_bigendian(statebytes + 12, state[3]);
  store_bigendian(statebytes + 16, state[4]);
  store_bigendian(statebytes + 20, state[5]);
  store_bigendian(statebytes + 24, state[6]);
  store_bigendian(statebytes + 28, state[7]);

  return (int)inlen;
}

// Each launch computes SHA-256 of a single input buffer (one thread is enough)
__global__ void sha256_gpu(uint8_t *in, uint8_t *out, uint32_t inlen)
{
  if (threadIdx.x != 0 || blockIdx.x != 0) return;

  uint8_t h[32];
  uint8_t padded[128];
  uint32_t i;
  size_t bits = ((size_t)inlen) << 3;

  // Initialize state with IV (constant memory)
  for (i = 0; i < 32; ++i) h[i] = kSha256IV[i];

  (void)blocks(h, in, inlen);
  in    += inlen;
  inlen &= 63;
  in    -= inlen;

  for (i = 0; i < inlen; ++i) padded[i] = in[i];
  padded[inlen] = 0x80;

  if (inlen < 56) {
    for (i = inlen + 1; i < 56; ++i) padded[i] = 0;
    padded[56] = (uint8_t)(bits >> 56);
    padded[57] = (uint8_t)(bits >> 48);
    padded[58] = (uint8_t)(bits >> 40);
    padded[59] = (uint8_t)(bits >> 32);
    padded[60] = (uint8_t)(bits >> 24);
    padded[61] = (uint8_t)(bits >> 16);
    padded[62] = (uint8_t)(bits >> 8);
    padded[63] = (uint8_t)(bits);
    (void)blocks(h, padded, 64);
  } else {
    for (i = inlen + 1; i < 120; ++i) padded[i] = 0;
    padded[120] = (uint8_t)(bits >> 56);
    padded[121] = (uint8_t)(bits >> 48);
    padded[122] = (uint8_t)(bits >> 40);
    padded[123] = (uint8_t)(bits >> 32);
    padded[124] = (uint8_t)(bits >> 24);
    padded[125] = (uint8_t)(bits >> 16);
    padded[126] = (uint8_t)(bits >> 8);
    padded[127] = (uint8_t)(bits);
    (void)blocks(h, padded, 128);
  }

  for (i = 0; i < 32; ++i) out[i] = h[i];
}

// ---------- toy field helpers (uint8_t) ----------

__device__ __forceinline__ int is_point_at_infinity(uint8_t P) {
  return P == 0;
}

__device__ __forceinline__ void mod_add(uint8_t *r, uint8_t a, uint8_t b, uint8_t m) { *r = (uint8_t)((a + b) % m); }
__device__ __forceinline__ void mod_sub(uint8_t *r, uint8_t a, uint8_t b, uint8_t m) { *r = (uint8_t)((a + m - b) % m); }
__device__ __forceinline__ void mod_mult(uint8_t *r, uint8_t a, uint8_t b, uint8_t m){ *r = (uint8_t)((a * b) % m); }
__device__ __forceinline__ void mod(uint8_t *r, uint8_t a, uint8_t m)               { *r = (uint8_t)(a % m); }

// Extended Euclid over small ints
__device__ int gcdExtended_int(int a, int b, int *x, int *y) {
  if (a == 0) { *x = 0; *y = 1; return b; }
  int x1, y1;
  int g = gcdExtended_int(b % a, a, &x1, &y1);
  *x = y1 - (b / a) * x1;
  *y = x1;
  return g;
}

// Return 1 on success; 0 on failure. Result written only on success.
__device__ int mod_inv_u8(uint8_t *result, uint8_t A, uint8_t M) {
  int x, y;
  int g = gcdExtended_int((int)A, (int)M, &x, &y);
  if (g != 1) return 0;
  int v = x % (int)M; if (v < 0) v += (int)M;
  *result = (uint8_t)v;
  return 1;
}

__device__ void Point_Doubling(uint8_t P, uint8_t *R)
{
  if (is_point_at_infinity(P)) { *R = 0; return; }

  uint8_t slope, t, t2;
  const uint8_t mod_q = (uint8_t)(KYBER_N - 1); // toy modulus

  mod_mult(&t, P, P, mod_q);        // t = P^2
  mod_mult(&t2, t, t, mod_q);       // t2 = P^4
  mod_sub(&t, t2, 3, mod_q);        // t = P^4 - 3
  mod_mult(&t2, P, 2, mod_q);       // t2 = 2P
  if (!mod_inv_u8(&t2, t2, mod_q)) { *R = 0; return; } // no inverse -> infinity
  mod_mult(&slope, t, t2, mod_q);   // slope

  mod_mult(&t, slope, slope, mod_q);
  mod_mult(&t2, P, 2, mod_q);
  mod_sub(R, t, t2, mod_q);
}

__device__ void Point_Addition(uint8_t P, uint8_t S, uint8_t *outX)
{
  const uint8_t mod_q = (uint8_t)(KYBER_N - 1);

  if (is_point_at_infinity(P)) { *outX = S; return; }
  if (is_point_at_infinity(S)) { *outX = P; return; }

  uint8_t slope, t, t2;
  mod_sub(&t, S, P, mod_q);           // S - P
  if (!mod_inv_u8(&slope, t, mod_q)) { *outX = 0; return; } // no inverse -> infinity

  mod_mult(&t, slope, slope, mod_q);  // slope^2
  mod_sub(&t2, t, P, mod_q);          // slope^2 - P
  mod_sub(outX, t2, S, mod_q);        // slope^2 - P - S
}

// Each thread works on one byte (toy demo)
__global__ void scalar_multiplication(uint8_t *pk_k,
                                      uint8_t *sharedSecret,
                                      uint8_t *sk_k)
{
  const uint32_t nbytes = KYBER_INDCPA_PUBLICKEYBYTES;   // matches your caller’s intent
  uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
  if (tid >= nbytes) return;

  if (sk_k[tid] == 0) { sharedSecret[tid] = 0; return; }

  uint8_t P = pk_k[tid];
  uint8_t S = 0;

  if (is_point_at_infinity(sk_k[tid])) {
    sharedSecret[tid] = pk_k[tid];    // fixed assignment
    return;
  }

  Point_Doubling(P, &S);
  Point_Addition(P, S, &sharedSecret[tid]);
}
