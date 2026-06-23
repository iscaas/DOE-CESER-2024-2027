#include <cuda.h>
#include <cuda_runtime.h>
#include <cuda_fp16.h>
#include "../include/params.h"
#include "../include/reduce.h"

__global__ void polyvec_decompress_gpu(int16_t *r, uint8_t *a)
{
  uint32_t tid = threadIdx.x;
  uint32_t bIdx1 = blockIdx.x * KYBER_K * KYBER_N;
  uint32_t bIdx2 = blockIdx.x * KYBER_INDCPA_BYTES;
  uint16_t t[8];

#if (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 352))
  for (uint32_t i = 0; i < KYBER_K; i++) {
    uint32_t base = bIdx2 + i * (KYBER_N/8) * 11 + tid * 11;
    t[0] =  (a[base + 0]      ) | ((uint16_t)a[base + 1] << 8);
    t[1] =  (a[base + 1] >> 3) | ((uint16_t)a[base + 2] << 5);
    t[2] =  (a[base + 2] >> 6) | ((uint16_t)a[base + 3] << 2) | ((uint16_t)a[base + 4] << 10);
    t[3] =  (a[base + 4] >> 1) | ((uint16_t)a[base + 5] << 7);
    t[4] =  (a[base + 5] >> 4) | ((uint16_t)a[base + 6] << 4);
    t[5] =  (a[base + 6] >> 7) | ((uint16_t)a[base + 7] << 1) | ((uint16_t)a[base + 8] << 9);
    t[6] =  (a[base + 8] >> 2) | ((uint16_t)a[base + 9] << 6);
    t[7] =  (a[base + 9] >> 5) | ((uint16_t)a[base +10] << 3);
    for (uint32_t k = 0; k < 8; k++)
      r[bIdx1 + i*KYBER_N + 8*tid + k] = (int16_t)((((uint32_t)(t[k] & 0x7FF) * KYBER_Q) + 1024) >> 11);
  }
#else
  for (uint32_t i = 0; i < KYBER_K; i++) {
    uint32_t base = bIdx2 + i * (KYBER_N/4) * 5 + tid * 5;
    t[0] =  (a[base + 0]      ) | ((uint16_t)a[base + 1] << 8);
    t[1] =  (a[base + 1] >> 2) | ((uint16_t)a[base + 2] << 6);
    t[2] =  (a[base + 2] >> 4) | ((uint16_t)a[base + 3] << 4);
    t[3] =  (a[base + 3] >> 6) | ((uint16_t)a[base + 4] << 2);
    for (uint32_t k = 0; k < 4; k++)
      r[bIdx1 + i*KYBER_N + 4*tid + k] = (int16_t)((((uint32_t)(t[k] & 0x03FF) * KYBER_Q) + 512) >> 10);
  }
#endif
}

__global__ void poly_decompress_gpu(int16_t *r, uint8_t *a)
{
  uint32_t bIdx1 = blockIdx.x * KYBER_N;
  uint32_t bIdx2 = blockIdx.x * KYBER_INDCPA_BYTES;
  uint8_t t[8];

#if (KYBER_POLYCOMPRESSEDBYTES == 96)
  uint32_t tid = KYBER_POLYVECCOMPRESSEDBYTES + threadIdx.x * 3;
  t[0] = (uint8_t)(a[bIdx2 + tid + 0] >> 0);
  t[1] = (uint8_t)(a[bIdx2 + tid + 0] >> 3);
  t[2] = (uint8_t)((a[bIdx2 + tid + 0] >> 6) | (a[bIdx2 + tid + 1] << 2));
  t[3] = (uint8_t)(a[bIdx2 + tid + 1] >> 1);
  t[4] = (uint8_t)(a[bIdx2 + tid + 1] >> 4);
  t[5] = (uint8_t)((a[bIdx2 + tid + 1] >> 7) | (a[bIdx2 + tid + 2] << 1));
  t[6] = (uint8_t)(a[bIdx2 + tid + 2] >> 2);
  t[7] = (uint8_t)(a[bIdx2 + tid + 2] >> 5);
  for (uint8_t j = 0; j < 8; j++)
    r[bIdx1 + 8*threadIdx.x + j] = (int16_t)((((uint16_t)(t[j] & 7) * KYBER_Q) + 4) >> 3);

#elif (KYBER_POLYCOMPRESSEDBYTES == 128)
  uint32_t tid = KYBER_POLYVECCOMPRESSEDBYTES + threadIdx.x;
  r[bIdx1 + 2*threadIdx.x + 0] = (int16_t)((((uint16_t)(a[bIdx2 + tid + 0] & 0x0F) * KYBER_Q) + 8) >> 4);
  r[bIdx1 + 2*threadIdx.x + 1] = (int16_t)((((uint16_t)(a[bIdx2 + tid + 0] >> 4)     * KYBER_Q) + 8) >> 4);

#elif (KYBER_POLYCOMPRESSEDBYTES == 160)
  uint32_t tid = KYBER_POLYVECCOMPRESSEDBYTES + threadIdx.x * 5;
  t[0] = (uint8_t)(a[bIdx2 + tid + 0] >> 0);
  t[1] = (uint8_t)((a[bIdx2 + tid + 0] >> 5) | (a[bIdx2 + tid + 1] << 3));
  t[2] = (uint8_t)(a[bIdx2 + tid + 1] >> 2);
  t[3] = (uint8_t)((a[bIdx2 + tid + 1] >> 7) | (a[bIdx2 + tid + 2] << 1));
  t[4] = (uint8_t)((a[bIdx2 + tid + 2] >> 4) | (a[bIdx2 + tid + 3] << 4));
  t[5] = (uint8_t)(a[bIdx2 + tid + 3] >> 1);
  t[6] = (uint8_t)((a[bIdx2 + tid + 3] >> 6) | (a[bIdx2 + tid + 4] << 2));
  t[7] = (uint8_t)(a[bIdx2 + tid + 4] >> 3);
  for (uint8_t j = 0; j < 8; j++)
    r[bIdx1 + 8*threadIdx.x + j] = (int16_t)((((uint16_t)(t[j] & 31) * KYBER_Q) + 16) >> 5);
#endif
}

__global__ void poly_frommsg_gpu(int16_t *msgpoly, uint8_t *msg)
{
  uint32_t tid = threadIdx.x;
  uint32_t bIdx1 = blockIdx.x * KYBER_N;
  uint32_t bIdx2 = blockIdx.x * KYBER_INDCPA_MSGBYTES;

  for (uint32_t j = 0; j < 8; j++) {
    int16_t mask = -(int16_t)((msg[bIdx2 + tid] >> j) & 1);
    msgpoly[bIdx1 + 8*tid + j] = (int16_t)(mask & ((KYBER_Q + 1) / 2));
  }
}

__constant__ int16_t zetas_gpu[128] = {
  2285,2571,2970,1812,1493,1422,287,202,3158,622,1577,182,962,2127,1855,1468,
  573,2004,264,383,2500,1458,1727,3199,2648,1017,732,608,1787,411,3124,1758,
  1223,652,2777,1015,2036,1491,3047,1785,516,3321,3009,2663,1711,2167,126,
  1469,2476,3239,3058,830,107,1908,3082,2378,2931,961,1821,2604,448,2264,677,
  2054,2226,430,555,843,2078,871,1550,105,422,587,177,3094,3038,2869,1574,
  1653,3083,778,1159,3182,2552,1483,2727,1119,1739,644,2457,349,418,329,3173,
  3254,817,1097,603,610,1322,2044,1864,384,2114,3193,1218,1994,2455,220,2142,
  1670,2144,1799,2051,794,1819,2475,2459,478,3221,3021,996,991,958,1869,1522,1628
};

__constant__ int16_t zetas_inv_gpu[128] = {
  1701,1807,1460,2371,2338,2333,308,108,2851,870,854,1510,2535,1278,1530,1185,
  1659,1187,3109,874,1335,2111,136,1215,2945,1465,1285,2007,2719,2726,2232,2512,
  75,156,3000,2911,2980,872,2685,1590,2210,602,1846,777,147,2170,2551,246,1676,
  1755,460,291,235,3152,2742,2907,3224,1779,2458,1251,2486,2774,2899,1103,1275,
  2652,1065,2881,725,1508,2368,398,951,247,1421,3222,2499,271,90,853,1860,3203,
  1162,1618,666,320,8,2813,1544,282,1838,1293,2314,552,2677,2106,1571,205,2918,
  1542,2721,2597,2312,681,130,1602,1871,829,2946,3065,1325,2756,1861,1474,1202,
  2367,3147,1752,2707,171,3127,3042,1907,1836,1517,359,758,1441
};

__device__ int16_t montgomery_reduce_gpu(int32_t a)
{
  int16_t u = (int16_t)(a * QINV);
  int32_t t = (int32_t)u * KYBER_Q;
  t = (a - t) >> 16;
  return (int16_t)t;
}

__device__ int16_t montgomery_reduce_gpu64(int64_t a)
{
  int64_t u = a * Q_INV64;
  int32_t m = (int32_t)u;
  int64_t t = a - (int64_t)m * KYBER_Q;
  t >>= 32;
  return (int16_t)t;
}

__device__ static inline int16_t fqmul_gpu(int16_t a, int16_t b)
{
  return montgomery_reduce_gpu((int32_t)a * b);
}

__device__ int16_t barrett_reduce_gpu(int16_t a)
{
  const int16_t v = (int16_t)(((1U << 26) + KYBER_Q/2) / KYBER_Q);
  int16_t t = (int16_t)(((int32_t)v * a) >> 26);
  t = (int16_t)(t * KYBER_Q);
  return (int16_t)(a - t);
}

__device__ int16_t csubq_gpu(int16_t a)
{
  a = (int16_t)(a - KYBER_Q);
  a = (int16_t)(a + (int16_t)((a >> 15) & KYBER_Q));
  return a;
}

__device__ void poly_reduce_gpu(int16_t *r)
{
  uint32_t tid = threadIdx.x;
  for (uint32_t i = 0; i < KYBER_N / blockDim.x; i++)
    r[i*blockDim.x + tid] = barrett_reduce_gpu(r[i*blockDim.x + tid]);
}

__global__ void polyvec_reduce_gpu(int16_t *r)
{
  uint32_t tid = threadIdx.x;
  uint32_t bIdx = blockIdx.x * KYBER_K * KYBER_N;
  for (uint32_t i = 0; i < KYBER_K; i++)
    r[bIdx + i*KYBER_N + tid] = barrett_reduce_gpu(r[bIdx + i*KYBER_N + tid]);
}

__global__ void poly_reduce_g(int16_t *r)
{
  uint32_t bid = blockIdx.x, tid = threadIdx.x;
  r[bid*KYBER_N + tid] = barrett_reduce_gpu(r[bid*KYBER_N + tid]);
}

__device__ void ntt_gpu5(int16_t *a)
{
  uint32_t tid = threadIdx.x, temp2, idx1;
  uint32_t len = 128, j;
  int16_t t, zeta, tmp3 = KYBER_Q, u;
  int32_t x, t1;
  float f_level = 1.f, temp1, two = 2.f, f_len, f_tid = (float)threadIdx.x;
  uint64_t tmp2;

  temp1 = (float)(tid / len);
  j = (uint32_t)(temp1 * len + tid);
  idx1 = (uint32_t)(f_level + temp1);

  for (len = 128; len >= 2; len >>= 1) {
    f_len = (float)(len >> 1);
    zeta = zetas_gpu[idx1];

    asm volatile ("{\n\t"
      "mul.wide.s16 %0, %10, %11;\n\t"
      "div.approx.f32 %5, %16, %14;\n\t"
      "cvt.rzi.u32.f32 %6, %5;\n\t"
      "mul.wide.s32 %1, %0, %12;\n\t"
      "mul.f32 %7, %7, %15;\n\t"
      "cvt.s16.s32 %2, %1;\n\t"
      "mul.wide.s16 %3, %2, %13;\n\t"
      "add.f32 %5, %7, %5;\n\t"
      "cvt.rzi.u32.f32 %8, %5;\n\t"
      "cvt.rz.f32.u32 %5, %6;\n\t"
      "sub.s32 %3, %0, %3;\n\t"
      "mul.f32 %5, %5, %14;\n\t"
      "shr.b32 %3, %3, 16;\n\t"
      "add.f32 %5, %5, %16;\n\t"
      "cvt.s16.s32 %4, %3;\n\t"
      "}"
      : "+r"(x), "+l"(tmp2), "+h"(u), "+r"(t1), "+h"(t), "+f"(temp1), "+r"(temp2), "+f"(f_level), "+r"(idx1), "+r"(j)
      : "h"(zeta), "h"(a[j + len]), "r"(QINV), "h"(tmp3), "f"(f_len), "f"(two), "f"(f_tid));

    a[j + len] = (int16_t)(a[j] - t);
    a[j]       = (int16_t)(a[j] + t);

    __syncthreads();

    asm volatile ("{\n\t"
      "div.approx.f32 %2, %8, %6;\n\t"
      "cvt.rzi.u32.f32 %3, %2;\n\t"
      "mul.f32 %0, %0, %7;\n\t"
      "add.f32 %2, %2, %0;\n\t"
      "cvt.rzi.u32.f32 %5, %2;\n\t"
      "cvt.rz.f32.u32 %2, %3;\n\t"
      "mul.f32 %2, %2, %6;\n\t"
      "add.f32 %2, %2, %8;\n\t"
      "cvt.rzi.u32.f32 %4, %2;\n\t"
      "}"
      : "+f"(f_level), "+r"(idx1), "+f"(temp1), "+r"(temp2), "+r"(j), "+r"(idx1)
      : "f"(f_len), "f"(two), "f"(f_tid));
  }
}

__device__ void ntt_gpu4(int16_t *a)
{
  uint32_t tid = threadIdx.x, idx1, temp2, j;
  int16_t t, zeta;
  float f_level = 1.f, temp1, two = 2.f, f_len, f_tid = (float)threadIdx.x;

  for (uint32_t len = 128; len >= 2; len >>= 1) {
    f_len = (float)len;
    asm volatile ("{\n\t"
      "div.approx.f32 %2, %7, %5;\n\t"
      "cvt.rzi.u32.f32 %3, %2;\n\t"
      "cvt.rzi.u32.f32 %1, %0;\n\t"
      "add.u32 %1, %1, %3;\n\t"
      "mul.f32 %0, %0, %6;\n\t"
      "cvt.rz.f32.u32 %2, %3;\n\t"
      "mul.f32 %2, %2, %5;\n\t"
      "add.f32 %2, %2, %7;\n\t"
      "cvt.rzi.u32.f32 %4, %2;\n\t"
      "}"
      : "+f"(f_level), "+r"(idx1), "+f"(temp1), "+r"(temp2), "+r"(j)
      : "f"(f_len), "f"(two), "f"(f_tid));

    zeta = zetas_gpu[idx1];
    t    = fqmul_gpu(zeta, a[j + len]);
    a[j + len] = (int16_t)(a[j] - t);
    a[j]       = (int16_t)(a[j] + t);
    __syncthreads();
  }
}

__device__ void ntt_gpu3(int16_t *a)
{
  uint32_t tid = threadIdx.x, temp2, idx1, j;
  uint32_t len = 128;
  int16_t t, zeta, tmp3 = KYBER_Q, u;
  int32_t x, t1;
  float f_level = 1.f, temp1, two = 2.f, f_len, f_tid = (float)threadIdx.x;
  uint64_t tmp2;

  temp1 = (float)(tid / len);
  j     = (uint32_t)(temp1 * len + tid);
  idx1  = (uint32_t)(f_level + temp1);

  for (len = 128; len >= 2; len >>= 1) {
    f_len = (float)(len >> 1);
    zeta  = zetas_gpu[idx1];

    asm volatile ("{\n\t"
      "mul.wide.s16 %0, %5, %6;\n\t"
      "mul.wide.s32 %1, %0, %7;\n\t"
      "cvt.s16.s32 %2, %1;\n\t"
      "mul.wide.s16 %3, %2, %8;\n\t"
      "sub.s32 %3, %0, %3;\n\t"
      "shr.b32 %3, %3, 16;\n\t"
      "cvt.s16.s32 %4, %3;\n\t"
      "}"
      : "+r"(x), "+l"(tmp2), "+h"(u), "+r"(t1), "+h"(t)
      : "h"(zeta), "h"(a[j + len]), "r"(QINV), "h"(tmp3));

    a[j + len] = (int16_t)(a[j] - t);
    a[j]       = (int16_t)(a[j] + t);
    __syncthreads();

    asm volatile ("{\n\t"
      "div.approx.f32 %2, %8, %6;\n\t"
      "cvt.rzi.u32.f32 %3, %2;\n\t"
      "mul.f32 %0, %0, %7;\n\t"
      "add.f32 %2, %2, %0;\n\t"
      "cvt.rzi.u32.f32 %5, %2;\n\t"
      "cvt.rz.f32.u32 %2, %3;\n\t"
      "mul.f32 %2, %2, %6;\n\t"
      "add.f32 %2, %2, %8;\n\t"
      "cvt.rzi.u32.f32 %4, %2;\n\t"
      "}"
      : "+f"(f_level), "+r"(idx1), "+f"(temp1), "+r"(temp2), "+r"(j), "+r"(idx1)
      : "f"(f_len), "f"(two), "f"(f_tid));
  }
}

//precompute the next addresses + PTX fqmul
__device__ void ntt_gpu2(int16_t *a){    
    uint32_t tid = threadIdx.x;
    uint32_t len =128, j, level, s;
    int32_t x, t1;  
    int16_t t, zeta, u, tmp3 = KYBER_Q;
    int64_t tmp2;;
    level = 1;
    
    s = (tid/len);
    j = s * len + tid;          
    for(len = 128; len >= 2; len >>= 1) {        
        zeta = zetas_gpu[level + s];             
        // t = fqmul_gpu(zeta, a[j + len]);     
      asm volatile ("{\n\t"        
        "mul.wide.s16 %0, %5, %6;\n\t"  //x = (int32_t)zeta * a[j + len];       
        "mul.wide.s32 %1, %0, %7;\n\t" 
        "cvt.s16.s32 %2, %1;\n\t"       // u = x*QINV;    
        "mul.wide.s16 %3, %2, %8;\n\t"  // t1 = (int32_t)u*KYBER_Q;
        "sub.s32 %3, %0, %3;\n\t"       // t1 = x - t1;
        "shr.b32 %3, %3, 16;\n\t"       //
        "cvt.s16.s32 %4, %3;\n\t"       // t = t1 >> 16;  
        "}"
      : "+r"(x), "+l"(tmp2), "+h"(u) , "+r"(t1), "+h"(t): "h"(zeta), "h"(a[j+len]), "r"(QINV), "h"(tmp3)) ;      
        a[j + len] = a[j] - t;
        a[j] = a[j] + t;
        __syncthreads();        
        level = level << 1;
        x = len/2;
        s = tid/x;
        j = s * x + tid;              
        // printf("len: %u tid: %u s: %u\n", len, tid, s);
    }
}

 // PTX fqmul
__device__ void ntt_gpu1(int16_t *a){    
    uint32_t tid = threadIdx.x;
    uint32_t len, j, level, s;
    int32_t x, t1;        
    int16_t t, zeta, u, tmp3 = KYBER_Q;
    int64_t tmp2;
    level = 1;
    
    for(len = 128; len >= 2; len >>= 1) {        
        zeta = zetas_gpu[level + (tid/len)];                
        j = (tid/len) * len + tid;          
            
        // t = fqmul_gpu(zeta, a[j + len]);        
        // x = (int32_t)zeta * a[j + len];    
        //    
      asm volatile ("{\n\t"        
        "mul.wide.s16 %0, %5, %6;\n\t"  //x = (int32_t)zeta * a[j + len];       
        "mul.wide.s32 %1, %0, %7;\n\t" 
        "cvt.s16.s32 %2, %1;\n\t"       // u = x*QINV;    
        "mul.wide.s16 %3, %2, %8;\n\t"  // t1 = (int32_t)u*KYBER_Q;
        "sub.s32 %3, %0, %3;\n\t"       // t1 = x - t1;
        "shr.b32 %3, %3, 16;\n\t"       //
        "cvt.s16.s32 %4, %3;\n\t"       // t = t1 >> 16;  
        "}"
      : "+r"(x), "+l"(tmp2), "+h"(u) , "+r"(t1), "+h"(t): "h"(zeta), "h"(a[j+len]), "r"(QINV), "h"(tmp3)) ;        

        a[j + len] = a[j] - t;
        a[j] = a[j] + t;
        __syncthreads();        
        level = level << 1;
    }
}

 // Original C code shared memory
__device__ void ntt_gpu_ori_sm(int16_t *a){    
    uint32_t tid = threadIdx.x;
    uint32_t len, j, level, s;
    int16_t t, zeta;
    level = 1;
    __shared__ int16_t s_a[KYBER_N];
    s_a [tid] = a[tid]; 
    s_a [tid + 128] = a[tid + 128];    
    __syncthreads();

    for(len = 128; len >= 2; len >>= 1) {        
        zeta = zetas_gpu[level + (tid/len)];                
        j = (tid/len) * len + tid;                  
        t = fqmul_gpu(zeta, s_a[j + len]);    
        if(tid<10) //printf("len %u tid %u zeta %d j %d t %d\n", len, tid, zeta, j, t);    
        s_a[j + len] = s_a[j] - t;
        s_a[j] = s_a[j] + t;
        __syncthreads();        
        level = level << 1;
    }
    a [tid] = s_a[tid]; 
    a [tid + 128] = s_a[tid + 128];
}

 // Original C code
__device__ void ntt_gpu_combine(int16_t *a){    
    uint32_t tid = threadIdx.x;
    uint32_t len, j1, j2, level, s;
    int16_t t, zeta, g1, g2, g3, g4;
    level = 1;    
    __shared__ int16_t s_a[KYBER_N];
    s_a [tid] = a[tid]; 
    s_a [tid + 64] = a[tid + 64];    
    s_a [tid + 128] = a[tid + 128]; 
    s_a [tid + 192] = a[tid + 192];    
    __syncthreads();
    len = 128;
        zeta = zetas_gpu[level + (tid/len)];                
        j1 = (tid/len) * len + tid;          
        j2 = (tid/len) * len + tid + 64;          
        t = fqmul_gpu(zeta, s_a[j1 + len]);        
        g1 = s_a[j1] - t; //a[j1 + len]
        g2 = s_a[j1] + t; //a[j1] 

        t = fqmul_gpu(zeta, s_a[j2 + len]);        
        g3 = s_a[j2] - t; //a[j2 + len]
        g4 = s_a[j2] + t; //a[j2]
    level = level << 1;
    // __syncthreads();
    len = 64;
        zeta = zetas_gpu[level + (tid/len)];                
        j1 = (tid/len) * len + tid;          
        j2 = (tid/len) * len + tid + 128;          
        t = fqmul_gpu(zeta, g4);        
        s_a[j1 + len] = g2 - t; //a[j1 + len]
        s_a[j1] = g2 + t; //a[j1] 

        zeta = zetas_gpu[level + ((tid+64)/len)]; 
        t = fqmul_gpu(zeta, g3);        
        s_a[j2 + len] = g1 - t; //a[j2 + len]
        s_a[j2] = g1 + t; //a[j2]
    level = level << 1;
    __syncthreads();
    for(len = 32; len >= 2; len >>= 1) {        
        zeta = zetas_gpu[level + (tid/len)];                
        j1 = (tid/len) * len + tid;          
        j2 = (tid/len) * len + tid + 128;           
        t = fqmul_gpu(zeta, s_a[j1 + len]);        
        s_a[j1 + len] = s_a[j1] - t;
        s_a[j1] = s_a[j1] + t;                    

        zeta = zetas_gpu[level + ((tid+64)/len)];  
        t = fqmul_gpu(zeta, s_a[j2 + len]);        
        s_a[j2 + len] = s_a[j2] - t;
        s_a[j2] = s_a[j2] + t;                  
        level = level << 1;
    }
    __syncthreads();
    a [tid] = s_a[tid]; 
    a [tid + 64] = s_a[tid + 64];
    a [tid + 128] = s_a[tid + 128]; 
    a [tid + 192] = s_a[tid + 192];
}

 // Original C code
__device__ void ntt_gpu_ori(int16_t *a){    
    uint32_t tid = threadIdx.x;
    uint32_t len, j, level, s;
    int16_t t, zeta;
    level = 1;    
    for(len = 128; len >= 2; len >>= 1) {        
        zeta = zetas_gpu[level + (tid/len)];                
        j = (tid/len) * len + tid;          
        t = fqmul_gpu(zeta, a[j + len]);        
        a[j + len] = a[j] - t;
        a[j] = a[j] + t;
        __syncthreads();        
        level = level << 1;
    }
}

__device__ void invntt_gpu(int16_t *r) {
  uint32_t start, len, j, k;
  int16_t t, zeta;
  uint32_t tid = threadIdx.x;
  uint32_t stride, level;
  __shared__ int16_t s_r[KYBER_N*KYBER_K];
  s_r [tid] = r[tid]; 
  s_r [tid + 128] = r[tid + 128];    
  __syncthreads();

  k = 0;  stride = 0;
  level = KYBER_N >> 1;
  for(len = 2; len <= 128; len <<= 1) {    
    k = stride + tid/len;
    level = level >> 1;    
    zeta = zetas_inv_gpu[k];
    j = (tid/len) * len + tid;
    __syncthreads();  
    t = s_r[j];
    s_r[j] = barrett_reduce_gpu(t + s_r[j + len]);
    // __syncthreads();
    s_r[j + len] = t - s_r[j + len];
    s_r[j + len] = fqmul_gpu(zeta, s_r[j + len]);
    // __syncthreads();
    stride = stride + level;
  }
  // r [tid] = s_r[tid]; 
  // r [tid + 128] = s_r[tid + 128];

  r[tid] = fqmul_gpu(s_r[tid], zetas_inv_gpu[127]);
  r[tid + blockDim.x] = fqmul_gpu(s_r[tid + blockDim.x], zetas_inv_gpu[127]);
  // __syncthreads();
}

__global__ void poly_invntt_tomont_gpu(int16_t *r) {
  uint32_t i;
  uint32_t bIdx = blockIdx.x*KYBER_N;
  invntt_gpu(r + bIdx);
}

__global__ void polyvec_invntt_tomont_red_gpu(int16_t *r, uint32_t repeat) {
  uint32_t i;
  uint32_t bIdx = blockIdx.x*KYBER_N*KYBER_K;  

  for(i=0;i<repeat;i++)
  {
    invntt_gpu(r + i*KYBER_N + bIdx);
    // __syncthreads();
    poly_reduce_gpu(r + i*KYBER_N + bIdx);
    // __syncthreads();
  }
}

__global__ void polyvec_ntt(int16_t *r)
{
    uint32_t i=0;
    uint32_t bIdx = blockIdx.x*KYBER_N*KYBER_K;
    // Process KYBER_K of NTT, each one is KYBER_N long    
    for(i=0;i<KYBER_K;i++)
    {  
      // ntt_gpu_ori(r + i*KYBER_N + bIdx);
      ntt_gpu_ori_sm(r + i*KYBER_N + bIdx);
      // __syncthreads();
      poly_reduce_gpu(r + i*KYBER_N + bIdx);      
    }
}

__global__ void polyvec_ntt2(int16_t *r)
{
    uint32_t i=0;
    uint32_t bIdx = blockIdx.x*KYBER_N*KYBER_K;
    // Process KYBER_K of NTT, each one is KYBER_N long    
    for(i=0;i<KYBER_K;i++)
    {  
      ntt_gpu_combine(r + i*KYBER_N + bIdx);      
      __syncthreads();
      poly_reduce_gpu(r + i*KYBER_N + bIdx);      
    }
}

__global__ void unpack_pk_gpu(int16_t *pk, uint8_t *seed,
                      const uint8_t *packedpk)
{
  uint32_t i = 0, j = 0;
  uint32_t tid = threadIdx.x;
  uint32_t bIdx1 = blockIdx.x * KYBER_INDCPA_PUBLICKEYBYTES;
  uint32_t bIdx2 = blockIdx.x * KYBER_N * KYBER_K;
  uint32_t bIdx3 = blockIdx.x * KYBER_SYMBYTES;
  for(i=0;i<KYBER_K;i++)
  { 
      pk[bIdx2 + i * KYBER_N + 2*tid]   = ((packedpk[bIdx1 + i * KYBER_POLYBYTES + 3*tid+0] >> 0) | ((uint16_t)packedpk[bIdx1 + i * KYBER_POLYBYTES + 3*tid+1] << 8)) & 0xFFF;
      pk[bIdx2 + i * KYBER_N + 2*tid+1] = ((packedpk[bIdx1 + i * KYBER_POLYBYTES + 3*tid+1] >> 4) | ((uint16_t)packedpk[bIdx1 + i * KYBER_POLYBYTES + 3*tid+2] << 4)) & 0xFFF;
  }

  if(tid<KYBER_SYMBYTES)
    seed[bIdx3 + tid] = packedpk[bIdx1 + tid+KYBER_POLYVECBYTES];  
}



__device__ void basemul_gpu(int16_t r[2],  const int16_t a[2],  const int16_t b[2], int16_t zeta)
{
  r[0]  = fqmul_gpu(a[1], b[1]);
  r[0]  = fqmul_gpu(r[0], zeta);
  r[0] += fqmul_gpu(a[0], b[0]);

  r[1]  = fqmul_gpu(a[0], b[1]);
  r[1] += fqmul_gpu(a[1], b[0]);
}

__device__ void poly_basemul_montgomery_gpu(int16_t *r, const int16_t *a, const int16_t *b)
{
  uint32_t i, tid = threadIdx.x;
  int16_t zeta = zetas_gpu[64+tid];
  basemul_gpu(&r[4*tid], &a[4*tid], &b[4*tid], zeta);
  // __syncthreads();
  basemul_gpu(&r[4*tid+2], &a[4*tid+2], &b[4*tid+2],-zeta);
  // __syncthreads();
}

__device__  void poly_add_gpu(int16_t *r, const int16_t *a, const int16_t *b)
{
  uint32_t i, tid = threadIdx.x;
  for(i=0;i<KYBER_N/blockDim.x;i++)    
    r[tid + i*blockDim.x] = a[tid + i*blockDim.x] + b[tid + i*blockDim.x];
  __syncthreads();
}
__global__  void poly_sub_gpu(int16_t *r, const int16_t *a, const int16_t *b)
{
  uint32_t tid = threadIdx.x;
  uint32_t bid = blockIdx.x;
  r[tid + bid*blockDim.x] = a[tid + bid*blockDim.x] - b[tid + bid*blockDim.x];
  __syncthreads();
}

__device__ void poly_csubq_gpu(int16_t *r)
{
  uint32_t i, tid = threadIdx.x;  
  uint32_t bid = blockIdx.x;
  r[bid*blockDim.x + tid] = csubq_gpu(r[bid*blockDim.x + tid]);
}

// __device__ void polyvec_csubq_gpu(int16_t *r)
// {
//   uint32_t i;
//   for(i=0;i<KYBER_K;i++)
//     poly_csubq_gpu(r + i*KYBER_N);
// }

__global__ void polyvec_add_gpu(int16_t *r, const int16_t *a, const int16_t *b, uint32_t repeat)
{
  uint32_t tid = threadIdx.x; 
  uint32_t bIdx = blockIdx.x*KYBER_N*KYBER_K;   
  r[tid + bIdx] = a[tid + bIdx] + b[tid + bIdx];    
  r[tid + bIdx + KYBER_N] = a[tid + bIdx + KYBER_N] + b[tid + bIdx + KYBER_N];
}

__global__ void polyvec_add_gpu3(int16_t *r, const int16_t *a, const int16_t *b)
{
  uint32_t tid = threadIdx.x, i; 
  uint32_t bIdx = blockIdx.x*KYBER_N*KYBER_K;   

  for(i=0;i<KYBER_K;i++)
  {
    r[tid + i*KYBER_N + bIdx] = a[tid + i*KYBER_N + bIdx] + b[tid + i*KYBER_N + bIdx];     
    // __syncthreads();
  }
}

__global__ void polyvec_add_gpu2(int16_t *r, const int16_t *a, const int16_t *b)
{
  uint32_t i;  
  uint32_t bIdx = blockIdx.x*KYBER_N; 
  poly_add_gpu(r + bIdx , a + bIdx , b + bIdx);
}

// // shared memory, faster
__global__ void polyvec_pointwise_acc_montgomery_gpu(int16_t *r, int16_t *t, const int16_t *a,  const int16_t *b)
{
  uint32_t i, j, tid = threadIdx.x;    
  uint32_t bIdx = blockIdx.x*KYBER_N*KYBER_K; 
  uint32_t bIdx2 = blockIdx.x*KYBER_N*KYBER_K*KYBER_K; 
  __shared__ int16_t s_r[KYBER_N*KYBER_K], s_t[KYBER_N];

  for(j=0;j<KYBER_K;j++)
  {
    uint32_t j_idx = bIdx2 + j*KYBER_N*KYBER_K ;
    poly_basemul_montgomery_gpu(s_r + j*KYBER_N, a + j_idx , b + bIdx);
    for(i=1;i<KYBER_K;i++) {
      poly_basemul_montgomery_gpu(s_t, a + i*KYBER_N + j_idx , b + i*KYBER_N + bIdx);
       __syncthreads();
      poly_add_gpu(s_r + j*KYBER_N, s_r + j*KYBER_N, s_t);      
    }    
    poly_reduce_gpu(s_r + j*KYBER_N);
  }

  for(j=0;j<KYBER_K;j++)
  {
    for(i=0;i<KYBER_N;i=i+blockDim.x)
      r[bIdx + tid + j*KYBER_N + i] = s_r[tid + j*KYBER_N + i]; 
  }
}

// shared memory, faster
__global__ void polyvec_pointwise_acc_montgomery_gpu2
(int16_t *r, int16_t *t, const int16_t *a,  const int16_t *b)
{
  uint32_t i, tid = threadIdx.x;
  uint32_t bIdx = blockIdx.x*KYBER_N; 
  uint32_t bIdx2 = blockIdx.x*KYBER_N*KYBER_K; 
  __shared__ int16_t s_r[KYBER_N], s_t[KYBER_N];

  poly_basemul_montgomery_gpu(s_r, a + bIdx2 , b + bIdx2);  
  for(i=1;i<KYBER_K;i++) {
    poly_basemul_montgomery_gpu(s_t, a + i*KYBER_N + bIdx2 , b + i*KYBER_N+ bIdx2);
           __syncthreads();
    poly_add_gpu(s_r, s_r, s_t);
  }  
  poly_reduce_gpu(s_r);  

  for(i=0;i<KYBER_N;i=i+blockDim.x)
      r[bIdx + tid + i] = s_r[tid + i]; 
}

__global__ void polyvec_compress_gpu(uint8_t *r, int16_t *a)
{
  uint32_t i,k;
  uint32_t tid = threadIdx.x;
  uint32_t bIdx = blockIdx.x * KYBER_INDCPA_BYTES;
  uint32_t bIdx2 = blockIdx.x * KYBER_K * KYBER_N;
  // polyvec_csubq_gpu(a);

#if (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 352))
  uint16_t t[8];
    
  for(i=0;i<KYBER_K;i++) {    
      for(k=0;k<8;k++)
        t[k] = ((((uint32_t)a[bIdx2 + i*KYBER_N + 8*tid+k] << 11) + KYBER_Q/2)
                / KYBER_Q) & 0x7ff;
      r[bIdx + i*352 + tid*11 + 0] = (t[0] >>  0);
      r[bIdx + i*352 + tid*11 +  1] = (t[0] >>  8) | (t[1] << 3);
      r[bIdx + i*352 + tid*11 +  2] = (t[1] >>  5) | (t[2] << 6);
      r[bIdx + i*352 + tid*11 +  3] = (t[2] >>  2);
      r[bIdx + i*352 + tid*11 +  4] = (t[2] >> 10) | (t[3] << 1);
      r[bIdx + i*352 + tid*11 +  5] = (t[3] >>  7) | (t[4] << 4);
      r[bIdx + i*352 + tid*11 +  6] = (t[4] >>  4) | (t[5] << 7);
      r[bIdx + i*352 + tid*11 +  7] = (t[5] >>  1);
      r[bIdx + i*352 + tid*11 +  8] = (t[5] >>  9) | (t[6] << 2);
      r[bIdx + i*352 + tid*11 +  9] = (t[6] >>  6) | (t[7] << 5);
      r[bIdx + i*352 + tid*11 + 10] = (t[7] >>  3);
  }  
#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 320))
  uint16_t t[4];//wklee, this may create race condition
  for(i=0;i<KYBER_K;i++) {    
      for(k=0;k<4;k++)
        t[k] = ((((uint32_t)a[bIdx2 + i*KYBER_N + 4*tid+k] << 10) + KYBER_Q/2)
                / KYBER_Q) & 0x3ff;
      // if (blockIdx.x==2) printf("i: %u tid: %u ==> %d ==> %u %u %u %u\n", i, tid, a[bIdx2 + i*KYBER_N + 4*tid+k], t[0], t[1], t[2], t[3]);
      r[bIdx + i*320 + tid*5 + 0] = (t[0] >> 0);
      r[bIdx + i*320 + tid*5 + 1] = (t[0] >> 8) | (t[1] << 2);
      r[bIdx + i*320 + tid*5 + 2] = (t[1] >> 6) | (t[2] << 4);
      r[bIdx + i*320 + tid*5 + 3] = (t[2] >> 4) | (t[3] << 6);
      r[bIdx + i*320 + tid*5 + 4] = (t[3] >> 2);    
  }
  #endif
}

__global__ void poly_compress_gpu(uint8_t *r, int16_t *a)
{
  uint32_t j;
  uint32_t tid = threadIdx.x;
  uint8_t t[8];
  uint32_t bIdx = blockIdx.x * KYBER_INDCPA_BYTES;
  uint32_t bIdx2 = blockIdx.x * KYBER_N;

#if (KYBER_POLYCOMPRESSEDBYTES == 96)
  for(j=0;j<8;j++)
      t[j] = ((((uint16_t)a[bIdx2 + 8*tid+j] << 3) + KYBER_Q/2)/KYBER_Q) & 7;    // __syncthreads();
  r[bIdx + tid*3 + 0] = (t[0] >> 0) | (t[1] << 3) | (t[2] << 6);
  r[bIdx + tid*3 + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
  r[bIdx + tid*3 + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);    
#elif (KYBER_POLYCOMPRESSEDBYTES == 128)
  for(j=0;j<8;j++)
      t[j] = ((((uint16_t)a[bIdx2 + 8*tid+j] << 4) + KYBER_Q/2)/KYBER_Q) & 15;    // __syncthreads();
  r[bIdx + tid*4 + 0] = t[0] | (t[1] << 4);
  r[bIdx + tid*4 + 1] = t[2] | (t[3] << 4);
  r[bIdx + tid*4 + 2] = t[4] | (t[5] << 4);   
  r[bIdx + tid*4 + 3] = t[6] | (t[7] << 4);   
#elif (KYBER_POLYCOMPRESSEDBYTES == 160)
  for(j=0;j<8;j++)
      t[j] = ((((uint16_t)a[bIdx2 + 8*tid+j] << 5) + KYBER_Q/2)/KYBER_Q) & 31;    // __syncthreads();
  r[bIdx + tid*5 + 0] = (t[0] >> 0) | (t[1] << 5);
  r[bIdx + tid*5 + 1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
  r[bIdx + tid*5 + 2] = (t[3] >> 1) | (t[4] << 4);   
  r[bIdx + tid*5 + 3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6); 
  r[bIdx + tid*5 + 4] = (t[6] >> 2) | (t[7] << 3);   
#endif
}

__global__ void polycopy(int16_t *out,  int16_t *in)
{
  uint32_t k, tid = threadIdx.x;
  uint32_t bid = blockIdx.x;      
  out[bid*KYBER_N + tid] = in[bid*(2*KYBER_K+1)*KYBER_N + k*KYBER_N+tid];  
}

__global__ void poly_veccopy(int16_t *out,  int16_t *in)
{
  uint32_t k, tid = threadIdx.x;
  uint32_t bid = blockIdx.x;      
  for(k=0; k<KYBER_K; k++)  
    out[bid*KYBER_K*KYBER_N + k*KYBER_N + tid] = in[bid*(2*KYBER_K+1)*KYBER_N + k*KYBER_N+tid];  
}

__device__ uint32_t load32_littleendian(const uint8_t x[4])
{
  uint32_t r;
  r  = (uint32_t)x[0];
  r |= (uint32_t)x[1] << 8;
  r |= (uint32_t)x[2] << 16;
  r |= (uint32_t)x[3] << 24;
  return r;
}

// version 2, coalesced memory access
__global__ void cbd_gpu2(int16_t *r, const uint8_t *buf)
{
#if KYBER_ETA != 2
#error "poly_getnoise in poly.c only supports eta=2"
#endif
  uint32_t tid = threadIdx.x;
  uint32_t t, d, bid = blockIdx.x;
  int16_t a,b;
  
  t  = load32_littleendian(buf+bid*(2*KYBER_K+1)*KYBER_ETA*KYBER_N/4 +4*(tid/8));
  d  = t & 0x55555555;
  d += (t>>1) & 0x55555555;
    
  a = (d >> (4*(tid%8)+0)) & 0x3;
  b = (d >> (4*(tid%8)+2)) & 0x3;
  r[bid*(2*KYBER_K+1)*KYBER_N + tid] = a - b;
}

// version 1, suffer from non-coalesced memory access
__global__ void cbd_gpu(int16_t *r, const uint8_t *buf)
{
#if KYBER_ETA != 2
#error "poly_getnoise in poly.c only supports eta=2"
#endif
    uint32_t j, tid = threadIdx.x;
    uint32_t t,d, bid = blockIdx.x;
    int16_t a,b;
  
    t  = load32_littleendian(buf+bid*(2*KYBER_K+1)*KYBER_ETA*KYBER_N/4 + 4*tid);
    d  = t & 0x55555555;
    d += (t>>1) & 0x55555555;

    for(j=0;j<8;j++) {
      a = (d >> (4*j+0)) & 0x3;
      b = (d >> (4*j+2)) & 0x3;
      r[bid*(2*KYBER_K+1) * KYBER_N + 8*tid+j] = a - b;
    }
}
//Generate buf with double size. Place good samples in r at first iteration.
//Then check for pos that is still 0, place good samples in r at second iterat.
__global__ void rej_uniform_gpu(int16_t *r, unsigned int len, const uint8_t *buf)
{  
  uint32_t tid = threadIdx.x;
  uint32_t bIdx1 = 0;  
  uint32_t bIdx2 = blockIdx.x * KYBER_N*KYBER_K*KYBER_K;
  uint16_t val;

  val = buf[bIdx1 + tid*2] | ((uint16_t)buf[bIdx1 + tid*2+1] << 8);
  
  if(val < 19*KYBER_Q) {
      val -= (val >> 12)*KYBER_Q; // Barrett reduction      
      r[bIdx2 + tid] = (int16_t)val;      
  }
  __syncthreads();
  val = buf[bIdx1 + tid*2 + blockDim.x] | ((uint16_t)buf[bIdx1 + tid*2+1 + blockDim.x] << 8);
  if(val < 19*KYBER_Q) {
    val -= (val >> 12)*KYBER_Q; // Barrett reduction
    //Only replace the empty space.
    if(r[bIdx2 + tid] == 0)  r[bIdx2 + tid] = (int16_t)val;      
  }
};

__global__ void poly_tomsg_gpu(uint8_t *msg, int16_t *a)
{
  uint32_t i,j, tid = threadIdx.x;
  uint16_t t;
  uint32_t bid = blockIdx.x;
  poly_csubq_gpu(a);

  if(tid <KYBER_N/8)
  {
    msg[bid*KYBER_INDCPA_MSGBYTES + tid] = 0;
    for(j=0;j<8;j++) {
      t = ((((uint16_t)a[bid*blockDim.x + 8*tid+j] << 1) + KYBER_Q/2)/KYBER_Q) & 1;
      msg[bid*KYBER_INDCPA_MSGBYTES + tid] |= t << j;
    }
  }
}
