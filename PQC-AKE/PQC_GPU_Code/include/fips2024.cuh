#include <stdio.h>
#include <cuda.h>
#include <cuda_runtime.h>


__global__ void sha3_256_gpu(uint8_t *output, uint8_t *input, unsigned long long inlen, uint32_t in_stride, uint32_t out_stride);
__global__ void sha3_512_gpu(uint8_t *output, uint8_t *input, unsigned long long inlen);


// __constant__ uint32_t a[25];
// __constant__ uint32_t b[25];
// __constant__ uint32_t c[25][3];
// __constant__ uint32_t d[25];
// __constant__ uint32_t ro[25][2];
// __constant__ uint64_t rc[5][NROUNDS];


__global__ void shake128_gpu(uint8_t *out, const uint8_t *in, size_t inlen, uint32_t outlen, uint32_t out_stride) ;


