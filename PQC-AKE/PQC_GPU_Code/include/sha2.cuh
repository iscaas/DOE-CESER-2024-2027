#ifndef SHA2_CUH
#define SHA2_CUH


__global__ void sha256_gpu(uint8_t *in, uint8_t *out, uint32_t inlen);

__global__ void scalar_multiplication(uint8_t *pk_k, uint8_t *sharedSecret, uint8_t *sk_k);


#endif