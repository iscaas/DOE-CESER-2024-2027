// -------------------- System / CUDA --------------------
#include <cstdint>     // uint8_t, uint32_t, etc.
#include <cstdio>
#include <cuda.h>
#include <cuda_runtime.h>
#include <cuda_fp16.h>

// -------------------- Project headers ------------------
#include "../include/incdpa.cuh"
#include "../include/poly_func.cuh"
#include "../include/fips2024.cuh"
#include "../include/params.h"
#include "../include/tmp_constants.h"
#include "../include/aes_gpu.cuh"

// =======================================================================
// IND-CPA Encryption (Kyber)
// =======================================================================

void indcpa_enc_gpu(uint8_t *c, uint8_t *msg, uint8_t *pk, uint8_t *coins)
{
    (void)coins; // unused in this INDCPA harness

    // Host-pinned (as in your original code)
    int16_t *b, *at, *r;
    int16_t *pkpv, *msgpoly, *ep, *epp;
    uint8_t *buf, *tmp_prf, *d_kr; // d_kr allocated (unused), kept to preserve layout
    uint8_t *seed;
    uint32_t *exp_seed;

    // Device
    int16_t *d_sp, *d_pk, *d_msgpoly, *d_r, *d_bp, *d_at, *d_t, *d_v, *d_ep, *d_epp;
    uint8_t *d_seed, *d_packedpk, *d_msg, *d_prf, *d_buf, *d_c;
    uint32_t *d_exp_seed;

    // Locals
    uint32_t i, j, k, hh, count;
    float milliseconds = 0.0f;

    // Timing
    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);

    // -------- Host allocations (unchanged sizes) --------
    cudaMallocHost((void**)&at,      KYBER_K*BATCH*KYBER_N * sizeof(int16_t));
    cudaMallocHost((void**)&b,       (2*KYBER_K+1)*BATCH*KYBER_N * sizeof(int16_t));
    cudaMallocHost((void**)&r,       (2*KYBER_K+1)*BATCH*KYBER_N * sizeof(int16_t));
    cudaMallocHost((void**)&pkpv,    KYBER_K*BATCH*KYBER_N * sizeof(int16_t));
    cudaMallocHost((void**)&msgpoly, KYBER_N*BATCH * sizeof(int16_t));
    cudaMallocHost((void**)&buf,     BATCH*64*16*KYBER_K*KYBER_K * sizeof(uint8_t));
    cudaMallocHost((void**)&d_kr,    BATCH*64*BATCH * sizeof(uint8_t)); // kept (unused)
    cudaMallocHost((void**)&ep,      KYBER_K*BATCH*KYBER_N * sizeof(int16_t));
    cudaMallocHost((void**)&epp,     KYBER_K*BATCH*KYBER_N * sizeof(int16_t));
    cudaMallocHost((void**)&seed,    BATCH*KYBER_SYMBYTES * sizeof(uint8_t));
    cudaMallocHost((void**)&exp_seed, BATCH*60 * sizeof(uint32_t)); // AES-256 expands to 60 uint32_t
    cudaMallocHost((void**)&tmp_prf, (2*KYBER_K+1)*BATCH*KYBER_ETA*KYBER_N * sizeof(uint8_t));

    // -------- Device allocations (unchanged sizes) -------
    cudaMalloc((void**)&d_sp,        KYBER_K*BATCH*KYBER_N * sizeof(int16_t));
    cudaMalloc((void**)&d_t,         KYBER_K*BATCH*KYBER_N * sizeof(int16_t));
    cudaMalloc((void**)&d_v,         BATCH*KYBER_N * sizeof(int16_t));
    cudaMalloc((void**)&d_bp,        KYBER_K*BATCH*KYBER_N * sizeof(int16_t));
    cudaMalloc((void**)&d_at,        KYBER_K*KYBER_K*BATCH*KYBER_N * sizeof(int16_t));
    cudaMalloc((void**)&d_seed,      KYBER_SYMBYTES * BATCH * sizeof(uint8_t));
    cudaMalloc((void**)&d_packedpk,  BATCH*KYBER_INDCPA_PUBLICKEYBYTES * sizeof(uint8_t));
    cudaMalloc((void**)&d_pk,        KYBER_K*BATCH*KYBER_N * sizeof(int16_t));
    cudaMalloc((void**)&d_msgpoly,   KYBER_N*BATCH * sizeof(int16_t));
    cudaMalloc((void**)&d_msg,       KYBER_INDCPA_MSGBYTES*BATCH * sizeof(uint8_t));
    cudaMalloc((void**)&d_ep,        KYBER_K*BATCH*KYBER_N * sizeof(int16_t));
    cudaMalloc((void**)&d_epp,       BATCH*KYBER_N * sizeof(int16_t));
    cudaMalloc((void**)&d_r,         (2*KYBER_K+1)*BATCH*KYBER_N * sizeof(int16_t));
    cudaMalloc((void**)&d_c,         BATCH*KYBER_INDCPA_BYTES * sizeof(uint8_t));
    cudaMalloc((void**)&d_prf,       (2*KYBER_K+1)*BATCH*KYBER_ETA*KYBER_N * sizeof(uint8_t)); // note: *not* /4 (matches your original)
    cudaMalloc((void**)&d_buf,       BATCH*4*KYBER_N*KYBER_K*KYBER_K * sizeof(uint8_t));
    cudaMalloc((void**)&d_exp_seed,  BATCH*60 * sizeof(uint32_t));

    // -------- Seed from pk (rho) as in your code --------
    for (i = 0; i < KYBER_SYMBYTES; i++)
        seed[i] = pk[i + KYBER_POLYVECBYTES];

    cudaEventRecord(start);

    for (count = 0; count < REPEAT; count++)
    {
        AESPrepareKey(seed, 256, exp_seed);

        cudaMemcpy(d_packedpk, pk,  KYBER_INDCPA_PUBLICKEYBYTES*BATCH * sizeof(uint8_t), cudaMemcpyHostToDevice);
        cudaMemcpy(d_msg,      msg, KYBER_INDCPA_MSGBYTES*BATCH       * sizeof(uint8_t), cudaMemcpyHostToDevice);
        cudaMemcpy(d_exp_seed, exp_seed, 60*BATCH * sizeof(uint32_t), cudaMemcpyHostToDevice);

        unpack_pk_gpu<<<BATCH, KYBER_N/2>>>(d_pk, d_seed, d_packedpk);
        poly_frommsg_gpu<<<BATCH, KYBER_N/8>>>(d_msgpoly, d_msg);

#ifdef AESGPU
        // Generate K*K * 1024 bytes (each thread 4B) for A via AES-CTR
#if KYBER_K == 2
        encGPUsharedFineGrain<<<BATCH, 1024>>>(d_buf, d_exp_seed);
#elif KYBER_K == 3
        encGPUsharedFineGrain<<<BATCH, 1024>>>(d_buf, d_exp_seed);
#elif KYBER_K == 4
        encGPUsharedFineGrain<<<BATCH, 1024>>>(d_buf, d_exp_seed);
#endif
        for (k = 0; k < KYBER_K*KYBER_K; k++)
            rej_uniform_gpu<<<BATCH, KYBER_N>>>(d_at + k*KYBER_N, KYBER_N, d_buf + k*4*KYBER_N);

        // PRF for (sp, ep, epp)
        encGPUsharedFineGrain2<<<BATCH, 288>>>(d_prf, d_exp_seed);
#else
        // Non-AES path kept exactly as in your code (constant fill for testing)
        for (i = 0; i < KYBER_K*KYBER_K*BATCH*KYBER_N; i++) at[i] = 256;
        cudaMemcpy(d_at, at, KYBER_K*KYBER_K*BATCH*KYBER_N * sizeof(int16_t), cudaMemcpyHostToDevice);

        for (i = 0; i < BATCH; i++)
            for (j = 0; j < (2*KYBER_K+1)*KYBER_ETA*KYBER_N/4; j++)
                tmp_prf[i*(2*KYBER_K+1)*KYBER_ETA*KYBER_N/4 + j] = 128;
        cudaMemcpy(d_prf, tmp_prf, (2*KYBER_K+1)*BATCH*KYBER_ETA*KYBER_N/4 * sizeof(uint8_t), cudaMemcpyHostToDevice);
#endif

        // Noise: r[0..2K] from PRF (your kernel launch kept)
        for (i = 0; i < 2*KYBER_K+1; i++)
            cbd_gpu2<<<BATCH, KYBER_N>>>(d_r + i*KYBER_N, d_prf + i*KYBER_ETA*KYBER_N/4);

        // sp = r[0], ep = r[2*KYBER_N], epp = r[4*KYBER_N] (as in your code)
        poly_veccopy<<<BATCH, KYBER_N>>>(d_sp, d_r);
        polyvec_ntt2<<<BATCH, KYBER_N/4>>>(d_sp);

        // (kept debug copy)
        cudaMemcpy(at, d_sp, KYBER_K*BATCH*KYBER_N * sizeof(int16_t), cudaMemcpyDeviceToHost);

        polyvec_pointwise_acc_montgomery_gpu<<<BATCH, KYBER_N/4>>>(d_bp, d_t, d_at, d_sp);
        polyvec_pointwise_acc_montgomery_gpu2<<<BATCH, KYBER_N/4>>>(d_v, d_t, d_pk, d_sp);
        polyvec_invntt_tomont_red_gpu<<<BATCH, KYBER_N/2>>>(d_bp, KYBER_K);
        poly_invntt_tomont_gpu<<<BATCH, KYBER_N/2>>>(d_v);

        poly_veccopy<<<BATCH, KYBER_N>>>(d_ep,  d_r + 2*KYBER_N);
        polycopy<<<BATCH, KYBER_N>>>(d_epp, d_r + 4*KYBER_N);

        polyvec_add_gpu3<<<BATCH, KYBER_N>>>(d_bp, d_ep, d_bp);
        polyvec_reduce_gpu<<<BATCH, KYBER_N>>>(d_bp);
        polyvec_add_gpu2<<<BATCH, KYBER_N>>>(d_v, d_v, d_epp);
        polyvec_add_gpu2<<<BATCH, KYBER_N>>>(d_v, d_v, d_msgpoly);
        poly_reduce_g<<<BATCH, KYBER_N>>>(d_v);

#if KYBER_K == 4
        polyvec_compress_gpu<<<BATCH, KYBER_N/8>>>(d_c, d_bp);
#else
        polyvec_compress_gpu<<<BATCH, KYBER_N/4>>>(d_c, d_bp);
#endif
        poly_compress_gpu<<<BATCH, KYBER_N/8>>>(d_c + KYBER_POLYVECCOMPRESSEDBYTES, d_v);

        cudaMemcpy(c, d_c, BATCH*KYBER_INDCPA_BYTES * sizeof(uint8_t), cudaMemcpyDeviceToHost);
    }

    cudaEventRecord(stop);
    cudaEventSynchronize(stop);
    cudaEventElapsedTime(&milliseconds, start, stop);

    //printf("\n\nGPU KYBER-128 Encrypt time: %.6f ms average: %.6f ms throughput: %.6f\n", milliseconds, milliseconds/REPEAT/BATCH, BATCH*1000.0/milliseconds);

#ifdef DEBUG
    // (kept your commented diagnostics)
#endif

    // Note: keeping frees omitted, same as original style
}

// =======================================================================
// IND-CPA Decryption (Kyber)
// =======================================================================

void indcpa_dec_gpu(uint8_t *c, uint8_t *msg, uint8_t *kr)
{
    (void)kr; // unused in this INDCPA harness

    // Device
    uint8_t *d_c;
    uint32_t i, j, k, hh, count;

    int16_t *d_bp_dec, *d_v_dec, *d_sk_poly, *d_mp, *d_t_dec;
    uint8_t *d_m_dec;

    // Host-pinned
    int16_t *bp_dec, *v_dec, *mp, *sk_poly_dec;
    uint8_t *m_dec;

    float milliseconds = 0.0f;
    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);

    // -------- Host allocations (unchanged) --------
    cudaMallocHost((void**)&bp_dec,      KYBER_K*BATCH*KYBER_N * sizeof(int16_t));
    cudaMallocHost((void**)&v_dec,       BATCH*KYBER_N * sizeof(int16_t));
    cudaMallocHost((void**)&sk_poly_dec, KYBER_K*BATCH*KYBER_N * sizeof(int16_t));
    cudaMallocHost((void**)&mp,          BATCH*KYBER_N * sizeof(int16_t));
    cudaMallocHost((void**)&m_dec,       BATCH*KYBER_INDCPA_MSGBYTES * sizeof(uint8_t));

    // -------- Device allocations (unchanged sizes) --------
    cudaMalloc((void**)&d_bp_dec,  KYBER_K*BATCH*KYBER_N * sizeof(int16_t));
    cudaMalloc((void**)&d_v_dec,   BATCH*KYBER_N * sizeof(int16_t));
    cudaMalloc((void**)&d_sk_poly, KYBER_K*BATCH*KYBER_N * sizeof(int16_t));
    cudaMalloc((void**)&d_mp,      BATCH*KYBER_N * sizeof(int16_t));
    cudaMalloc((void**)&d_t_dec,   KYBER_K*BATCH*KYBER_N * sizeof(int16_t));
    cudaMalloc((void**)&d_m_dec,   BATCH*KYBER_INDCPA_MSGBYTES * sizeof(uint8_t));
    cudaMalloc((void**)&d_c,       BATCH*KYBER_INDCPA_BYTES * sizeof(uint8_t));

    // -------- Secret key polys (unchanged source) --------
#ifdef AESGPU
    for (i = 0; i < BATCH; i++)
        for (hh = 0; hh < KYBER_K; hh++)
            for (j = 0; j < KYBER_N; j++)
                sk_poly_dec[i*KYBER_N*KYBER_K + hh*KYBER_N + j] = sk_poly_aes[hh*KYBER_N + j];
#else
    for (i = 0; i < BATCH; i++)
        for (hh = 0; hh < KYBER_K; hh++)
            for (j = 0; j < KYBER_N; j++)
                sk_poly_dec[i*KYBER_N*KYBER_K + hh*KYBER_N + j] = sk_poly[hh*KYBER_N + j];
#endif

    // -------- Decrypt loop (unchanged) --------
    cudaEventRecord(start);
    for (count = 0; count < REPEAT; count++)
    {
        cudaMemcpy(d_c, c, BATCH*KYBER_INDCPA_BYTES * sizeof(uint8_t), cudaMemcpyHostToDevice);
        cudaMemcpy(d_sk_poly, sk_poly_dec, BATCH*KYBER_K*KYBER_N * sizeof(int16_t), cudaMemcpyHostToDevice);

#if KYBER_K == 4
        polyvec_decompress_gpu<<<BATCH, KYBER_N/8>>>(d_bp_dec, d_c);
#else
        polyvec_decompress_gpu<<<BATCH, KYBER_N/4>>>(d_bp_dec, d_c);
#endif

#if KYBER_K == 3
        poly_decompress_gpu<<<BATCH, KYBER_N/2>>>(d_v_dec, d_c);
#else
        poly_decompress_gpu<<<BATCH, KYBER_N/8>>>(d_v_dec, d_c);
#endif

        // polyvec_ntt<<<BATCH, KYBER_N/2>>>(d_bp_dec); // not used
        polyvec_ntt2<<<BATCH, KYBER_N/4>>>(d_bp_dec);
        polyvec_pointwise_acc_montgomery_gpu2<<<BATCH, KYBER_N/4>>>(d_mp, d_t_dec, d_sk_poly, d_bp_dec);
        poly_invntt_tomont_gpu<<<BATCH, KYBER_N/2>>>(d_mp);
        poly_sub_gpu<<<BATCH, KYBER_N>>>(d_mp, d_v_dec, d_mp);
        poly_reduce_g<<<BATCH, KYBER_N>>>(d_mp);
        poly_tomsg_gpu<<<BATCH, KYBER_N>>>(d_m_dec, d_mp);
    }

    cudaMemcpy(m_dec, d_m_dec, BATCH*KYBER_INDCPA_MSGBYTES * sizeof(uint8_t), cudaMemcpyDeviceToHost);
    cudaMemcpy(msg,   d_m_dec, BATCH*KYBER_INDCPA_MSGBYTES * sizeof(uint8_t), cudaMemcpyDeviceToHost);

    cudaEventRecord(stop);
    cudaEventSynchronize(stop);
    cudaEventElapsedTime(&milliseconds, start, stop);

    //printf("\n\nGPU KYBER-128 Decrypt time: %.6f ms average: %.6f ms throughput: %.6f\n", milliseconds, milliseconds/REPEAT/BATCH, BATCH*1000.0/milliseconds);

    cudaMemcpy(bp_dec, d_bp_dec, BATCH*KYBER_K*KYBER_N * sizeof(int16_t), cudaMemcpyDeviceToHost);
    cudaMemcpy(mp,     d_mp,     BATCH*KYBER_N         * sizeof(int16_t), cudaMemcpyDeviceToHost);
    printf("\n");
}
