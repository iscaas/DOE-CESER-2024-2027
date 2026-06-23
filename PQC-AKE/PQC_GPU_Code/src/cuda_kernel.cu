// CUDA libraries.
#include <cuda.h>
#include <cuda_runtime.h>

// C/C++
#include <cstdio>
#include <cstdint>
#include <cstring>

// Project headers.
#include "../include/cuda_kernel.cuh"
#include "../include/test_vector.cuh"
#include "../include/fpr.cuh"
#include "../include/fft.cuh"
#include "../include/shake.cuh"
#include "../include/ffSampling.cuh"
#include "../include/common.cuh"
#include "../include/rng.cuh"
#include "../include/params.h"

// --------------------------- helpers ---------------------------
#define CUDA_OK(stmt)                                                     \
    do {                                                                  \
        cudaError_t __e = (stmt);                                         \
        if (__e != cudaSuccess) {                                         \
            std::fprintf(stderr, "CUDA error %s:%d: %s\n",                \
                         __FILE__, __LINE__, cudaGetErrorString(__e));    \
            goto cleanup;                                                 \
        }                                                                 \
    } while (0)

static inline void start_event(cudaEvent_t &start, cudaEvent_t &stop) {
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start);
}
static inline float stop_event(cudaEvent_t &start, cudaEvent_t &stop) {
    cudaEventRecord(stop);
    cudaEventSynchronize(stop);
    float ms = 0.f;
    cudaEventElapsedTime(&ms, start, stop);
    cudaEventDestroy(start);
    cudaEventDestroy(stop);
    return ms;
}

// ===============================================================
// Falcon sign (host wrapper driving your CUDA kernels)
// ===============================================================
void crypto_sign(uint8_t *h_sm, uint8_t *h_m) {
    cudaEvent_t start, stop;
    float elapsed = 0.0f;

    // Device buffers
    fpr      *d_bb   = nullptr;
    int8_t   *d_F    = nullptr, *d_G = nullptr, *d_f = nullptr, *d_g = nullptr;
    uint16_t *d_hm   = nullptr, *d_t1 = nullptr, *d_t2 = nullptr;
    int16_t  *d_s1tmp= nullptr, *d_s2tmp = nullptr;
    uint64_t *d_scA  = nullptr, *d_scdptr = nullptr;
    uint8_t  *d_seed = nullptr, *d_nonce = nullptr, *d_m_d = nullptr;
    uint8_t  *d_esig = nullptr, *d_sm = nullptr, *d_sk = nullptr;
    uint32_t *d_sqn  = nullptr, *d_s = nullptr, *d_esiglen = nullptr;

    // Host pinned buffers (only what we actually use)
    uint8_t  *h_seed = nullptr, *h_nonce = nullptr, *h_sk = nullptr, *h_esig = nullptr;

    // ---------- host allocations ----------
    CUDA_OK(cudaMallocHost((void**)&h_seed,  BATCH*48*sizeof(uint8_t)));
    CUDA_OK(cudaMallocHost((void**)&h_nonce, BATCH*NONCELEN*sizeof(uint8_t)));
    CUDA_OK(cudaMallocHost((void**)&h_sk,    BATCH*CRYPTO_SECRETKEYBYTES*sizeof(uint8_t)));
    CUDA_OK(cudaMallocHost((void**)&h_esig,  BATCH*(CRYPTO_BYTES - 2 - NONCELEN)*sizeof(uint8_t)));

    // Seed / nonce / secret key test vectors (per-batch copy)
    for (int j=0; j<BATCH; j++) {
        for (int i=0; i<48; i++)         h_seed[j*48 + i] = seed_tv[i];
        for (int i=0; i<NONCELEN; i++)   h_nonce[j*NONCELEN + i] = nonce_tv[i];
        for (int i=0; i<CRYPTO_SECRETKEYBYTES; i++) h_sk[j*CRYPTO_SECRETKEYBYTES + i] = sk[i];
        // esig first byte (scheme/domain marker)
        h_esig[j*(CRYPTO_BYTES - 2 - NONCELEN) + 0] = (uint8_t)(0x20 + 9);
    }

    // ---------- device allocations ----------
    CUDA_OK(cudaMalloc((void**)&d_F,   BATCH*N*sizeof(int8_t)));
    CUDA_OK(cudaMalloc((void**)&d_G,   BATCH*N*sizeof(int8_t)));
    CUDA_OK(cudaMalloc((void**)&d_f,   BATCH*N*sizeof(int8_t)));
    CUDA_OK(cudaMalloc((void**)&d_g,   BATCH*N*sizeof(int8_t)));

    CUDA_OK(cudaMalloc((void**)&d_bb,  BATCH*10*N*sizeof(fpr)));
    CUDA_OK(cudaMalloc((void**)&d_hm,  BATCH*N*sizeof(uint16_t)));
    CUDA_OK(cudaMalloc((void**)&d_t1,  BATCH*N*sizeof(uint16_t)));
    CUDA_OK(cudaMalloc((void**)&d_t2,  BATCH*N*sizeof(uint16_t)));

    CUDA_OK(cudaMalloc((void**)&d_sqn, BATCH*sizeof(uint32_t)));
    CUDA_OK(cudaMalloc((void**)&d_s1tmp, BATCH*N*sizeof(int16_t)));
    CUDA_OK(cudaMalloc((void**)&d_s2tmp, BATCH*N*sizeof(int16_t)));
    CUDA_OK(cudaMalloc((void**)&d_scA,   BATCH*25*sizeof(uint64_t)));
    CUDA_OK(cudaMalloc((void**)&d_scdptr,BATCH*sizeof(uint64_t)));

    CUDA_OK(cudaMalloc((void**)&d_seed,  BATCH*48*sizeof(uint8_t)));
    CUDA_OK(cudaMalloc((void**)&d_nonce, BATCH*NONCELEN*sizeof(uint8_t)));
    CUDA_OK(cudaMalloc((void**)&d_m_d,   BATCH*MLEN*sizeof(uint8_t)));

    CUDA_OK(cudaMalloc((void**)&d_s,     BATCH*sizeof(uint32_t)));
    CUDA_OK(cudaMalloc((void**)&d_esig,  BATCH*(CRYPTO_BYTES - 2 - NONCELEN)*sizeof(uint8_t)));
    CUDA_OK(cudaMalloc((void**)&d_esiglen, BATCH*sizeof(uint32_t)));
    CUDA_OK(cudaMalloc((void**)&d_sm,    BATCH*(MLEN + CRYPTO_BYTES)*sizeof(uint8_t)));
    CUDA_OK(cudaMalloc((void**)&d_sk,    BATCH*CRYPTO_SECRETKEYBYTES*sizeof(uint8_t)));

    // Init
    CUDA_OK(cudaMemset(d_bb,    0, BATCH*10*N*sizeof(fpr)));
    CUDA_OK(cudaMemset(d_scdptr,0, BATCH*sizeof(uint64_t)));
    CUDA_OK(cudaMemset(d_hm,    0, BATCH*N*sizeof(uint16_t)));

    // Timing
    start_event(start, stop);

    for (int rep=0; rep<REPEAT; rep++) {
        // host->device copies for this run
        CUDA_OK(cudaMemcpy(d_seed,  h_seed,  BATCH*48*sizeof(uint8_t), cudaMemcpyHostToDevice));
        CUDA_OK(cudaMemcpy(d_nonce, h_nonce, BATCH*NONCELEN*sizeof(uint8_t), cudaMemcpyHostToDevice));
        CUDA_OK(cudaMemcpy(d_m_d,   h_m,     BATCH*MLEN*sizeof(uint8_t),     cudaMemcpyHostToDevice));
        CUDA_OK(cudaMemcpy(d_esig,  h_esig,  BATCH*(CRYPTO_BYTES - 2 - NONCELEN)*sizeof(uint8_t), cudaMemcpyHostToDevice));
        CUDA_OK(cudaMemcpy(d_sk,    h_sk,    BATCH*CRYPTO_SECRETKEYBYTES*sizeof(uint8_t), cudaMemcpyHostToDevice));

        // ---- your kernel pipeline (unchanged semantics) ----
        trim_i8_decode_gpu<<<BATCH, 1>>>(d_f, d_g, d_F, 9, max_fg_bits[9], d_sk + 1, CRYPTO_SECRETKEYBYTES - 1);

#ifdef COMB_KER
        complete_private_comb_gpu<<<BATCH, N/2>>>(d_G, d_f, d_g, d_F, 9, d_t1, d_t2);
#else
        complete_private_gpu<<<BATCH, N>>>(d_G, d_f, d_g, d_F, 9, d_t1, d_t2);
        mq_NTT_gpu<<<BATCH, N/2>>>(d_t1, LOGN);
        mq_NTT_gpu<<<BATCH, N/2>>>(d_t2, LOGN);
        mq_poly_tomonty<<<BATCH, N/2>>>(d_t1);
        mq_poly_montymul_ntt_gpu<<<BATCH, N>>>(d_t1, d_t2);
        mq_conv_small_gpu<<<BATCH, N>>>(d_t2, d_f);
        mq_NTT_gpu<<<BATCH, N/2>>>(d_t2, LOGN);
        complete_private_gpu2<<<BATCH, N>>>(d_t1, d_t2);
        mq_iNTT_gpu<<<BATCH, N/2>>>(d_t1);
        complete_private_gpu3<<<BATCH, N>>>(d_t1, d_G);
#endif

        i_shake256_inject_gpu2<<<BATCH, 1>>>(d_scA, d_scdptr, d_nonce, NONCELEN);
        i_shake256_inject_gpu2<<<BATCH, 1>>>(d_scA, d_scdptr, d_m_d,   MLEN);
        i_shake256_flip_gpu<<<BATCH, 1>>>(d_scA, d_scdptr);
        hash_to_point_vartime_par<<<BATCH,32>>>(d_scA, d_scdptr, d_hm);

        i_shake256_init_gpu<<<BATCH, 1>>>(d_scA, d_scdptr);
        i_shake256_inject_gpu2<<<BATCH, 1>>>(d_scA, d_scdptr, d_seed, 48);
        i_shake256_flip_gpu<<<BATCH, 1>>>(d_scA, d_scdptr);

        smallints_to_fpr_g<<<BATCH, N>>>(d_bb,     d_g, N, 10*N);
        smallints_to_fpr_g<<<BATCH, N>>>(d_bb+N,   d_f, N, 10*N);
        smallints_to_fpr_g<<<BATCH, N>>>(d_bb+2*N, d_G, N, 10*N);
        smallints_to_fpr_g<<<BATCH, N>>>(d_bb+3*N, d_F, N, 10*N);

#ifdef COMB_KER
        FFT_SMx4_g<<<BATCH,128>>>(d_bb, d_bb+N, d_bb+2*N, d_bb+3*N, 10*N, 10*N);
#else
        FFT_SM_g<<<BATCH,128>>>(d_bb,     10*N, 10*N);
        FFT_SM_g<<<BATCH,128>>>(d_bb+N,   10*N, 10*N);
        FFT_SM_g<<<BATCH,128>>>(d_bb+2*N, 10*N, 10*N);
        FFT_SM_g<<<BATCH,128>>>(d_bb+3*N, 10*N, 10*N);
#endif

        poly_neg_g<<<BATCH,N>>>(d_bb+N,   10*N, 10*N);
        poly_neg_g<<<BATCH,N>>>(d_bb+3*N, 10*N, 10*N);

        poly_copy<<<BATCH,N>>>(d_bb+4*N, d_bb+N);
        poly_copy<<<BATCH,N>>>(d_bb+5*N, d_bb);

        poly_mulselfadj_fft_g<<<BATCH,N/2>>>(d_bb+4*N);
        poly_muladj_fft_g<<<BATCH,N/2>>>(d_bb+5*N, d_bb+2*N);
        poly_mulselfadj_fft_g<<<BATCH,N/2>>>(d_bb);
        poly_add_g<<<BATCH,N>>>(d_bb, d_bb+4*N);

        poly_copy<<<BATCH,N>>>(d_bb+4*N, d_bb+N);
        poly_muladj_fft_g<<<BATCH,N/2>>>(d_bb+N, d_bb+3*N);
        poly_add_g<<<BATCH,N>>>(d_bb+N, d_bb+5*N);
        poly_mulselfadj_fft_g<<<BATCH,N/2>>>(d_bb+2*N);
        poly_copy<<<BATCH,N>>>(d_bb+5*N, d_bb+3*N);
        poly_mulselfadj_fft_g<<<BATCH,N/2>>>(d_bb+5*N);
        poly_add_g<<<BATCH,N>>>(d_bb+2*N, d_bb+5*N);

        poly_set_g<<<BATCH,N>>>(d_bb+5*N, d_hm);
        FFT_SM_g<<<BATCH,128>>>(d_bb+5*N, 10*N, 10*N);
        poly_copy<<<BATCH,N>>>(d_bb+6*N, d_bb+5*N);
        poly_mul_fft<<<BATCH,N/2>>>(d_bb+6*N, d_bb+4*N);
        poly_mulconst<<<BATCH,N>>>(d_bb+6*N, fpr_n(fpr_inverse_of_q));
        poly_mul_fft<<<BATCH,N/2>>>(d_bb+5*N, d_bb+3*N);
        poly_mulconst<<<BATCH,N>>>(d_bb+5*N, fpr_inverse_of_q);

        poly_copy<<<BATCH,N>>>(d_bb+3*N, d_bb+5*N); // t0
        poly_copy<<<BATCH,N>>>(d_bb+4*N, d_bb+6*N); // t1

        ffSampling_fft_dyntree<<<BATCH,1>>>(d_bb+3*N, d_bb+4*N, d_bb, d_bb+1*N, d_bb+2*N, LOGN, LOGN, d_bb+5*N, d_scA, d_scdptr);

        // Rebuild basis
        poly_copy<<<BATCH,N>>>(d_bb+5*N, d_bb+4*N);
        poly_copy<<<BATCH,N>>>(d_bb+4*N, d_bb+3*N);
        smallints_to_fpr_g<<<BATCH, N>>>(d_bb,     d_g, N, 10*N);
        smallints_to_fpr_g<<<BATCH, N>>>(d_bb+N,   d_f, N, 10*N);
        smallints_to_fpr_g<<<BATCH, N>>>(d_bb+2*N, d_G, N, 10*N);
        smallints_to_fpr_g<<<BATCH, N>>>(d_bb+3*N, d_F, N, 10*N);

#ifdef COMB_KER
        FFT_SMx4_g<<<BATCH,128>>>(d_bb, d_bb+N, d_bb+2*N, d_bb+3*N, 10*N, 10*N);
#else
        FFT_SM_g<<<BATCH,128>>>(d_bb,     10*N, 10*N);
        FFT_SM_g<<<BATCH,128>>>(d_bb+N,   10*N, 10*N);
        FFT_SM_g<<<BATCH,128>>>(d_bb+2*N, 10*N, 10*N);
        FFT_SM_g<<<BATCH,128>>>(d_bb+3*N, 10*N, 10*N);
#endif

        poly_neg_g<<<BATCH,N>>>(d_bb+N,   10*N, 10*N);
        poly_neg_g<<<BATCH,N>>>(d_bb+3*N, 10*N, 10*N);

        poly_copy<<<BATCH,N>>>(d_bb+7*N, d_bb+5*N); // ty
        poly_copy<<<BATCH,N>>>(d_bb+6*N, d_bb+4*N); // tx
        poly_mul_fft<<<BATCH,N/2>>>(d_bb+6*N, d_bb);
        poly_mul_fft<<<BATCH,N/2>>>(d_bb+7*N, d_bb+2*N);
        poly_add_g<<<BATCH,N>>>(d_bb+6*N, d_bb+7*N);
        poly_copy<<<BATCH,N>>>(d_bb+7*N, d_bb+4*N);
        poly_mul_fft<<<BATCH,N/2>>>(d_bb+7*N, d_bb+N);
        poly_copy<<<BATCH,N>>>(d_bb+4*N, d_bb+6*N);
        poly_mul_fft<<<BATCH,N/2>>>(d_bb+5*N, d_bb+3*N);
        poly_add_g<<<BATCH,N>>>(d_bb+5*N, d_bb+7*N);
        iFFT_g<<<BATCH,128>>>(d_bb+4*N, 10*N, 10*N);
        iFFT_g<<<BATCH,128>>>(d_bb+5*N, 10*N, 10*N);

        // *** FIXED pointer arithmetic: offset in fpr-units, then cast ***
        d_s1tmp = (int16_t*)(d_bb + 6*N);  // tx region reinterpreted
        d_s2tmp = (int16_t*)(d_bb);        // base region reinterpreted

        check1<<<BATCH, 1>>>(d_s1tmp, d_bb+4*N, d_hm, d_sqn);
        check2<<<BATCH, N>>>(d_s2tmp, d_bb+5*N);
        is_short_half_gpu<<<BATCH,1>>>(d_sqn, d_s2tmp, d_s);

        // Encode + bundle [len||nonce||m||sig]
        comp_encode_gpu<<<BATCH, 1>>>(d_esig+1, (CRYPTO_BYTES - 2 - NONCELEN - 1), d_s2tmp, LOGN, d_esiglen);
        byte_copy<<<BATCH, MLEN>>>(d_sm + 2 + NONCELEN, d_m_d, (MLEN+CRYPTO_BYTES), MLEN);
        write_smlen_gpu<<<BATCH, 1>>>(d_sm, d_esiglen);
        byte_copy<<<BATCH, NONCELEN>>>(d_sm + 2, d_nonce, (MLEN+CRYPTO_BYTES), NONCELEN);
        byte_copy2<<<BATCH, 1>>>(d_sm + 2 + NONCELEN + MLEN, d_esig, (MLEN+CRYPTO_BYTES), d_esiglen);

        CUDA_OK(cudaMemcpy(h_sm, d_sm, BATCH*(MLEN+CRYPTO_BYTES)*sizeof(uint8_t), cudaMemcpyDeviceToHost));
    }

    elapsed = stop_event(start, stop);
    //std::printf("\nTotal time for Signatures: %.4f ms, TP: %.0f \n", elapsed/REPEAT, 1000.0 * BATCH / (elapsed/REPEAT));

cleanup:
    // free device
    cudaFree(d_F); cudaFree(d_G); cudaFree(d_f); cudaFree(d_g);
    cudaFree(d_bb); cudaFree(d_hm); cudaFree(d_t1); cudaFree(d_t2);
    cudaFree(d_sqn); cudaFree(d_s1tmp); cudaFree(d_s2tmp);
    cudaFree(d_scA); cudaFree(d_scdptr);
    cudaFree(d_seed); cudaFree(d_nonce); cudaFree(d_m_d);
    cudaFree(d_s); cudaFree(d_esig); cudaFree(d_esiglen);
    cudaFree(d_sm); cudaFree(d_sk);

    // free host
    cudaFreeHost(h_seed);
    cudaFreeHost(h_nonce);
    cudaFreeHost(h_sk);
    cudaFreeHost(h_esig);
}

// ===============================================================
// Falcon verify (host wrapper)
// ===============================================================
void crypto_ver(uint8_t *h_sm, uint8_t *h_m, uint8_t *h_m2) {
    cudaEvent_t start, stop;
    float elapsed = 0.0f;

    // Host pinned
    uint8_t  *h_pk = nullptr;
    uint32_t *h_smlen = nullptr;

#ifdef DEBUG
    uint16_t *h_tmp = nullptr;
#endif

    // Device
    uint16_t *d_tmp = nullptr, *d_h = nullptr, *d_hm = nullptr;
    int16_t  *d_s2  = nullptr, *d_sig = nullptr;
    uint32_t *d_s = nullptr, *d_smlen = nullptr, *d_msg_len = nullptr, *d_sig_len = nullptr;
    uint8_t  *d_pk = nullptr, *d_sm_d = nullptr, *d_m_d = nullptr;
    uint64_t *d_scA = nullptr, *d_scdptr = nullptr;

    // Host alloc
    CUDA_OK(cudaMallocHost((void**)&h_pk,    BATCH*CRYPTO_PUBLICKEYBYTES*sizeof(uint8_t)));
    CUDA_OK(cudaMallocHost((void**)&h_smlen, BATCH*sizeof(uint32_t)));
#ifdef DEBUG
    CUDA_OK(cudaMallocHost((void**)&h_tmp,   BATCH*N*sizeof(uint16_t)));
#endif

    // Fill pk, smlen
    for (int j=0; j<BATCH; j++) {
        for (int i=0; i<CRYPTO_PUBLICKEYBYTES; i++)
            h_pk[j*CRYPTO_PUBLICKEYBYTES + i] = pk[i];
        h_smlen[j] = 691; // known-length in your TV; can be made dynamic
    }

    // Device alloc
    CUDA_OK(cudaMalloc((void**)&d_h,     BATCH*N*sizeof(uint16_t)));
    CUDA_OK(cudaMalloc((void**)&d_tmp,   BATCH*N*sizeof(uint16_t)));
    CUDA_OK(cudaMalloc((void**)&d_s2,    BATCH*N*sizeof(int16_t)));
    CUDA_OK(cudaMalloc((void**)&d_hm,    BATCH*N*sizeof(uint16_t)));
    CUDA_OK(cudaMalloc((void**)&d_s,     BATCH*sizeof(uint32_t)));
    CUDA_OK(cudaMalloc((void**)&d_pk,    BATCH*CRYPTO_PUBLICKEYBYTES*sizeof(uint8_t)));
    CUDA_OK(cudaMalloc((void**)&d_sm_d,  BATCH*(MLEN+CRYPTO_BYTES)*sizeof(uint8_t)));
    CUDA_OK(cudaMalloc((void**)&d_smlen, BATCH*sizeof(uint32_t)));
    CUDA_OK(cudaMalloc((void**)&d_msg_len, BATCH*sizeof(uint32_t)));
    CUDA_OK(cudaMalloc((void**)&d_sig_len, BATCH*sizeof(uint32_t)));
    CUDA_OK(cudaMalloc((void**)&d_sig,   BATCH*N*sizeof(int16_t)));
    CUDA_OK(cudaMalloc((void**)&d_scA,   BATCH*25*sizeof(uint64_t)));
    CUDA_OK(cudaMalloc((void**)&d_scdptr,BATCH*sizeof(uint64_t)));
    CUDA_OK(cudaMalloc((void**)&d_m_d,   BATCH*MLEN*sizeof(uint8_t))); // *** FIXED ***

    CUDA_OK(cudaMemset(d_scdptr, 0, BATCH*sizeof(uint64_t)));
    CUDA_OK(cudaMemset(d_hm,     0, BATCH*sizeof(uint16_t)));
    CUDA_OK(cudaDeviceSetSharedMemConfig(cudaSharedMemBankSizeEightByte));
    CUDA_OK(cudaFuncSetCacheConfig(hash_to_point_vartime_par, cudaFuncCachePreferShared));

    start_event(start, stop);

    for (int rep=0; rep<REPEAT; rep++) {
        CUDA_OK(cudaMemcpy(d_pk,    h_pk,    BATCH*CRYPTO_PUBLICKEYBYTES*sizeof(uint8_t), cudaMemcpyHostToDevice));
        CUDA_OK(cudaMemcpy(d_sm_d,  h_sm,    BATCH*(MLEN+CRYPTO_BYTES)*sizeof(uint8_t),  cudaMemcpyHostToDevice));
        CUDA_OK(cudaMemcpy(d_smlen, h_smlen, BATCH*sizeof(uint32_t),                      cudaMemcpyHostToDevice));
        CUDA_OK(cudaMemcpy(d_m_d,   h_m,     BATCH*MLEN*sizeof(uint8_t),                  cudaMemcpyHostToDevice));

        modq_decode_gpu<<<BATCH, N/4>>>(d_h, LOGN, d_pk+1, CRYPTO_PUBLICKEYBYTES - 1);
        mq_NTT_gpu<<<BATCH, N/2>>>(d_h, LOGN);
        mq_poly_tomonty<<<BATCH, N/2>>>(d_h);
        msg_len_gpu<<<BATCH, 1>>>(d_sm_d, d_msg_len, d_smlen, d_sig_len);

#ifdef COMB_KER
        comb_all_kernels<<<BATCH, N/2>>>(d_tmp, d_sig, d_h, d_hm);
#else
        comp_decode_gpu<<<BATCH, 1>>>(d_sig, 9, d_sm_d, d_sig_len, d_msg_len);
        i_shake256_inject_gpu<<<BATCH, 1>>>(d_scA, d_scdptr, d_sm_d + 2, d_msg_len);
        i_shake256_flip_gpu<<<BATCH, 1>>>(d_scA, d_scdptr);
        hash_to_point_vartime_par<<<BATCH,32>>>(d_scA, d_scdptr, d_hm);

        reduce_s2<<<BATCH, N>>>(d_sig, d_tmp);
        mq_NTT_gpu<<<BATCH, N/2>>>(d_tmp, LOGN);
        mq_poly_montymul_ntt_gpu<<<BATCH, N>>>(d_tmp, d_h);
        mq_iNTT_gpu<<<BATCH, N/2>>>(d_tmp);
        mq_poly_sub<<<BATCH, N>>>(d_tmp, d_hm);
        norm_s2<<<BATCH, N>>>(d_tmp);
#endif
        is_short_gpu<<<BATCH, 1>>>((int16_t*)d_tmp, d_sig, d_s);

        // Recover m (compare/copy out)
        byte_cmp<<<BATCH, MLEN>>>(d_m_d, d_sm_d + 2 + NONCELEN);

#ifdef DEBUG
        CUDA_OK(cudaMemcpy(h_tmp, d_tmp, BATCH*N*sizeof(uint16_t), cudaMemcpyDeviceToHost));
#endif
        CUDA_OK(cudaMemcpy(h_m2, d_m_d, BATCH*MLEN*sizeof(uint8_t), cudaMemcpyDeviceToHost));
    }

    elapsed = stop_event(start, stop);
    //std::printf("\nTotal time for Verification: %.4f ms, TP: %.0f \n", elapsed/REPEAT, 1000.0 * BATCH / (elapsed/REPEAT));

cleanup:
    // device
    cudaFree(d_tmp);  cudaFree(d_h);    cudaFree(d_hm);
    cudaFree(d_s2);   cudaFree(d_sig);  cudaFree(d_s);
    cudaFree(d_pk);   cudaFree(d_sm_d); cudaFree(d_smlen);
    cudaFree(d_msg_len); cudaFree(d_sig_len);
    cudaFree(d_scA);  cudaFree(d_scdptr);
    cudaFree(d_m_d);

    // host
#ifdef DEBUG
    cudaFreeHost(h_tmp);
#endif
    cudaFreeHost(h_pk);
    cudaFreeHost(h_smlen);
}

// ===============================================================
// Compare recovered messages (per batch)
// ===============================================================
int check_signatures(uint8_t *h_m1, uint8_t *h_m2) {
    for (int j = 0; j < BATCH; j++) {
        for (int i = 0; i < MLEN; i++) {
            // *** FIXED: index by MLEN (message length), not N (Falcon degree) ***
            if (h_m1[j*MLEN + i] != h_m2[j*MLEN + i]) {
                std::printf("\nError: signature not verified (batch %d, byte %d: %u != %u)\n",
                            j, i, (unsigned)h_m1[j*MLEN + i], (unsigned)h_m2[j*MLEN + i]);
                return 0;
            }
        }
    }
    return 1;
}
