#include "../include/fft.cuh"
#include "../include/consts.cuh"

__global__ void poly_set_g(fpr *out, const uint16_t *in)
{
    uint32_t tid = threadIdx.x, bid = blockIdx.x;
    out[bid*10*N + tid] = fpr_of(in[bid*N + tid]);
}

__global__ void poly_mulselfadj_fft_g(fpr *a)
{
    uint32_t tid = threadIdx.x, bid = blockIdx.x, hn = N >> 1;
    fpr a_re = a[bid*10*N + tid];
    fpr a_im = a[bid*10*N + tid + hn];
    a[bid*10*N + tid]       = fpr_add(fpr_sqr(a_re), fpr_sqr(a_im));
    a[bid*10*N + tid + hn]  = fpr_zero;
}

__global__ void poly_muladj_fft_g(fpr *a, const fpr *b)
{
    uint32_t tid = threadIdx.x, bid = blockIdx.x, hn = N >> 1;
    fpr a_re = a[bid*10*N + tid];
    fpr a_im = a[bid*10*N + tid + hn];
    fpr b_re = b[bid*10*N + tid];
    fpr b_im = fpr_neg(b[bid*10*N + tid + hn]);
    FPC_MUL(a[bid*10*N + tid], a[bid*10*N + tid + hn], a_re, a_im, b_re, b_im);
}

__global__ void poly_add_g(fpr *a, const fpr *b)
{
    uint32_t tid = threadIdx.x, bid = blockIdx.x;
    a[bid*10*N + tid] = fpr_add(a[bid*10*N + tid], b[bid*10*N + tid]);
}

__global__ void FFT_SM_g(fpr *f, uint32_t in_s, uint32_t out_s)
{
    uint32_t tid = threadIdx.x, bid = blockIdx.x;
    uint32_t hn = N >> 1, t = hn, m = 2, u;
    uint32_t ht, j, j2, i1 = 0, j1 = 0;
    fpr x_re, x_im, y_re, y_im, s_re, s_im;
    __shared__ fpr s_f[N];

    for (u = 0; u < N / blockDim.x; u++)
        s_f[u*blockDim.x + tid].v = f[bid*in_s + u*blockDim.x + tid].v;
    __syncthreads();

    for (u = 1; u < 9; u++) {
        i1 = 0; j1 = 0;
        ht = t >> 1;
        j2 = j1 + ht;
        i1 = (tid / j2);
        j  = tid % j2 + (tid / j2) * 2 * j2;

        s_re = fpr_gm_tab[((m + i1) << 1) + 0];
        s_im = fpr_gm_tab[((m + i1) << 1) + 1];

        x_re = s_f[j];
        x_im = s_f[j + hn];
        y_re = s_f[j + ht];
        y_im = s_f[j + ht + hn];

        FPC_MUL(y_re, y_im, y_re, y_im, s_re, s_im);
        FPC_ADD(s_f[j],          s_f[j + hn],          x_re, x_im, y_re, y_im);
        FPC_SUB(s_f[j + ht],     s_f[j + ht + hn],     x_re, x_im, y_re, y_im);

        m <<= 1;
        t  = ht;
        __syncthreads();
    }

    for (u = 0; u < N / blockDim.x; u++)
        f[bid*in_s + u*blockDim.x + tid].v = s_f[u*blockDim.x + tid].v;
}

__global__ void FFT_SMx4_g(fpr *f0, fpr *f1, fpr *f2, fpr *f3, uint32_t in_s, uint32_t out_s)
{
    uint32_t tid = threadIdx.x, bid = blockIdx.x, u;
    uint32_t hn = N >> 1, t = hn, m = 2, ht, j, j2, i1 = 0, j1 = 0;
    fpr x_re, x_im, y_re, y_im, s_re, s_im;
    __shared__ fpr s_f[N];

    for (u = 0; u < N / blockDim.x; u++)
        s_f[u*blockDim.x + tid].v = f0[bid*in_s + u*blockDim.x + tid].v;
    __syncthreads();
    for (u = 1; u < 9; u++) {
        i1 = 0; j1 = 0;
        ht = t >> 1;
        j2 = j1 + ht;
        i1 = (tid / j2);
        j  = tid % j2 + (tid / j2) * 2 * j2;

        s_re = fpr_gm_tab[((m + i1) << 1) + 0];
        s_im = fpr_gm_tab[((m + i1) << 1) + 1];

        x_re = s_f[j];
        x_im = s_f[j + hn];
        y_re = s_f[j + ht];
        y_im = s_f[j + ht + hn];

        FPC_MUL(y_re, y_im, y_re, y_im, s_re, s_im);
        FPC_ADD(s_f[j],          s_f[j + hn],          x_re, x_im, y_re, y_im);
        FPC_SUB(s_f[j + ht],     s_f[j + ht + hn],     x_re, x_im, y_re, y_im);

        m <<= 1;
        t  = ht;
        __syncthreads();
    }
    for (u = 0; u < N / blockDim.x; u++)
        f0[bid*in_s + u*blockDim.x + tid].v = s_f[u*blockDim.x + tid].v;

    hn = N >> 1; t = hn; m = 2;
    for (u = 0; u < N / blockDim.x; u++)
        s_f[u*blockDim.x + tid].v = f1[bid*in_s + u*blockDim.x + tid].v;
    __syncthreads();
    for (u = 1; u < 9; u++) {
        i1 = 0; j1 = 0;
        ht = t >> 1;
        j2 = j1 + ht;
        i1 = (tid / j2);
        j  = tid % j2 + (tid / j2) * 2 * j2;

        s_re = fpr_gm_tab[((m + i1) << 1) + 0];
        s_im = fpr_gm_tab[((m + i1) << 1) + 1];

        x_re = s_f[j];
        x_im = s_f[j + hn];
        y_re = s_f[j + ht];
        y_im = s_f[j + ht + hn];

        FPC_MUL(y_re, y_im, y_re, y_im, s_re, s_im);
        FPC_ADD(s_f[j],          s_f[j + hn],          x_re, x_im, y_re, y_im);
        FPC_SUB(s_f[j + ht],     s_f[j + ht + hn],     x_re, x_im, y_re, y_im);

        m <<= 1;
        t  = ht;
        __syncthreads();
    }
    for (u = 0; u < N / blockDim.x; u++)
        f1[bid*in_s + u*blockDim.x + tid].v = s_f[u*blockDim.x + tid].v;

    hn = N >> 1; t = hn; m = 2;
    for (u = 0; u < N / blockDim.x; u++)
        s_f[u*blockDim.x + tid].v = f2[bid*in_s + u*blockDim.x + tid].v;
    __syncthreads();
    for (u = 1; u < 9; u++) {
        i1 = 0; j1 = 0;
        ht = t >> 1;
        j2 = j1 + ht;
        i1 = (tid / j2);
        j  = tid % j2 + (tid / j2) * 2 * j2;

        s_re = fpr_gm_tab[((m + i1) << 1) + 0];
        s_im = fpr_gm_tab[((m + i1) << 1) + 1];

        x_re = s_f[j];
        x_im = s_f[j + hn];
        y_re = s_f[j + ht];
        y_im = s_f[j + ht + hn];

        FPC_MUL(y_re, y_im, y_re, y_im, s_re, s_im);
        FPC_ADD(s_f[j],          s_f[j + hn],          x_re, x_im, y_re, y_im);
        FPC_SUB(s_f[j + ht],     s_f[j + ht + hn],     x_re, x_im, y_re, y_im);

        m <<= 1;
        t  = ht;
        __syncthreads();
    }
    for (u = 0; u < N / blockDim.x; u++)
        f2[bid*in_s + u*blockDim.x + tid].v = s_f[u*blockDim.x + tid].v;

    hn = N >> 1; t = hn; m = 2;
    for (u = 0; u < N / blockDim.x; u++)
        s_f[u*blockDim.x + tid].v = f3[bid*in_s + u*blockDim.x + tid].v;
    __syncthreads();
    for (u = 1; u < 9; u++) {
        i1 = 0; j1 = 0;
        ht = t >> 1;
        j2 = j1 + ht;
        i1 = (tid / j2);
        j  = tid % j2 + (tid / j2) * 2 * j2;

        s_re = fpr_gm_tab[((m + i1) << 1) + 0];
        s_im = fpr_gm_tab[((m + i1) << 1) + 1];

        x_re = s_f[j];
        x_im = s_f[j + hn];
        y_re = s_f[j + ht];
        y_im = s_f[j + ht + hn];

        FPC_MUL(y_re, y_im, y_re, y_im, s_re, s_im);
        FPC_ADD(s_f[j],          s_f[j + hn],          x_re, x_im, y_re, y_im);
        FPC_SUB(s_f[j + ht],     s_f[j + ht + hn],     x_re, x_im, y_re, y_im);

        m <<= 1;
        t  = ht;
        __syncthreads();
    }
    for (u = 0; u < N / blockDim.x; u++)
        f3[bid*in_s + u*blockDim.x + tid].v = s_f[u*blockDim.x + tid].v;
}

__global__ void FFT_g(fpr *f, uint32_t in_s, uint32_t out_s)
{
    uint32_t tid = threadIdx.x, bid = blockIdx.x;
    uint32_t hn = N >> 1, t = hn, m = 2, u;
    uint32_t ht, j, j2, i1 = 0, j1 = 0;
    fpr x_re, x_im, y_re, y_im, s_re, s_im;
    __shared__ fpr s_fpr_gm_tab[2*N];

    for (u = 0; u < 2*N / blockDim.x; u++)
        s_fpr_gm_tab[u*blockDim.x + tid].v = fpr_gm_tab[u*blockDim.x + tid].v;
    __syncthreads();

    for (u = 1; u < 9; u++) {
        i1 = 0; j1 = 0;
        ht = t >> 1;
        j2 = j1 + ht;
        i1 = (tid / j2);
        j  = tid % j2 + (tid / j2) * 2 * j2;

        s_re = s_fpr_gm_tab[((m + i1) << 1) + 0];
        s_im = s_fpr_gm_tab[((m + i1) << 1) + 1];

        x_re = f[bid*in_s + j];
        x_im = f[bid*in_s + j + hn];
        y_re = f[bid*in_s + j + ht];
        y_im = f[bid*in_s + j + ht + hn];

        FPC_MUL(y_re, y_im, y_re, y_im, s_re, s_im);
        FPC_ADD(f[bid*out_s + j],          f[bid*out_s + j + hn],          x_re, x_im, y_re, y_im);
        FPC_SUB(f[bid*out_s + j + ht],     f[bid*out_s + j + ht + hn],     x_re, x_im, y_re, y_im);

        m <<= 1;
        t  = ht;
        __syncthreads();
    }
}

__global__ void iFFT_g(fpr *f, uint32_t in_s, uint32_t out_s)
{
    uint32_t tid = threadIdx.x, bid = blockIdx.x;
    uint32_t hn = N >> 1, t = 1, m = N;
    uint32_t u, j;
    for (u = 9; u > 1; u--) {
        uint32_t hm = m >> 1, dt = t << 1;
        j = tid % t + (tid / t) * dt;

        fpr s_re = fpr_gm_tab[(hm*2 + (tid/t)*2) + 0];
        fpr s_im = fpr_neg(fpr_gm_tab[(hm*2 + (tid/t)*2) + 1]);

        fpr x_re = f[bid*in_s + j];
        fpr x_im = f[bid*in_s + j + hn];
        fpr y_re = f[bid*in_s + j + t];
        fpr y_im = f[bid*in_s + j + t + hn];

        FPC_ADD(f[bid*out_s + j],          f[bid*out_s + j + hn],          x_re, x_im, y_re, y_im);
        FPC_SUB(x_re, x_im, x_re, x_im, y_re, y_im);
        FPC_MUL(f[bid*out_s + j + t],      f[bid*out_s + j + t + hn],      x_re, x_im, s_re, s_im);

        t = dt; m = hm;
        __syncthreads();
    }

    for (u = 0; u < N / blockDim.x; u++)
        f[bid*out_s + u*blockDim.x + tid] = fpr_mul(f[bid*out_s + u*blockDim.x + tid], fpr_p2_tab[9]);
}

__global__ void poly_mul_fft(fpr *a, const fpr *b)
{
    uint32_t tid = threadIdx.x, bid = blockIdx.x, hn = N >> 1;
    fpr a_re = a[bid*10*N + tid];
    fpr a_im = a[bid*10*N + tid + hn];
    fpr b_re = b[bid*10*N + tid];
    fpr b_im = b[bid*10*N + tid + hn];
    FPC_MUL(a[bid*10*N + tid], a[bid*10*N + tid + hn], a_re, a_im, b_re, b_im);
}

__global__ void poly_mulconst(fpr *a, fpr x)
{
    uint32_t tid = threadIdx.x, bid = blockIdx.x;
    a[bid*10*N + tid] = fpr_mul(a[bid*10*N + tid], x);
}

__global__ void smallints_to_fpr_g(fpr *r, int8_t *t, uint32_t in_s, uint32_t out_s)
{
    uint32_t tid = threadIdx.x, bid = blockIdx.x;
    r[bid*out_s + tid].v = (double)t[bid*in_s + tid];
}

__global__ void poly_neg_g(fpr *a, uint32_t in_s, uint32_t out_s)
{
    uint32_t tid = threadIdx.x, bid = blockIdx.x;
    a[bid*out_s + tid] = fpr_neg(a[bid*in_s + tid]);
}

__global__ void poly_copy(fpr *out, fpr *in)
{
    uint32_t tid = threadIdx.x, bid = blockIdx.x;
    out[bid*10*N + tid] = in[bid*10*N + tid];
}

__global__ void byte_copy(uint8_t *out, uint8_t *in, uint32_t outlen, uint32_t inlen)
{
    uint32_t tid = threadIdx.x, bid = blockIdx.x;
    out[bid*outlen + tid] = in[bid*inlen + tid];
}

__global__ void byte_copy2(uint8_t *out, uint8_t *in, uint32_t outlen, uint32_t *inlen)
{
    uint32_t bid = blockIdx.x;
    for (uint32_t i = 0; i < inlen[bid]; i++)
        out[bid*outlen + i] = in[bid*(CRYPTO_BYTES - 2 - NONCELEN) + i];
}

__device__ void poly_LDL_fft(const fpr *g00, fpr *g01, fpr *g11, unsigned logn)
{
    size_t n = (size_t)1 << logn, hn = n >> 1;
    for (size_t u = 0; u < hn; u++) {
        fpr g00_re = g00[u],     g00_im = g00[u + hn];
        fpr g01_re = g01[u],     g01_im = g01[u + hn];
        fpr g11_re = g11[u],     g11_im = g11[u + hn];
        fpr mu_re, mu_im;
        FPC_DIV(mu_re, mu_im, g01_re, g01_im, g00_re, g00_im);
        FPC_MUL(g01_re, g01_im, mu_re, mu_im, g01_re, fpr_neg(g01_im));
        FPC_SUB(g11[u], g11[u + hn], g11_re, g11_im, g01_re, g01_im);
        g01[u] = mu_re;
        g01[u + hn] = fpr_neg(mu_im);
    }
}

__device__ void poly_split_fft(fpr *f0, fpr *f1, const fpr *f, unsigned logn)
{
    size_t n = (size_t)1 << logn, hn = n >> 1, qn = hn >> 1;
    f0[0] = f[0];
    f1[0] = f[hn];
    for (size_t u = 0; u < qn; u++) {
        fpr a_re = f[(u << 1) + 0], a_im = f[(u << 1) + 0 + hn];
        fpr b_re = f[(u << 1) + 1], b_im = f[(u << 1) + 1 + hn];
        fpr t_re, t_im;
        FPC_ADD(t_re, t_im, a_re, a_im, b_re, b_im);
        f0[u]      = fpr_half(t_re);
        f0[u + qn] = fpr_half(t_im);
        FPC_SUB(t_re, t_im, a_re, a_im, b_re, b_im);
        FPC_MUL(t_re, t_im, t_re, t_im, fpr_gm_tab[((u + hn) << 1) + 0], fpr_neg(fpr_gm_tab[((u + hn) << 1) + 1]));
        f1[u]      = fpr_half(t_re);
        f1[u + qn] = fpr_half(t_im);
    }
}

__device__ void poly_merge_fft(fpr *f, const fpr *f0, const fpr *f1, unsigned logn)
{
    size_t n = (size_t)1 << logn, hn = n >> 1, qn = hn >> 1;
    f[0]  = f0[0];
    f[hn] = f1[0];
    for (size_t u = 0; u < qn; u++) {
        fpr a_re = f0[u], a_im = f0[u + qn];
        fpr b_re, b_im, t_re, t_im;
        FPC_MUL(b_re, b_im, f1[u], f1[u + qn], fpr_gm_tab[((u + hn) << 1) + 0], fpr_gm_tab[((u + hn) << 1) + 1]);
        FPC_ADD(t_re, t_im, a_re, a_im, b_re, b_im);
        f[(u << 1) + 0]      = t_re;
        f[(u << 1) + 0 + hn] = t_im;
        FPC_SUB(t_re, t_im, a_re, a_im, b_re, b_im);
        f[(u << 1) + 1]      = t_re;
        f[(u << 1) + 1 + hn] = t_im;
    }
}

__device__ void poly_add(fpr *a, const fpr *b, unsigned logn)
{
    size_t n = (size_t)1 << logn;
    for (size_t u = 0; u < n; u++) a[u] = fpr_add(a[u], b[u]);
}

__device__ void poly_sub(fpr *a, const fpr *b, unsigned logn)
{
    size_t n = (size_t)1 << logn;
    for (size_t u = 0; u < n; u++) a[u] = fpr_sub(a[u], b[u]);
}

__device__ __forceinline__ uint32_t mq_add(uint32_t x, uint32_t y)
{
    uint32_t d = x + y - Q;
    d += Q & -(d >> 31);
    return d;
}

__device__ __forceinline__ uint32_t mq_sub(uint32_t x, uint32_t y)
{
    uint32_t d = x - y;
    d += Q & -(d >> 31);
    return d;
}

__device__ __forceinline__ uint32_t mq_montymul(uint32_t x, uint32_t y)
{
    uint32_t z = x * y;
    uint32_t w = ((z * Q0I) & 0xFFFFU) * Q;
    z = (z + w) >> 16;
    z -= Q;
    z += Q & -(z >> 31);
    return z;
}

__global__ void mq_NTT_gpu(uint16_t *a, unsigned logn)
{
    uint32_t tid = threadIdx.x, bid = blockIdx.x;
    __shared__ uint16_t s_a[N];

    s_a[tid]       = a[bid*N + tid];
    s_a[tid + 256] = a[bid*N + tid + 256];
    __syncthreads();

    size_t t = N;
    for (size_t m = 1; m < N; m <<= 1) {
        uint32_t ht = t >> 1;
        uint32_t s  = GMb[m + tid/ht];
        uint32_t j  = tid % ht + (tid / ht) * t;

        uint32_t u = s_a[j];
        uint32_t v = mq_montymul(s_a[j + ht], s);

        s_a[j]       = (uint16_t)mq_add(u, v);
        s_a[j + ht]  = (uint16_t)mq_sub(u, v);
        t = ht;
        __syncthreads();
    }

    a[bid*N + tid]       = s_a[tid];
    a[bid*N + tid + 256] = s_a[tid + 256];
}

__global__ void mq_poly_tomonty(uint16_t *f)
{
    uint32_t tid = threadIdx.x, bid = blockIdx.x;
    f[bid*N + tid]            = (uint16_t)mq_montymul(f[bid*N + tid], R2);
    f[bid*N + N/2 + tid]      = (uint16_t)mq_montymul(f[bid*N + N/2 + tid], R2);
}

__global__ void mq_poly_montymul_ntt_gpu(uint16_t *f, const uint16_t *g)
{
    uint32_t tid = threadIdx.x, bid = blockIdx.x;
    f[bid*N + tid] = (uint16_t)mq_montymul(f[bid*N + tid], g[bid*N + tid]);
}

__global__ void mq_iNTT_gpu(uint16_t *a)
{
    uint32_t tid = threadIdx.x, bid = blockIdx.x;
    uint32_t ni = 128;
    __shared__ uint16_t s_a[N];

    s_a[tid]       = a[bid*N + tid];
    s_a[tid + 256] = a[bid*N + tid + 256];
    __syncthreads();

    uint32_t t = 1;
    for (uint32_t m = N; m > 1; m >>= 1) {
        uint32_t hm = m >> 1;
        uint32_t dt = t << 1;
        uint32_t s  = iGMb[hm + tid/t];
        uint32_t j  = tid % t + (tid / t) * dt;

        uint32_t u = s_a[j];
        uint32_t v = s_a[j + t];
        s_a[j]      = (uint16_t)mq_add(u, v);
        uint32_t w  = mq_sub(u, v);
        s_a[j + t]  = (uint16_t)mq_montymul(w, s);

        t = dt;
        __syncthreads();
    }

    a[bid*N + tid]            = (uint16_t)mq_montymul(s_a[tid], ni);
    a[bid*N + N/2 + tid]      = (uint16_t)mq_montymul(s_a[N/2 + tid], ni);
}

__global__ void mq_poly_sub(uint16_t *f, const uint16_t *g)
{
    uint32_t tid = threadIdx.x, bid = blockIdx.x;
    f[bid*N + tid] = (uint16_t)mq_sub(f[bid*N + tid], g[bid*N + tid]);
}

__global__ void comb_all_kernels(uint16_t *a, int16_t *s2, uint16_t *g, uint16_t *h)
{
    uint32_t tid = threadIdx.x, bid = blockIdx.x;
    __shared__ uint16_t s_a[N];

    uint32_t w = (uint32_t)s2[bid*N + tid];
    w += Q & -(w >> 31);
    a[bid*N + tid] = (uint16_t)w;

    w = (uint32_t)s2[bid*N + tid + 256];
    w += Q & -(w >> 31);
    a[bid*N + tid + 256] = (uint16_t)w;

    s_a[tid]       = a[bid*N + tid];
    s_a[tid + 256] = a[bid*N + tid + 256];
    __syncthreads();

    size_t t = N;
    for (size_t m = 1; m < N; m <<= 1) {
        uint32_t ht = t >> 1;
        uint32_t s  = GMb[m + tid/ht];
        uint32_t j  = tid % ht + (tid / ht) * t;

        uint32_t u = s_a[j];
        uint32_t v = mq_montymul(s_a[j + ht], s);

        s_a[j]       = (uint16_t)mq_add(u, v);
        s_a[j + ht]  = (uint16_t)mq_sub(u, v);
        t = ht;
        __syncthreads();
    }

    s_a[tid]            = (uint16_t)mq_montymul(s_a[tid],            g[bid*N + tid]);
    s_a[256 + tid]      = (uint16_t)mq_montymul(s_a[256 + tid],      g[bid*N + 256 + tid]);
    __syncthreads();

    uint32_t ni = 128; t = 1;
    for (uint32_t m = N; m > 1; m >>= 1) {
        uint32_t hm = m >> 1, dt = t << 1;
        uint32_t s  = iGMb[hm + tid/t];
        uint32_t j  = tid % t + (tid / t) * dt;

        uint32_t u = s_a[j];
        uint32_t v = s_a[j + t];
        s_a[j]      = (uint16_t)mq_add(u, v);
        uint32_t ww = mq_sub(u, v);
        s_a[j + t]  = (uint16_t)mq_montymul(ww, s);

        t = dt;
        __syncthreads();
    }

    s_a[tid]            = (uint16_t)mq_montymul(s_a[tid],       ni);
    s_a[N/2 + tid]      = (uint16_t)mq_montymul(s_a[N/2 + tid], ni);

    s_a[tid]            = (uint16_t)mq_sub(s_a[tid],            h[bid*N + tid]);
    s_a[N/2 + tid]      = (uint16_t)mq_sub(s_a[N/2 + tid],      h[bid*N + N/2 + tid]);

    int32_t z = (int32_t)s_a[tid];
    z -= (int32_t)(Q & -(((Q >> 1) - (uint32_t)z) >> 31));
    a[bid*N + tid] = (int16_t)z;

    z = (int32_t)s_a[N/2 + tid];
    z -= (int32_t)(Q & -(((Q >> 1) - (uint32_t)z) >> 31));
    a[bid*N + N/2 + tid] = (int16_t)z;
}
