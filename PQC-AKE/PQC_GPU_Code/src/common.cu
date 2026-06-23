#include "../include/common.cuh"
#include "../include/fft.cuh"

__global__ void check2(int16_t* s2tmp, fpr *t1)
{
    uint32_t tid = threadIdx.x, bid = blockIdx.x;
    s2tmp[bid*N + tid] = (int16_t)-fpr_rint(t1[bid*10*N + tid]);
}

__global__ void check1(int16_t* s1tmp, fpr *t0, uint16_t *hm, uint32_t *sqn)
{
    uint32_t bid = blockIdx.x;
    uint32_t ng = 0;
    sqn[bid] = 0;
    for (uint32_t u = 0; u < N; u++) {
        int32_t z = (int32_t)hm[bid*N + u] - (int32_t)fpr_rint(t0[bid*10*N + u]);
        sqn[bid] += (uint32_t)(z * z);
        ng |= sqn[bid];
        s1tmp[bid*10*N + u] = (int16_t)z;
    }
    sqn[bid] |= -(ng >> 31);
}

__global__ void reduce_s2(int16_t *s2, uint16_t *tt)
{
    uint32_t tid = threadIdx.x, bid = blockIdx.x;
    uint32_t w = (uint32_t)s2[bid*N + tid];
    w += Q & -(w >> 31);
    tt[bid*N + tid] = (uint16_t)w;
}

__global__ void norm_s2(uint16_t *tt)
{
    uint32_t tid = threadIdx.x, bid = blockIdx.x;
    int32_t w = (int32_t)tt[bid*N + tid];
    w -= (int32_t)(Q & -(((Q >> 1) - (uint32_t)w) >> 31));
    ((int16_t *)tt)[bid*N + tid] = (int16_t)w;
}

__global__ void is_short_gpu(int16_t *s1, int16_t *s2, uint32_t *s)
{
    uint32_t bid = blockIdx.x;
    uint32_t ng = 0, tmp = 0;
    for (size_t u = 0; u < N; u++) {
        int32_t z = s1[bid*N + u];
        tmp += (uint32_t)(z * z);
        ng  |= tmp;
        z = s2[bid*N + u];
        tmp += (uint32_t)(z * z);
        ng  |= tmp;
    }
    tmp |= -(ng >> 31);
    if (tmp <= l2bound[9]) s[bid] = 1;
    if (!s[bid]) printf("short detected %u\n", s[bid]);
}

__global__ void is_short_half_gpu(uint32_t *sqn, const int16_t *s2, uint32_t *s)
{
    uint32_t bid = blockIdx.x;
    size_t n = (size_t)1 << 9;
    uint32_t ng = -(sqn[bid] >> 31);
    for (size_t u = 0; u < n; u++) {
        int32_t z = s2[bid*N + u];
        sqn[bid] += (uint32_t)(z * z);
        ng |= sqn[bid];
    }
    sqn[bid] |= -(ng >> 31);
    if (sqn[bid] <= l2bound[9]) s[bid] = 1;
    if (!s[bid]) printf("short half detected %u\n", s[bid]);
}

__global__ void modq_decode_gpu(uint16_t *x, unsigned logn, uint8_t *in, size_t max_in_len)
{
    uint32_t tid = threadIdx.x, bid = blockIdx.x;
    uint32_t n = (size_t)1 << logn;
    uint32_t in_len = ((n * 14) + 7) >> 3;
    if (in_len > max_in_len) return;

    uint32_t acc = 0, acc_len = 0, u = 0, i = 0;
    while (u < 4) {
        acc = (acc << 8) | (in[bid*CRYPTO_PUBLICKEYBYTES + tid*7 + i]);
        acc_len += 8;
        if (acc_len >= 14) {
            acc_len -= 14;
            unsigned w = (acc >> acc_len) & 0x3FFF;
            if (w >= 12289) return;
            x[bid*N + tid*4 + u] = (uint16_t)w;
            u++;
        }
        i++;
    }
    if ((acc & (((uint32_t)1 << acc_len) - 1)) != 0) return;
}

__global__ void msg_len_gpu(uint8_t *sm, uint32_t *msg_len, uint32_t *smlen, uint32_t *sig_len)
{
    uint32_t bid = blockIdx.x;
    uint32_t mlen = MLEN;
    sig_len[bid] = ((uint64_t)sm[bid*(mlen + CRYPTO_BYTES) + 0] << 8)
                 | (uint64_t)sm[bid*(mlen + CRYPTO_BYTES) + 1];
    msg_len[bid] = smlen[bid] - 2 - NONCELEN - sig_len[bid];
}

__global__ void comp_decode_gpu(int16_t *x, unsigned logn, uint8_t *in, uint32_t *in_len, uint32_t *msg_len)
{
    uint32_t bid = blockIdx.x;
    uint32_t max_in_len = in_len[bid] - 1;
    uint8_t *buf = in + 3 + NONCELEN + msg_len[bid];

    uint32_t acc = 0; unsigned acc_len = 0; uint32_t v = 0;
    for (uint32_t u = 0; u < N; u++) {
        if (v >= max_in_len) return;
        acc = (acc << 8) | (uint32_t)buf[bid*(MLEN+CRYPTO_BYTES) + v++];
        unsigned b = acc >> acc_len;
        unsigned sgn = b & 128;
        unsigned m = b & 127;

        for (;;) {
            if (acc_len == 0) {
                if (v >= max_in_len) return;
                acc = (acc << 8) | (uint32_t)buf[bid*(MLEN+CRYPTO_BYTES) + v++];
                acc_len = 8;
            }
            acc_len--;
            if (((acc >> acc_len) & 1) != 0) break;
            m += 128;
            if (m > 2047) return;
        }
        if (sgn && m == 0) return;
        x[bid*N + u] = (int16_t)(sgn ? -(int)m : (int)m);
    }
    if ((acc & ((1u << acc_len) - 1u)) != 0) return;
}

__global__ void comp_encode_gpu(uint8_t *buf, size_t max_out_len, const int16_t *x, unsigned logn, uint32_t *len)
{
    uint32_t bid = blockIdx.x;
    size_t n = (size_t)1 << logn;
    uint32_t outlen = (CRYPTO_BYTES - 2 - NONCELEN);

    for (size_t u = 0; u < n; u++) {
        if (x[bid*N + u] < -2047 || x[bid*N + u] > +2047) return;
    }

    uint32_t acc = 0; unsigned acc_len = 0; size_t v = 0;
    for (size_t u = 0; u < n; u++) {
        int t = x[bid*N + u];
        acc <<= 1;
        if (t < 0) { t = -t; acc |= 1; }
        unsigned w = (unsigned)t;

        acc <<= 7; acc |= w & 127u; w >>= 7;
        acc_len += 8;

        acc <<= (w + 1);
        acc |= 1;
        acc_len += w + 1;

        while (acc_len >= 8) {
            acc_len -= 8;
            if (buf != NULL) {
                if (v >= max_out_len) return;
                buf[bid*outlen + v] = (uint8_t)(acc >> acc_len);
            }
            v++;
        }
    }

    if (acc_len > 0) {
        if (buf != NULL) {
            if (v >= max_out_len) return;
            buf[bid*outlen + v] = (uint8_t)(acc << (8 - acc_len));
        }
        v++;
    }
    len[bid] = (uint32_t)(v + 1);
}

__global__ void write_smlen_gpu(uint8_t *sm, uint32_t *sig_len)
{
    uint32_t bid = blockIdx.x;
    sm[bid*(MLEN+CRYPTO_BYTES) + 0] = (unsigned char)(sig_len[bid] >> 8);
    sm[bid*(MLEN+CRYPTO_BYTES) + 1] = (unsigned char)sig_len[bid];
}

__global__ void byte_cmp(uint8_t *m, uint8_t *m1)
{
    uint32_t tid = threadIdx.x, bid = blockIdx.x;
    if (m[bid*MLEN + tid] != m1[bid*(MLEN+CRYPTO_BYTES) + tid]) {
        printf("wrong signature at %u %u: %u %u \n",
               bid, tid, m[bid*MLEN + tid], m1[bid*(MLEN+CRYPTO_BYTES) + tid]);
    }
}

__device__ static inline uint32_t mq_montymul(uint32_t x, uint32_t y)
{
    uint32_t z = x * y;
    uint32_t w = ((z * Q0I) & 0xFFFF) * Q;
    z = (z + w) >> 16;
    z -= Q;
    z += Q & -(z >> 31);
    return z;
}

__device__ static inline uint32_t mq_montysqr(uint32_t x)
{
    return mq_montymul(x, x);
}

__device__ static inline uint32_t mq_div_12289(uint32_t x, uint32_t y)
{
    uint32_t y0,y1,y2,y3,y4,y5,y6,y7,y8,y9,y10,y11,y12,y13,y14,y15,y16,y17,y18;
    y0  = mq_montymul(y, R2);
    y1  = mq_montysqr(y0);
    y2  = mq_montymul(y1, y0);
    y3  = mq_montymul(y2, y1);
    y4  = mq_montysqr(y3);
    y5  = mq_montysqr(y4);
    y6  = mq_montysqr(y5);
    y7  = mq_montysqr(y6);
    y8  = mq_montysqr(y7);
    y9  = mq_montymul(y8, y2);
    y10 = mq_montymul(y9, y8);
    y11 = mq_montysqr(y10);
    y12 = mq_montysqr(y11);
    y13 = mq_montymul(y12, y9);
    y14 = mq_montysqr(y13);
    y15 = mq_montysqr(y14);
    y16 = mq_montymul(y15, y10);
    y17 = mq_montysqr(y16);
    y18 = mq_montymul(y17, y0);
    return mq_montymul(y18, x);
}

__device__ static inline uint32_t mq_conv_small(int x)
{
    uint32_t y = (uint32_t)x;
    y += Q & -(y >> 31);
    return y;
}

__global__ void mq_conv_small_gpu(uint16_t *d, int8_t *x)
{
    uint32_t tid = threadIdx.x, bid = blockIdx.x;
    d[bid*N + tid] = (uint16_t)mq_conv_small(x[bid*N + tid]);
}

__global__ void complete_private_gpu(int8_t *G, const int8_t *f, const int8_t *g, const int8_t *F,
    unsigned logn, uint16_t *t1, uint16_t *t2)
{
    uint32_t tid = threadIdx.x, bid = blockIdx.x;
    t1[bid*N + tid] = (uint16_t)mq_conv_small(g[bid*N + tid]);
    t2[bid*N + tid] = (uint16_t)mq_conv_small(F[bid*N + tid]);
}

__global__ void complete_private_gpu2(uint16_t *t1, uint16_t *t2)
{
    uint32_t tid = threadIdx.x, bid = blockIdx.x;
    if (t2[bid*N + tid] == 0) return;
    t1[bid*N + tid] = (uint16_t)mq_div_12289(t1[bid*N + tid], t2[bid*N + tid]);
}

__global__ void complete_private_gpu3(uint16_t *t1, int8_t *G)
{
    uint32_t tid = threadIdx.x, bid = blockIdx.x;
    uint32_t w = t1[bid*N + tid];
    w -= (Q & ~-((w - (Q >> 1)) >> 31));
    int32_t gi = *(int32_t *)&w;
    if (gi < -127 || gi > +127) return;
    G[bid*N + tid] = (int8_t)gi;
}

__device__ static inline uint32_t mq_add(uint32_t x, uint32_t y)
{
    uint32_t d = x + y - Q;
    d += Q & -(d >> 31);
    return d;
}

__device__ static inline uint32_t mq_sub(uint32_t x, uint32_t y)
{
    uint32_t d = x - y;
    d += Q & -(d >> 31);
    return d;
}

__global__ void complete_private_comb_gpu(int8_t *G, const int8_t *f, const int8_t *g, const int8_t *F,
    unsigned logn, uint16_t *t1, uint16_t *t2)
{
    uint32_t tid = threadIdx.x, bid = blockIdx.x;

    t1[bid*N + tid]          = (uint16_t)mq_conv_small(g[bid*N + tid]);
    t2[bid*N + tid]          = (uint16_t)mq_conv_small(F[bid*N + tid]);
    t1[bid*N + tid+N/2]      = (uint16_t)mq_conv_small(g[bid*N + tid+N/2]);
    t2[bid*N + tid+N/2]      = (uint16_t)mq_conv_small(F[bid*N + tid+N/2]);

    __shared__ uint16_t s_a[N];

    s_a[tid] = t1[bid*N + tid];
    s_a[tid+256] = t1[bid*N + tid+256];
    __syncthreads();

    size_t t = N;
    for (size_t m = 1; m < N; m <<= 1) {
        uint32_t ht = t >> 1, j = tid%ht + (tid/ht)*t, s = GMb[m + tid/ht];
        uint32_t u = s_a[j], v = mq_montymul(s_a[j + ht], s);
        s_a[j] = (uint16_t)mq_add(u, v);
        s_a[j + ht] = (uint16_t)mq_sub(u, v);
        t = ht;
        __syncthreads();
    }
    t1[bid*N + tid] = s_a[tid];
    t1[bid*N + tid+256] = s_a[tid+256];

    s_a[tid] = t2[bid*N + tid];
    s_a[tid+256] = t2[bid*N + tid+256];
    __syncthreads();

    t = N;
    for (size_t m = 1; m < N; m <<= 1) {
        uint32_t ht = t >> 1, j = tid%ht + (tid/ht)*t, s = GMb[m + tid/ht];
        uint32_t u = s_a[j], v = mq_montymul(s_a[j + ht], s);
        s_a[j] = (uint16_t)mq_add(u, v);
        s_a[j + ht] = (uint16_t)mq_sub(u, v);
        t = ht;
        __syncthreads();
    }

    t1[bid*N + tid] = (uint16_t)mq_montymul(t1[bid*N + tid], R2);
    t1[bid*N + N/2 + tid] = (uint16_t)mq_montymul(t1[bid*N + N/2 + tid], R2);

    t1[bid*N + tid] = (uint16_t)mq_montymul(t1[bid*N + tid], s_a[tid]);
    t1[bid*N + N/2 + tid] = (uint16_t)mq_montymul(t1[bid*N + N/2 + tid], s_a[N/2 + tid]);

    t2[bid*N + tid] = (uint16_t)mq_conv_small(f[bid*N + tid]);
    t2[bid*N + N/2 + tid] = (uint16_t)mq_conv_small(f[bid*N + N/2 + tid]);

    s_a[tid] = t2[bid*N + tid];
    s_a[tid+256] = t2[bid*N + tid+256];
    __syncthreads();

    t = N;
    for (size_t m = 1; m < N; m <<= 1) {
        uint32_t ht = t >> 1, j = tid%ht + (tid/ht)*t, s = GMb[m + tid/ht];
        uint32_t u = s_a[j], v = mq_montymul(s_a[j + ht], s);
        s_a[j] = (uint16_t)mq_add(u, v);
        s_a[j + ht] = (uint16_t)mq_sub(u, v);
        t = ht;
        __syncthreads();
    }

    if (s_a[tid] == 0) return;
    t1[bid*N + tid] = (uint16_t)mq_div_12289(t1[bid*N + tid], s_a[tid]);
    if (s_a[N/2 + tid] == 0) return;
    t1[bid*N + N/2 + tid] = (uint16_t)mq_div_12289(t1[bid*N + N/2 + tid], s_a[N/2 + tid]);

    uint32_t ni = 128;
    uint32_t u, v, w;
    uint32_t hm, dt;

    t = 1;
    s_a[tid] = t1[bid*N + tid];
    s_a[tid+256] = t1[bid*N + tid+256];
    __syncthreads();

    for (size_t m = N; m > 1; m >>= 1) {
        hm = m >> 1;
        dt = t << 1;
        uint32_t j = tid%t + (tid/t)*dt, s = iGMb[hm + tid/t];
        u = s_a[j];
        v = s_a[j + t];
        s_a[j] = (uint16_t)mq_add(u, v);
        w = mq_sub(u, v);
        s_a[j + t] = (uint16_t)mq_montymul(w, s);
        t = dt;
        __syncthreads();
    }

    s_a[tid]        = (uint16_t)mq_montymul(s_a[tid],        ni);
    s_a[N/2 + tid]  = (uint16_t)mq_montymul(s_a[N/2 + tid],  ni);

    int32_t gi;
    w = s_a[tid];
    w -= (Q & ~-((w - (Q >> 1)) >> 31));
    gi = *(int32_t *)&w;
    if (gi < -127 || gi > +127) return;
    G[bid*N + tid] = (int8_t)gi;

    w = s_a[N/2 + tid];
    w -= (Q & ~-((w - (Q >> 1)) >> 31));
    gi = *(int32_t *)&w;
    if (gi < -127 || gi > +127) return;
    G[bid*N + N/2 + tid] = (int8_t)gi;
}

__global__ void trim_i8_decode_gpu(int8_t *x, int8_t *y, int8_t *z, unsigned logn, unsigned bits, uint8_t *buf, size_t max_in_len)
{
    size_t n = (size_t)1 << logn;
    size_t in_len = ((n * bits) + 7) >> 3;
    uint32_t bid = blockIdx.x;

    if (in_len > max_in_len) return;

    uint32_t acc = 0, acc_len = 0, mask1 = ((uint32_t)1 << bits) - 1, mask2 = (uint32_t)1 << (bits - 1);
    size_t u = 0, count = 0;

    while (u < n) {
        acc = (acc << 8) | buf[count + bid*CRYPTO_SECRETKEYBYTES];
        acc_len += 8;
        while (acc_len >= bits && u < n) {
            uint32_t w;
            acc_len -= bits;
            w = (acc >> acc_len) & mask1;
            w |= -(w & mask2);
            if (w == (uint32_t)(-((int32_t)mask2))) return;
            x[bid*N + u] = (int8_t)*(int32_t *)&w;
            u++;
        }
        count++;
    }
    if ((acc & (((uint32_t)1 << acc_len) - 1)) != 0) return;

    max_in_len -= in_len; buf += in_len;
    in_len = ((n * bits) + 7) >> 3;
    if (in_len > max_in_len) return;

    u = 0; count = 0; acc = 0; acc_len = 0;
    while (u < n) {
        acc = (acc << 8) | buf[count + bid*CRYPTO_SECRETKEYBYTES];
        acc_len += 8;
        while (acc_len >= bits && u < n) {
            uint32_t w;
            acc_len -= bits;
            w = (acc >> acc_len) & mask1;
            w |= -(w & mask2);
            if (w == (uint32_t)(-((int32_t)mask2))) return;
            y[bid*N + u] = (int8_t)*(int32_t *)&w;
            u++;
        }
        count++;
    }
    if ((acc & (((uint32_t)1 << acc_len) - 1)) != 0) return;

    bits = 8;
    max_in_len -= in_len; buf += in_len;
    in_len = ((n * bits) + 7) >> 3;
    if (in_len > max_in_len) return;

    u = 0; count = 0; acc = 0; acc_len = 0;
    mask1 = ((uint32_t)1 << bits) - 1; mask2 = (uint32_t)1 << (bits - 1);
    while (u < n) {
        acc = (acc << 8) | buf[count + bid*CRYPTO_SECRETKEYBYTES];
        acc_len += 8;
        while (acc_len >= bits && u < n) {
            uint32_t w;
            acc_len -= bits;
            w = (acc >> acc_len) & mask1;
            w |= -(w & mask2);
            if (w == (uint32_t)(-((int32_t)mask2))) return;
            z[bid*N + u] = (int8_t)*(int32_t *)&w;
            u++;
        }
        count++;
    }
    if ((acc & (((uint32_t)1 << acc_len) - 1)) != 0) return;
}
