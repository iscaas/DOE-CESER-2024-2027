#include "../include/fft.cuh"
#include "../include/ffSampling.cuh"
#include "../include/consts.cuh"

__device__ void poly_merge_fft_s(fpr *f, const fpr *f0, const fpr *f1, unsigned logn)
{
	size_t n = (size_t)1 << logn, hn = n >> 1, qn = hn >> 1;

	f[0] = f0[0];
	f[hn] = f1[0];

	for (size_t u = 0; u < qn; u++) {
		fpr a_re = f0[u],     a_im = f0[u + qn];
		fpr b_re, b_im, t_re, t_im;
		FPC_MUL(b_re, b_im, f1[u], f1[u + qn],
		        fpr_gm_tab[((u + hn) << 1) + 0],
		        fpr_gm_tab[((u + hn) << 1) + 1]);
		FPC_ADD(t_re, t_im, a_re, a_im, b_re, b_im);
		f[(u << 1) + 0]      = t_re;
		f[(u << 1) + 0 + hn] = t_im;
		FPC_SUB(t_re, t_im, a_re, a_im, b_re, b_im);
		f[(u << 1) + 1]      = t_re;
		f[(u << 1) + 1 + hn] = t_im;
	}
}

__global__ void poly_merge_fft_p(fpr *f, const fpr *f0, const fpr *f1, unsigned logn)
{
	size_t n = (size_t)1 << logn, hn = n >> 1, qn = hn >> 1;
	uint32_t tid = threadIdx.x;

	f[0]  = f0[0];
	f[hn] = f1[0];

	fpr a_re = f0[tid], a_im = f0[tid + qn];
	fpr b_re, b_im, t_re, t_im;

	FPC_MUL(b_re, b_im, f1[tid], f1[tid + qn],
	        fpr_gm_tab[((tid + hn) << 1) + 0],
	        fpr_gm_tab[((tid + hn) << 1) + 1]);
	FPC_ADD(t_re, t_im, a_re, a_im, b_re, b_im);
	f[(tid << 1) + 0]      = t_re;
	f[(tid << 1) + 0 + hn] = t_im;
	FPC_SUB(t_re, t_im, a_re, a_im, b_re, b_im);
	f[(tid << 1) + 1]      = t_re;
	f[(tid << 1) + 1 + hn] = t_im;
}

__device__ void poly_LDL_fft_s(const fpr *g00, fpr *g01, fpr *g11, unsigned logn)
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
		g01[u]       = mu_re;
		g01[u + hn]  = fpr_neg(mu_im);
	}
}

__global__ void poly_LDL_fft_p(const fpr *g00, fpr *g01, fpr *g11, unsigned logn)
{
	size_t n = (size_t)1 << logn, hn = n >> 1;
	uint32_t tid = threadIdx.x;

	fpr g00_re = g00[tid],     g00_im = g00[tid + hn];
	fpr g01_re = g01[tid],     g01_im = g01[tid + hn];
	fpr g11_re = g11[tid],     g11_im = g11[tid + hn];
	fpr mu_re, mu_im;

	FPC_DIV(mu_re, mu_im, g01_re, g01_im, g00_re, g00_im);
	FPC_MUL(g01_re, g01_im, mu_re, mu_im, g01_re, fpr_neg(g01_im));
	FPC_SUB(g11[tid], g11[tid + hn], g11_re, g11_im, g01_re, g01_im);
	g01[tid]      = mu_re;
	g01[tid + hn] = fpr_neg(mu_im);
}

__device__ void poly_split_fft_s(fpr *f0, fpr *f1, const fpr *f, unsigned logn)
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
		FPC_MUL(t_re, t_im, t_re, t_im,
		        fpr_gm_tab[((u + hn) << 1) + 0],
		        fpr_neg(fpr_gm_tab[((u + hn) << 1) + 1]));
		f1[u]      = fpr_half(t_re);
		f1[u + qn] = fpr_half(t_im);
	}
}

__device__ void poly_mul_fft_s(fpr *a, const fpr *b, unsigned logn)
{
	size_t n = (size_t)1 << logn, hn = n >> 1;
	for (size_t u = 0; u < hn; u++) {
		fpr a_re = a[u],     a_im = a[u + hn];
		fpr b_re = b[u],     b_im = b[u + hn];
		FPC_MUL(a[u], a[u + hn], a_re, a_im, b_re, b_im);
	}
}

__global__ void poly_mul_add_fft_p(fpr *a, const fpr *b, fpr *c, unsigned logn)
{
	size_t n = (size_t)1 << logn, hn = n >> 1;
	uint32_t tid = threadIdx.x;

	fpr a_re = a[tid], a_im = a[tid + hn];
	fpr b_re = b[tid], b_im = b[tid + hn];

	FPC_MUL(a[tid], a[tid + hn], a_re, a_im, b_re, b_im);
	c[tid]      = fpr_add(a[tid],      c[tid]);
	c[tid + hn] = fpr_add(a[tid + hn], c[tid + hn]);
}

__device__ void poly_add_s(fpr *a, const fpr *b, unsigned logn)
{
	size_t n = (size_t)1 << logn;
	for (size_t u = 0; u < n; u++) a[u] = fpr_add(a[u], b[u]);
}

__global__ void poly_add_p(fpr *a, const fpr *b, unsigned logn)
{
	uint32_t tid = threadIdx.x;
	a[tid] = fpr_add(a[tid], b[tid]);
}

__device__ void poly_sub_s(fpr *a, const fpr *b, unsigned logn)
{
	size_t n = (size_t)1 << logn;
	for (size_t u = 0; u < n; u++) a[u] = fpr_sub(a[u], b[u]);
}

__device__ uint64_t prng_get_u64(prng_s *p)
{
	size_t u = p->ptr;
	if (u >= (sizeof p->buf.d) - 9) { prng_refill_s(p); u = 0; }
	p->ptr = u + 8;
	return  (uint64_t)p->buf.d[u + 0]
	      | ((uint64_t)p->buf.d[u + 1] << 8)
	      | ((uint64_t)p->buf.d[u + 2] << 16)
	      | ((uint64_t)p->buf.d[u + 3] << 24)
	      | ((uint64_t)p->buf.d[u + 4] << 32)
	      | ((uint64_t)p->buf.d[u + 5] << 40)
	      | ((uint64_t)p->buf.d[u + 6] << 48)
	      | ((uint64_t)p->buf.d[u + 7] << 56);
}

__device__ unsigned prng_get_u8(prng_s *p)
{
	unsigned v = p->buf.d[p->ptr++];
	if (p->ptr == sizeof p->buf.d) prng_refill_s(p);
	return v;
}

__device__ int prng_sgaussian0_sampler(prng_s *p)
{
	static const uint32_t dist[] = {
		10745844u,3068844u,3741698u, 5559083u,1580863u,8248194u, 2260429u,13669192u,2736639u,
		708981u,4421575u,10046180u, 169348u,7122675u,4136815u, 30538u,13063405u,7650655u,
		4132u,14505003u,7826148u, 417u,16768101u,11363290u, 31u,8444042u,8086568u,
		1u,12844466u,265321u, 0u,1232676u,13644283u, 0u,38047u,9111839u, 0u,870u,6138264u,
		0u,14u,12545723u, 0u,0u,3104126u, 0u,0u,28824u, 0u,0u,198u, 0u,0u,1u
	};

	uint64_t lo = prng_get_u64(p);
	uint32_t hi = prng_get_u8(p);

	uint32_t v0 = (uint32_t)lo & 0xFFFFFFU;
	uint32_t v1 = (uint32_t)(lo >> 24) & 0xFFFFFFU;
	uint32_t v2 = (uint32_t)(lo >> 48) | (hi << 16);

	int z = 0;
	for (size_t u = 0; u < sizeof(dist)/sizeof(dist[0]); u += 3) {
		uint32_t w0 = dist[u + 2];
		uint32_t w1 = dist[u + 1];
		uint32_t w2 = dist[u + 0];
		uint32_t cc = (v0 - w0) >> 31;
		cc = (v1 - w1 - cc) >> 31;
		cc = (v2 - w2 - cc) >> 31;
		z += (int)cc;
	}
	return z;
}

__device__ int BerExp(prng_s *p, fpr x, fpr ccs)
{
	int s = (int)fpr_trunc(fpr_mul(x, fpr_inv_log2));
	fpr r = fpr_sub(x, fpr_mul(fpr_of(s), fpr_log2));

	uint32_t sw = (uint32_t)s;
	sw ^= (sw ^ 63U) & -((63U - sw) >> 31);
	s = (int)sw;

	uint64_t z = ((fpr_expm_p63(r, ccs) << 1) - 1) >> s;

	int i = 64;
	uint32_t w;
	do {
		i -= 8;
		w = prng_get_u8(p) - ((uint32_t)(z >> i) & 0xFFU);
	} while (!w && i > 0);
	return (int)(w >> 31);
}

__device__ int sampler(sampler_context_s *spc, fpr mu, fpr isigma)
{
	int s = (int)fpr_floor(mu);
	fpr r = fpr_sub(mu, fpr_of(s));
	fpr dss = fpr_half(fpr_sqr(isigma));
	fpr ccs = fpr_mul(isigma, fpr_sigma_min[9]);

	for (;;) {
		int z0 = prng_sgaussian0_sampler(&spc->p);
		int b  = (int)prng_get_u8(&spc->p) & 1;
		int z  = b + ((b << 1) - 1) * z0;

		fpr x = fpr_mul(fpr_sqr(fpr_sub(fpr_of(z), r)), dss);
		x = fpr_sub(x, fpr_mul(fpr_of(z0 * z0), fpr_inv_2sqrsigma0));
		if (BerExp(&spc->p, x, ccs)) return s + z;
	}
}

__global__ void ffSampling_fft_dyntree(fpr *t0, fpr *t1, fpr *g00, fpr *g01, fpr *g11,
                                       unsigned orig_logn, unsigned logn, fpr *tmp, uint64_t *scA, uint64_t *scdptr)
{
	size_t n, hn, i;
	STACK stack[LOGN + 1];
	unsigned stack_top = 0;
	uint32_t bid = blockIdx.x;

	stack[0].t0   = t0  + bid*10*N;
	stack[0].g00  = g00 + bid*10*N;
	stack[0].g11  = g11 + bid*10*N;
	stack[0].logn = logn;
	stack[0].is_z0 = 0;
	stack[0].is_z1 = 0;

	__shared__ inner_shake256_context_s rng;
	__shared__ sampler_context_s samp_ctx;
	samp_ctx.sigma_min = fpr_sigma_min[logn];
	samp_ctx.p.ptr = 0;
	samp_ctx.p.type = 0;
	rng.dptr = scdptr[bid];
	for (i = 0; i < 25; i++) rng.st.A[i] = scA[i];
	prng_init_s(&samp_ctx.p, &rng);

	while (1) {
		if (stack[stack_top].logn == 0) {
			fpr leaf = stack[stack_top].g00[0];
			leaf = fpr_mul(fpr_sqrt(leaf), fpr_inv_sigma[orig_logn]);
			stack[stack_top].t0[0] = fpr_of(sampler(&samp_ctx, stack[stack_top].t0[0], leaf));
			stack[stack_top].t0[1] = fpr_of(sampler(&samp_ctx, stack[stack_top].t0[1], leaf));

			if (!stack[--stack_top].is_z0)
				poly_merge_fft_s(stack[stack_top].t0 + 8, stack[stack_top].t0 + 6, stack[stack_top].t0 + 7, 1);
			else
				poly_merge_fft_s(stack[stack_top].t0,     stack[stack_top].t0 + 4, stack[stack_top].t0 + 5, 1);
		} else {
			n  = (size_t)1 << stack[stack_top].logn;
			hn = n >> 1;

			if (!stack[stack_top].is_z1) {
				poly_LDL_fft_s(stack[stack_top].g00, stack[stack_top].g00 + n, stack[stack_top].g11, stack[stack_top].logn);

				poly_split_fft_s(stack[stack_top].t0 + (n << 1), stack[stack_top].t0 + (n << 1) + hn, stack[stack_top].g00, stack[stack_top].logn);
				memcpy(stack[stack_top].g00, stack[stack_top].t0 + (n << 1), n * sizeof *(t0 + (n << 1)));
				poly_split_fft_s(stack[stack_top].t0 + (n << 1), stack[stack_top].t0 + (n << 1) + hn, stack[stack_top].g11, stack[stack_top].logn);
				memcpy(stack[stack_top].g11, stack[stack_top].t0 + (n << 1), n * sizeof *(t0 + (n << 1)));
				memcpy(stack[stack_top].t0 + (n << 1), stack[stack_top].g00 + n, n  * sizeof *(g00 + n));
				memcpy(stack[stack_top].g00 + n,       stack[stack_top].g00,     hn * sizeof *g00);
				memcpy(stack[stack_top].g00 + n + hn,  stack[stack_top].g11,     hn * sizeof *g00);

				stack[stack_top].is_z1 = 1;
				poly_split_fft_s(stack[stack_top].t0 + 3*n, stack[stack_top].t0 + 3*n + hn, stack[stack_top].t0 + n, stack[stack_top].logn);

				stack[stack_top + 1].t0    = stack[stack_top].t0 + 3*n;
				stack[stack_top + 1].g00   = stack[stack_top].g11;
				stack[stack_top + 1].g11   = stack[stack_top].g00 + n + hn;
				stack[stack_top + 1].logn  = stack[stack_top].logn - 1;
				stack[stack_top + 1].is_z0 = 0;
				stack[++stack_top].is_z1   = 0;

			} else if (!stack[stack_top].is_z0) {
				memcpy(stack[stack_top].t0 + 3*n, stack[stack_top].t0 + n, n * sizeof *(t0 + n));
				poly_sub_s(stack[stack_top].t0 + 3*n, stack[stack_top].t0 + (n << 2), stack[stack_top].logn);
				memcpy(stack[stack_top].t0 + n, stack[stack_top].t0 + (n << 2), n * sizeof *(t0 + (n << 1)));
				poly_mul_fft_s(stack[stack_top].t0 + (n << 1), stack[stack_top].t0 + 3*n, stack[stack_top].logn);
				poly_add_s(stack[stack_top].t0, stack[stack_top].t0 + (n << 1), stack[stack_top].logn);

				stack[stack_top].is_z0 = 1;
				poly_split_fft_s(stack[stack_top].t0 + (n << 1), stack[stack_top].t0 + (n << 1) + hn, stack[stack_top].t0, stack[stack_top].logn);

				stack[stack_top + 1].t0    = stack[stack_top].t0 + (n << 1);
				stack[stack_top + 1].g00   = stack[stack_top].g00;
				stack[stack_top + 1].g11   = stack[stack_top].g00 + n;
				stack[stack_top + 1].logn  = stack[stack_top].logn - 1;
				stack[stack_top + 1].is_z0 = 0;
				stack[++stack_top].is_z1   = 0;

			} else {
				if (stack[stack_top].logn == orig_logn) {
					return;
				} else {
					if (!stack[--stack_top].is_z0)
						poly_merge_fft_s(stack[stack_top].t0 + (n << 3), stack[stack_top].t0 + 6*n, stack[stack_top].t0 + 7*n, stack[stack_top].logn);
					else
						poly_merge_fft_s(stack[stack_top].t0, stack[stack_top].t0 + (n << 2), stack[stack_top].t0 + 5*n, stack[stack_top].logn);
				}
			}
		}
	}
}
