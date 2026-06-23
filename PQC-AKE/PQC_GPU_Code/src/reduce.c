#include <stdint.h>
#include <stdio.h>
#include "../include/params.h"
#include "../include/reduce.h"

/* Montgomery reduction */
int16_t montgomery_reduce(int32_t a)
{
  int32_t t;
  int16_t u;

  u = (int16_t)(a * QINV);
  t = (int32_t)u * KYBER_Q;
  t = a - t;
  t >>= 16;
  return (int16_t)t;
}

/* Barrett reduction */
int16_t barrett_reduce(int16_t a)
{
  int16_t t;
  const int16_t v = (int16_t)(((1U << 26) + KYBER_Q/2) / KYBER_Q);

  t  = (int16_t)(((int32_t)v * a) >> 26);
  t  = (int16_t)(t * KYBER_Q);
  return (int16_t)(a - t);
}

/* Conditionally subtract q */
int16_t csubq(int16_t a)
{
  a = (int16_t)(a - KYBER_Q);
  a = (int16_t)(a + (int16_t)(((int16_t)(a >> 15)) & KYBER_Q));
  return a;
}

/* Unpack pk and rho */
void unpack_pk(int16_t *pk,
               uint8_t seed[KYBER_SYMBYTES],
               const uint8_t packedpk[KYBER_INDCPA_PUBLICKEYBYTES])
{
  uint32_t i, j;
  for (i = 0; i < KYBER_K; i++) {
    for (j = 0; j < KYBER_N/2; j++) {
      const uint32_t base = i * KYBER_POLYBYTES + 3U * j;
      uint16_t w0 = (uint16_t)(packedpk[base + 0])
                  | (uint16_t)((uint16_t)packedpk[base + 1] << 8);
      uint16_t w1 = (uint16_t)(packedpk[base + 1] >> 4)
                  | (uint16_t)((uint16_t)packedpk[base + 2] << 4);
      pk[i * KYBER_N + 2U*j + 0U] = (int16_t)(w0 & 0x0FFFu);
      pk[i * KYBER_N + 2U*j + 1U] = (int16_t)(w1 & 0x0FFFu);
    }
  }
  for (i = 0; i < KYBER_SYMBYTES; i++)
    seed[i] = packedpk[i + KYBER_POLYVECBYTES];
}

/* Rejection sampling */
unsigned int rej_uniform(int16_t *r, unsigned int len,
                         const uint8_t *buf, unsigned int buflen)
{
  unsigned int ctr = 0, pos = 0;
  while (ctr < len && (pos + 2U) <= buflen) {
    uint16_t val = (uint16_t)buf[pos] | (uint16_t)((uint16_t)buf[pos + 1] << 8);
    pos += 2U;
    if (val < 19U * (uint16_t)KYBER_Q) {
      val -= (uint16_t)((val >> 12) * (uint16_t)KYBER_Q);
      r[ctr++] = (int16_t)val;
    }
  }
  return ctr;
}
