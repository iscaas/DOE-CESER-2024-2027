#include "ascon.h"
#include <string.h>
#include <stdint.h>

typedef uint64_t bit64;

static bit64 state[5], t[5];
static const bit64 constants[16] = {
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
    0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f
};

static inline bit64 rotate(bit64 x, int l) {
    return (x >> l) ^ (x << (64 - l));
}

static void add_constant(bit64 state[5], int i, int a) {
    state[2] ^= constants[12 - a + i];
}

static void sbox(bit64 x[5]) {
    x[0] ^= x[4]; x[4] ^= x[3]; x[2] ^= x[1];
    t[0] = ~x[0] & x[1];
    t[1] = ~x[1] & x[2];
    t[2] = ~x[2] & x[3];
    t[3] = ~x[3] & x[4];
    t[4] = ~x[4] & x[0];
    x[0] ^= t[1]; x[1] ^= t[2]; x[2] ^= t[3]; x[3] ^= t[4]; x[4] ^= t[0];
    x[1] ^= x[0]; x[0] ^= x[4]; x[3] ^= x[2]; x[2] = ~x[2];
}

static void linear(bit64 state[5]) {
    state[0] ^= rotate(state[0], 19) ^ rotate(state[0], 28);
    state[1] ^= rotate(state[1], 61) ^ rotate(state[1], 39);
    state[2] ^= rotate(state[2], 1)  ^ rotate(state[2], 6);
    state[3] ^= rotate(state[3], 10) ^ rotate(state[3], 17);
    state[4] ^= rotate(state[4], 7)  ^ rotate(state[4], 41);
}

static void p(bit64 state[5], int a) {
    for (int i = 0; i < a; i++) {
        add_constant(state, i, a);
        sbox(state);
        linear(state);
    }
}

static void initialization(bit64 state[5], const bit64 key[2], const bit64 nonce[2]) {
    const bit64 IV = 0x80400c0600000000;
    state[0] = IV;
    state[1] = key[0];
    state[2] = key[1];
    state[3] = nonce[0];
    state[4] = nonce[1];
    p(state, 12);
    state[3] ^= key[0];
    state[4] ^= key[1];
}

static void finalization(bit64 state[5], const bit64 key[2]) {
    state[1] ^= key[0];
    state[2] ^= key[1];
    p(state, 12);
    state[3] ^= key[0];
    state[4] ^= key[1];
}

int ascon_aead128_encrypt(const uint8_t key[16], const uint8_t nonce[16],
                          const uint8_t *plaintext, uint8_t *ciphertext,
                          uint8_t tag[16], size_t len) {
    bit64 k[2], n[2];
    memcpy(k, key, 16);
    memcpy(n, nonce, 16);

    // Initialize state
    initialization(state, k, n);

    // Encrypt in 8-byte (64-bit) blocks
    for (size_t i = 0; i < len; i += 8) {
        bit64 block = 0;
        size_t block_size = (i + 8 <= len) ? 8 : len - i;
        memcpy(&block, plaintext + i, block_size);

        block ^= state[0];
        memcpy(ciphertext + i, &block, block_size);

        state[0] = block;
        p(state, 6);
    }

    // Finalization and tag generation
    finalization(state, k);
    memcpy(tag,     &state[3], 8);
    memcpy(tag + 8, &state[4], 8);

    return 0; // success
}

int ascon_decrypt(const uint8_t key[16], const uint8_t nonce[16],
                  const uint8_t *ciphertext, uint8_t *plaintext,
                  const uint8_t tag[16], size_t len) {
    bit64 k[2], n[2], state[5];

    memcpy(k, key, 16);
    memcpy(n, nonce, 16);

    initialization(state, k, n);

    for (size_t i = 0; i < len; i += 8) {
        bit64 block;
        memcpy(&block, ciphertext + i, 8);
        bit64 pt = block ^ state[0];
        memcpy(plaintext + i, &pt, 8);
        state[0] = block;
        p(state, 6);
    }

    finalization(state, k);

    if (memcmp(tag, &state[3], 8) != 0 || memcmp(tag + 8, &state[4], 8) != 0)
        return -1;  // Auth tag mismatch

    return 0;  // Success
}

