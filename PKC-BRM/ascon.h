#ifndef ASCON_H
#define ASCON_H

#include <stdint.h>
#include <stddef.h>

int ascon_aead128_encrypt(const uint8_t key[16], const uint8_t nonce[16],
                          const uint8_t *plaintext, uint8_t *ciphertext,
                          uint8_t tag[16], size_t len);

int ascon_aead128_decrypt(const uint8_t key[16], const uint8_t nonce[16],
                          const uint8_t *ciphertext, uint8_t *plaintext,
                          const uint8_t tag[16], size_t len);

#endif // ASCON_H
