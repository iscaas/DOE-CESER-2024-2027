#include <stdio.h>
#include <stdint.h>

void geenratekeyHMAC(uint8_t *pk_k, uint8_t *sk_k, uint8_t *keylocal);

void HMAC( uint8_t *inputMsg, int noOfInput, uint8_t *Key, uint8_t *macDigest );

void concatenate_HMAC(uint8_t *output, uint8_t *hmac);

int check_HMAC(uint8_t *h_m1, uint8_t *h_m2); 

void geenrateSymKey(uint8_t *keySym);