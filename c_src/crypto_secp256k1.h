#ifndef CRYPTO_SECP256K1_H
#define CRYPTO_SECP256K1_H

#include "evm_arith256.h"

#include <stddef.h>
#include <stdint.h>

typedef struct {
	uint256_t x;
	uint256_t y;
	uint256_t z;
} secp256k1_jac_t;

void secp256k1_fe_inv(const uint256_t *a, uint256_t *out);
void secp256k1_jac_double(const secp256k1_jac_t *p, secp256k1_jac_t *out);
void secp256k1_jac_add(const secp256k1_jac_t *p, const secp256k1_jac_t *q,
    secp256k1_jac_t *out);
void secp256k1_jac_mul(const secp256k1_jac_t *p, const uint256_t *k,
    secp256k1_jac_t *out);
int secp256k1_ecrecover(const uint8_t hash[32], uint8_t v, const uint8_t r[32],
    const uint8_t s[32], uint8_t out_pubkey[64]);
int secp256k1_pubkey_from_seckey(const uint8_t seckey[32], uint8_t out_pubkey[64]);

#endif
