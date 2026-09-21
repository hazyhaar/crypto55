#ifndef EVM_BITWISE256_H
#define EVM_BITWISE256_H

#include "evm_arith256.h"

int evm_lt256(const uint256_t *a, const uint256_t *b);
int evm_gt256(const uint256_t *a, const uint256_t *b);
int evm_slt256(const uint256_t *a, const uint256_t *b);
int evm_sgt256(const uint256_t *a, const uint256_t *b);
int evm_eq256(const uint256_t *a, const uint256_t *b);
int evm_iszero256(const uint256_t *a);
void evm_and256(const uint256_t *a, const uint256_t *b, uint256_t *out);
void evm_or256(const uint256_t *a, const uint256_t *b, uint256_t *out);
void evm_xor256(const uint256_t *a, const uint256_t *b, uint256_t *out);
void evm_not256(const uint256_t *a, uint256_t *out);
void evm_byte256(uint64_t i, const uint256_t *x, uint256_t *out);
void evm_shl256(const uint256_t *shift, const uint256_t *val, uint256_t *out);
void evm_shr256(const uint256_t *shift, const uint256_t *val, uint256_t *out);
void evm_sar256(const uint256_t *shift, const uint256_t *val, uint256_t *out);

#endif
