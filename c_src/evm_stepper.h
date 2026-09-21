#ifndef EVM_STEPPER_H
#define EVM_STEPPER_H

#include "evm_arith256.h"
#include "evm_bitwise256.h"
#include "crypto_keccak.h"

#include <stddef.h>
#include <stdint.h>

#define EVM_STACK_MAX 1024
#define EVM_MEM_MAX 65536

typedef struct {
	uint256_t stack[1024];
	int32_t sp; /* pointe vers le prochain slot libre (0 = vide) */
	uint32_t pc;
	uint64_t gas;
	int status; /* 0=RUNNING, 1=STOP, 2=REVERT, 3=STACK_UNDERFLOW, 4=STACK_OVERFLOW, 5=OUT_OF_GAS, 6=INVALID_OPCODE */
	uint8_t memory[65536];
	uint32_t memory_size;
} evm_frame_t;

void evm_frame_init(evm_frame_t *f, uint64_t initial_gas);
int evm_step_one(evm_frame_t *f, const uint8_t *code, size_t code_len);

#endif
