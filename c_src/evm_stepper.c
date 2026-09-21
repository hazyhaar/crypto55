#include "evm_stepper.h"

#include <string.h>

#define EVM_RUNNING 0
#define EVM_STOP 1
#define EVM_REVERT 2
#define EVM_STACK_UNDERFLOW 3
#define EVM_STACK_OVERFLOW 4
#define EVM_OUT_OF_GAS 5
#define EVM_INVALID_OPCODE 6

#define GAS_INVALID (~(uint64_t)0)

static int halt_ex(evm_frame_t *f, int st)
{
	f->status = st;
	f->gas = 0;
	return st;
}

static int require_stack(evm_frame_t *f, int32_t n)
{
	if (f->sp < n) {
		return halt_ex(f, EVM_STACK_UNDERFLOW);
	}
	return 0;
}

static int require_room(evm_frame_t *f)
{
	if (f->sp >= EVM_STACK_MAX) {
		return halt_ex(f, EVM_STACK_OVERFLOW);
	}
	return 0;
}

static void u256_zero(uint256_t *x)
{
	x->w[0] = 0;
	x->w[1] = 0;
	x->w[2] = 0;
	x->w[3] = 0;
}

static void u256_set_u64(uint256_t *x, uint64_t v)
{
	x->w[0] = v;
	x->w[1] = 0;
	x->w[2] = 0;
	x->w[3] = 0;
}

static int u256_as_u64(const uint256_t *x, uint64_t *out)
{
	if ((x->w[1] | x->w[2] | x->w[3]) != 0ULL) {
		return -1;
	}
	*out = x->w[0];
	return 0;
}

static unsigned u256_byte_len(const uint256_t *x)
{
	int i;

	for (i = 31; i >= 0; i--) {
		unsigned limb = (unsigned)i >> 3;
		unsigned sh = ((unsigned)i & 7U) * 8U;
		if (((x->w[limb] >> sh) & 0xffULL) != 0ULL) {
			return (unsigned)i + 1U;
		}
	}
	return 0U;
}

static void bytes_be_to_u256(const uint8_t *be, uint256_t *out)
{
	int i;

	for (i = 0; i < 4; i++) {
		const uint8_t *p = be + (3 - i) * 8;
		out->w[i] = ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
		    ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
		    ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
		    ((uint64_t)p[6] << 8) | (uint64_t)p[7];
	}
}

static void u256_to_bytes_be(const uint256_t *x, uint8_t *be)
{
	int i;

	for (i = 0; i < 4; i++) {
		uint64_t v = x->w[3 - i];
		uint8_t *p = be + i * 8;
		p[0] = (uint8_t)(v >> 56);
		p[1] = (uint8_t)(v >> 48);
		p[2] = (uint8_t)(v >> 40);
		p[3] = (uint8_t)(v >> 32);
		p[4] = (uint8_t)(v >> 24);
		p[5] = (uint8_t)(v >> 16);
		p[6] = (uint8_t)(v >> 8);
		p[7] = (uint8_t)v;
	}
}

static uint64_t mem_gas(uint64_t words)
{
	return 3ULL * words + (words * words) / 512ULL;
}

static int charge_mem(evm_frame_t *f, uint64_t offset, uint64_t size)
{
	uint64_t end;
	uint64_t words;
	uint64_t new_size;
	uint64_t old_words;
	uint64_t old_cost;
	uint64_t new_cost;
	uint64_t delta;

	if (size == 0ULL) {
		return 0;
	}
	if (offset >= (uint64_t)EVM_MEM_MAX) {
		return -1;
	}
	if (size > (uint64_t)EVM_MEM_MAX - offset) {
		return -1;
	}
	end = offset + size;
	words = (end + 31ULL) / 32ULL;
	new_size = words * 32ULL;
	if (new_size > (uint64_t)EVM_MEM_MAX) {
		return -1;
	}
	if (new_size <= (uint64_t)f->memory_size) {
		return 0;
	}
	old_words = ((uint64_t)f->memory_size + 31ULL) / 32ULL;
	old_cost = mem_gas(old_words);
	new_cost = mem_gas(words);
	if (new_cost < old_cost) {
		return -1;
	}
	delta = new_cost - old_cost;
	if (f->gas < delta) {
		return -1;
	}
	f->gas -= delta;
	f->memory_size = (uint32_t)new_size;
	return 0;
}

static int jumpdest_ok(const uint8_t *code, size_t code_len, uint32_t dest)
{
	size_t i;

	if ((size_t)dest >= code_len) {
		return 0;
	}
	if (code[dest] != 0x5b) {
		return 0;
	}
	i = 0;
	while (i < (size_t)dest) {
		uint8_t op = code[i];
		if (op >= 0x60 && op <= 0x7f) {
			i += 1U + (size_t)(op - 0x5f);
		} else {
			i += 1U;
		}
	}
	return i == (size_t)dest;
}

static uint64_t opcode_base_gas(uint8_t op)
{
	switch (op) {
	case 0x00:
		return 0;
	case 0x01:
		return 3;
	case 0x02:
		return 5;
	case 0x03:
		return 3;
	case 0x04:
		return 5;
	case 0x05:
		return 5;
	case 0x06:
		return 5;
	case 0x07:
		return 5;
	case 0x08:
		return 8;
	case 0x09:
		return 8;
	case 0x0a:
		return 10;
	case 0x0b:
		return 5;
	case 0x10:
	case 0x11:
	case 0x12:
	case 0x13:
	case 0x14:
	case 0x15:
	case 0x16:
	case 0x17:
	case 0x18:
	case 0x19:
	case 0x1a:
	case 0x1b:
	case 0x1c:
	case 0x1d:
		return 3;
	case 0x20:
		return 30;
	case 0x50:
		return 2;
	case 0x51:
		return 3;
	case 0x52:
		return 3;
	case 0x53:
		return 3;
	case 0x56:
		return 8;
	case 0x57:
		return 10;
	case 0x58:
		return 2;
	case 0x59:
		return 2;
	case 0x5a:
		return 2;
	case 0x5b:
		return 1;
	case 0x5f:
		return 2;
	case 0x60:
	case 0x61:
	case 0x62:
	case 0x63:
	case 0x64:
	case 0x65:
	case 0x66:
	case 0x67:
	case 0x68:
	case 0x69:
	case 0x6a:
	case 0x6b:
	case 0x6c:
	case 0x6d:
	case 0x6e:
	case 0x6f:
	case 0x70:
	case 0x71:
	case 0x72:
	case 0x73:
	case 0x74:
	case 0x75:
	case 0x76:
	case 0x77:
	case 0x78:
	case 0x79:
	case 0x7a:
	case 0x7b:
	case 0x7c:
	case 0x7d:
	case 0x7e:
	case 0x7f:
		return 3;
	case 0x80:
	case 0x81:
	case 0x82:
	case 0x83:
	case 0x84:
	case 0x85:
	case 0x86:
	case 0x87:
	case 0x88:
	case 0x89:
	case 0x8a:
	case 0x8b:
	case 0x8c:
	case 0x8d:
	case 0x8e:
	case 0x8f:
		return 3;
	case 0x90:
	case 0x91:
	case 0x92:
	case 0x93:
	case 0x94:
	case 0x95:
	case 0x96:
	case 0x97:
	case 0x98:
	case 0x99:
	case 0x9a:
	case 0x9b:
	case 0x9c:
	case 0x9d:
	case 0x9e:
	case 0x9f:
		return 3;
	case 0xfd:
		return 0;
	default:
		return GAS_INVALID;
	}
}

static int exec_binop(evm_frame_t *f,
    void (*fn)(const uint256_t *, const uint256_t *, uint256_t *))
{
	if (require_stack(f, 2) < 0) {
		return -1;
	}
	fn(&f->stack[f->sp - 1], &f->stack[f->sp - 2], &f->stack[f->sp - 2]);
	f->sp--;
	return 0;
}

static int exec_cmp(evm_frame_t *f,
    int (*fn)(const uint256_t *, const uint256_t *))
{
	int r;

	if (require_stack(f, 2) < 0) {
		return -1;
	}
	r = fn(&f->stack[f->sp - 1], &f->stack[f->sp - 2]);
	u256_set_u64(&f->stack[f->sp - 2], r ? 1ULL : 0ULL);
	f->sp--;
	return 0;
}

static int exec_push(evm_frame_t *f, const uint8_t *code, size_t code_len,
    unsigned n)
{
	uint8_t buf[32];
	unsigned i;
	uint256_t v;

	if (require_room(f) < 0) {
		return -1;
	}
	memset(buf, 0, sizeof(buf));
	for (i = 0; i < n; i++) {
		uint8_t b = 0;
		if ((size_t)f->pc < code_len) {
			b = code[f->pc];
		}
		f->pc++;
		buf[32U - n + i] = b;
	}
	bytes_be_to_u256(buf, &v);
	f->stack[f->sp] = v;
	f->sp++;
	return 0;
}

void evm_frame_init(evm_frame_t *f, uint64_t initial_gas)
{
	memset(f, 0, sizeof(*f));
	f->gas = initial_gas;
	f->status = EVM_RUNNING;
	f->sp = 0;
	f->pc = 0;
	f->memory_size = 0;
}

int evm_step_one(evm_frame_t *f, const uint8_t *code, size_t code_len)
{
	uint8_t op;
	uint64_t cost;

	if (f->status != EVM_RUNNING) {
		return f->status;
	}
	if ((size_t)f->pc >= code_len) {
		f->status = EVM_STOP;
		return f->status;
	}
	op = code[f->pc];
	cost = opcode_base_gas(op);
	if (cost == GAS_INVALID) {
		return halt_ex(f, EVM_INVALID_OPCODE);
	}
	if (f->gas < cost) {
		return halt_ex(f, EVM_OUT_OF_GAS);
	}
	f->gas -= cost;
	f->pc++;

	switch (op) {
	case 0x00:
		f->status = EVM_STOP;
		break;
	case 0x01:
		if (exec_binop(f, evm_add256) < 0) {
			return f->status;
		}
		break;
	case 0x02:
		if (exec_binop(f, evm_mul256) < 0) {
			return f->status;
		}
		break;
	case 0x03:
		if (exec_binop(f, evm_sub256) < 0) {
			return f->status;
		}
		break;
	case 0x04:
		if (exec_binop(f, evm_div256) < 0) {
			return f->status;
		}
		break;
	case 0x05:
		if (exec_binop(f, evm_sdiv256) < 0) {
			return f->status;
		}
		break;
	case 0x06:
		if (exec_binop(f, evm_mod256) < 0) {
			return f->status;
		}
		break;
	case 0x07:
		if (exec_binop(f, evm_smod256) < 0) {
			return f->status;
		}
		break;
	case 0x08: {
		if (require_stack(f, 3) < 0) {
			return f->status;
		}
		evm_addmod256(&f->stack[f->sp - 1], &f->stack[f->sp - 2],
		    &f->stack[f->sp - 3], &f->stack[f->sp - 3]);
		f->sp -= 2;
		break;
	}
	case 0x09: {
		if (require_stack(f, 3) < 0) {
			return f->status;
		}
		evm_mulmod256(&f->stack[f->sp - 1], &f->stack[f->sp - 2],
		    &f->stack[f->sp - 3], &f->stack[f->sp - 3]);
		f->sp -= 2;
		break;
	}
	case 0x0a: {
		unsigned blen;
		uint64_t extra;

		if (require_stack(f, 2) < 0) {
			return f->status;
		}
		blen = u256_byte_len(&f->stack[f->sp - 2]);
		extra = 50ULL * (uint64_t)blen;
		if (f->gas < extra) {
			return halt_ex(f, EVM_OUT_OF_GAS);
		}
		f->gas -= extra;
		evm_exp256(&f->stack[f->sp - 1], &f->stack[f->sp - 2],
		    &f->stack[f->sp - 2]);
		f->sp--;
		break;
	}
	case 0x0b: {
		uint64_t b;

		if (require_stack(f, 2) < 0) {
			return f->status;
		}
		if (u256_as_u64(&f->stack[f->sp - 1], &b) < 0) {
			b = 31ULL;
		}
		evm_signextend256(b, &f->stack[f->sp - 2], &f->stack[f->sp - 2]);
		f->sp--;
		break;
	}
	case 0x10:
		if (exec_cmp(f, evm_lt256) < 0) {
			return f->status;
		}
		break;
	case 0x11:
		if (exec_cmp(f, evm_gt256) < 0) {
			return f->status;
		}
		break;
	case 0x12:
		if (exec_cmp(f, evm_slt256) < 0) {
			return f->status;
		}
		break;
	case 0x13:
		if (exec_cmp(f, evm_sgt256) < 0) {
			return f->status;
		}
		break;
	case 0x14:
		if (exec_cmp(f, evm_eq256) < 0) {
			return f->status;
		}
		break;
	case 0x15: {
		int z;

		if (require_stack(f, 1) < 0) {
			return f->status;
		}
		z = evm_iszero256(&f->stack[f->sp - 1]);
		u256_set_u64(&f->stack[f->sp - 1], z ? 1ULL : 0ULL);
		break;
	}
	case 0x16:
		if (exec_binop(f, evm_and256) < 0) {
			return f->status;
		}
		break;
	case 0x17:
		if (exec_binop(f, evm_or256) < 0) {
			return f->status;
		}
		break;
	case 0x18:
		if (exec_binop(f, evm_xor256) < 0) {
			return f->status;
		}
		break;
	case 0x19: {
		if (require_stack(f, 1) < 0) {
			return f->status;
		}
		evm_not256(&f->stack[f->sp - 1], &f->stack[f->sp - 1]);
		break;
	}
	case 0x1a: {
		uint64_t i;

		if (require_stack(f, 2) < 0) {
			return f->status;
		}
		if (u256_as_u64(&f->stack[f->sp - 1], &i) < 0) {
			i = 32ULL;
		}
		evm_byte256(i, &f->stack[f->sp - 2], &f->stack[f->sp - 2]);
		f->sp--;
		break;
	}
	case 0x1b:
		if (require_stack(f, 2) < 0) {
			return f->status;
		}
		evm_shl256(&f->stack[f->sp - 1], &f->stack[f->sp - 2],
		    &f->stack[f->sp - 2]);
		f->sp--;
		break;
	case 0x1c:
		if (require_stack(f, 2) < 0) {
			return f->status;
		}
		evm_shr256(&f->stack[f->sp - 1], &f->stack[f->sp - 2],
		    &f->stack[f->sp - 2]);
		f->sp--;
		break;
	case 0x1d:
		if (require_stack(f, 2) < 0) {
			return f->status;
		}
		evm_sar256(&f->stack[f->sp - 1], &f->stack[f->sp - 2],
		    &f->stack[f->sp - 2]);
		f->sp--;
		break;
	case 0x20: {
		uint64_t off;
		uint64_t sz;
		uint64_t words;
		uint64_t extra;
		uint8_t digest[32];
		uint256_t outv;

		if (require_stack(f, 2) < 0) {
			return f->status;
		}
		if (u256_as_u64(&f->stack[f->sp - 1], &off) < 0) {
			return halt_ex(f, EVM_OUT_OF_GAS);
		}
		if (u256_as_u64(&f->stack[f->sp - 2], &sz) < 0) {
			return halt_ex(f, EVM_OUT_OF_GAS);
		}
		if (charge_mem(f, off, sz) < 0) {
			return halt_ex(f, EVM_OUT_OF_GAS);
		}
		words = (sz + 31ULL) / 32ULL;
		if (sz == 0ULL) {
			words = 0ULL;
		}
		extra = 6ULL * words;
		if (f->gas < extra) {
			return halt_ex(f, EVM_OUT_OF_GAS);
		}
		f->gas -= extra;
		if (sz == 0ULL) {
			keccak256(f->memory, 0, digest);
		} else {
			keccak256(f->memory + (size_t)off, (size_t)sz, digest);
		}
		bytes_be_to_u256(digest, &outv);
		f->sp--;
		f->stack[f->sp - 1] = outv;
		break;
	}
	case 0x50:
		if (require_stack(f, 1) < 0) {
			return f->status;
		}
		f->sp--;
		break;
	case 0x51: {
		uint64_t off;
		uint256_t v;

		if (require_stack(f, 1) < 0) {
			return f->status;
		}
		if (u256_as_u64(&f->stack[f->sp - 1], &off) < 0) {
			return halt_ex(f, EVM_OUT_OF_GAS);
		}
		if (charge_mem(f, off, 32ULL) < 0) {
			return halt_ex(f, EVM_OUT_OF_GAS);
		}
		bytes_be_to_u256(f->memory + (size_t)off, &v);
		f->stack[f->sp - 1] = v;
		break;
	}
	case 0x52: {
		uint64_t off;
		uint8_t be[32];

		if (require_stack(f, 2) < 0) {
			return f->status;
		}
		if (u256_as_u64(&f->stack[f->sp - 1], &off) < 0) {
			return halt_ex(f, EVM_OUT_OF_GAS);
		}
		if (charge_mem(f, off, 32ULL) < 0) {
			return halt_ex(f, EVM_OUT_OF_GAS);
		}
		u256_to_bytes_be(&f->stack[f->sp - 2], be);
		memcpy(f->memory + (size_t)off, be, 32);
		f->sp -= 2;
		break;
	}
	case 0x53: {
		uint64_t off;

		if (require_stack(f, 2) < 0) {
			return f->status;
		}
		if (u256_as_u64(&f->stack[f->sp - 1], &off) < 0) {
			return halt_ex(f, EVM_OUT_OF_GAS);
		}
		if (charge_mem(f, off, 1ULL) < 0) {
			return halt_ex(f, EVM_OUT_OF_GAS);
		}
		f->memory[(size_t)off] = (uint8_t)(f->stack[f->sp - 2].w[0] & 0xffULL);
		f->sp -= 2;
		break;
	}
	case 0x56: {
		uint64_t dest;

		if (require_stack(f, 1) < 0) {
			return f->status;
		}
		if (u256_as_u64(&f->stack[f->sp - 1], &dest) < 0 ||
		    dest > 0xffffffffULL ||
		    !jumpdest_ok(code, code_len, (uint32_t)dest)) {
			return halt_ex(f, EVM_INVALID_OPCODE);
		}
		f->sp--;
		f->pc = (uint32_t)dest;
		break;
	}
	case 0x57: {
		uint64_t dest;
		int take;

		if (require_stack(f, 2) < 0) {
			return f->status;
		}
		take = !evm_iszero256(&f->stack[f->sp - 2]);
		if (take) {
			if (u256_as_u64(&f->stack[f->sp - 1], &dest) < 0 ||
			    dest > 0xffffffffULL ||
			    !jumpdest_ok(code, code_len, (uint32_t)dest)) {
				return halt_ex(f, EVM_INVALID_OPCODE);
			}
			f->pc = (uint32_t)dest;
		}
		f->sp -= 2;
		break;
	}
	case 0x58: {
		uint256_t v;

		if (require_room(f) < 0) {
			return f->status;
		}
		u256_set_u64(&v, (uint64_t)(f->pc - 1U));
		f->stack[f->sp] = v;
		f->sp++;
		break;
	}
	case 0x59: {
		uint256_t v;

		if (require_room(f) < 0) {
			return f->status;
		}
		u256_set_u64(&v, (uint64_t)f->memory_size);
		f->stack[f->sp] = v;
		f->sp++;
		break;
	}
	case 0x5a: {
		uint256_t v;

		if (require_room(f) < 0) {
			return f->status;
		}
		u256_set_u64(&v, f->gas);
		f->stack[f->sp] = v;
		f->sp++;
		break;
	}
	case 0x5b:
		break;
	case 0x5f: {
		if (require_room(f) < 0) {
			return f->status;
		}
		u256_zero(&f->stack[f->sp]);
		f->sp++;
		break;
	}
	case 0x60:
	case 0x61:
	case 0x62:
	case 0x63:
	case 0x64:
	case 0x65:
	case 0x66:
	case 0x67:
	case 0x68:
	case 0x69:
	case 0x6a:
	case 0x6b:
	case 0x6c:
	case 0x6d:
	case 0x6e:
	case 0x6f:
	case 0x70:
	case 0x71:
	case 0x72:
	case 0x73:
	case 0x74:
	case 0x75:
	case 0x76:
	case 0x77:
	case 0x78:
	case 0x79:
	case 0x7a:
	case 0x7b:
	case 0x7c:
	case 0x7d:
	case 0x7e:
	case 0x7f:
		if (exec_push(f, code, code_len, (unsigned)(op - 0x5f)) < 0) {
			return f->status;
		}
		break;
	case 0x80:
	case 0x81:
	case 0x82:
	case 0x83:
	case 0x84:
	case 0x85:
	case 0x86:
	case 0x87:
	case 0x88:
	case 0x89:
	case 0x8a:
	case 0x8b:
	case 0x8c:
	case 0x8d:
	case 0x8e:
	case 0x8f: {
		int32_t n = (int32_t)(op - 0x80) + 1;

		if (require_stack(f, n) < 0) {
			return f->status;
		}
		if (require_room(f) < 0) {
			return f->status;
		}
		f->stack[f->sp] = f->stack[f->sp - n];
		f->sp++;
		break;
	}
	case 0x90:
	case 0x91:
	case 0x92:
	case 0x93:
	case 0x94:
	case 0x95:
	case 0x96:
	case 0x97:
	case 0x98:
	case 0x99:
	case 0x9a:
	case 0x9b:
	case 0x9c:
	case 0x9d:
	case 0x9e:
	case 0x9f: {
		int32_t n = (int32_t)(op - 0x90) + 1;
		uint256_t t;

		if (require_stack(f, n + 1) < 0) {
			return f->status;
		}
		t = f->stack[f->sp - 1];
		f->stack[f->sp - 1] = f->stack[f->sp - 1 - n];
		f->stack[f->sp - 1 - n] = t;
		break;
	}
	case 0xfd: {
		uint64_t off;
		uint64_t sz;

		if (require_stack(f, 2) < 0) {
			return f->status;
		}
		if (u256_as_u64(&f->stack[f->sp - 1], &off) < 0) {
			return halt_ex(f, EVM_OUT_OF_GAS);
		}
		if (u256_as_u64(&f->stack[f->sp - 2], &sz) < 0) {
			return halt_ex(f, EVM_OUT_OF_GAS);
		}
		if (charge_mem(f, off, sz) < 0) {
			return halt_ex(f, EVM_OUT_OF_GAS);
		}
		f->sp -= 2;
		f->status = EVM_REVERT;
		break;
	}
	default:
		return halt_ex(f, EVM_INVALID_OPCODE);
	}
	return f->status;
}
