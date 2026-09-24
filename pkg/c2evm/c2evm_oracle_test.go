// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 HazyHaar. See LICENSE and NOTICE.

package c2evm

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"code.hazyhaar.fr/devhoros/crypto55/pkg/evm256"
)

const oracleRunnerC = `
#include "evm_stepper.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hexval(int c)
{
	if (c >= '0' && c <= '9') {
		return c - '0';
	}
	if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	}
	if (c >= 'A' && c <= 'F') {
		return c - 'A' + 10;
	}
	return -1;
}

static size_t parse_hex(const char *s, uint8_t *out, size_t cap)
{
	size_t n = 0;
	size_t i;

	if (s[0] == '-' && s[1] == '\0') {
		return 0;
	}
	for (i = 0; s[i] != '\0' && s[i + 1] != '\0'; i += 2) {
		int hi = hexval((unsigned char)s[i]);
		int lo = hexval((unsigned char)s[i + 1]);
		if (hi < 0 || lo < 0 || n >= cap) {
			exit(2);
		}
		out[n++] = (uint8_t)((hi << 4) | lo);
	}
	if (s[i] != '\0') {
		exit(2);
	}
	return n;
}

static void run_one(uint64_t gas, const uint8_t *code, size_t code_len)
{
	evm_frame_t f;
	int steps = 0;
	int32_t i;
	uint32_t m;

	evm_frame_init(&f, gas);
	while (f.status == 0) {
		evm_step_one(&f, code, code_len);
		steps++;
		if (steps > 1000000) {
			break;
		}
	}
	printf("%d %d %u %" PRIu64 " %u", f.status, f.sp, f.pc, f.gas, f.memory_size);
	for (i = 0; i < f.sp; i++) {
		printf(" %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64,
		    f.stack[i].w[0], f.stack[i].w[1], f.stack[i].w[2], f.stack[i].w[3]);
	}
	printf(" ");
	if (f.memory_size == 0) {
		printf("-");
	} else {
		for (m = 0; m < f.memory_size; m++) {
			printf("%02x", f.memory[m]);
		}
	}
	printf("\n");
}

int main(void)
{
	uint64_t gas;
	char hex[16384];
	uint8_t code[8192];
	size_t n;

	while (scanf("%" SCNu64 " %16383s", &gas, hex) == 2) {
		n = parse_hex(hex, code, sizeof(code));
		run_one(gas, code, n);
	}
	return 0;
}
`

type oracleSnap struct {
	status int
	sp     int32
	pc     uint32
	gas    uint64
	msize  uint32
	stack  []evm256.Uint256
	mem    []byte
}

func csrcDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "c_src")
}

func buildCOracle(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc introuvable: oracle C non exécutable")
	}
	csrc := csrcDir(t)
	dir := t.TempDir()
	runner := filepath.Join(dir, "runner.c")
	if err := os.WriteFile(runner, []byte(oracleRunnerC), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "oracle")
	cmd := exec.Command("gcc", "-O2", "-Wall", "-Werror", "-std=c11",
		"-I", csrc, "-o", bin, runner,
		filepath.Join(csrc, "evm_stepper.c"),
		filepath.Join(csrc, "evm_arith256.c"),
		filepath.Join(csrc, "evm_bitwise256.c"),
		filepath.Join(csrc, "crypto_keccak.c"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("gcc -O2: %v\n%s", err, out)
	}
	return bin
}

func runCOracle(t *testing.T, bin, input string) []string {
	t.Helper()
	cmd := exec.Command(bin)
	cmd.Stdin = strings.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("oracle C: %v\n%s\ninput prefix: %.200s", err, stderr.String(), input)
	}
	s := strings.TrimSpace(stdout.String())
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func parseSnap(t *testing.T, line string) oracleSnap {
	t.Helper()
	fields := strings.Fields(line)
	if len(fields) < 6 {
		t.Fatalf("ligne oracle trop courte: %q", line)
	}
	mustInt := func(s string) int {
		v, err := strconv.Atoi(s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	mustU64 := func(s string) uint64 {
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	st := oracleSnap{
		status: mustInt(fields[0]),
		sp:     int32(mustInt(fields[1])),
		pc:     uint32(mustU64(fields[2])),
		gas:    mustU64(fields[3]),
		msize:  uint32(mustU64(fields[4])),
	}
	need := 5 + int(st.sp)*4 + 1
	if len(fields) != need {
		t.Fatalf("champs=%d attendu=%d ligne=%q", len(fields), need, line)
	}
	st.stack = make([]evm256.Uint256, st.sp)
	off := 5
	for i := int32(0); i < st.sp; i++ {
		st.stack[i] = evm256.Uint256{
			mustU64(fields[off]),
			mustU64(fields[off+1]),
			mustU64(fields[off+2]),
			mustU64(fields[off+3]),
		}
		off += 4
	}
	memhex := fields[off]
	if memhex != "-" {
		b, err := hex.DecodeString(memhex)
		if err != nil {
			t.Fatal(err)
		}
		st.mem = b
	}
	return st
}

func runGo(gas uint64, code []byte) oracleSnap {
	f := new(ExecutionFrame)
	f.Reset(gas)
	steps := 0
	for f.Status == StatusRunning {
		StepOne(f, code)
		steps++
		if steps > 1000000 {
			break
		}
	}
	st := oracleSnap{
		status: f.Status,
		sp:     f.SP,
		pc:     f.PC,
		gas:    f.Gas,
		msize:  f.MemorySize,
	}
	if f.SP > 0 {
		st.stack = make([]evm256.Uint256, f.SP)
		copy(st.stack, f.Stack[:f.SP])
	}
	if f.MemorySize > 0 {
		st.mem = make([]byte, f.MemorySize)
		copy(st.mem, f.Memory[:f.MemorySize])
	}
	return st
}

func dumpSnap(s oracleSnap) string {
	var b strings.Builder
	fmt.Fprintf(&b, "status=%d sp=%d pc=%d gas=%d msize=%d stack=[", s.status, s.sp, s.pc, s.gas, s.msize)
	for i, w := range s.stack {
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%d:%d:%d:%d", w[0], w[1], w[2], w[3])
	}
	b.WriteString("] mem=")
	if len(s.mem) == 0 {
		b.WriteByte('-')
	} else {
		b.WriteString(hex.EncodeToString(s.mem))
	}
	return b.String()
}

func equalSnap(a, b oracleSnap) bool {
	if a.status != b.status || a.sp != b.sp || a.pc != b.pc || a.gas != b.gas || a.msize != b.msize {
		return false
	}
	if len(a.stack) != len(b.stack) {
		return false
	}
	for i := range a.stack {
		if a.stack[i] != b.stack[i] {
			return false
		}
	}
	return bytes.Equal(a.mem, b.mem)
}

type bcCase struct {
	name string
	gas  uint64
	hex  string
}

func TestStepperVsCOracle(t *testing.T) {
	bin := buildCOracle(t)
	const g = uint64(10_000_000)
	cases := []bcCase{
		{"empty", g, "-"},
		{"stop", g, "00"},
		{"add", g, "600560030100"},
		{"mul", g, "600560030200"},
		{"sub", g, "600560030300"},
		{"div", g, "600a60030400"},
		{"div0", g, "600a5f0400"},
		{"sdiv", g, "60ff60000b60020500"},
		{"mod", g, "600a60030600"},
		{"mod0", g, "600a5f0600"},
		{"smod", g, "60ff60000b60020700"},
		{"addmod", g, "6005600460030800"},
		{"mulmod", g, "6005600460030900"},
		{"exp", g, "600260080a00"},
		{"signextend", g, "60ff60000b00"},
		{"lt", g, "600560031000"},
		{"gt", g, "600560031100"},
		{"slt", g, "60ff60000b60011200"},
		{"sgt", g, "60ff60000b60011300"},
		{"eq", g, "600560051400"},
		{"eq_ne", g, "600560041400"},
		{"iszero0", g, "5f1500"},
		{"iszero1", g, "60011500"},
		{"and", g, "600f60031600"},
		{"or", g, "600560031700"},
		{"xor", g, "600f60031800"},
		{"not", g, "5f1900"},
		{"byte_lsb", g, "60ff601f1a00"},
		{"byte_oob", g, "60ff60201a00"},
		{"shl", g, "600160011b00"},
		{"shr", g, "600860011c00"},
		{"sar", g, "60ff60000b60011d00"},
		{"pop", g, "60015000"},
		{"push0", g, "5f00"},
		{"push1", g, "602a00"},
		{"push2", g, "61012300"},
		{"push32", g, "7f000000000000000000000000000000000000000000000000000000000000000100"},
		{"push_trunc", g, "60"},
		{"dup1", g, "60018000"},
		{"dup2", g, "600160028100"},
		{"swap1", g, "600160029000"},
		{"swap2", g, "6001600260039100"},
		{"pc", g, "5800"},
		{"msize0", g, "5900"},
		{"gas", g, "5a00"},
		{"jumpdest", g, "5b00"},
		{"jump", g, "600456005b602a00"},
		{"jumpi_taken", g, "6001600657005b00"},
		{"jumpi_skip", g, "5f600757602a5b00"},
		{"loop_jumpi", g, "60005b6001018060031060025700"},
		{"mstore_mload", g, "602a5f5260005100"},
		{"mstore8", g, "60ff60055360055100"},
		{"msize_after_store", g, "602a5f525900"},
		{"sha3_empty", g, "5f5f2000"},
		{"sha3_word", g, "7f00000000000000000000000000000000000000000000000000000000000000015f5260205f2000"},
		{"revert", g, "5f5ffd"},
		{"invalid", g, "fe"},
		{"oog", 1, "600100"},
		{"stop_gas_kept", 42, "00"},
	}

	var in strings.Builder
	for _, tc := range cases {
		fmt.Fprintf(&in, "%d %s\n", tc.gas, tc.hex)
	}
	lines := runCOracle(t, bin, in.String())
	if len(lines) != len(cases) {
		t.Fatalf("oracle lignes=%d cas=%d", len(lines), len(cases))
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code := []byte{}
			if tc.hex != "-" {
				var err error
				code, err = hex.DecodeString(tc.hex)
				if err != nil {
					t.Fatal(err)
				}
			}
			want := parseSnap(t, lines[i])
			got := runGo(tc.gas, code)
			if !equalSnap(got, want) {
				t.Fatalf("parité C/Go rompue\nC  %s\nGo %s", dumpSnap(want), dumpSnap(got))
			}
		})
	}

	t.Run("allocs", func(t *testing.T) {
		code, err := hex.DecodeString("5f5f015000")
		if err != nil {
			t.Fatal(err)
		}
		f := new(ExecutionFrame)
		n := testing.AllocsPerRun(1000, func() {
			f.Reset(1_000_000)
			for f.Status == StatusRunning {
				StepOne(f, code)
			}
		})
		if n != 0 {
			t.Fatalf("StepOne: %f allocs/op, attendu 0", n)
		}
	})
}

type memState struct {
	key evm256.Uint256
	val evm256.Uint256
	set bool
}

func (m *memState) GetStorage(addr, key, val *evm256.Uint256) {
	k := *key
	if m.set && k == m.key {
		*val = m.val
		return
	}
	*val = evm256.Uint256{}
}

func (m *memState) SetStorage(addr, key, val *evm256.Uint256) {
	m.key = *key
	m.val = *val
	m.set = true
}

func TestSloadSstore(t *testing.T) {
	st := &memState{}
	f := new(ExecutionFrame)
	f.StateDB = st
	f.Reset(1_000_000)
	code, err := hex.DecodeString("602a60015560015400")
	if err != nil {
		t.Fatal(err)
	}
	for f.Status == StatusRunning {
		StepOne(f, code)
	}
	if f.Status != StatusSuccess {
		t.Fatalf("status=%d", f.Status)
	}
	if f.SP != 1 || f.Stack[0] != evm256.FromU64(0x2a) {
		t.Fatalf("stack=%v sp=%d", f.Stack[0], f.SP)
	}
	if !st.set || st.val != evm256.FromU64(0x2a) {
		t.Fatalf("storage non écrit")
	}
}

func TestJumpDestInvalid(t *testing.T) {
	f := new(ExecutionFrame)
	f.Reset(1_000_000)
	code, err := hex.DecodeString("60015600")
	if err != nil {
		t.Fatal(err)
	}
	for f.Status == StatusRunning {
		StepOne(f, code)
	}
	if f.Status != StatusJumpDestInvalid {
		t.Fatalf("status=%d attendu %d", f.Status, StatusJumpDestInvalid)
	}
	if f.Gas != 0 {
		t.Fatalf("gas=%d, halt doit zéroter", f.Gas)
	}
}

func TestStackUnderflow(t *testing.T) {
	f := new(ExecutionFrame)
	f.Reset(1_000_000)
	code := []byte{0x01, 0x00}
	for f.Status == StatusRunning {
		StepOne(f, code)
	}
	if f.Status != StatusStackUnderflow {
		t.Fatalf("status=%d attendu %d", f.Status, StatusStackUnderflow)
	}
}

func TestEVMOpcodeStackOrderGroundTruth(t *testing.T) {
	cases := []struct {
		name    string
		hexCode string
		want    evm256.Uint256
	}{
		{
			name:    "SUB_3_minus_5_underflow",
			hexCode: "600560030300", // PUSH1 5, PUSH1 3, SUB, STOP -> top=3, second=5 -> 3 - 5 = 2^256 - 2
			want:    evm256.Uint256{^uint64(1), ^uint64(0), ^uint64(0), ^uint64(0)},
		},
		{
			name:    "SUB_5_minus_3",
			hexCode: "600360050300", // PUSH1 3, PUSH1 5, SUB, STOP -> top=5, second=3 -> 5 - 3 = 2
			want:    evm256.FromU64(2),
		},
		{
			name:    "DIV_10_by_2",
			hexCode: "6002600a0400", // PUSH1 2, PUSH1 10, DIV, STOP -> top=10, second=2 -> 10 / 2 = 5
			want:    evm256.FromU64(5),
		},
		{
			name:    "LT_5_less_than_10",
			hexCode: "600a60051000", // PUSH1 10, PUSH1 5, LT, STOP -> top=5, second=10 -> 5 < 10 = 1
			want:    evm256.FromU64(1),
		},
		{
			name:    "LT_10_less_than_5",
			hexCode: "6005600a1000", // PUSH1 5, PUSH1 10, LT, STOP -> top=10, second=5 -> 10 < 5 = 0
			want:    evm256.FromU64(0),
		},
		{
			name:    "EXP_2_pow_3",
			hexCode: "600360020a00", // PUSH1 3, PUSH1 2, EXP, STOP -> top=2 (base), second=3 (exp) -> 2^3 = 8
			want:    evm256.FromU64(8),
		},
		{
			name:    "ADDMOD_5_plus_7_mod_10",
			hexCode: "600a600760050800", // PUSH1 10, PUSH1 7, PUSH1 5, ADDMOD -> top=5, second=7, third=10 -> (5+7)%10 = 2
			want:    evm256.FromU64(2),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := new(ExecutionFrame)
			f.Reset(1_000_000)
			code, err := hex.DecodeString(tc.hexCode)
			if err != nil {
				t.Fatalf("decode hex: %v", err)
			}
			for f.Status == StatusRunning {
				StepOne(f, code)
			}
			if f.Status != StatusSuccess {
				t.Fatalf("status=%d attendu %d", f.Status, StatusSuccess)
			}
			if f.SP != 1 {
				t.Fatalf("SP=%d attendu 1", f.SP)
			}
			if !evm256.Eq(&f.Stack[0], &tc.want) {
				t.Fatalf("résultat pile=%v, attendu %v", f.Stack[0], tc.want)
			}
		})
	}
}
