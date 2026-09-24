// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 HazyHaar. See LICENSE and NOTICE.

package evm256

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

const oracleRunnerC = `
#include "evm_arith256.h"
#include "evm_bitwise256.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void need256(uint256_t *x)
{
	if (scanf("%" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64,
		&x->w[0], &x->w[1], &x->w[2], &x->w[3]) != 4) {
		exit(2);
	}
}

static uint64_t needu64(void)
{
	uint64_t v;
	if (scanf("%" SCNu64, &v) != 1) {
		exit(2);
	}
	return v;
}

static void emit256(const uint256_t *x)
{
	printf("%" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n",
		x->w[0], x->w[1], x->w[2], x->w[3]);
}

static void emitint(int v)
{
	uint256_t x;
	x.w[0] = v ? 1ULL : 0ULL;
	x.w[1] = 0;
	x.w[2] = 0;
	x.w[3] = 0;
	emit256(&x);
}

int main(void)
{
	char op[32];
	uint256_t a, b, m, out;
	uint64_t u;

	while (scanf("%31s", op) == 1) {
		if (strcmp(op, "ADD") == 0) {
			need256(&a); need256(&b);
			evm_add256(&a, &b, &out);
			emit256(&out);
		} else if (strcmp(op, "SUB") == 0) {
			need256(&a); need256(&b);
			evm_sub256(&a, &b, &out);
			emit256(&out);
		} else if (strcmp(op, "MUL") == 0) {
			need256(&a); need256(&b);
			evm_mul256(&a, &b, &out);
			emit256(&out);
		} else if (strcmp(op, "DIV") == 0) {
			need256(&a); need256(&b);
			evm_div256(&a, &b, &out);
			emit256(&out);
		} else if (strcmp(op, "SDIV") == 0) {
			need256(&a); need256(&b);
			evm_sdiv256(&a, &b, &out);
			emit256(&out);
		} else if (strcmp(op, "MOD") == 0) {
			need256(&a); need256(&b);
			evm_mod256(&a, &b, &out);
			emit256(&out);
		} else if (strcmp(op, "SMOD") == 0) {
			need256(&a); need256(&b);
			evm_smod256(&a, &b, &out);
			emit256(&out);
		} else if (strcmp(op, "ADDMOD") == 0) {
			need256(&a); need256(&b); need256(&m);
			evm_addmod256(&a, &b, &m, &out);
			emit256(&out);
		} else if (strcmp(op, "MULMOD") == 0) {
			need256(&a); need256(&b); need256(&m);
			evm_mulmod256(&a, &b, &m, &out);
			emit256(&out);
		} else if (strcmp(op, "EXP") == 0) {
			need256(&a); need256(&b);
			evm_exp256(&a, &b, &out);
			emit256(&out);
		} else if (strcmp(op, "SIGNEXTEND") == 0) {
			u = needu64();
			need256(&a);
			evm_signextend256(u, &a, &out);
			emit256(&out);
		} else if (strcmp(op, "AND") == 0) {
			need256(&a); need256(&b);
			evm_and256(&a, &b, &out);
			emit256(&out);
		} else if (strcmp(op, "OR") == 0) {
			need256(&a); need256(&b);
			evm_or256(&a, &b, &out);
			emit256(&out);
		} else if (strcmp(op, "XOR") == 0) {
			need256(&a); need256(&b);
			evm_xor256(&a, &b, &out);
			emit256(&out);
		} else if (strcmp(op, "NOT") == 0) {
			need256(&a);
			evm_not256(&a, &out);
			emit256(&out);
		} else if (strcmp(op, "BYTE") == 0) {
			u = needu64();
			need256(&a);
			evm_byte256(u, &a, &out);
			emit256(&out);
		} else if (strcmp(op, "SHL") == 0) {
			need256(&a); need256(&b);
			evm_shl256(&a, &b, &out);
			emit256(&out);
		} else if (strcmp(op, "SHR") == 0) {
			need256(&a); need256(&b);
			evm_shr256(&a, &b, &out);
			emit256(&out);
		} else if (strcmp(op, "SAR") == 0) {
			need256(&a); need256(&b);
			evm_sar256(&a, &b, &out);
			emit256(&out);
		} else if (strcmp(op, "LT") == 0) {
			need256(&a); need256(&b);
			emitint(evm_lt256(&a, &b));
		} else if (strcmp(op, "GT") == 0) {
			need256(&a); need256(&b);
			emitint(evm_gt256(&a, &b));
		} else if (strcmp(op, "SLT") == 0) {
			need256(&a); need256(&b);
			emitint(evm_slt256(&a, &b));
		} else if (strcmp(op, "SGT") == 0) {
			need256(&a); need256(&b);
			emitint(evm_sgt256(&a, &b));
		} else if (strcmp(op, "EQ") == 0) {
			need256(&a); need256(&b);
			emitint(evm_eq256(&a, &b));
		} else if (strcmp(op, "ISZERO") == 0) {
			need256(&a);
			emitint(evm_iszero256(&a));
		} else if (strcmp(op, "ADD_ALIAS_A") == 0) {
			need256(&a); need256(&b);
			evm_add256(&a, &b, &a);
			emit256(&a);
		} else if (strcmp(op, "ADD_ALIAS_B") == 0) {
			need256(&a); need256(&b);
			evm_add256(&a, &b, &b);
			emit256(&b);
		} else if (strcmp(op, "SUB_ALIAS_A") == 0) {
			need256(&a); need256(&b);
			evm_sub256(&a, &b, &a);
			emit256(&a);
		} else if (strcmp(op, "MUL_ALIAS_A") == 0) {
			need256(&a); need256(&b);
			evm_mul256(&a, &b, &a);
			emit256(&a);
		} else if (strcmp(op, "AND_ALIAS_A") == 0) {
			need256(&a); need256(&b);
			evm_and256(&a, &b, &a);
			emit256(&a);
		} else if (strcmp(op, "SHL_ALIAS") == 0) {
			need256(&a); need256(&b);
			evm_shl256(&a, &b, &b);
			emit256(&b);
		} else {
			exit(3);
		}
	}
	return 0;
}
`

var sink Uint256
var sink32 [32]byte
var sinkBool bool
var sinkInt int

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
		filepath.Join(csrc, "evm_arith256.c"),
		filepath.Join(csrc, "evm_bitwise256.c"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("gcc -O2: %v\n%s", err, out)
	}
	return bin
}

func fmtU256(z Uint256) string {
	return fmt.Sprintf("%d %d %d %d", z[0], z[1], z[2], z[3])
}

func parseU256(line string) (Uint256, error) {
	fields := strings.Fields(line)
	if len(fields) != 4 {
		return Uint256{}, fmt.Errorf("ligne oracle %q", line)
	}
	var z Uint256
	for i := 0; i < 4; i++ {
		v, err := strconv.ParseUint(fields[i], 10, 64)
		if err != nil {
			return Uint256{}, err
		}
		z[i] = v
	}
	return z, nil
}

func runCOracle(t *testing.T, bin, input string) []Uint256 {
	t.Helper()
	cmd := exec.Command(bin)
	cmd.Stdin = strings.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("oracle C: %v\n%s\ninput prefix: %.200s", err, stderr.String(), input)
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if stdout.Len() == 0 {
		return nil
	}
	out := make([]Uint256, 0, len(lines))
	for _, line := range lines {
		z, err := parseU256(line)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, z)
	}
	return out
}

func boolU256(v bool) Uint256 {
	if v {
		return Uint256{1, 0, 0, 0}
	}
	return Uint256{}
}

func specials() []Uint256 {
	return []Uint256{
		{},
		{1, 0, 0, 0},
		{2, 0, 0, 0},
		{^uint64(0), 0, 0, 0},
		{0, 1, 0, 0},
		{0, 0, 1, 0},
		{0, 0, 0, 1},
		{0, 0, 0, 1 << 63},
		{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)},
	}
}

func randU256(rng *rand.Rand) Uint256 {
	return Uint256{rng.Uint64(), rng.Uint64(), rng.Uint64(), rng.Uint64()}
}

type oracleCase struct {
	op   string
	line string
	want Uint256
}

func appendBin(cs *[]oracleCase, op string, a, b Uint256, want Uint256) {
	*cs = append(*cs, oracleCase{
		op:   op,
		line: op + " " + fmtU256(a) + " " + fmtU256(b) + "\n",
		want: want,
	})
}

func TestArithVsCOracle(t *testing.T) {
	bin := buildCOracle(t)
	rng := rand.New(rand.NewSource(1))
	var cs []oracleCase
	sp := specials()
	var out Uint256

	binops := []struct {
		op string
		fn func(a, b, out *Uint256)
	}{
		{"ADD", Add256},
		{"SUB", Sub256},
		{"MUL", Mul256},
		{"DIV", Div256},
		{"SDIV", SDiv256},
		{"MOD", Mod256},
		{"SMOD", SMod256},
	}
	for _, op := range binops {
		for _, a := range sp {
			for _, b := range sp {
				aa, bb := a, b
				op.fn(&aa, &bb, &out)
				appendBin(&cs, op.op, a, b, out)
			}
		}
		for i := 0; i < 1000; i++ {
			a, b := randU256(rng), randU256(rng)
			op.fn(&a, &b, &out)
			appendBin(&cs, op.op, a, b, out)
		}
	}

	for _, a := range sp {
		for _, b := range sp {
			for _, m := range sp {
				aa, bb, mm := a, b, m
				AddMod256(&aa, &bb, &mm, &out)
				cs = append(cs, oracleCase{
					op:   "ADDMOD",
					line: "ADDMOD " + fmtU256(a) + " " + fmtU256(b) + " " + fmtU256(m) + "\n",
					want: out,
				})
				MulMod256(&aa, &bb, &mm, &out)
				cs = append(cs, oracleCase{
					op:   "MULMOD",
					line: "MULMOD " + fmtU256(a) + " " + fmtU256(b) + " " + fmtU256(m) + "\n",
					want: out,
				})
			}
		}
	}
	for i := 0; i < 1000; i++ {
		a, b, m := randU256(rng), randU256(rng), randU256(rng)
		AddMod256(&a, &b, &m, &out)
		cs = append(cs, oracleCase{
			op:   "ADDMOD",
			line: "ADDMOD " + fmtU256(a) + " " + fmtU256(b) + " " + fmtU256(m) + "\n",
			want: out,
		})
		MulMod256(&a, &b, &m, &out)
		cs = append(cs, oracleCase{
			op:   "MULMOD",
			line: "MULMOD " + fmtU256(a) + " " + fmtU256(b) + " " + fmtU256(m) + "\n",
			want: out,
		})
	}

	expSpecials := []Uint256{
		{},
		{1, 0, 0, 0},
		{2, 0, 0, 0},
		{3, 0, 0, 0},
		{8, 0, 0, 0},
		{255, 0, 0, 0},
		{^uint64(0), 0, 0, 0},
		{0, 0, 0, 1 << 63},
		{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)},
	}
	for _, a := range expSpecials {
		for _, e := range expSpecials {
			aa, ee := a, e
			Exp256(&aa, &ee, &out)
			appendBin(&cs, "EXP", a, e, out)
		}
	}
	for i := 0; i < 200; i++ {
		a := randU256(rng)
		e := FromU64(uint64(rng.Intn(65)))
		Exp256(&a, &e, &out)
		appendBin(&cs, "EXP", a, e, out)
	}

	for _, x := range sp {
		for _, b := range []uint64{0, 1, 2, 7, 8, 15, 16, 30, 31, 32, 33, ^uint64(0)} {
			xx := x
			SignExtend256(b, &xx, &out)
			cs = append(cs, oracleCase{
				op:   "SIGNEXTEND",
				line: fmt.Sprintf("SIGNEXTEND %d %s\n", b, fmtU256(x)),
				want: out,
			})
		}
	}
	for i := 0; i < 1000; i++ {
		x := randU256(rng)
		b := rng.Uint64()
		if rng.Intn(2) == 0 {
			b = uint64(rng.Intn(40))
		}
		SignExtend256(b, &x, &out)
		cs = append(cs, oracleCase{
			op:   "SIGNEXTEND",
			line: fmt.Sprintf("SIGNEXTEND %d %s\n", b, fmtU256(x)),
			want: out,
		})
	}

	compareOracle(t, bin, cs)
}

func TestBitwiseVsCOracle(t *testing.T) {
	bin := buildCOracle(t)
	rng := rand.New(rand.NewSource(2))
	var cs []oracleCase
	sp := specials()
	var out Uint256

	binops := []struct {
		op string
		fn func(a, b, out *Uint256)
	}{
		{"AND", And256},
		{"OR", Or256},
		{"XOR", Xor256},
		{"SHL", Shl256},
		{"SHR", Shr256},
		{"SAR", Sar256},
	}
	for _, op := range binops {
		for _, a := range sp {
			for _, b := range sp {
				aa, bb := a, b
				op.fn(&aa, &bb, &out)
				appendBin(&cs, op.op, a, b, out)
			}
		}
		for i := 0; i < 1000; i++ {
			a, b := randU256(rng), randU256(rng)
			if op.op == "SHL" || op.op == "SHR" || op.op == "SAR" {
				switch rng.Intn(6) {
				case 0:
					a = FromU64(uint64(rng.Intn(257)))
				case 1:
					a = FromU64(256)
				case 2:
					a = FromU64(257)
				case 3:
					a = Uint256{0, 1, 0, 0}
				}
			}
			op.fn(&a, &b, &out)
			appendBin(&cs, op.op, a, b, out)
		}
	}

	cmps := []struct {
		op string
		fn func(a, b *Uint256) bool
	}{
		{"LT", Lt256},
		{"GT", Gt256},
		{"SLT", Slt256},
		{"SGT", Sgt256},
		{"EQ", Eq},
	}
	for _, op := range cmps {
		for _, a := range sp {
			for _, b := range sp {
				aa, bb := a, b
				appendBin(&cs, op.op, a, b, boolU256(op.fn(&aa, &bb)))
			}
		}
		for i := 0; i < 1000; i++ {
			a, b := randU256(rng), randU256(rng)
			appendBin(&cs, op.op, a, b, boolU256(op.fn(&a, &b)))
		}
	}

	for _, a := range sp {
		aa := a
		Not256(&aa, &out)
		cs = append(cs, oracleCase{op: "NOT", line: "NOT " + fmtU256(a) + "\n", want: out})
		cs = append(cs, oracleCase{op: "ISZERO", line: "ISZERO " + fmtU256(a) + "\n", want: boolU256(IsZero(&aa))})
	}
	for i := 0; i < 1000; i++ {
		a := randU256(rng)
		Not256(&a, &out)
		cs = append(cs, oracleCase{op: "NOT", line: "NOT " + fmtU256(a) + "\n", want: out})
		cs = append(cs, oracleCase{op: "ISZERO", line: "ISZERO " + fmtU256(a) + "\n", want: boolU256(IsZero(&a))})
	}

	for _, x := range sp {
		for _, i := range []uint64{0, 1, 2, 15, 16, 30, 31, 32, 33, 255, ^uint64(0)} {
			xx := x
			Byte256(i, &xx, &out)
			cs = append(cs, oracleCase{
				op:   "BYTE",
				line: fmt.Sprintf("BYTE %d %s\n", i, fmtU256(x)),
				want: out,
			})
		}
	}
	for i := 0; i < 1000; i++ {
		x := randU256(rng)
		idx := rng.Uint64()
		if rng.Intn(2) == 0 {
			idx = uint64(rng.Intn(40))
		}
		Byte256(idx, &x, &out)
		cs = append(cs, oracleCase{
			op:   "BYTE",
			line: fmt.Sprintf("BYTE %d %s\n", idx, fmtU256(x)),
			want: out,
		})
	}

	shiftVals := []Uint256{
		{},
		{1, 0, 0, 0},
		{63, 0, 0, 0},
		{64, 0, 0, 0},
		{65, 0, 0, 0},
		{127, 0, 0, 0},
		{128, 0, 0, 0},
		{191, 0, 0, 0},
		{192, 0, 0, 0},
		{255, 0, 0, 0},
		{256, 0, 0, 0},
		{257, 0, 0, 0},
		{0, 1, 0, 0},
	}
	for _, s := range shiftVals {
		for _, v := range sp {
			ss, vv := s, v
			Shl256(&ss, &vv, &out)
			appendBin(&cs, "SHL", s, v, out)
			Shr256(&ss, &vv, &out)
			appendBin(&cs, "SHR", s, v, out)
			Sar256(&ss, &vv, &out)
			appendBin(&cs, "SAR", s, v, out)
		}
	}

	compareOracle(t, bin, cs)
}

func TestAliasingVsCOracle(t *testing.T) {
	bin := buildCOracle(t)
	rng := rand.New(rand.NewSource(3))
	var cs []oracleCase
	sp := specials()
	ops := []string{"ADD_ALIAS_A", "ADD_ALIAS_B", "SUB_ALIAS_A", "MUL_ALIAS_A", "AND_ALIAS_A", "SHL_ALIAS"}
	for _, op := range ops {
		for _, a := range sp {
			for _, b := range sp {
				want := goAlias(op, a, b)
				appendBin(&cs, op, a, b, want)
			}
		}
		for i := 0; i < 200; i++ {
			a, b := randU256(rng), randU256(rng)
			want := goAlias(op, a, b)
			appendBin(&cs, op, a, b, want)
		}
	}
	compareOracle(t, bin, cs)
}

func goAlias(op string, a, b Uint256) Uint256 {
	switch op {
	case "ADD_ALIAS_A":
		Add256(&a, &b, &a)
		return a
	case "ADD_ALIAS_B":
		Add256(&a, &b, &b)
		return b
	case "SUB_ALIAS_A":
		Sub256(&a, &b, &a)
		return a
	case "MUL_ALIAS_A":
		Mul256(&a, &b, &a)
		return a
	case "AND_ALIAS_A":
		And256(&a, &b, &a)
		return a
	case "SHL_ALIAS":
		Shl256(&a, &b, &b)
		return b
	default:
		return Uint256{}
	}
}

func compareOracle(t *testing.T, bin string, cs []oracleCase) {
	t.Helper()
	var b strings.Builder
	b.Grow(len(cs) * 80)
	for i := range cs {
		b.WriteString(cs[i].line)
	}
	got := runCOracle(t, bin, b.String())
	if len(got) != len(cs) {
		t.Fatalf("oracle: %d lignes, attendu %d", len(got), len(cs))
	}
	for i := range cs {
		if got[i] != cs[i].want {
			t.Fatalf("%s case %d: Go=%v oracle C=%v ligne=%q", cs[i].op, i, cs[i].want, got[i], strings.TrimSpace(cs[i].line))
		}
	}
}

func TestBytesRoundtrip(t *testing.T) {
	rng := rand.New(rand.NewSource(4))
	for i := 0; i < 1000; i++ {
		z := randU256(rng)
		be := BytesBE(z)
		got := FromBytesBE(be[:])
		if got != z {
			t.Fatalf("roundtrip %v -> %v", z, got)
		}
	}
	if FromU64(0) != (Uint256{}) {
		t.Fatal("FromU64(0)")
	}
	if !IsZero(new(Uint256)) {
		t.Fatal("IsZero")
	}
	one := FromU64(1)
	if FromBytesBE([]byte{1}) != one {
		t.Fatal("FromBytesBE short")
	}
	max := Uint256{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)}
	var allff [32]byte
	for i := range allff {
		allff[i] = 0xff
	}
	if FromBytesBE(allff[:]) != max {
		t.Fatal("FromBytesBE max")
	}
	if Cmp(&one, new(Uint256)) <= 0 {
		t.Fatal("Cmp")
	}
	if !Eq(&one, &one) || Eq(&one, new(Uint256)) {
		t.Fatal("Eq")
	}
}

func TestAllocsPerRun(t *testing.T) {
	a := FromU64(0xdeadbeefcafebabe)
	b := FromU64(0x123456789abcdef0)
	m := FromU64(0xffffff)
	e := FromU64(7)
	u := uint64(3)
	var out Uint256
	be := BytesBE(a)
	check := func(name string, fn func()) {
		t.Helper()
		n := testing.AllocsPerRun(1000, fn)
		if n != 0 {
			t.Fatalf("%s: %f allocs/op, attendu 0", name, n)
		}
	}
	check("Add256", func() { Add256(&a, &b, &out) })
	check("Sub256", func() { Sub256(&a, &b, &out) })
	check("Mul256", func() { Mul256(&a, &b, &out) })
	check("Div256", func() { Div256(&a, &b, &out) })
	check("SDiv256", func() { SDiv256(&a, &b, &out) })
	check("Mod256", func() { Mod256(&a, &b, &out) })
	check("SMod256", func() { SMod256(&a, &b, &out) })
	check("AddMod256", func() { AddMod256(&a, &b, &m, &out) })
	check("MulMod256", func() { MulMod256(&a, &b, &m, &out) })
	check("Exp256", func() { Exp256(&a, &e, &out) })
	check("SignExtend256", func() { SignExtend256(u, &a, &out) })
	check("And256", func() { And256(&a, &b, &out) })
	check("Or256", func() { Or256(&a, &b, &out) })
	check("Xor256", func() { Xor256(&a, &b, &out) })
	check("Not256", func() { Not256(&a, &out) })
	check("Byte256", func() { Byte256(u, &a, &out) })
	check("Shl256", func() { Shl256(&e, &a, &out) })
	check("Shr256", func() { Shr256(&e, &a, &out) })
	check("Sar256", func() { Sar256(&e, &a, &out) })
	check("Lt256", func() { sinkBool = Lt256(&a, &b) })
	check("Gt256", func() { sinkBool = Gt256(&a, &b) })
	check("Slt256", func() { sinkBool = Slt256(&a, &b) })
	check("Sgt256", func() { sinkBool = Sgt256(&a, &b) })
	check("FromU64", func() { sink = FromU64(42) })
	check("FromBytesBE", func() { sink = FromBytesBE(be[:]) })
	check("BytesBE", func() { sink32 = BytesBE(a) })
	check("IsZero", func() { sinkBool = IsZero(&a) })
	check("Eq", func() { sinkBool = Eq(&a, &b) })
	check("Cmp", func() { sinkInt = Cmp(&a, &b) })
	sink = out
}

func BenchmarkAdd256(b *testing.B) {
	x := FromU64(1)
	y := FromU64(2)
	var z Uint256
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Add256(&x, &y, &z)
	}
	sink = z
}

func BenchmarkMul256(b *testing.B) {
	x := FromU64(0xdeadbeefcafebabe)
	y := FromU64(0x123456789abcdef0)
	var z Uint256
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Mul256(&x, &y, &z)
	}
	sink = z
}

func BenchmarkDiv256(b *testing.B) {
	x := Uint256{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)}
	y := FromU64(3)
	var z Uint256
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Div256(&x, &y, &z)
	}
	sink = z
}

func BenchmarkMulMod256(b *testing.B) {
	x := Uint256{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)}
	y := x
	m := Uint256{^uint64(0), ^uint64(0), ^uint64(0), 0x7fffffffffffffff}
	var z Uint256
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		MulMod256(&x, &y, &m, &z)
	}
	sink = z
}
