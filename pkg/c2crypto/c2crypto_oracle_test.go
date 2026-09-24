// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 HazyHaar. See LICENSE and NOTICE.

package c2crypto

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
)

const oracleRunnerC = `
#include "crypto_keccak.h"
#include "crypto_secp256k1.h"
#include "crypto_brotli_l2.h"
#include "mpt_hash.h"
#include "evm_arith256.h"

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

static int parse_hex(const char *s, uint8_t *out, size_t cap, size_t *n)
{
	size_t len;
	size_t i;

	if (s[0] == '-' && s[1] == '\0') {
		*n = 0;
		return 0;
	}
	len = strlen(s);
	if ((len & 1U) != 0 || (len / 2U) > cap) {
		return -1;
	}
	for (i = 0; i < len; i += 2U) {
		int hi = hexval((unsigned char)s[i]);
		int lo = hexval((unsigned char)s[i + 1U]);
		if (hi < 0 || lo < 0) {
			return -1;
		}
		out[i / 2U] = (uint8_t)((hi << 4) | lo);
	}
	*n = len / 2U;
	return 0;
}

static void print_hex(const uint8_t *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		printf("%02x", p[i]);
	}
	printf("\n");
}

int main(void)
{
	char op[32];
	char a[8192];
	char b[8192];
	char c[8192];
	uint8_t buf[8192];
	uint8_t buf2[8192];
	uint8_t outb[65536];
	size_t n, n2;

	while (scanf("%31s", op) == 1) {
		if (strcmp(op, "K256") == 0) {
			uint8_t dgst[32];
			if (scanf("%8191s", a) != 1) {
				return 2;
			}
			if (parse_hex(a, buf, sizeof(buf), &n) != 0) {
				return 2;
			}
			keccak256(buf, n, dgst);
			print_hex(dgst, 32);
		} else if (strcmp(op, "K512") == 0) {
			uint8_t dgst[64];
			if (scanf("%8191s", a) != 1) {
				return 2;
			}
			if (parse_hex(a, buf, sizeof(buf), &n) != 0) {
				return 2;
			}
			keccak512(buf, n, dgst);
			print_hex(dgst, 64);
		} else if (strcmp(op, "F1600") == 0) {
			keccak_state_t st;
			int i;
			for (i = 0; i < 25; i++) {
				if (scanf("%" SCNu64, &st.a[i]) != 1) {
					return 2;
				}
			}
			keccak_f1600(&st);
			for (i = 0; i < 25; i++) {
				printf("%" PRIu64 "%s", st.a[i], i == 24 ? "\n" : " ");
			}
		} else if (strcmp(op, "ECREC") == 0) {
			uint8_t hash[32], r[32], s[32], pub[64];
			unsigned v;
			int rc;
			if (scanf("%8191s %u %8191s %8191s", a, &v, b, c) != 4) {
				return 2;
			}
			if (parse_hex(a, hash, 32, &n) != 0 || n != 32) {
				return 2;
			}
			if (parse_hex(b, r, 32, &n) != 0 || n != 32) {
				return 2;
			}
			if (parse_hex(c, s, 32, &n) != 0 || n != 32) {
				return 2;
			}
			rc = secp256k1_ecrecover(hash, (uint8_t)v, r, s, pub);
			if (rc != 0) {
				printf("FAIL\n");
			} else {
				print_hex(pub, 64);
			}
		} else if (strcmp(op, "BROTLI") == 0) {
			size_t cap, outn = 0;
			int rc;
			if (scanf("%8191s %zu", a, &cap) != 2) {
				return 2;
			}
			if (parse_hex(a, buf, sizeof(buf), &n) != 0) {
				return 2;
			}
			if (cap > sizeof(outb)) {
				cap = sizeof(outb);
			}
			rc = brotli_l2_decompress(buf, n, outb, cap, &outn);
			if (rc != 0) {
				printf("ERR %d\n", rc);
			} else {
				printf("OK ");
				print_hex(outb, outn);
			}
		} else if (strcmp(op, "MPT_COMPACT") == 0) {
			int leaf;
			size_t m;
			if (scanf("%8191s %d", a, &leaf) != 2) {
				return 2;
			}
			if (parse_hex(a, buf, sizeof(buf), &n) != 0) {
				return 2;
			}
			m = mpt_compact_encode(buf, n, leaf, outb);
			print_hex(outb, m);
		} else if (strcmp(op, "RLP_BYTES") == 0) {
			size_t m;
			if (scanf("%8191s", a) != 1) {
				return 2;
			}
			if (parse_hex(a, buf, sizeof(buf), &n) != 0) {
				return 2;
			}
			m = rlp_encode_bytes(buf, n, outb);
			print_hex(outb, m);
		} else if (strcmp(op, "RLP_LIST") == 0) {
			size_t plen, m;
			if (scanf("%zu", &plen) != 1) {
				return 2;
			}
			m = rlp_encode_list_header(plen, outb);
			print_hex(outb, m);
		} else if (strcmp(op, "MPT_HASH") == 0) {
			uint8_t dgst[32];
			if (scanf("%8191s", a) != 1) {
				return 2;
			}
			if (parse_hex(a, buf, sizeof(buf), &n) != 0) {
				return 2;
			}
			mpt_hash_node(buf, n, dgst);
			print_hex(dgst, 32);
		} else if (strcmp(op, "MPT_LEAF") == 0) {
			size_t m;
			if (scanf("%8191s %8191s", a, b) != 2) {
				return 2;
			}
			if (parse_hex(a, buf, sizeof(buf), &n) != 0) {
				return 2;
			}
			if (parse_hex(b, buf2, sizeof(buf2), &n2) != 0) {
				return 2;
			}
			m = mpt_encode_leaf(buf, n, buf2, n2, outb);
			print_hex(outb, m);
		} else if (strcmp(op, "MPT_CHILDREF") == 0) {
			size_t m;
			if (scanf("%8191s", a) != 1) {
				return 2;
			}
			if (parse_hex(a, buf, sizeof(buf), &n) != 0) {
				return 2;
			}
			m = mpt_encode_child_ref(buf, n, outb);
			print_hex(outb, m);
		} else if (strcmp(op, "MPT_EXT") == 0) {
			size_t m;
			if (scanf("%8191s %8191s", a, b) != 2) {
				return 2;
			}
			if (parse_hex(a, buf, sizeof(buf), &n) != 0) {
				return 2;
			}
			if (parse_hex(b, buf2, sizeof(buf2), &n2) != 0) {
				return 2;
			}
			m = mpt_encode_extension(buf, n, buf2, n2, outb);
			print_hex(outb, m);
		} else if (strcmp(op, "MPT_BRANCH") == 0) {
			static uint8_t childbuf[16][8192];
			const uint8_t *children_rlp[16];
			size_t child_lens[16];
			int has_child[16];
			int i;
			size_t m;
			for (i = 0; i < 16; i++) {
				if (scanf("%8191s", a) != 1) {
					return 2;
				}
				children_rlp[i] = childbuf[i];
				if (a[0] == '-' && a[1] == '\0') {
					has_child[i] = 0;
					child_lens[i] = 0;
				} else {
					if (parse_hex(a, childbuf[i],
					    sizeof(childbuf[i]), &child_lens[i]) != 0) {
						return 2;
					}
					has_child[i] = 1;
				}
			}
			if (scanf("%8191s", b) != 1) {
				return 2;
			}
			if (parse_hex(b, buf2, sizeof(buf2), &n2) != 0) {
				return 2;
			}
			m = mpt_encode_branch(children_rlp, child_lens, has_child, buf2,
			    n2, outb);
			print_hex(outb, m);
		} else {
			return 2;
		}
	}
	return 0;
}
`

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
		filepath.Join(csrc, "crypto_keccak.c"),
		filepath.Join(csrc, "crypto_secp256k1.c"),
		filepath.Join(csrc, "crypto_brotli_l2.c"),
		filepath.Join(csrc, "mpt_hash.c"),
		filepath.Join(csrc, "evm_arith256.c"))
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
	s := strings.TrimRight(stdout.String(), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func hexOrDash(b []byte) string {
	if len(b) == 0 {
		return "-"
	}
	return hex.EncodeToString(b)
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, "0x", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestKeccakVsCOracle(t *testing.T) {
	bin := buildCOracle(t)
	type vec struct {
		in   []byte
		want string
	}
	official := []vec{
		{[]byte{}, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"},
		{[]byte("abc"), "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"},
		{[]byte("hello"), "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"},
	}
	for _, v := range official {
		var out [32]byte
		Keccak256(v.in, &out)
		got := hex.EncodeToString(out[:])
		if got != v.want {
			t.Fatalf("keccak256(%q) = %s, vecteur officiel %s", v.in, got, v.want)
		}
	}
	k512empty := "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e"
	var out512 [64]byte
	Keccak512(nil, &out512)
	if hex.EncodeToString(out512[:]) != k512empty {
		t.Fatalf("keccak512(empty) = %s", hex.EncodeToString(out512[:]))
	}

	inputs := [][]byte{
		{},
		[]byte("a"),
		[]byte("abc"),
		[]byte("hello"),
		bytes.Repeat([]byte{0x00}, 135),
		bytes.Repeat([]byte{0x00}, 136),
		bytes.Repeat([]byte{0x01}, 137),
		bytes.Repeat([]byte{0x5a}, 200),
		bytes.Repeat([]byte{0xff}, 300),
		[]byte("The quick brown fox jumps over the lazy dog"),
	}
	var b strings.Builder
	for _, in := range inputs {
		fmt.Fprintf(&b, "K256 %s\n", hexOrDash(in))
		fmt.Fprintf(&b, "K512 %s\n", hexOrDash(in))
	}
	var st [25]uint64
	fmt.Fprintf(&b, "F1600")
	for i := 0; i < 25; i++ {
		fmt.Fprintf(&b, " %d", st[i])
	}
	b.WriteByte('\n')
	for i := 0; i < 25; i++ {
		st[i] = uint64(i)*0x9e3779b97f4a7c15 + 1
	}
	fmt.Fprintf(&b, "F1600")
	for i := 0; i < 25; i++ {
		fmt.Fprintf(&b, " %d", st[i])
	}
	b.WriteByte('\n')
	lines := runCOracle(t, bin, b.String())
	li := 0
	for _, in := range inputs {
		var d32 [32]byte
		var d64 [64]byte
		Keccak256(in, &d32)
		Keccak512(in, &d64)
		if hex.EncodeToString(d32[:]) != lines[li] {
			t.Fatalf("K256 mismatch in=%q go=%s c=%s", in, hex.EncodeToString(d32[:]), lines[li])
		}
		li++
		if hex.EncodeToString(d64[:]) != lines[li] {
			t.Fatalf("K512 mismatch in=%q go=%s c=%s", in, hex.EncodeToString(d64[:]), lines[li])
		}
		li++
	}
	var zero [25]uint64
	KeccakF1600(&zero)
	cfields := strings.Fields(lines[li])
	if len(cfields) != 25 {
		t.Fatalf("F1600 zero: %q", lines[li])
	}
	for i := 0; i < 25; i++ {
		v, err := strconv.ParseUint(cfields[i], 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		if zero[i] != v {
			t.Fatalf("F1600 zero[%d] go=%d c=%d", i, zero[i], v)
		}
	}
	li++
	var patterned [25]uint64
	for i := 0; i < 25; i++ {
		patterned[i] = uint64(i)*0x9e3779b97f4a7c15 + 1
	}
	KeccakF1600(&patterned)
	cfields = strings.Fields(lines[li])
	for i := 0; i < 25; i++ {
		v, err := strconv.ParseUint(cfields[i], 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		if patterned[i] != v {
			t.Fatalf("F1600 pat[%d] go=%d c=%d", i, patterned[i], v)
		}
	}
}

func TestSecp256k1VsCOracle(t *testing.T) {
	bin := buildCOracle(t)
	type rec struct {
		hash, r, s []byte
		v          uint8
	}
	gx := mustHex(t, "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	var zero32 [32]byte
	one := make([]byte, 32)
	one[31] = 1
	n := mustHex(t, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
	nHalfP1 := mustHex(t, "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1")
	hash0 := make([]byte, 32)
	cases := []rec{
		{hash0, zero32[:], one, 27},
		{hash0, one, zero32[:], 27},
		{hash0, n, one, 27},
		{hash0, one, n, 27},
		{hash0, one, nHalfP1, 27},
		{hash0, gx, one, 2},
		{hash0, gx, one, 27},
		{hash0, gx, one, 28},
		{hash0, gx, one, 0},
		{hash0, gx, one, 1},
		{
			mustHex(t, "ce0677bb30baa8cf067c88db9811f4333d131bf8bcf12fe7065d211dce971008"),
			mustHex(t, "90f27b8b488db00b00606796d2987f7373c4cdb9c5cd7438c2c4f857cd8e7c70"),
			mustHex(t, "07a8b8471be4c4c8dbedb2ce185fe2b2c389347a7e34993febc249bd2a51c33f"),
			28,
		},
		{
			mustHex(t, "456e9aea5e197a1f1af7a3e85a4931b6f6f3571c08c959be869f657baacf7853"),
			mustHex(t, "09242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038823c0"),
			mustHex(t, "4c069c1a18b58ad15ea182ddf605d12cd12a6209d3221c04ff8ebdd77aebc8cd"),
			28,
		},
	}
	var b strings.Builder
	for _, c := range cases {
		fmt.Fprintf(&b, "ECREC %s %d %s %s\n", hex.EncodeToString(c.hash), c.v, hex.EncodeToString(c.r), hex.EncodeToString(c.s))
	}
	lines := runCOracle(t, bin, b.String())
	if len(lines) != len(cases) {
		t.Fatalf("oracle lignes %d cas %d", len(lines), len(cases))
	}
	for i, c := range cases {
		var pub [64]byte
		err := EcRecover(c.hash, c.v, c.r, c.s, &pub)
		if lines[i] == "FAIL" {
			if err == nil {
				t.Fatalf("cas %d: Go succès, C FAIL", i)
			}
			continue
		}
		if err != nil {
			t.Fatalf("cas %d: Go err %v, C %s", i, err, lines[i])
		}
		got := hex.EncodeToString(pub[:])
		if got != lines[i] {
			t.Fatalf("cas %d pubkey go=%s c=%s", i, got, lines[i])
		}
	}
}

func brotliUncompressed(payload []byte) []byte {
	mlen := len(payload)
	if mlen == 0 {
		return []byte{0x06}
	}
	var acc uint64
	var nbits int
	put := func(v uint64, n int) {
		acc |= v << nbits
		nbits += n
	}
	put(0, 1)
	put(0, 1)
	put(0, 2)
	put(uint64(mlen-1), 16)
	put(1, 1)
	for nbits%8 != 0 {
		put(0, 1)
	}
	out := make([]byte, 0, nbits/8+len(payload)+1)
	for i := 0; i < nbits; i += 8 {
		out = append(out, byte(acc>>i))
	}
	out = append(out, payload...)
	out = append(out, 0x03)
	return out
}

func brotliErrCode(err error) int {
	switch err {
	case nil:
		return 0
	case ErrBrotliArg:
		return brotliL2ErrArg
	case ErrBrotliCapacity:
		return brotliL2ErrCapacity
	case ErrBrotliTrunc:
		return brotliL2ErrTrunc
	case ErrBrotliFormat:
		return brotliL2ErrFormat
	case ErrBrotliWindow:
		return brotliL2ErrWindow
	case ErrBrotliDict:
		return brotliL2ErrDict
	default:
		return 99
	}
}

func TestBrotliVsCOracle(t *testing.T) {
	bin := buildCOracle(t)
	payloads := [][]byte{
		{},
		[]byte("a"),
		[]byte("abc"),
		[]byte("hello brotli l2"),
		bytes.Repeat([]byte{0x00}, 64),
		bytes.Repeat([]byte{0x61}, 300),
		{0xff, 0x00, 0x01, 0x02, 0xfe},
	}
	type job struct {
		in  []byte
		cap int
	}
	var jobs []job
	for _, p := range payloads {
		in := brotliUncompressed(p)
		jobs = append(jobs, job{in, len(p) + 16})
		jobs = append(jobs, job{in, 0})
		if len(p) > 0 {
			jobs = append(jobs, job{in, len(p) - 1})
		}
	}
	jobs = append(jobs, job{[]byte{0x06}, 8})
	jobs = append(jobs, job{[]byte{}, 8})
	jobs = append(jobs, job{[]byte{0xff}, 8})
	var b strings.Builder
	for _, j := range jobs {
		fmt.Fprintf(&b, "BROTLI %s %d\n", hexOrDash(j.in), j.cap)
	}
	lines := runCOracle(t, bin, b.String())
	if len(lines) != len(jobs) {
		t.Fatalf("oracle lignes %d jobs %d", len(lines), len(jobs))
	}
	for i, j := range jobs {
		out := make([]byte, j.cap)
		n, err := BrotliL2Decompress(j.in, out)
		cline := lines[i]
		if strings.HasPrefix(cline, "ERR ") {
			code, _ := strconv.Atoi(strings.TrimPrefix(cline, "ERR "))
			got := brotliErrCode(err)
			if got != code {
				t.Fatalf("job %d err go=%d (%v) c=%d in=%s cap=%d", i, got, err, code, hexOrDash(j.in), j.cap)
			}
			continue
		}
		if err != nil {
			t.Fatalf("job %d Go err %v C %s", i, err, cline)
		}
		if !strings.HasPrefix(cline, "OK") {
			t.Fatalf("job %d C inattendu %q", i, cline)
		}
		want := strings.TrimSpace(strings.TrimPrefix(cline, "OK"))
		got := hex.EncodeToString(out[:n])
		if got != want {
			t.Fatalf("job %d out go=%s c=%s", i, got, want)
		}
	}
}

func TestMPTVsCOracle(t *testing.T) {
	bin := buildCOracle(t)
	var b strings.Builder
	nibbles := [][]byte{
		{},
		{0x0a},
		{0x01, 0x02, 0x03},
		{0x0f, 0x0e, 0x0d, 0x0c},
		bytes.Repeat([]byte{0x01}, 20),
	}
	for _, n := range nibbles {
		fmt.Fprintf(&b, "MPT_COMPACT %s 0\n", hexOrDash(n))
		fmt.Fprintf(&b, "MPT_COMPACT %s 1\n", hexOrDash(n))
	}
	rlps := [][]byte{
		{},
		{0x00},
		{0x7f},
		{0x80},
		[]byte("dog"),
		bytes.Repeat([]byte{0xab}, 55),
		bytes.Repeat([]byte{0xcd}, 56),
		bytes.Repeat([]byte{0xef}, 60),
	}
	for _, r := range rlps {
		fmt.Fprintf(&b, "RLP_BYTES %s\n", hexOrDash(r))
		fmt.Fprintf(&b, "MPT_HASH %s\n", hexOrDash(r))
	}
	for _, plen := range []int{0, 1, 55, 56, 200, 1024} {
		fmt.Fprintf(&b, "RLP_LIST %d\n", plen)
	}
	leafNibs := []byte{0x01, 0x02, 0x03, 0x04}
	leafVal := []byte("ok")
	fmt.Fprintf(&b, "MPT_LEAF %s %s\n", hexOrDash(leafNibs), hexOrDash(leafVal))
	fmt.Fprintf(&b, "MPT_LEAF %s %s\n", hexOrDash([]byte{0x0a}), hexOrDash([]byte{}))
	for _, r := range rlps {
		fmt.Fprintf(&b, "MPT_CHILDREF %s\n", hexOrDash(r))
	}
	extChildren := [][]byte{
		{},
		{0x0a},
		[]byte("dog"),
		bytes.Repeat([]byte{0xab}, 40),
	}
	for _, ch := range extChildren {
		fmt.Fprintf(&b, "MPT_EXT %s %s\n", hexOrDash([]byte{0x01, 0x02}), hexOrDash(ch))
	}
	branchChildren := [16][]byte{}
	var branchHas [16]int
	branchChildren[0] = []byte{0x0a}
	branchHas[0] = 1
	branchChildren[15] = bytes.Repeat([]byte{0xcd}, 40)
	branchHas[15] = 1
	fmt.Fprintf(&b, "MPT_BRANCH")
	for i := 0; i < 16; i++ {
		if branchHas[i] != 0 {
			fmt.Fprintf(&b, " %s", hex.EncodeToString(branchChildren[i]))
		} else {
			fmt.Fprintf(&b, " -")
		}
	}
	fmt.Fprintf(&b, " %s\n", hexOrDash([]byte("val")))
	fmt.Fprintf(&b, "MPT_BRANCH")
	for i := 0; i < 16; i++ {
		fmt.Fprintf(&b, " -")
	}
	fmt.Fprintf(&b, " -\n")
	lines := runCOracle(t, bin, b.String())
	li := 0
	cmp := func(name, got string) {
		t.Helper()
		if li >= len(lines) {
			t.Fatalf("%s: plus de lignes oracle", name)
		}
		if got != lines[li] {
			t.Fatalf("%s go=%s c=%s", name, got, lines[li])
		}
		li++
	}
	var enc [512]byte
	for _, n := range nibbles {
		k := MptCompactEncode(n, false, enc[:])
		cmp("compact ext", hex.EncodeToString(enc[:k]))
		k = MptCompactEncode(n, true, enc[:])
		cmp("compact leaf", hex.EncodeToString(enc[:k]))
	}
	for _, r := range rlps {
		k := RlpEncodeBytes(r, enc[:])
		cmp("rlp", hex.EncodeToString(enc[:k]))
		var h [32]byte
		MptHashNode(r, &h)
		cmp("hash", hex.EncodeToString(h[:]))
	}
	for _, plen := range []int{0, 1, 55, 56, 200, 1024} {
		k := RlpEncodeListHeader(plen, enc[:])
		cmp("list", hex.EncodeToString(enc[:k]))
	}
	k := MptEncodeLeaf(leafNibs, leafVal, enc[:])
	cmp("leaf", hex.EncodeToString(enc[:k]))
	k = MptEncodeLeaf([]byte{0x0a}, nil, enc[:])
	cmp("leaf empty", hex.EncodeToString(enc[:k]))
	for _, r := range rlps {
		k = MptEncodeChildRef(r, enc[:])
		cmp("childref", hex.EncodeToString(enc[:k]))
	}
	for _, ch := range extChildren {
		k = MptEncodeExtension([]byte{0x01, 0x02}, ch, enc[:])
		cmp("ext", hex.EncodeToString(enc[:k]))
	}
	k = MptEncodeBranch(&branchChildren, &branchHas, []byte("val"), enc[:])
	cmp("branch", hex.EncodeToString(enc[:k]))
	var emptyHas [16]int
	var emptyCh [16][]byte
	k = MptEncodeBranch(&emptyCh, &emptyHas, nil, enc[:])
	cmp("branch empty", hex.EncodeToString(enc[:k]))
}

var (
	sink32  [32]byte
	sink64  [64]byte
	sinkInt int
	sinkErr error
)

func TestAllocsPerRun(t *testing.T) {
	in := []byte("abcdefghijklmnopqrstuvwxyz0123456789")
	var d32 [32]byte
	var d64 [64]byte
	var st [25]uint64
	check := func(name string, fn func()) {
		t.Helper()
		n := testing.AllocsPerRun(200, fn)
		if n != 0 {
			t.Fatalf("%s: %f allocs/op, attendu 0", name, n)
		}
	}
	check("Keccak256", func() { Keccak256(in, &d32) })
	check("Keccak512", func() { Keccak512(in, &d64) })
	check("KeccakF1600", func() { KeccakF1600(&st) })
	var enc [256]byte
	nibs := []byte{0x01, 0x02, 0x03, 0x04}
	val := []byte("v")
	check("MptCompactEncode", func() { sinkInt = MptCompactEncode(nibs, true, enc[:]) })
	check("RlpEncodeBytes", func() { sinkInt = RlpEncodeBytes(val, enc[:]) })
	check("RlpEncodeListHeader", func() { sinkInt = RlpEncodeListHeader(3, enc[:]) })
	check("MptHashNode", func() { MptHashNode(in, &d32) })
	check("MptEncodeLeaf", func() { sinkInt = MptEncodeLeaf(nibs, val, enc[:]) })
	childRLP := []byte{0x0a}
	check("MptEncodeChildRef", func() { sinkInt = MptEncodeChildRef(childRLP, enc[:]) })
	check("MptEncodeExtension", func() { sinkInt = MptEncodeExtension(nibs, childRLP, enc[:]) })
	var children [16][]byte
	var has [16]int
	has[1] = 1
	children[1] = childRLP
	check("MptEncodeBranch", func() { sinkInt = MptEncodeBranch(&children, &has, val, enc[:]) })
	empty := brotliUncompressed([]byte("x"))
	bout := make([]byte, 16)
	check("BrotliL2Decompress", func() { sinkInt, sinkErr = BrotliL2Decompress(empty, bout) })
	hash := mustHex(t, "0000000000000000000000000000000000000000000000000000000000000001")
	r0 := make([]byte, 32)
	s1 := make([]byte, 32)
	s1[31] = 1
	var pub [64]byte
	check("EcRecoverReject", func() { sinkErr = EcRecover(hash, 27, r0, s1, &pub) })
	sink32 = d32
	sink64 = d64
}

func BenchmarkKeccak256(b *testing.B) {
	in := []byte("arbitrum nitro transaction data payload test vector")
	var d32 [32]byte
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Keccak256(in, &d32)
	}
	sink32 = d32
}

func BenchmarkBrotliL2Decompress(b *testing.B) {
	data := []byte("arbitrum nitro brotli batch payload compression test vector")
	empty := brotliUncompressed(data)
	bout := make([]byte, 128)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sinkInt, sinkErr = BrotliL2Decompress(empty, bout)
	}
}

func BenchmarkSecp256k1EcRecover(b *testing.B) {
	hash, _ := hex.DecodeString("ce0677bb30baa8cf067c88db9811f4333d131bf8bcf12fe7065d211dce971008")
	r, _ := hex.DecodeString("90f27b8b488db00b00606796d2987f7373c4cdb9c5cd7438c2c4f857cd8e7c70")
	s, _ := hex.DecodeString("07a8b8471be4c4c8dbedb2ce185fe2b2c389347a7e34993febc249bd2a51c33f")
	v := uint8(28)
	var pub [64]byte
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sinkErr = EcRecover(hash, v, r, s, &pub)
	}
}
