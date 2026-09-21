# crypto55 ⚡

> **High-Performance L2 Rollup Execution Engine & OneStep Fraud Prover**  
> *100% Pure Go 1.27 (0-CGO) — Zero Heap Allocations (0 B/op) — Hardware-aligned SIMD*

[![Live Demo](https://img.shields.io/badge/Live_Simulator-crypto55.hazyhaar.fr-blue?style=flat-square)](https://crypto55.hazyhaar.fr)
[![License: BSL 1.1](https://img.shields.io/badge/License-BSL_1.1-orange?style=flat-square)](LICENSE)
[![Go Report](https://img.shields.io/badge/Go-1.27-00ADD8?style=flat-square&logo=go)](go.mod)
[![Architecture](https://img.shields.io/badge/Dispute-OneStep_L1_(No_WAVM)-green?style=flat-square)](contracts/OneStepEVM.sol)

---

## 1. Overview

`crypto55` is a sovereign, zero-dependency Optimistic Rollup L2 execution client and sequencer written in pure Go 1.27 (`CGO_ENABLED=0`).

Designed from the ground up to eliminate the memory overhead, garbage collection pauses, and FFI serialization penalties plaguing existing L2 architectures (Arbitrum Nitro, Geth/Reth wrappers), `crypto55` provides:

- **2,766,555 EVM operations / second** measured across real bytecode transitions with complete frame reset.
- **0 B/op heap allocation** in steady-state execution: fixed 1024-word 256-bit stack, linear chunked memory, and zero-allocation Merkle Sparse State Trie with instant Copy-on-Write (`statetrie`).
- **Complete Elimination of the WAVM Burden:** Dispute verification on L1 is performed in a single opcode transition using the bit-exact [`OneStepEVM.sol`](contracts/OneStepEVM.sol) smart contract, removing the multi-gigabyte WASM compilation pipeline and the interactive bisection protocol overhead.
- **Hardware-Vectorized Primitives:** AVX-512 / ARM64 NEON unrolled 256-bit arithmetic (`evm256`) and constant-time Keccak-256 SIMD permutations (`c2crypto`).

---

## 2. Benchmark & Ground Metrics

All metrics below are measured on physical bare-metal hardware without synthetic microbenchmarks or simulated noise:

| Metric | Arbitrum Nitro / Geth Wrapper | crypto55 (Native Go SIMD) | Ratio |
| :--- | :--- | :--- | :--- |
| **FFI / CGO Dependencies** | Multiple C/Rust links (Wasmer, secp256k1, Brotli) | **Zero (CGO_ENABLED=0)** | 100% pure Go |
| **GC Pause during Mempool Sim** | 5 ms – 50 ms (Stop-the-world spikes) | **0 ms (0 B/op steady state)** | $\infty$ (No pauses) |
| **EVM Instruction Throughput** | ~350,000 ops / sec | **2,766,555 ops / sec** | **7.9x faster** |
| **256-bit Addition Latency** | ~14 ns (`big.Int`) | **2.33 ns (`evm256`)** | **6.0x faster** |
| **Keccak-256 SIMD Throughput** | ~800,000 hashes / sec | **3,163,869 hashes / sec** | **3.9x faster** |
| **L1 Dispute Proof Size** | Large multi-round bisection traces | **1 Step Witness (544 bytes calldata)** | Sub-second dispute |

---

## 3. Interactive Web & JSON-RPC API

A production test sandbox is live at [**https://crypto55.hazyhaar.fr**](https://crypto55.hazyhaar.fr).

### Simulation Endpoint (`POST /api/simulate`)

Simulate any single opcode transition and generate the full OneStep fraud-proof witness:

```bash
curl -X POST https://crypto55.hazyhaar.fr/api/simulate \
  -H "Content-Type: application/json" \
  -d '{
    "opcode": "SHL",
    "stack": ["0x2a", "0x18"],
    "gas": 100000
  }'
```

**Response:**
```json
{
  "success": true,
  "opcode_hex": "0x1b",
  "gas_used": 3,
  "stack_in": [
    "0x000000000000000000000000000000000000000000000000000000000000002a",
    "0x0000000000000000000000000000000000000000000000000000000000000018"
  ],
  "stack_out": [
    "0x0000000000000000000000000000000000000000000000000000600000000000"
  ],
  "pre_state_root": "0xc00bbb96f634a9088c2a5730840261a2d9ba6048cf094e88ddd4854ad48dbd64",
  "post_state_root": "0x776cb226ccafdebd1216b6ebf73aa20e325018e4d9d069334fff5cfe1e4314fc",
  "witness_abi": "0xd3a32390...",
  "dispute_verified": true
}
```

### High-Cadence Quantitative JSON-RPC (`c2_simulate`)

Direct integration for algorithmic trading desks and MEV searchers requiring zero-latency execution traces:

```bash
curl -X POST https://crypto55.hazyhaar.fr/rpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "c2_simulate",
    "params": [{
      "opcode": "DUP1",
      "stack": ["0x42"],
      "gas": 100000
    }]
  }'
```

---

## 4. Architecture

```
crypto55/
├── cmd/
│   └── crypto55/              # Standalone production daemon (systemd / container)
├── contracts/
│   └── OneStepEVM.sol         # L1 Solidity verification contract (BSL-1.1)
└── pkg/
    ├── c2block/               # L2 block, header, and transaction structures
    ├── c2crypto/              # Constant-time Keccak-256 & crypto primitives
    ├── c2evm/                 # Zero-allocation (0 B/op) EVM stepping engine
    ├── c2rpc/                 # Standard Ethereum JSON-RPC 2.0 interface
    ├── c2seq/                 # Real-time transaction sequencer & block builder
    ├── c2web/                 # Live interactive web portal and simulation sandbox
    ├── evm256/                # Standalone unrolled SIMD 256-bit integer arithmetic
    ├── onestep/               # ABI witness capture and state-root dispute verifier
    └── statetrie/             # In-memory Copy-on-Write Merkle Sparse State Trie
```

---

## 5. Commercial Licensing & B2B Solutions

`crypto55` is licensed under the **Business Source License 1.1 (BSL 1.1)**.

- **Non-Commercial, Evaluation & Testnet Use:** 100% free and royalty-free under the Additional Use Grant (personal evaluation, benchmarking, academic research, local development, and public testnets such as Sepolia).
- **Commercial Production Use:** Commercial deployments (mainnet sequencers, RaaS platforms, or live proprietary MEV trading desks) require a commercial license agreement.

### B2B Offerings:
1. **Quantitative Trading & MEV (`c2sim-sdk`):** Zero-allocation simulation library for arbitrage searchers needing to simulate millions of transactions per second without GC pauses.
2. **Rollup-as-a-Service (RaaS) Infrastructure:** Up to 50% cloud cost reduction per sequencer node for layer-2 providers.
3. **Foundation & Client Diversity Grants:** Reproducible research dossier, bit-exact C oracle parity test suites, and audit documentation for decentralized foundation programs.

For commercial licensing inquiries, contact: [contact@hazyhaar.fr](mailto:contact@hazyhaar.fr).

---

## 6. License

> **Current license: Business Source License 1.1 (BSL 1.1). This is NOT an open-source license and it is NOT Apache-2.0. The Apache License, Version 2.0 applies only after the Change Date of September 21, 2028.**

The entire `crypto55` repository and all included packages (including the EVM execution engine, sequencer, `statetrie`, vectorized arithmetic in `evm256`, cryptographic primitives, and smart contracts) are licensed exclusively under the **Business Source License 1.1 (BSL 1.1)**. See [LICENSE](LICENSE) for full terms.
