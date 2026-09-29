# Ghostless — Proof of Non-Omission for Decision Ledgers on MST Blockchain

> **One-liner:** Blockchains can prove that what was logged was not changed. They cannot prove that nothing was *left out*. Ghostless makes omission **provable, bonded, and economically irrational**, even against a fully malicious operator who controls the decision engine, database, signing keys, and chain client.

[![MST Testnet](https://img.shields.io/badge/Network-MST%20Testnet%20(91562037)-4f46e5)](https://mstscan.com)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.20-blue)](contracts/GhostlessLedger.sol)
[![EVM Version](https://img.shields.io/badge/EVM-Paris%20%2F%20Shanghai%20(PUSH0)-green)](preflight.json)
[![Red-Team](https://img.shields.io/badge/Red--Team%20Scoreboard-Passing%20(S1--S10)-success)](results.json)

---

## 🔗 Official MST Developer Resources & Integration

This codebase is directly integrated with and tested against the official MST Blockchain infrastructure:
- **MST Testnet RPC**: `https://testnetrpc.mstblockchain.com` (Chain ID: `91562037` / Hex: `0x5752035`)
- **MSTScan Explorer**: `https://mstscan.com`
- **Official Faucet**: `https://faucet.masterstroke.academy`
- **MST Python SDK**: `mst-sdk-python` (`mst_blockchain_sdk`)
- **MST TypeScript / Node SDK**: `@mstblockchain/mst-sdk` & `@mstblockchain/mst-vibe-kit`
- **BridgeKey**: `https://bridgekey.io`

---

## 🚀 Deployed Contracts (MST Testnet)

| Contract | MST Testnet Address | Explorer Link |
|---|---|---|
| **GhostlessLedger** | `0x7B0b975D1C044225be49f178F34332029b28620c` | [View on MSTScan](https://mstscan.com/address/0x7B0b975D1C044225be49f178F34332029b28620c) |
| **PerTxAnchor (Baseline B0)** | `0xa42618de5862e582e55Cdd212cA11F890a5249f2` | [View on MSTScan](https://mstscan.com/address/0xa42618de5862e582e55Cdd212cA11F890a5249f2) |
| **BatchRootAnchor (Baseline B1)** | `0x7d38Ccc9fFE711353007e488D47991E378aF8c13` | [View on MSTScan](https://mstscan.com/address/0x7d38Ccc9fFE711353007e488D47991E378aF8c13) |

---

## 🎯 Key Architectural Pillars & Rectifications

1. **Pre-Reservation Before Decisions**: `openWindow(n)` commits contiguous sequence numbers on-chain *before* content exists. History length is monotonic and gapless ($I_1$).
2. **Actuator Gate ("No Receipt → No Effect")**: Downstream actuators refuse execution without an unspent, valid EIP-712 signed receipt matching the exact subject, action hash, actuator ID, and replay nonce.
3. **Bonded Pull-Based Demand Deadline**: A subject can challenge any receipt on-chain (`demandInclusion`). If the operator does not supply the Merkle proof within $R$ blocks, the operator's bond is slashed and permanently frozen.
4. **On-Chain Policy Fraud Engine**: Introduces `provePolicyFraud(...)` so that committed leaves violating policy invariants (e.g. invalid outcome codes or rule contradictions) can be proven and slashed on-chain.
5. **Positional Merkle Trees with Domain Separation**: Domain bytes `0x00` (leaf) and `0x01` (node) with fixed depth $\log_2(N)$ prevent second-preimage attacks.
6. **Honest Impossibility Boundary**: Ungated off-chain actions that leave zero traces to any receipt-demanding party are mathematically unobservable. Ghostless shrinks the boundary by binding real-world effects strictly to receipts.

---

## 📊 Measured Benchmark Results (MST Testnet)

### Gas Comparison vs Baselines
- **Baseline B0 (Per-Tx Anchor)**: `68,028 gas` per decision
- **Ghostless (size 64)**: `3,801.8 gas` (**17.9x cheaper**)
- **Ghostless (size 128)**: `1,366.6 gas` (**49.8x cheaper**)
- **Ghostless (size 256)**: `683.3 gas` (**99.6x cheaper**)

### Red-Team Adversarial Scoreboard
```
Attack | Description                         | B0           | B1           | Ghostless Protocol
----------------------------------------------------------------------------------------------------
A1     | Mutate logged decision post-sealing | DETECTED     | DETECTED     | DETECTED & SLASHED (NoResponse)
A2     | Omit receipted decision / void      | NOT DETECTED | NOT DETECTED | DETECTED & SLASHED (NoResponse)
A2'    | Ghost decision (unreceipted action) | NOT DETECTED | NOT DETECTED | PREVENTED (Actuator Gate: 403)
A3     | Equivocate (conflicting receipts)   | NOT DETECTED | NOT DETECTED | DETECTED & SLASHED (proveEquivocation)
A4     | Backdate / reorder decisions        | PARTIAL      | NOT DETECTED | BOUNDED ([openedAt, sealDeadline])
A5     | Withhold window (never seal)        | N/A          | NOT DETECTED | DETECTED & SLASHED (slashUnsealed)
A6     | Falsify policy fields               | NOT DETECTED | NOT DETECTED | DETECTED & SLASHED (provePolicyFraud)
```

---

## 🛠️ Quickstart & Reproduction

### 1. Preflight Verification (Phase 0)
```bash
./venv/bin/python scripts/preflight.py
```

### 2. Run Hardhat Invariant & Unit Tests (AC1)
```bash
CI=true ./node_modules/.bin/hardhat test
```

### 3. Run Cross-Language Conformance (AC2)
```bash
CI=true ./node_modules/.bin/hardhat test test/cross_conformance.test.js
PYTHONPATH=. ./venv/bin/pytest test/test_cross_conformance.py
```

### 4. Run Gas Benchmarks on MST Testnet (AC5)
```bash
PYTHONPATH=. ./venv/bin/python bench/gas_bench.py
```

### 5. Run Red-Team Adversarial Harness on MST Testnet (AC3, AC4, AC6)
```bash
PYTHONPATH=. ./venv/bin/python redteam/run_all.py
```

### 6. Launch Operator Service & Live Visual Dashboard
```bash
PYTHONPATH=. ./venv/bin/uvicorn operator.main:app --host 0.0.0.0 --port 8000
```
Open `http://localhost:8000` in your browser to view the live interactive dashboard!

---

## 📁 Repository Structure

```
├── contracts/
│   ├── GhostlessLedger.sol         # Main protocol contract (bonding, windows, slashing)
│   ├── baselines/
│   │   ├── PerTxAnchor.sol         # Baseline B0 (one tx per decision)
│   │   └── BatchRootAnchor.sol     # Baseline B1 (naive Merkle batching)
│   └── utils/
│       └── ReentrancyGuard.sol     # Zero-dependency reentrancy guard
├── operator/
│   ├── main.py                     # FastAPI service + Web Dashboard
│   ├── merkle.py                   # Positional Merkle tree & proof generator
│   ├── receipts.py                 # EIP-712 typing and signing
│   ├── window_manager.py           # Atomic SQLite allocation, pipelining, sealing
│   └── db.py                       # SQLite database manager
├── actuator/
│   └── gate.py                     # "No Receipt -> No Effect" Actuator Gate
├── watcher/
│   └── watcher.py                  # Verifier service (chain invariants, receipt vault)
├── subjects/
│   └── simulator.py                # S10 Monte Carlo vigilance population study
├── redteam/
│   ├── malicious_operator.py       # Adversarial operator implementation
│   └── run_all.py                  # Full automated red-team test harness
├── bench/
│   └── gas_bench.py                # Live MST testnet gas benchmark suite
├── dashboard/
│   └── index.html                  # Standalone & FastAPI-served interactive UI
├── docs/
│   ├── ARCHITECTURE.md             # In-depth architectural design
│   ├── THREAT_MODEL.md             # Formal threat model & assumptions
│   ├── RESULTS.md                  # Comprehensive measured testnet results
│   └── FLAW_RECTIFICATIONS.md      # Response to brutal review critiques
├── preflight.json                  # Measured MST testnet network parameters
├── gas_report.json                 # Real gas costs on MST Testnet
└── results.json                    # Measured red-team scoreboard & transaction logs
```
