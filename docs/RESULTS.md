# Ghostless Experimental Results (MST Testnet)

All metrics, gas costs, transaction hashes, and red-team detection latencies in this report were measured live on **MST Blockchain Testnet (Chain ID 91562037 / `0x5752035`)**.

---

## 1. Deployed On-Chain Contracts

- **Network**: MST Testnet
- **RPC URL**: `https://testnetrpc.mstblockchain.com`
- **Explorer**: `https://mstscan.com`
- **GhostlessLedger**: [`0xa1401c940e576E8D25aB03b93444c9f19ae52755`](https://mstscan.com/address/0xa1401c940e576E8D25aB03b93444c9f19ae52755)
- **ReceiptGatedEscrow (Exposure Cap k=2)**: [`0xd271379747318248eF16d4BC6F8653Ad0D6726A7`](https://mstscan.com/address/0xd271379747318248eF16d4BC6F8653Ad0D6726A7)
- **OperatorRegistry (Trust Score)**: [`0xfE08b4abBa893d36Ea8006271897B4f9c8348C38`](https://mstscan.com/address/0xfE08b4abBa893d36Ea8006271897B4f9c8348C38)
- **PerTxAnchor (Baseline B0)**: [`0xD3c32217661A5679f649E3Dda559bA7B5faEa041`](https://mstscan.com/address/0xD3c32217661A5679f649E3Dda559bA7B5faEa041)
- **BatchRootAnchor (Baseline B1)**: [`0x99232680AcD8D8cbACAE2F284f07F0B9B7f4E198`](https://mstscan.com/address/0x99232680AcD8D8cbACAE2F284f07F0B9B7f4E198)

---

## 2. Phase 0 Preflight Measurements

- **Chain ID**: `91562037` (`0x5752035`) — Confirmed
- **Average Block Time ($T$)**: `3.00s` (measured over 50 blocks)
- **Block Gas Limit**: `55,000,000` gas
- **EIP-1559 Support**: Yes (`baseFeePerGas = 0`)
- **PUSH0 / Shanghai EVM**: Supported (`0xf8A7fb1190a0D26b7e948dBbD4CbF206a0b10cfE`)
- **Derived Timing Parameters**:
  - Demo Profile: $W = 1000$ blocks, $R = 30$ blocks (90.0s), $D = 1,200$ blocks (3,600s), size = 64
  - Realistic Profile: $W = 100$ blocks (300.0s), $R = 200$ blocks (600.0s), $D = 201,600$ blocks (7 days), size = 128

---

## 3. Gas Benchmarks & Cost Amortization (AC5)

Measured transaction gas on MST Testnet:

| Architecture | Window Size ($N$) | Total Window Gas (Open + Seal) | Amortized Gas / Decision | Efficiency vs Baseline B0 |
|--------------|-------------------|--------------------------------|--------------------------|---------------------------|
| **B0: PerTxAnchor** | 1 | N/A | **68,028 gas** | 1.0x (Baseline) |
| **B1: BatchRootAnchor** | 128 | 114,468 gas | **894.28 gas** | 76.1x Cheaper |
| **Ghostless** | 64 | 243,315 gas | **3,801.80 gas** | **17.9x Cheaper** |
| **Ghostless** | 128 | 174,927 gas | **1,366.62 gas** | **49.8x Cheaper** |
| **Ghostless** | 256 | 174,927 gas | **683.31 gas** | **99.6x Cheaper** |

### Understanding the Cost Dynamics:
1. **$O(1)$ Constant Storage Overhead**: In EVM, `openWindow(N)` and `sealWindow(id, root)` only write a 4-word Window struct and fold a single 32-byte root into `headCheckpoint`. The on-chain write cost is fixed at **174,927 gas** whether $N = 128$ or $N = 256$. Amortized per decision, doubling $N$ cuts gas exactly in half (1,366 gas $\rightarrow$ 683 gas).
2. **Window 0 Storage Initialization**: Size 64 has a higher base cost (243,315 gas) because Window #0 pays initial cold `SSTORE` initialization costs, whereas subsequent windows reuse warm storage slots.
3. **Ghostless vs Naive Batching (B1)**:
   - Baseline B1 costs `894 gas / decision`.
   - Ghostless ($N=128$) costs `1,366 gas / decision` (~1.5x of B1).
   - **Why this 1.5x trade-off is essential**: Naive batching provides **zero completeness guarantees**; an operator can omit 90% of decisions before publishing the root with zero penalty. In Ghostless, that 1.5x gas delta buys **pre-reserved monotonic slots, EIP-712 bonded receipts, and automatic slashing for any omission**.

---

## 4. Red-Team Adversarial Scoreboard (AC3)

All scenarios were executed live by `redteam/run_all.py` against MST Testnet:

| ID | Attack Scenario | B0 (Per-Tx) | B1 (Batch) | Actuator Gate | Contract Enforcement | Measured Latency |
|---|---|---|---|---|---|---|
| **A1** | Withhold or alter committed leaf | DETECTED (hash mismatch) | DETECTED (root mismatch) | Rejects unproven changes | **DETECTED & SLASHED (NoResponse)** | $R$ blocks |
| **A2** | Omit receipted decision / false void | NOT DETECTED | NOT DETECTED | Holds signed receipt | **DETECTED & SLASHED (NoResponse)** | $R$ blocks |
| **A2'**| Ghost decision (unreceipted action) | NOT DETECTED | NOT DETECTED | **BLOCKED (403 No Receipt)** | N/A (Stopped at Gate) | 0.01s |
| **A3** | Equivocate (two histories for slot) | NOT DETECTED | NOT DETECTED | Exposes conflicting sigs | **SLASHED IN 1 TX (proveEquivocation)** | 3.2s |
| **A4** | Backdate or reorder decisions | PARTIAL (block timestamp) | NOT DETECTED | Enforces monotonic slots | **BOUNDED ([openedAt, sealDeadline])** | Enforced |
| **A5** | Withhold window (never seal) | N/A | NOT DETECTED (silent) | Fails closed after $W$ | **DETECTED & SLASHED (slashUnsealed)** | $W$ blocks |
| **A6** | Falsify policy fields (rule 999 fraud)| NOT DETECTED | NOT DETECTED | Checks outcome == 1 | **SLASHED ON-CHAIN (provePolicyFraud)** | 4.1s |

### Measured Live Slashing Transactions on MST Testnet:
- **Equivocation Slash (S5)**: [`0x0278691ff5d0fa3c139cba38ed5757a2ea38f8deaba9653938f4976d1a72d0e2`](https://mstscan.com/tx/0x0278691ff5d0fa3c139cba38ed5757a2ea38f8deaba9653938f4976d1a72d0e2) (Operator slashed 50% on-chain)
- **Policy Fraud Slash (S11)**: [`0x6068f4c661d9170c8fcf38b789922f37412bacc9bd1d5e8fc983edf224fb0acf`](https://mstscan.com/tx/0x6068f4c661d9170c8fcf38b789922f37412bacc9bd1d5e8fc983edf224fb0acf) (Rule 999 violation proven on-chain, 60% paid to victim)

---

## 5. S10 Vigilance Planner & Detection Probability

Monte Carlo population simulation ($M=500$ subjects, $1,500$ trials per cell) on $P(\text{detect}) = 1 - (1 - q)^m$:

| Vigilance ($q$) | Omissions ($m$) | Theoretical $P(\text{detect})$ | Empirical $P(\text{detect})$ | Delta | Status |
|-----------------|-----------------|-------------------------------|-----------------------------|-------|--------|
| **1.0%** | 10 | 9.56% | 8.93% | 0.63% | **PASS** |
| **1.0%** | 50 | 39.50% | 39.13% | 0.37% | **PASS** |
| **1.0%** | 100 | 63.40% | 62.27% | 1.13% | **PASS** |
| **1.0%** | 200 | 86.60% | 87.73% | 1.13% | **PASS** |
| **2.0%** | 50 | 63.58% | 64.13% | 0.55% | **PASS** |
| **2.0%** | 100 | 86.74% | 86.40% | 0.34% | **PASS** |
| **2.0%** | 200 | 98.24% | 97.20% | 1.04% | **PASS** |
| **5.0%** | 50 | 92.31% | 91.60% | 0.71% | **PASS** |
| **5.0%** | 100 | 99.41% | 99.67% | 0.26% | **PASS** |
| **5.0%** | 200 | 100.00% | 100.00% | 0.00% | **PASS** |

**Conclusion**: At just $q = 2\%$ vigilance, omitting 150 decisions is caught with $95.3\%$ certainty. At $q = 5\%$, omitting just 60 decisions is caught with $95.4\%$ certainty.

---

## 6. Live Interactive Demos

- **Public Slash Theater URL**: [ghostless.hirthikbalaji.dpdns.org](https://ghostless.hirthikbalaji.dpdns.org)
- **Local Dashboard**: [http://localhost:8000](http://localhost:8000)
- **Autonomous AI Procurement Agent Run**:
  - Deposit Tx: [`0x305d62145ac8a1fc23fd49b8e4d731ced7d4ec449243b62ec7a544f15976c6cb`](https://mstscan.com/tx/0x305d62145ac8a1fc23fd49b8e4d731ced7d4ec449243b62ec7a544f15976c6cb)
  - Release Tx: [`0xc6a46486bb609f8a3a55f8db3f83987a1d8ef2692de16057b0c5a0d9c5ffb241`](https://mstscan.com/tx/0xc6a46486bb609f8a3a55f8db3f83987a1d8ef2692de16057b0c5a0d9c5ffb241)
