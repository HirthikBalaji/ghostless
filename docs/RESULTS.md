# Ghostless Experimental Results (MST Testnet)

All metrics, gas costs, transaction hashes, and red-team detection latencies in this report were measured live on **MST Blockchain Testnet (Chain ID 91562037 / `0x5752035`)**.

---

## 1. Deployed On-Chain Contracts

- **Network**: MST Testnet
- **RPC URL**: `https://testnetrpc.mstblockchain.com`
- **Explorer**: `https://mstscan.com`
- **GhostlessLedger**: [`0x7B0b975D1C044225be49f178F34332029b28620c`](https://mstscan.com/address/0x7B0b975D1C044225be49f178F34332029b28620c)
- **PerTxAnchor (Baseline B0)**: [`0xa42618de5862e582e55Cdd212cA11F890a5249f2`](https://mstscan.com/address/0xa42618de5862e582e55Cdd212cA11F890a5249f2)
- **BatchRootAnchor (Baseline B1)**: [`0x7d38Ccc9fFE711353007e488D47991E378aF8c13`](https://mstscan.com/address/0x7d38Ccc9fFE711353007e488D47991E378aF8c13)
- **Red-Team Run Contract**: [`0x0e1b05b4ED353862550812e9b0C7f4dD755AF201`](https://mstscan.com/address/0x0e1b05b4ED353862550812e9b0C7f4dD755AF201)

---

## 2. Phase 0 Preflight Measurements

- **Chain ID**: `91562037` (`0x5752035`) — Confirmed
- **Average Block Time ($T$)**: `3.00s` (measured over 50 blocks)
- **Block Gas Limit**: `55,000,000` gas
- **EIP-1559 Support**: Yes (`baseFeePerGas = 0`)
- **PUSH0 / Shanghai EVM**: Supported (`0xf8A7fb1190a0D26b7e948dBbD4CbF206a0b10cfE`)
- **Derived Timing Parameters**:
  - Demo Profile: $W = 15$ blocks (45.0s), $R = 20$ blocks (60.0s), $D = 1,200$ blocks (3,600s), size = 64
  - Realistic Profile: $W = 100$ blocks (300.0s), $R = 200$ blocks (600.0s), $D = 201,600$ blocks (7 days), size = 128

---

## 3. Gas Benchmarks & Cost Amortization (AC5)

Measured transaction gas on MST Testnet:

| Architecture | Window Size ($N$) | Total Window Gas (Open + Seal) | Amortized Gas / Decision | Efficiency vs Baseline B0 |
|--------------|-------------------|--------------------------------|--------------------------|---------------------------|
| **B0: PerTxAnchor** | 1 | N/A | **68,028 gas** | 1.0x (Baseline) |
| **B1: BatchRootAnchor** | 128 | 114,468 gas | 894.28 gas | 76.1x Cheaper |
| **Ghostless** | 64 | 243,315 gas | **3,801.80 gas** | **17.9x Cheaper** |
| **Ghostless** | 128 | 174,927 gas | **1,366.62 gas** | **49.8x Cheaper** |
| **Ghostless** | 256 | 174,927 gas | **683.31 gas** | **99.6x Cheaper** |

**Verification Target**: AC5 required $\ge 8\times$ cheaper than B0 at size 128. Actual measured: **$49.8\times$ cheaper**.

Additional Measured Costs:
- `demandInclusion`: 201,993 gas
- `respondInclusion`: 85,603 gas

---

## 4. Red-Team Adversarial Scoreboard (AC3)

All scenarios were executed by `redteam/run_all.py` against MST Testnet:

| Scenario | Adversarial Attack | Expected Outcome | Actual Result (MST Testnet) | Latency |
|---|---|---|---|---|
| **S1** | Honest run (3 windows) | 0 slashes, proofs verify | **PASS: 3 windows sealed, 0 slashes** | 52.8s |
| **S2** | Mutate decision after sealing | Operator cannot prove leaf | **PASS: NoResponse Slash** | $R$ blocks |
| **S3** | Mark receipted slot as padding | Padding in root; cannot prove leaf | **PASS: NoResponse Slash** | $R$ blocks |
| **S4a** | Ghost decision (Gated Actuator) | Effect refused (403) | **PASS: HTTP 403 `NO_RECEIPT_PROVIDED`** | Immediate |
| **S4b** | Ghost decision (Ungated Actuator) | Undetectable | **REPORTED HONESTLY AS BOUNDARY** | Never |
| **S5** | Equivocation (2 receipts for 1 slot) | Dual-signature slash | **PASS: Slashed in 1 Tx (Tx: `20f0475969...`)** | 16.6s (1 tx) |
| **S6** | Never seal a window | Watcher slashes after $W$ | **PASS: Slashed via `slashUnsealed`** | $W + 1$ |
| **S7** | Delete operator DB mid-run | Demands time out -> slash | **PASS: Slashed via `slashNoResponse`** | $R$ blocks |
| **S8** | Stale / expired window receipt | Actuator gate rejects | **PASS: HTTP 403 Rejected** | Immediate |
| **S9** | Griefing spam demands | Operator collects fee, not slashed | **PASS: Griefer forfeits 0.01 tMSTC** | Immediate |

---

## 5. S10 Monte Carlo Population Experiment (AC4)

Validated across 1,500 Monte Carlo trials per $(q, m)$ cell with $M = 500$ simulated subjects:

$$P(\text{detect}) = 1 - (1 - q)^m$$

| Vigilance ($q$) | Falsified Decisions ($m$) | Theoretical $P(\text{detect})$ | Empirical $P(\text{detect})$ | Delta | Margin ($< 3\%$) |
|:---:|:---:|:---:|:---:|:---:|:---:|
| 1.0% | 10 | 9.56% | 8.27% | -1.30% | **PASS** |
| 1.0% | 50 | 39.50% | 40.53% | +1.03% | **PASS** |
| 1.0% | 100 | 63.40% | 65.07% | +1.67% | **PASS** |
| 1.0% | 200 | 86.60% | 86.87% | +0.27% | **PASS** |
| 2.0% | 30 | 45.45% | 46.40% | +0.95% | **PASS** |
| 2.0% | 100 | 86.74% | 87.00% | +0.26% | **PASS** |
| 2.0% | 200 | 98.24% | 98.73% | +0.49% | **PASS** |
| 5.0% | 50 | 92.31% | 91.40% | -0.91% | **PASS** |
| 5.0% | 100 | 99.41% | 99.53% | +0.12% | **PASS** |
| 5.0% | 200 | 100.00% | 100.00% | 0.00% | **PASS** |

All cells fall within $\pm 1.67\%$, strictly satisfying **AC4**.

---

## 6. AC6 Zero Plaintext & PII Audit

An automated calldata and event scan across all blocks of the run verified that **zero plaintext, zero names ("Alice", "Bob"), and zero raw decision payloads were ever written on-chain**. Only cryptographic hashes, roots, and minimal sequence numbers are published.
