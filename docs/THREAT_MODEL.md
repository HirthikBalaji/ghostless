# Ghostless Threat Model & Security Analysis

## 1. Adversary Definition

The adversary in the Ghostless protocol is a **fully malicious operator**. The operator controls:
- The decision engine & routing heuristics
- The off-chain SQLite / persistent databases
- The operator ECDSA signing keys
- The network path and RPC client
- The off-chain API responses and inclusion proof distribution

The operator can delete, corrupt, or modify any off-chain database at any time.

---

## 2. Assumptions

- **$H_1$ (Chain Liveness)**: MST Blockchain is live and processes non-censored verifier transactions within response window $R$.
- **$H_2$ (1-of-N Honesty)**: At least one honest watcher exists and audits chain invariants at least once per demand horizon $D$.
- **$H_3$ (Vigilance $q > 0$)**: A non-zero fraction $q$ of affected subjects verify their receipts.
- **$H_4$ (Gated Effect Boundary)**: Real-world actuators enforce the Actuator Gate (`No Receipt -> No Effect`).
- **$H_5$ (Cryptographic Hardness)**: ECDSA (secp256k1) and keccak256 are collision and preimage resistant.

---

## 3. Threat Matrix & Defense Mechanisms

| Attack ID | Adversary Action | Ghostless Defense | Contract Enforcement |
|-----------|------------------|-------------------|----------------------|
| **A1** | Mutate decision after sealing | Leaf bound to positional root | `NoResponse` slash |
| **A2** | Omit decision for which receipt was issued | Pull-based `demandInclusion` with bonded deadline $R$ | `NoResponse` slash |
| **A2'** | Ghost decision (no log entry at all) | Actuator Gate (`No Receipt -> No Effect`) | Actuator 403 Rejection |
| **A3** | Equivocation (conflicting receipts for 1 slot) | Dual-signature receipt presentation | `proveEquivocation` slash |
| **A4** | Backdate or reorder decisions | Pre-reserved slots $[openedAt, sealDeadline]$ | Monotonic sequence $I_1$ |
| **A5** | Withhold window (never seal) | Bounded seal deadline $W$ | `slashUnsealed` slash |
| **A6** | Falsify policy fields | On-chain invariant verification | `provePolicyFraud` slash |

---

## 4. The Impossibility Boundary (Honest Evaluation)

**S4b Boundary Condition**: If a decision leaves no observable trace to any party demanding a receipt, and operates through an ungated or bypass channel, no cryptographic protocol can prove it occurred. 

Ghostless does not claim to solve ungated omissions. Rather, its architectural contribution is to make a slashable receipt a **mandatory precondition of effect**, shrinking the space of undetectable omissions strictly to systems that lack enforcement boundaries.
