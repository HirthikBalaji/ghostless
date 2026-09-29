# Ghostless Protocol Architecture

Ghostless solves the fundamental completeness problem for decision audit trails on **MST Blockchain**: proving that an operator did not omit, void, equivocate, backdate, or withhold decisions.

---

## 1. System Components

```
                   +----------------------------------+
                   |           SUBJECT                |
                   | (Holds EIP-712 Receipt & Vault)  |
                   +----------------+-----------------+
                                    |
     1. Decide Request              | 3. Demand Proof
                                    v
+------------------+       +------------------+       +------------------+
|  DECISION ENGINE | ----> |   OPERATOR DB    | ----> | GHOSTLESS LEDGER |
|  & ROUTER        | <---- | (Atomic Slots)   |       | (MST Testnet)    |
+------------------+       +------------------+       +------------------+
         |                                                      ^
         | 2. Receipted Execution                               | 4. Invariant
         v                                                      |    Audit & Slash
+------------------+                                            |
|  ACTUATOR GATE   | -------------------------------------------+
| (No Receipt ->   |       Checks acceptable(win, seq) / frozen
|   No Effect)     |
+------------------+
```

### 1.1 GhostlessLedger.sol
The core contract deployed on **MST Testnet** at `0x7B0b975D1C044225be49f178F34332029b28620c`.
- **Pre-reservation**: `openWindow(size)` commits sequence number range `[startSeq, startSeq + size)` on-chain *before* any decision exists. Contiguous by construction ($I_1$).
- **Positional Tree Anchoring**: `sealWindow(id, root)` folds the positional root into `headCheckpoint`.
- **Bonded Challenge-Response**: `demandInclusion(receipt, sig)` obliges the operator to supply the Merkle proof within $R$ blocks or suffer automatic bond slashing (`slashNoResponse`).
- **Equivocation Slashing**: `proveEquivocation(rA, sigA, rB, sigB)` slashes an operator who signs two different leaves for the same slot.
- **Policy Fraud Proof**: `provePolicyFraud(...)` verifies leaf inclusion and evaluates semantic policy correctness on-chain.

### 1.2 Cryptographic Primitives & Data Structures
- **Leaf Hash**:
  $$\text{leaf} = \text{keccak256}(0x00 \parallel \text{abi.encode}(\text{windowId}, \text{seq}, \text{keccak256}(\text{recordP}), \text{privCommit}))$$
- **Node Hash**:
  $$\text{node} = \text{keccak256}(0x01 \parallel \text{left} \parallel \text{right})$$
- **Positional Orientation**: Non-commutative. Left/right placement is strictly dictated by `(index >> layer) & 1`.
- **EIP-712 Receipt**:
  $$\text{Receipt} = \{\text{uint256 windowId}, \text{uint64 seq}, \text{bytes32 leaf}\}$$
- **Effect Binding**: `recordP` binds `subject`, `actuatorId`, `actionHash`, and `nonce`.

---

## 2. Protocol Invariants

- **$I_1$ (Contiguity)**: $\text{nextSeq} = \sum \text{windows}[i].\text{size}$. Sequence numbers have zero gaps and zero overlaps.
- **$I_2$ (Single Seal)**: A window is sealed at most once, strictly in order; `root` never changes after sealing.
- **$I_3$ (Checkpoint Fold)**: `headCheckpoint` folds all sealed windows in order:
  $$\text{headCheckpoint} = \text{keccak256}(\text{headCheckpoint}, \text{id}, \text{startSeq}, \text{size}, \text{root})$$
- **$I_4$ (Monotonic Freeze)**: Once an operator is slashed, `frozen = true` permanently.
- **$I_5$ (Proof Soundness)**: Proof verification succeeds if and only if depth equals $\log_2(\text{size})$ and positional sibling matches root.
- **$I_6$ (Checks-Effects-Interactions)**: Reentrancy-safe, state updated prior to ETH transfers.
