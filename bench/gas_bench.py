"""
bench/gas_bench.py
Gas benchmark script measuring on-chain execution costs for Ghostless vs Baselines B0 & B1.
Measures:
- openWindow gas
- sealWindow gas (for size in {64, 128, 256})
- demandInclusion gas
- respondInclusion gas
- PerTxAnchor (B0) gas per decision
- BatchRootAnchor (B1) gas per batch
- Computes amortized gas per decision and efficiency multiplier
"""

import os
import json
import secrets
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware
from dotenv import load_dotenv

from operator.merkle import build_tree, get_root, get_proof
from operator.receipts import sign_receipt

load_dotenv()

RPC_URL = os.getenv("RPC_URL", "https://testnetrpc.mstblockchain.com")
CHAIN_ID = int(os.getenv("CHAIN_ID", "91562037"))
OPERATOR_KEY = os.getenv("OPERATOR_KEY")
SUBJECT_KEY = os.getenv("SUBJECT_KEY")

w3 = Web3(Web3.HTTPProvider(RPC_URL))
w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

operator_acct = w3.eth.account.from_key(OPERATOR_KEY)
subject_acct = w3.eth.account.from_key(SUBJECT_KEY)

def load_contract(artifact_rel_path, address):
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    full_path = os.path.join(root_dir, artifact_rel_path)
    with open(full_path) as f:
        art = json.load(f)
    return w3.eth.contract(address=Web3.to_checksum_address(address), abi=art["abi"])

def send_signed_tx(acct, build_fn, value=0):
    nonce = w3.eth.get_transaction_count(acct.address)
    tx = build_fn().build_transaction({
        "from": acct.address,
        "nonce": nonce,
        "gasPrice": int(w3.eth.gas_price * 1.15),
        "chainId": CHAIN_ID,
        "value": value
    })
    gas_est = w3.eth.estimate_gas(tx)
    tx["gas"] = int(gas_est * 1.3)
    signed = acct.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    rc = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
    return rc.gasUsed, tx_hash.hex()

def run_benchmarks():
    print("=" * 60)
    print("GHOSTLESS GAS & AMORTIZATION BENCHMARK (MST TESTNET)")
    print("=" * 60)

    ghostless_addr = os.getenv("GHOSTLESS_CONTRACT_ADDRESS")
    b0_addr = os.getenv("PER_TX_CONTRACT_ADDRESS")
    b1_addr = os.getenv("BATCH_ROOT_CONTRACT_ADDRESS")

    ghostless = load_contract("artifacts/contracts/GhostlessLedger.sol/GhostlessLedger.json", ghostless_addr)
    b0 = load_contract("artifacts/contracts/baselines/PerTxAnchor.sol/PerTxAnchor.json", b0_addr)
    b1 = load_contract("artifacts/contracts/baselines/BatchRootAnchor.sol/BatchRootAnchor.json", b1_addr)

    results = {"ghostless": {}, "b0_per_tx": {}, "b1_batch_root": {}, "comparison": {}}

    # 1. Baseline B0: PerTxAnchor
    dummy_leaf = Web3.keccak(b"decision-sample-payload")
    gas_b0, tx_b0 = send_signed_tx(operator_acct, lambda: b0.functions.anchorDecision(dummy_leaf))
    print(f"[B0 PerTxAnchor] Anchor 1 decision: {gas_b0} gas (tx: {tx_b0[:18]}...)")
    results["b0_per_tx"]["gas_per_decision"] = gas_b0

    # 2. Baseline B1: BatchRootAnchor
    dummy_root = Web3.keccak(b"batch-root-sample")
    gas_b1, tx_b1 = send_signed_tx(operator_acct, lambda: b1.functions.anchorBatch(dummy_root, 128))
    print(f"[B1 BatchRootAnchor] Anchor batch root (128 items): {gas_b1} gas (tx: {tx_b1[:18]}...)")
    results["b1_batch_root"]["gas_per_batch"] = gas_b1
    results["b1_batch_root"]["amortized_gas_at_128"] = round(gas_b1 / 128, 2)

    # 3. Ghostless Benchmark for window sizes 64, 128, 256
    sizes = [64, 128, 256]
    for sz in sizes:
        print(f"\nBenchmarking Ghostless with window size = {sz}...")
        gas_open, tx_open = send_signed_tx(operator_acct, lambda: ghostless.functions.openWindow(sz))
        window_id = ghostless.functions.windowCount().call() - 1
        print(f"  openWindow({sz}): {gas_open} gas (windowId: {window_id})")

        # Create dummy leaves and root
        leaves = [Web3.keccak(f"leaf-{window_id}-{i}".encode()) for i in range(sz)]
        tree = build_tree(leaves)
        root = get_root(tree)

        gas_seal, tx_seal = send_signed_tx(operator_acct, lambda: ghostless.functions.sealWindow(window_id, root))
        print(f"  sealWindow({sz}): {gas_seal} gas")

        total_window_gas = gas_open + gas_seal
        amortized_per_decision = total_window_gas / sz
        ratio_vs_b0 = gas_b0 / amortized_per_decision

        print(f"  Total window write pair gas: {total_window_gas}")
        print(f"  --> Amortized gas per decision: {amortized_per_decision:.2f} gas")
        print(f"  --> Efficiency vs B0: {ratio_vs_b0:.1f}x cheaper!")

        results["ghostless"][f"size_{sz}"] = {
            "window_size": sz,
            "open_window_gas": gas_open,
            "seal_window_gas": gas_seal,
            "total_pair_gas": total_window_gas,
            "amortized_gas_per_decision": round(amortized_per_decision, 2),
            "savings_vs_b0_factor": round(ratio_vs_b0, 2)
        }

    # 4. Measure demandInclusion and respondInclusion gas
    sample_window_id = ghostless.functions.windowCount().call() - 1
    sample_seq = ghostless.functions.getWindow(sample_window_id).call()[0] + 3 # slot index 3
    sample_leaf = leaves[3]

    sig = sign_receipt(OPERATOR_KEY, CHAIN_ID, ghostless_addr, sample_window_id, sample_seq, sample_leaf)
    demand_fee = ghostless.functions.demandFee().call()
    r = (sample_window_id, sample_seq, sample_leaf)
    sig_bytes = bytes.fromhex(sig.replace("0x", ""))

    print("\nMeasuring Demand & Response gas costs...")
    gas_demand, tx_dem = send_signed_tx(subject_acct, lambda: ghostless.functions.demandInclusion(r, sig_bytes), value=demand_fee)
    demand_id = ghostless.functions.demandCount().call() - 1
    print(f"  demandInclusion: {gas_demand} gas (demandId: {demand_id})")

    proof_bytes = get_proof(tree, 3)
    gas_respond, tx_resp = send_signed_tx(operator_acct, lambda: ghostless.functions.respondInclusion(demand_id, proof_bytes))
    print(f"  respondInclusion: {gas_respond} gas")

    results["ghostless"]["demand_inclusion_gas"] = gas_demand
    results["ghostless"]["respond_inclusion_gas"] = gas_respond

    out_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "gas_report.json")
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[✓] Gas benchmark complete! Saved to {out_file}")
    print("=" * 60)

if __name__ == "__main__":
    run_benchmarks()
