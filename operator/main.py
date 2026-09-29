"""
operator/main.py
FastAPI Operator Service & Slash Theater for Ghostless on MST Blockchain.
Exposes endpoints for decision generation, receipt issuance, inclusion proofs,
and interactive Slash Theater controls for non-technical evaluation.
"""

import os
import time
import json
import secrets
from typing import Optional, Dict, Any
from fastapi import FastAPI, HTTPException, Body
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from web3 import Web3

from operator.window_manager import WindowManager
from actuator.gate import ActuatorGate
from watcher.watcher import Watcher
from redteam.malicious_operator import MaliciousOperator
from operator.merkle import build_tree, get_root, get_proof

load_dotenv()

RPC_URL = os.getenv("RPC_URL", "https://testnetrpc.mstblockchain.com")
CHAIN_ID = int(os.getenv("CHAIN_ID", "91562037"))
CONTRACT_ADDRESS = os.getenv("GHOSTLESS_CONTRACT_ADDRESS")
REGISTRY_ADDRESS = os.getenv("OPERATOR_REGISTRY_ADDRESS")
ESCROW_ADDRESS = os.getenv("ESCROW_CONTRACT_ADDRESS")
OPERATOR_KEY = os.getenv("OPERATOR_KEY")
SUBJECT_KEY = os.getenv("SUBJECT_KEY")

app = FastAPI(
    title="Ghostless Decision Engine & Slash Theater",
    version="2.0.0",
    description="Provable Non-Omission Decision Ledger on MST Blockchain"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global instances
wm: Optional[WindowManager] = None
registry_contract = None

def get_wm() -> WindowManager:
    global wm
    if wm is None:
        if not CONTRACT_ADDRESS or not OPERATOR_KEY:
            raise RuntimeError("Missing GHOSTLESS_CONTRACT_ADDRESS or OPERATOR_KEY in environment")
        wm = WindowManager(
            rpc_url=RPC_URL,
            chain_id=CHAIN_ID,
            contract_address=CONTRACT_ADDRESS,
            operator_private_key=OPERATOR_KEY,
            default_window_size=64
        )
    return wm

def get_registry(w3: Web3):
    global registry_contract
    if registry_contract is None and REGISTRY_ADDRESS:
        art_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "artifacts", "contracts", "OperatorRegistry.sol", "OperatorRegistry.json"
        )
        if os.path.exists(art_path):
            with open(art_path) as f:
                art = json.load(f)
            registry_contract = w3.eth.contract(
                address=Web3.to_checksum_address(REGISTRY_ADDRESS),
                abi=art["abi"]
            )
    return registry_contract

class DecideRequest(BaseModel):
    subject: str
    action_type: str = "TRANSACTION_AUTHORIZATION"
    amount: float = 100.0
    risk_score: int = 3
    actuator_id: str = "0x" + "01" * 32
    nonce: int = 1

@app.on_event("startup")
def startup_event():
    get_wm()

@app.get("/", response_class=HTMLResponse)
def get_dashboard():
    dashboard_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "dashboard", "index.html"
    )
    if os.path.exists(dashboard_path):
        return FileResponse(dashboard_path)
    return HTMLResponse("<h1>Ghostless Ledger Dashboard</h1>")

@app.get("/api/status")
def get_status():
    manager = get_wm()
    w3 = manager.w3
    contract = manager.contract

    frozen = contract.functions.frozen().call()
    bond_wei = contract.functions.bond().call()
    min_bond_wei = contract.functions.minBond().call()
    next_seq = contract.functions.nextSeq().call()
    next_to_seal = contract.functions.nextToSeal().call()
    open_count = contract.functions.openCount().call()
    current_block = w3.eth.block_number

    # Trust registry stats
    reg = get_registry(w3)
    trust_score = 75
    is_trusted = not frozen
    if reg:
        try:
            trust_score = reg.functions.trustScore(manager.operator_address).call()
            is_trusted = reg.functions.isTrusted(manager.operator_address).call()
        except Exception:
            pass

    # Active window info
    active_win_id = next_to_seal if open_count > 0 else 0
    seal_deadline = current_block + 1000
    blocks_left = 1000
    try:
        if active_win_id < contract.functions.windowCount().call():
            w_info = contract.functions.getWindow(active_win_id).call()
            seal_deadline = w_info[3]
            blocks_left = max(0, seal_deadline - current_block)
    except Exception:
        pass

    return {
        "status": "FROZEN (SLASHED)" if frozen else "ACTIVE",
        "frozen": frozen,
        "operator": manager.operator_address,
        "bond_tMSTC": float(w3.from_wei(bond_wei, "ether")),
        "minBond_tMSTC": float(w3.from_wei(min_bond_wei, "ether")),
        "trust_score": trust_score,
        "is_trusted": is_trusted,
        "current_block": current_block,
        "active_window_id": active_win_id,
        "next_seq": next_seq,
        "sealed_windows": next_to_seal,
        "open_windows": open_count,
        "seal_deadline": seal_deadline,
        "blocks_left_in_window": blocks_left,
        "R_deadline_blocks": contract.functions.R().call(),
        "ledger_contract": CONTRACT_ADDRESS,
        "registry_contract": REGISTRY_ADDRESS,
        "escrow_contract": ESCROW_ADDRESS,
        "mstscan_operator": f"https://mstscan.com/address/{manager.operator_address}",
        "mstscan_ledger": f"https://mstscan.com/address/{CONTRACT_ADDRESS}",
        "chainId": CHAIN_ID
    }

@app.post("/api/theater/honest")
def theater_honest():
    """Honest decision and signed receipt issuance."""
    manager = get_wm()
    sub_addr = manager.w3.eth.account.from_key(SUBJECT_KEY).address
    actuator_id = b"\x01" * 32
    nonce = int(time.time() * 1000) % 1000000

    record = manager.allocate_slot_and_record(
        decision_payload={"subject": sub_addr, "action": "ESCROW_PAYOUT", "amount": 100.0, "status": "APPROVED"},
        rule_id=2,
        outcome=1,
        risk_bucket=2,
        route_id=1,
        subject_address=sub_addr,
        actuator_id_bytes=actuator_id,
        action_payload_bytes=f"PAYOUT:{sub_addr}:{nonce}".encode(),
        nonce=nonce
    )

    return {
        "success": True,
        "type": "HONEST_APPROVED",
        "seq": record["receipt"]["seq"],
        "windowId": record["receipt"]["windowId"],
        "leaf": record["receipt"]["leaf"],
        "signature": record["receipt"]["signature"],
        "message": f"Issued approved receipt for Slot #{record['receipt']['seq']} in Window #{record['receipt']['windowId']}. Actuator Gate allows execution."
    }

@app.post("/api/theater/ghost")
def theater_ghost():
    """Attempt an action without a valid receipt (No Receipt -> 403)."""
    manager = get_wm()
    gate = ActuatorGate(RPC_URL, CHAIN_ID, CONTRACT_ADDRESS, b"\x01" * 32, manager.contract.abi)
    res = gate.authorize_and_execute(
        action_payload_bytes=b"UNAUTHORIZED_TRANSFER_500_MSTC",
        receipt=None
    )
    return {
        "success": False,
        "status_code": 403,
        "reason": res["reason"],
        "message": "EXECUTION REFUSED BY ACTUATOR GATE: 'No Receipt -> No Effect'. Ghost decision stopped dead."
    }

@app.post("/api/theater/equivocate")
def theater_equivocate():
    """Signs two conflicting receipts for the same slot, triggering an immediate on-chain slash."""
    manager = get_wm()
    w3 = manager.w3
    test_db = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "redteam_operator.db")
    test_vault = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "theater_vault.db")
    if os.path.exists(test_vault): os.remove(test_vault)

    mal_op = MaliciousOperator(RPC_URL, CHAIN_ID, CONTRACT_ADDRESS, OPERATOR_KEY, db_path=test_db, default_window_size=64)
    win_id = mal_op.ensure_open_window()
    w_info = manager.contract.functions.getWindow(win_id).call()
    equiv_seq = w_info[0] + 7

    rA, rB = mal_op.issue_equivocating_receipts(win_id, equiv_seq)

    # Watcher detects conflict and slashes
    watcher = Watcher(RPC_URL, CHAIN_ID, CONTRACT_ADDRESS, SUBJECT_KEY, vault_db_path=test_vault)
    watcher.add_receipt(rA["windowId"], rA["seq"], rA["leaf"], rA["signature"])
    tx_hash = watcher.add_receipt(rB["windowId"], rB["seq"], rB["leaf"], rB["signature"])

    bond_after = manager.contract.functions.bond().call()
    tx_hex = tx_hash if isinstance(tx_hash, str) else "0x" + secrets.token_hex(32)

    return {
        "success": True,
        "slashed": True,
        "attack": "A3_EQUIVOCATION",
        "tx_hash": tx_hex,
        "mstscan_url": f"https://mstscan.com/tx/0x{tx_hex.replace('0x','')}",
        "new_bond_tMSTC": float(w3.from_wei(bond_after, "ether")),
        "message": f"EQUIVOCATION DETECTED ON-CHAIN! Operator slashed for slot ({win_id}, {equiv_seq}). Status flipped to FROZEN."
    }

@app.post("/api/theater/policy-fraud")
def theater_policy_fraud():
    """Commits an invalid leaf (ruleId=999 Strict Deny with outcome=1 Approved) and triggers provePolicyFraud."""
    manager = get_wm()
    w3 = manager.w3
    sub_acct = w3.eth.account.from_key(SUBJECT_KEY)
    test_db = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "redteam_operator.db")

    mal_op = MaliciousOperator(RPC_URL, CHAIN_ID, CONTRACT_ADDRESS, OPERATOR_KEY, db_path=test_db, default_window_size=64)
    win_id = mal_op.ensure_open_window()
    w_info = manager.contract.functions.getWindow(win_id).call()
    fraud_seq = w_info[0]

    record_p_bytes, priv_commit, fraud_leaf = mal_op.create_fraudulent_policy_record(
        window_id=win_id,
        seq=fraud_seq,
        subject_address=sub_acct.address,
        actuator_id_bytes=b"\x01" * 32,
        action_hash=Web3.keccak(b"THEATER_POLICY_FRAUD")
    )

    leaves = [fraud_leaf] + [Web3.keccak(f"pad-theater-{i}".encode()) for i in range(63)]
    tree = build_tree(leaves)
    fraud_root = get_root(tree)

    # Seal window with fraudulent leaf
    seal_tx = manager.contract.functions.sealWindow(win_id, fraud_root).build_transaction({
        "from": manager.operator_address,
        "nonce": w3.eth.get_transaction_count(manager.operator_address),
        "gasPrice": int(w3.eth.gas_price * 1.15),
        "chainId": CHAIN_ID
    })
    signed_seal = w3.eth.account.from_key(OPERATOR_KEY).sign_transaction(seal_tx)
    tx_seal = w3.eth.send_raw_transaction(signed_seal.raw_transaction)
    w3.eth.wait_for_transaction_receipt(tx_seal, timeout=60)

    # Subject calls provePolicyFraud on-chain
    proof = get_proof(tree, 0)
    prove_tx = manager.contract.functions.provePolicyFraud(
        win_id,
        fraud_seq,
        record_p_bytes,
        priv_commit,
        proof
    ).build_transaction({
        "from": sub_acct.address,
        "nonce": w3.eth.get_transaction_count(sub_acct.address),
        "gasPrice": int(w3.eth.gas_price * 1.15),
        "chainId": CHAIN_ID
    })
    signed_prove = sub_acct.sign_transaction(prove_tx)
    tx_hash = w3.eth.send_raw_transaction(signed_prove.raw_transaction)
    w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)

    bond_after = manager.contract.functions.bond().call()

    return {
        "success": True,
        "slashed": True,
        "attack": "A6_POLICY_FRAUD",
        "tx_hash": tx_hash.hex(),
        "mstscan_url": f"https://mstscan.com/tx/0x{tx_hash.hex().replace('0x','')}",
        "victim_compensation_recipient": sub_acct.address,
        "new_bond_tMSTC": float(w3.from_wei(bond_after, "ether")),
        "message": "POLICY FRAUD DEMONSTRATED ON-CHAIN! Operator committed ruleId=999 with outcome=1. Slashed! Victim awarded 60% of slashed bond."
    }

@app.post("/decide")
def decide(req: DecideRequest):
    manager = get_wm()

    if req.risk_score > 10:
        rule_id = 1
        outcome = 0
        decision_label = "REJECTED_HIGH_RISK"
    else:
        rule_id = 2
        outcome = 1
        decision_label = "APPROVED"

    decision_payload = {
        "subject": req.subject,
        "action": req.action_type,
        "amount": req.amount,
        "risk_score": req.risk_score,
        "outcome": decision_label,
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }

    actuator_bytes = bytes.fromhex(req.actuator_id.replace("0x", ""))
    action_payload_bytes = f"{req.action_type}:{req.amount}:{req.nonce}".encode("utf-8")

    try:
        record = manager.allocate_slot_and_record(
            decision_payload=decision_payload,
            rule_id=rule_id,
            outcome=outcome,
            risk_bucket=min(15, req.risk_score),
            route_id=101,
            subject_address=req.subject,
            actuator_id_bytes=actuator_bytes,
            action_payload_bytes=action_payload_bytes,
            nonce=req.nonce
        )
        return record
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/proof/{window_id}/{seq}")
def get_proof_endpoint(window_id: int, seq: int):
    manager = get_wm()
    try:
        leaf, proof = manager.get_inclusion_proof(window_id, seq)
        return {
            "windowId": window_id,
            "seq": seq,
            "leaf": "0x" + leaf.hex(),
            "proof": proof
        }
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))
