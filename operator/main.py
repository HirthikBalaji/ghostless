"""
operator/main.py
FastAPI Operator Service for Ghostless on MST Blockchain.
Exposes endpoints for decision generation, receipt issuance, and inclusion proofs.
"""

import os
from typing import Optional, Dict, Any
from fastapi import FastAPI, HTTPException, Body
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel
from dotenv import load_dotenv

from operator.window_manager import WindowManager

load_dotenv()

RPC_URL = os.getenv("RPC_URL", "https://testnetrpc.mstblockchain.com")
CHAIN_ID = int(os.getenv("CHAIN_ID", "91562037"))
CONTRACT_ADDRESS = os.getenv("GHOSTLESS_CONTRACT_ADDRESS")
OPERATOR_KEY = os.getenv("OPERATOR_KEY")

app = FastAPI(
    title="Ghostless Decision Engine & Operator",
    version="1.0.0",
    description="Provable Non-Omission Decision Ledger on MST Blockchain"
)

# Global window manager instance
wm: Optional[WindowManager] = None

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

@app.get("/health")
def health():
    manager = get_wm()
    frozen = manager.contract.functions.frozen().call()
    bond = manager.contract.functions.bond().call()
    next_seq = manager.contract.functions.nextSeq().call()
    return {
        "status": "HEALTHY" if not frozen else "FROZEN",
        "frozen": frozen,
        "operator": manager.operator_address,
        "bond_tMSTC": float(manager.w3.from_wei(bond, "ether")),
        "nextSeq": next_seq,
        "contract": manager.contract_address,
        "chainId": CHAIN_ID
    }

@app.post("/decide")
def decide(req: DecideRequest):
    manager = get_wm()

    # Deterministic rule engine evaluation
    # Rule 1: High risk (> 10) -> Deny (0)
    # Rule 2: Low/Med risk (<= 10) -> Approve (1)
    # Rule 999: Strict deny
    if req.risk_score > 10:
        rule_id = 1
        outcome = 0 # Denied
        decision_label = "REJECTED_HIGH_RISK"
    else:
        rule_id = 2
        outcome = 1 # Approved
        decision_label = "APPROVED"

    decision_payload = {
        "subject": req.subject,
        "action": req.action_type,
        "amount": req.amount,
        "risk_score": req.risk_score,
        "outcome": decision_label,
        "timestamp_utc": "2026-09-29T14:00:00Z"
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
def get_proof(window_id: int, seq: int):
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

@app.get("/window/{window_id}")
def get_window(window_id: int):
    manager = get_wm()
    try:
        w_data = manager.contract.functions.getWindow(window_id).call()
        start_seq, size, opened_at, seal_deadline, sealed_at, root = w_data
        return {
            "windowId": window_id,
            "startSeq": start_seq,
            "size": size,
            "openedAt": opened_at,
            "sealDeadline": seal_deadline,
            "sealedAt": sealed_at,
            "root": "0x" + root.hex(),
            "isSealed": sealed_at > 0
        }
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.post("/seal/{window_id}")
def seal_window_endpoint(window_id: int):
    manager = get_wm()
    try:
        root_hex = manager.seal_window(window_id)
        return {"windowId": window_id, "root": "0x" + root_hex, "status": "SEALED"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
