"""
watcher/watcher.py
Independent Verifier / Watcher for Ghostless on MST Blockchain.
Requires ONLY public RPC and contract address (Zero access to operator DB).
Maintains receipt vault, verifies chain invariants, monitors deadlines,
and triggers on-chain slashing for equivocation, unsealed windows, and missing inclusion responses.
"""

import os
import json
import time
import sqlite3
from typing import Dict, Any, List, Optional
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

from operator.merkle import verify_proof

DEFAULT_VAULT_DB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "watcher_vault.db")

class Watcher:
    def __init__(
        self,
        rpc_url: str,
        chain_id: int,
        contract_address: str,
        watcher_private_key: str,
        vault_db_path: str = DEFAULT_VAULT_DB
    ):
        self.rpc_url = rpc_url
        self.chain_id = chain_id
        self.contract_address = Web3.to_checksum_address(contract_address)
        self.watcher_key = watcher_private_key
        self.vault_db_path = vault_db_path

        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
        self.account = self.w3.eth.account.from_key(watcher_private_key)
        self.address = self.account.address

        artifact_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "artifacts", "contracts", "GhostlessLedger.sol", "GhostlessLedger.json"
        )
        with open(artifact_path) as f:
            art = json.load(f)
            self.contract_abi = art["abi"]

        self.contract = self.w3.eth.contract(
            address=self.contract_address,
            abi=self.contract_abi
        )

        self.event_stream: List[Dict[str, Any]] = []
        self._init_vault()

    def _init_vault(self):
        with sqlite3.connect(self.vault_db_path) as conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS receipt_vault (
                window_id INTEGER NOT NULL,
                seq INTEGER NOT NULL,
                leaf TEXT NOT NULL,
                sig_hex TEXT NOT NULL,
                status TEXT DEFAULT 'HELD',
                demand_id INTEGER DEFAULT -1,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (window_id, seq, leaf)
            );
            """)
            conn.commit()

    def emit_event(self, kind: str, window_id: int, seq: int, tx_hash: str, details: str = ""):
        evt = {
            "ts": time.time(),
            "kind": kind,
            "windowId": window_id,
            "seq": seq,
            "txHash": tx_hash,
            "details": details
        }
        self.event_stream.append(evt)
        print(f"[Watcher Event] {kind} | Win: {window_id} Seq: {seq} | Tx: {tx_hash} | {details}")

    def send_tx(self, build_fn, value: int = 0) -> str:
        nonce = self.w3.eth.get_transaction_count(self.address)
        tx = build_fn().build_transaction({
            "from": self.address,
            "nonce": nonce,
            "gasPrice": int(self.w3.eth.gas_price * 1.15),
            "chainId": self.chain_id,
            "value": value
        })
        gas_est = self.w3.eth.estimate_gas(tx)
        tx["gas"] = int(gas_est * 1.3)
        signed = self.account.sign_transaction(tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
        if receipt.status != 1:
            raise RuntimeError(f"Watcher tx failed: {tx_hash.hex()}")
        return tx_hash.hex()

    def add_receipt(self, window_id: int, seq: int, leaf: str, sig_hex: str):
        """
        Stores receipt in vault and immediately checks for equivocation!
        """
        leaf_clean = leaf.lower()
        with sqlite3.connect(self.vault_db_path) as conn:
            # Check for equivocation: same (window_id, seq) but different leaf
            cur = conn.execute(
                "SELECT leaf, sig_hex FROM receipt_vault WHERE window_id = ? AND seq = ? AND leaf != ?",
                (window_id, seq, leaf_clean)
            )
            conflict = cur.fetchone()
            if conflict:
                print(f"[Watcher] EQUIVOCATION DETECTED in slot ({window_id}, {seq})! Calling proveEquivocation on-chain...")
                # Present both receipts to contract
                rA = (window_id, seq, bytes.fromhex(leaf_clean.replace("0x", "")))
                rB = (window_id, seq, bytes.fromhex(conflict[0].replace("0x", "")))
                sigA = bytes.fromhex(sig_hex.replace("0x", ""))
                sigB = bytes.fromhex(conflict[1].replace("0x", ""))

                tx_hash = self.send_tx(lambda: self.contract.functions.proveEquivocation(rA, sigA, rB, sigB))
                self.emit_event("EQUIVOCATION_SLASH", window_id, seq, tx_hash, "Slashed operator for equivocation")
                return tx_hash

            conn.execute(
                "INSERT OR IGNORE INTO receipt_vault (window_id, seq, leaf, sig_hex) VALUES (?, ?, ?, ?)",
                (window_id, seq, leaf_clean, sig_hex)
            )
            conn.commit()

    def check_chain_invariants(self) -> Dict[str, Any]:
        """
        Verifies Invariants I1, I2, I3 on public chain data.
        """
        count = self.contract.functions.windowCount().call()
        next_seq = self.contract.functions.nextSeq().call()
        current_block = self.w3.eth.block_number

        total_size = 0
        computed_checkpoint = b"\x00" * 32
        open_windows = 0
        unsealed_past_deadline = []

        for w_id in range(count):
            w_data = self.contract.functions.getWindow(w_id).call()
            start_seq, size, opened_at, seal_deadline, sealed_at, root = w_data
            total_size += size

            if sealed_at > 0:
                # Recompute checkpoint fold
                encoded = self.w3.codec.encode(
                    ['bytes32', 'uint256', 'uint64', 'uint32', 'bytes32'],
                    [computed_checkpoint, w_id, start_seq, size, root]
                )
                computed_checkpoint = Web3.keccak(encoded)
            else:
                open_windows += 1
                if current_block > seal_deadline:
                    unsealed_past_deadline.append((w_id, seal_deadline))

        head_cp = self.contract.functions.headCheckpoint().call()
        frozen = self.contract.functions.frozen().call()

        invariants_ok = (
            (total_size == next_seq) and
            (computed_checkpoint == head_cp) and
            (open_windows <= 2)
        )

        # Trigger slashUnsealed if any expired unsealed windows exist and operator not already frozen
        for u_id, deadline in unsealed_past_deadline:
            if not frozen:
                print(f"[Watcher] Window {u_id} unsealed past deadline {deadline}. Slashing on-chain...")
                try:
                    tx_hash = self.send_tx(lambda: self.contract.functions.slashUnsealed(u_id))
                    self.emit_event("UNSEALED_SLASH", u_id, 0, tx_hash, f"Window unsealed past deadline {deadline}")
                    frozen = True
                except Exception as e:
                    print(f"[Watcher] slashUnsealed note: {e}")

        return {
            "invariants_ok": invariants_ok,
            "invariant_I1_contiguous": (total_size == next_seq),
            "invariant_I3_checkpoint": (computed_checkpoint == head_cp),
            "total_windows": count,
            "open_windows": open_windows,
            "current_block": current_block,
            "frozen": frozen,
            "unsealed_past_deadline": unsealed_past_deadline
        }

    def escalate_demand(self, window_id: int, seq: int) -> int:
        """
        Escalates a missing inclusion proof to an on-chain demand.
        """
        with sqlite3.connect(self.vault_db_path) as conn:
            cur = conn.execute(
                "SELECT leaf, sig_hex FROM receipt_vault WHERE window_id = ? AND seq = ?",
                (window_id, seq)
            )
            row = cur.fetchone()
            if not row:
                raise ValueError("Receipt not in vault")

            leaf_bytes = bytes.fromhex(row[0].replace("0x", ""))
            sig_bytes = bytes.fromhex(row[1].replace("0x", ""))

        demand_fee = self.contract.functions.demandFee().call()
        r = (window_id, seq, leaf_bytes)

        tx_hash = self.send_tx(
            lambda: self.contract.functions.demandInclusion(r, sig_bytes),
            value=demand_fee
        )
        demand_id = self.contract.functions.demandCount().call() - 1

        with sqlite3.connect(self.vault_db_path) as conn:
            conn.execute(
                "UPDATE receipt_vault SET status = 'DEMANDED', demand_id = ? WHERE window_id = ? AND seq = ?",
                (demand_id, window_id, seq)
            )
            conn.commit()

        self.emit_event("DEMAND_OPENED", window_id, seq, tx_hash, f"Demand ID: {demand_id}")
        return demand_id

    def check_demand_and_slash(self, demand_id: int):
        """
        Checks if demand response deadline passed; if unanswered, slashes operator!
        """
        d_data = self.contract.functions.getDemand(demand_id).call()
        receipt_tuple, demander, answer_by, fee, resolved = d_data
        cur_block = self.w3.eth.block_number

        if not resolved and cur_block > answer_by:
            print(f"[Watcher] Demand {demand_id} timed out without operator response! Slashing on-chain...")
            tx_hash = self.send_tx(lambda: self.contract.functions.slashNoResponse(demand_id))
            self.emit_event(
                "NO_RESPONSE_SLASH",
                receipt_tuple[0],
                receipt_tuple[1],
                tx_hash,
                f"Demand {demand_id} slashed"
            )
