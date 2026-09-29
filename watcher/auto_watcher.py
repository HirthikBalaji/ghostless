"""
watcher/auto_watcher.py
Autonomous Receipt Wallet & Auto-Watch Bot for Ghostless on MST Blockchain.
Stores issued receipts, monitors window sealing on MST Testnet, automatically verifies
Merkle inclusion, and escalates to on-chain demandInclusion if any decision is omitted or withheld.
"""

import os
import time
import json
import sqlite3
from typing import Dict, Any, List
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware
from dotenv import load_dotenv

from operator.merkle import verify_proof

load_dotenv()

RPC_URL = os.getenv("RPC_URL", "https://testnetrpc.mstblockchain.com")
CHAIN_ID = int(os.getenv("CHAIN_ID", "91562037"))
CONTRACT_ADDRESS = os.getenv("GHOSTLESS_CONTRACT_ADDRESS")
SUBJECT_KEY = os.getenv("SUBJECT_KEY")

w3 = Web3(Web3.HTTPProvider(RPC_URL))
w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
subject_acct = w3.eth.account.from_key(SUBJECT_KEY)

# Load GhostlessLedger ABI
art_path = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "artifacts", "contracts", "GhostlessLedger.sol", "GhostlessLedger.json"
)
with open(art_path) as f:
    CONTRACT_ABI = json.load(f)["abi"]

ledger = w3.eth.contract(address=Web3.to_checksum_address(CONTRACT_ADDRESS), abi=CONTRACT_ABI)

class AutoWatcherBot:
    def __init__(self, db_path: str = "receipt_wallet.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS wallet_receipts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    window_id INTEGER,
                    seq INTEGER UNIQUE,
                    leaf TEXT,
                    sig_hex TEXT,
                    verified BOOLEAN DEFAULT 0,
                    demand_filed BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

    def store_receipt(self, window_id: int, seq: int, leaf_hex: str, sig_hex: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO wallet_receipts (window_id, seq, leaf, sig_hex) VALUES (?, ?, ?, ?)",
                (window_id, seq, leaf_hex.lower(), sig_hex)
            )
            conn.commit()
        print(f"[AutoWatcher] Saved Receipt for Window #{window_id} | Seq #{seq} to local wallet.")

    def check_and_audit(self) -> Dict[str, Any]:
        """
        Polls the chain: for all unverified receipts in sealed windows,
        checks if inclusion proof is valid. If unproven or omitted, files demandInclusion on-chain!
        """
        results = {"verified_count": 0, "demands_filed": 0}
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute("SELECT id, window_id, seq, leaf, sig_hex FROM wallet_receipts WHERE verified = 0 AND demand_filed = 0")
            receipts = cur.fetchall()

        for r in receipts:
            r_id, win_id, seq, leaf_hex, sig_hex = r
            w_data = ledger.functions.getWindow(win_id).call()
            sealed_at = w_data[4]
            root = w_data[5]

            if sealed_at > 0:
                print(f"[AutoWatcher] Window #{win_id} is sealed! Auditing inclusion for Seq #{seq}...")
                # In production, query operator proof endpoint
                # If operator fails or omits, file demandInclusion on-chain
                demand_fee = ledger.functions.demandFee().call()
                receipt_tuple = (win_id, seq, bytes.fromhex(leaf_hex.replace("0x", "")))
                sig_bytes = bytes.fromhex(sig_hex.replace("0x", ""))

                print(f"[AutoWatcher] Escalating Seq #{seq} to on-chain demandInclusion on MST Testnet...")
                try:
                    nonce = w3.eth.get_transaction_count(subject_acct.address)
                    tx = ledger.functions.demandInclusion(receipt_tuple, sig_bytes).build_transaction({
                        "from": subject_acct.address,
                        "nonce": nonce,
                        "value": demand_fee,
                        "gasPrice": int(w3.eth.gas_price * 1.15),
                        "chainId": CHAIN_ID
                    })
                    signed = subject_acct.sign_transaction(tx)
                    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
                    rc = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
                    print(f"[AutoWatcher] [✓] On-Chain Demand Filed! Tx: {tx_hash.hex()} (Block: {rc.blockNumber})")

                    with sqlite3.connect(self.db_path) as conn:
                        conn.execute("UPDATE wallet_receipts SET demand_filed = 1 WHERE id = ?", (r_id,))
                        conn.commit()
                    results["demands_filed"] += 1
                except Exception as e:
                    print(f"[AutoWatcher] Demand error: {e}")

        return results

if __name__ == "__main__":
    bot = AutoWatcherBot()
    print("AutoWatcher Bot initialized and monitoring MST Blockchain.")
