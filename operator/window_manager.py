"""
operator/window_manager.py
Window lifecycle management and atomic slot allocation for Ghostless.
Handles pipelining (MAX_OPEN = 2), auto-padding unused slots, building Merkle roots,
and executing on-chain transactions on MST Testnet.
"""

import os
import json
import secrets
from typing import Dict, Any, Tuple, Optional, List
from eth_abi import encode
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

from operator.db import get_db, init_db, DEFAULT_DB_PATH
from operator.merkle import hash_leaf, build_tree, get_root, get_proof
from operator.receipts import sign_receipt

RECORD_P_TYPES = [
    '(uint16,uint8,uint8,uint32,uint64,bytes4,address,bytes32,bytes32,uint64)'
]

class WindowManager:
    def __init__(
        self,
        rpc_url: str,
        chain_id: int,
        contract_address: str,
        operator_private_key: str,
        db_path: str = DEFAULT_DB_PATH,
        default_window_size: int = 64
    ):
        self.rpc_url = rpc_url
        self.chain_id = chain_id
        self.contract_address = Web3.to_checksum_address(contract_address)
        self.operator_key = operator_private_key
        self.db_path = db_path
        self.default_window_size = default_window_size

        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
        self.operator_account = self.w3.eth.account.from_key(operator_private_key)
        self.operator_address = self.operator_account.address

        init_db(self.db_path)

        # Load contract ABI
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

    def get_latest_block_info(self) -> Tuple[int, bytes]:
        blk = self.w3.eth.get_block("latest")
        blk_num = blk["number"]
        blk_hash = blk["hash"]
        prefix = blk_hash[:4]
        return blk_num, prefix

    def send_tx(self, build_fn, value: int = 0) -> str:
        nonce = self.w3.eth.get_transaction_count(self.operator_address)
        tx = build_fn().build_transaction({
            "from": self.operator_address,
            "nonce": nonce,
            "gasPrice": int(self.w3.eth.gas_price * 1.15),
            "chainId": self.chain_id,
            "value": value
        })
        gas_est = self.w3.eth.estimate_gas(tx)
        tx["gas"] = int(gas_est * 1.25)
        signed = self.operator_account.sign_transaction(tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
        if receipt.status != 1:
            raise RuntimeError(f"Transaction failed: {tx_hash.hex()}")
        return tx_hash.hex()

    def ensure_open_window(self) -> int:
        """
        Ensures at least one open window exists. If none, calls openWindow on-chain.
        """
        with get_db(self.db_path) as conn:
            cur = conn.execute(
                "SELECT window_id, start_seq, size FROM windows WHERE status = 'OPEN' ORDER BY window_id ASC LIMIT 1"
            )
            row = cur.fetchone()
            if row:
                return row["window_id"]

        # Call contract openWindow
        print(f"[WindowManager] Opening new window with size {self.default_window_size} on-chain...")
        tx_hash = self.send_tx(lambda: self.contract.functions.openWindow(self.default_window_size))
        print(f"[WindowManager] openWindow tx confirmed: {tx_hash}")

        count = self.contract.functions.windowCount().call()
        window_id = count - 1
        w_data = self.contract.functions.getWindow(window_id).call()
        # struct Window { uint64 startSeq; uint32 size; uint64 openedAt; uint64 sealDeadline; uint64 sealedAt; bytes32 root; }
        start_seq, size, opened_at, seal_deadline, sealed_at, root = w_data

        with get_db(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO windows 
                (window_id, start_seq, size, opened_at, seal_deadline, sealed_at, root, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'OPEN')
                """,
                (window_id, start_seq, size, opened_at, seal_deadline, sealed_at, root.hex())
            )
            conn.commit()

        return window_id

    def allocate_slot_and_record(
        self,
        decision_payload: dict,
        rule_id: int,
        outcome: int,
        risk_bucket: int,
        route_id: int,
        subject_address: str,
        actuator_id_bytes: bytes,
        action_payload_bytes: bytes,
        nonce: int
    ) -> Dict[str, Any]:
        """
        Atomically allocates the next slot in SQLite and signs an EIP-712 Receipt.
        Checks if the window is 75% full to pipeline the next window.
        """
        window_id = self.ensure_open_window()

        with get_db(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute(
                "SELECT window_id, start_seq, size FROM windows WHERE window_id = ?",
                (window_id,)
            )
            win = cur.fetchone()
            start_seq = win["start_seq"]
            size = win["size"]

            cur_cnt = conn.execute(
                "SELECT COUNT(*) as cnt FROM slots WHERE window_id = ?",
                (window_id,)
            ).fetchone()["cnt"]

            if cur_cnt >= size:
                # Window full, seal it and retry
                conn.commit()
                self.seal_window(window_id)
                return self.allocate_slot_and_record(
                    decision_payload, rule_id, outcome, risk_bucket, route_id,
                    subject_address, actuator_id_bytes, action_payload_bytes, nonce
                )

            seq = start_seq + cur_cnt

            blk_num, blk_prefix = self.get_latest_block_info()
            action_hash = Web3.keccak(action_payload_bytes)
            subject_addr = Web3.to_checksum_address(subject_address)

            # RecordP structure matching Solidity PolicyRecord
            record_p_tuple = (
                rule_id,
                outcome,
                risk_bucket,
                route_id,
                blk_num,
                blk_prefix,
                subject_addr,
                actuator_id_bytes,
                action_hash,
                nonce
            )
            record_p_bytes = encode(RECORD_P_TYPES, [record_p_tuple])

            # PrivCommit = keccak256(salt32 || canonicalJSON(fullDecision))
            salt = secrets.token_bytes(32)
            canonical_json = json.dumps(decision_payload, sort_keys=True, separators=(',', ':')).encode('utf-8')
            priv_commit = Web3.keccak(salt + canonical_json)

            leaf = hash_leaf(window_id, seq, record_p_bytes, priv_commit)

            # Insert slot
            conn.execute(
                """
                INSERT INTO slots (window_id, seq, leaf, record_p_hex, priv_commit_hex, salt_hex, status)
                VALUES (?, ?, ?, ?, ?, ?, 'ALLOCATED')
                """,
                (window_id, seq, leaf.hex(), record_p_bytes.hex(), priv_commit.hex(), salt.hex())
            )

            # Sign Receipt
            sig = sign_receipt(
                self.operator_key,
                self.chain_id,
                self.contract_address,
                window_id,
                seq,
                leaf
            )

            conn.execute(
                "INSERT INTO receipts (window_id, seq, leaf, sig_hex) VALUES (?, ?, ?, ?)",
                (window_id, seq, leaf.hex(), sig)
            )

            conn.commit()

            # Pipelining: if window is >= 75% full, open next window if openCount < MAX_OPEN
            if cur_cnt + 1 >= int(0.75 * size):
                self._check_pipeline_next_window(window_id)

            return {
                "decision": decision_payload,
                "receipt": {
                    "windowId": window_id,
                    "seq": seq,
                    "leaf": "0x" + leaf.hex(),
                    "signature": sig
                },
                "recordP": "0x" + record_p_bytes.hex(),
                "privCommit": "0x" + priv_commit.hex(),
            }

    def _check_pipeline_next_window(self, current_window_id: int):
        try:
            open_count = self.contract.functions.openCount().call()
            if open_count < 2:
                print(f"[WindowManager] Window {current_window_id} is >= 75% full. Pipelining next window on-chain...")
                self.send_tx(lambda: self.contract.functions.openWindow(self.default_window_size))
                count = self.contract.functions.windowCount().call()
                new_id = count - 1
                w_data = self.contract.functions.getWindow(new_id).call()
                start_seq, size, opened_at, seal_deadline, sealed_at, root = w_data
                with get_db(self.db_path) as conn:
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO windows 
                        (window_id, start_seq, size, opened_at, seal_deadline, sealed_at, root, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?, 'OPEN')
                        """,
                        (new_id, start_seq, size, opened_at, seal_deadline, sealed_at, root.hex())
                    )
                    conn.commit()
        except Exception as e:
            print(f"[WindowManager] Pipelining note: {e}")

    def seal_window(self, window_id: int) -> str:
        """
        Pads any unused slots up to window size, constructs positional Merkle tree,
        and calls sealWindow(windowId, root) on-chain.
        """
        with get_db(self.db_path) as conn:
            cur = conn.execute(
                "SELECT window_id, start_seq, size FROM windows WHERE window_id = ?",
                (window_id,)
            )
            win = cur.fetchone()
            if not win:
                # Fetch directly from contract
                w_data = self.contract.functions.getWindow(window_id).call()
                start_seq, size, opened_at, seal_deadline, sealed_at, root = w_data
                conn.execute(
                    """
                    INSERT OR REPLACE INTO windows 
                    (window_id, start_seq, size, opened_at, seal_deadline, sealed_at, root, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'OPEN')
                    """,
                    (window_id, start_seq, size, opened_at, seal_deadline, sealed_at, root.hex())
                )
                conn.commit()
            else:
                start_seq = win["start_seq"]
                size = win["size"]

            slots = conn.execute(
                "SELECT seq, leaf FROM slots WHERE window_id = ? ORDER BY seq ASC",
                (window_id,)
            ).fetchall()

            leaves = [None] * size
            for row in slots:
                idx = row["seq"] - start_seq
                leaves[idx] = bytes.fromhex(row["leaf"])

            # Fill unallocated slots with padding leaves (outcome = 255)
            blk_num, blk_prefix = self.get_latest_block_info()
            for idx in range(size):
                if leaves[idx] is None:
                    seq = start_seq + idx
                    pad_tuple = (
                        0,      # ruleId
                        255,    # outcome = 255 (Padding)
                        0,      # riskBucket
                        0,      # routeId
                        blk_num,
                        blk_prefix,
                        "0x0000000000000000000000000000000000000000",
                        b"\x00" * 32,
                        b"\x00" * 32,
                        0       # nonce
                    )
                    record_p_bytes = encode(RECORD_P_TYPES, [pad_tuple])
                    priv_commit = Web3.keccak(secrets.token_bytes(32))
                    leaf = hash_leaf(window_id, seq, record_p_bytes, priv_commit)
                    leaves[idx] = leaf
                    conn.execute(
                        """
                        INSERT INTO slots (window_id, seq, leaf, record_p_hex, priv_commit_hex, salt_hex, status)
                        VALUES (?, ?, ?, ?, ?, ?, 'PADDING')
                        """,
                        (window_id, seq, leaf.hex(), record_p_bytes.hex(), priv_commit.hex(), "")
                    )

            tree = build_tree(leaves)
            root = get_root(tree)

            print(f"[WindowManager] Sealing window {window_id} with root 0x{root.hex()} on-chain...")
            tx_hash = self.send_tx(lambda: self.contract.functions.sealWindow(window_id, root))
            print(f"[WindowManager] Window {window_id} sealed! tx: {tx_hash}")

            w_data = self.contract.functions.getWindow(window_id).call()
            sealed_at = w_data[4]

            conn.execute(
                "UPDATE windows SET sealed_at = ?, root = ?, status = 'SEALED' WHERE window_id = ?",
                (sealed_at, root.hex(), window_id)
            )
            conn.commit()

            return root.hex()

    def get_inclusion_proof(self, window_id: int, seq: int) -> Tuple[bytes, List[str]]:
        """
        Retrieves positional Merkle inclusion proof for (windowId, seq).
        """
        with get_db(self.db_path) as conn:
            win = conn.execute(
                "SELECT start_seq, size, status FROM windows WHERE window_id = ?",
                (window_id,)
            ).fetchone()
            if not win:
                raise ValueError(f"Window {window_id} not found")

            start_seq = win["start_seq"]
            size = win["size"]
            index = seq - start_seq

            slots = conn.execute(
                "SELECT seq, leaf FROM slots WHERE window_id = ? ORDER BY seq ASC",
                (window_id,)
            ).fetchall()

            if len(slots) < size:
                raise ValueError("Window is not yet fully sealed/padded")

            leaves = [bytes.fromhex(s["leaf"]) for s in slots]
            tree = build_tree(leaves)
            proof_bytes = get_proof(tree, index)
            leaf = leaves[index]

            return leaf, ["0x" + p.hex() for p in proof_bytes]
