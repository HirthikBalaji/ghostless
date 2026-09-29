"""
redteam/malicious_operator.py
Malicious Operator subclass implementing adversarial attacks:
- S2: Mutate committed decision / alter leaf
- S3: Void/replace receipted slot with padding
- S5: Equivocate by signing conflicting receipts for the same slot
- S6: Withhold window sealing past sealDeadline
- S7: Simulate database loss / wipe
- S8: Issue expired/stale window receipts
"""

import os
import json
import secrets
from typing import Dict, Any, Tuple
from eth_abi import encode
from web3 import Web3

from operator.window_manager import WindowManager, RECORD_P_TYPES
from operator.merkle import hash_leaf, build_tree, get_root
from operator.receipts import sign_receipt
from operator.db import get_db

class MaliciousOperator(WindowManager):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def issue_equivocating_receipts(
        self,
        window_id: int,
        seq: int
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Attack A3/S5: Signs TWO conflicting receipts for the exact same slot.
        """
        # Leaf A
        saltA = secrets.token_bytes(32)
        priv_commitA = Web3.keccak(saltA + b'{"subject":"Alice","action":"ALLOW"}')
        dummy_record_p_A = encode(RECORD_P_TYPES, [(1, 1, 3, 10, 5800000, b'\x00'*4, "0x" + "11"*20, b'\x01'*32, b'\x02'*32, 1)])
        leafA = hash_leaf(window_id, seq, dummy_record_p_A, priv_commitA)

        sigA = sign_receipt(
            self.operator_key,
            self.chain_id,
            self.contract_address,
            window_id,
            seq,
            leafA
        )

        # Leaf B (Conflicting leaf for SAME slot)
        saltB = secrets.token_bytes(32)
        priv_commitB = Web3.keccak(saltB + b'{"subject":"Bob","action":"DENY"}')
        dummy_record_p_B = encode(RECORD_P_TYPES, [(2, 0, 12, 20, 5800000, b'\x00'*4, "0x" + "22"*20, b'\x01'*32, b'\x03'*32, 2)])
        leafB = hash_leaf(window_id, seq, dummy_record_p_B, priv_commitB)

        sigB = sign_receipt(
            self.operator_key,
            self.chain_id,
            self.contract_address,
            window_id,
            seq,
            leafB
        )

        receiptA = {"windowId": window_id, "seq": seq, "leaf": "0x" + leafA.hex(), "signature": sigA}
        receiptB = {"windowId": window_id, "seq": seq, "leaf": "0x" + leafB.hex(), "signature": sigB}

        return receiptA, receiptB

    def mutate_slot_post_sealing(self, window_id: int, seq: int):
        """
        Attack A1/S2: Mutates stored leaf in DB post-sealing, making it impossible
        to produce the correct Merkle proof for the original receipted leaf.
        """
        corrupted_leaf = Web3.keccak(secrets.token_bytes(32)).hex()
        with get_db(self.db_path) as conn:
            conn.execute(
                "UPDATE slots SET leaf = ? WHERE window_id = ? AND seq = ?",
                (corrupted_leaf, window_id, seq)
            )
            conn.commit()
        print(f"[MaliciousOperator] Corrupted slot ({window_id}, {seq}) leaf in DB to 0x{corrupted_leaf}")

    def void_receipted_slot_with_padding(self, window_id: int, seq: int):
        """
        Attack A2/S3: Silently marks an issued receipt slot as PADDING before sealing.
        When sealed, the Merkle tree commits to a padding leaf instead of the subject's leaf!
        """
        blk_num, blk_prefix = self.get_latest_block_info()
        pad_tuple = (
            0, 255, 0, 0, blk_num, blk_prefix,
            "0x0000000000000000000000000000000000000000",
            b"\x00" * 32, b"\x00" * 32, 0
        )
        record_p_bytes = encode(RECORD_P_TYPES, [pad_tuple])
        priv_commit = Web3.keccak(secrets.token_bytes(32))
        padding_leaf = hash_leaf(window_id, seq, record_p_bytes, priv_commit)

        with get_db(self.db_path) as conn:
            conn.execute(
                "UPDATE slots SET leaf = ?, status = 'PADDING' WHERE window_id = ? AND seq = ?",
                (padding_leaf.hex(), window_id, seq)
            )
            conn.commit()
        print(f"[MaliciousOperator] Replaced slot ({window_id}, {seq}) with PADDING leaf!")

    def wipe_local_database(self):
        """
        Attack A5/S7: Deletes local database mid-run.
        """
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
            print(f"[MaliciousOperator] Nuked operator database at {self.db_path}!")
