"""
actuator/gate.py
Enforces the core Ghostless security invariant: 'No Receipt -> No Effect'.
Independent verification boundary:
- Recovers EIP-712 signer and verifies it matches the bonded on-chain operator.
- Reconstructs leaf from recordP and privCommit.
- Verifies action payload matches recordP.actionHash and actuator matches recordP.actuatorId.
- Monotonic replay protection store (rejects repeated nonce).
- Cache of on-chain acceptable/frozen status with fail-closed timeout.
"""

import time
import json
from typing import Optional, Dict, Any, Set
from eth_abi import decode
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

from operator.merkle import hash_leaf, verify_proof
from operator.receipts import recover_receipt_signer

RECORD_P_TYPES = [
    '(uint16,uint8,uint8,uint32,uint64,bytes4,address,bytes32,bytes32,uint64)'
]

class ActuatorGate:
    def __init__(
        self,
        rpc_url: str,
        chain_id: int,
        contract_address: str,
        my_actuator_id_bytes: bytes,
        contract_abi: list,
        cache_ttl_seconds: float = 6.0,
        fail_closed_max_stale: float = 18.0
    ):
        self.rpc_url = rpc_url
        self.chain_id = chain_id
        self.contract_address = Web3.to_checksum_address(contract_address)
        self.my_actuator_id = my_actuator_id_bytes
        self.cache_ttl = cache_ttl_seconds
        self.max_stale = fail_closed_max_stale

        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
        self.contract = self.w3.eth.contract(address=self.contract_address, abi=contract_abi)

        # On-chain state cache
        self.cached_operator: Optional[str] = None
        self.cached_frozen: bool = False
        self.cached_bond: int = 0
        self.last_cache_update: float = 0.0

        # Replay protection store: set of (subject_address, nonce)
        self.executed_actions: Set[str] = set()

        # Metrics & counters
        self.counters = {
            "accepted": 0,
            "rejected_no_receipt": 0,
            "rejected_bad_receipt": 0,
            "rejected_frozen": 0,
            "rejected_stale_cache": 0,
            "rejected_replay": 0,
            "rejected_mismatch_actuator": 0,
            "rejected_mismatch_action": 0,
        }

        # Initialize cache
        self._refresh_cache()

    def _refresh_cache(self, force: bool = False) -> bool:
        now = time.time()
        if not force and (now - self.last_cache_update < self.cache_ttl):
            return True

        try:
            op = self.contract.functions.operator().call()
            fr = self.contract.functions.frozen().call()
            bnd = self.contract.functions.bond().call()
            self.cached_operator = Web3.to_checksum_address(op)
            self.cached_frozen = fr
            self.cached_bond = bnd
            self.last_cache_update = now
            return True
        except Exception as e:
            print(f"[ActuatorGate] Cache refresh failed: {e}")
            return False

    def authorize_and_execute(
        self,
        action_payload_bytes: bytes,
        receipt: Optional[Dict[str, Any]],
        record_p_hex: Optional[str],
        priv_commit_hex: Optional[str],
        proof_hex_list: Optional[list] = None
    ) -> Dict[str, Any]:
        """
        Gating execution check:
        1. Validates presence of receipt.
        2. Enforces fail-closed policy if cache cannot be refreshed past max_stale.
        3. Enforces operator not frozen.
        4. Recovers EIP-712 signer == operator.
        5. Recomputes leaf from recordP + privCommit.
        6. Enforces target actuator and action payload match.
        7. Enforces replay protection on nonce.
        8. Verifies acceptable(windowId, seq) or on-chain verifyInclusion.
        """
        now = time.time()
        # 1. Check receipt presence
        if not receipt or not record_p_hex or not priv_commit_hex:
            self.counters["rejected_no_receipt"] += 1
            return {"authorized": False, "status_code": 403, "reason": "NO_RECEIPT_PROVIDED"}

        # 2. Cache freshness / fail-closed check
        cache_ok = self._refresh_cache()
        if not cache_ok and (now - self.last_cache_update > self.max_stale):
            self.counters["rejected_stale_cache"] += 1
            return {"authorized": False, "status_code": 503, "reason": "FAIL_CLOSED_CHAIN_RPC_STALE"}

        # 3. Check frozen status
        if self.cached_frozen:
            self.counters["rejected_frozen"] += 1
            return {"authorized": False, "status_code": 403, "reason": "OPERATOR_FROZEN_ON_CHAIN"}

        try:
            window_id = int(receipt["windowId"])
            seq = int(receipt["seq"])
            leaf_bytes = bytes.fromhex(receipt["leaf"].replace("0x", ""))
            sig_hex = receipt["signature"]

            # 4. Recover receipt signer
            recovered_op = recover_receipt_signer(
                chain_id=self.chain_id,
                contract_address=self.contract_address,
                window_id=window_id,
                seq=seq,
                leaf=leaf_bytes,
                signature_hex=sig_hex
            )
            if recovered_op != self.cached_operator:
                self.counters["rejected_bad_receipt"] += 1
                return {"authorized": False, "status_code": 403, "reason": "INVALID_RECEIPT_SIGNATURE"}

            # 5. Recompute leaf
            record_p_bytes = bytes.fromhex(record_p_hex.replace("0x", ""))
            priv_commit_bytes = bytes.fromhex(priv_commit_hex.replace("0x", ""))
            expected_leaf = hash_leaf(window_id, seq, record_p_bytes, priv_commit_bytes)
            if expected_leaf != leaf_bytes:
                self.counters["rejected_bad_receipt"] += 1
                return {"authorized": False, "status_code": 403, "reason": "LEAF_MISMATCH"}

            # Decode recordP
            decoded_tuple = decode(RECORD_P_TYPES, record_p_bytes)[0]
            rule_id, outcome, risk_bucket, route_id, blk_ref, blk_prefix, subject_addr, act_id, act_hash, nonce = decoded_tuple

            # 6. Verify actuatorId and actionHash binding (Flaw #4 rectification)
            if act_id != self.my_actuator_id:
                self.counters["rejected_mismatch_actuator"] += 1
                return {"authorized": False, "status_code": 403, "reason": "ACTUATOR_ID_MISMATCH"}

            computed_action_hash = Web3.keccak(action_payload_bytes)
            if act_hash != computed_action_hash:
                self.counters["rejected_mismatch_action"] += 1
                return {"authorized": False, "status_code": 403, "reason": "ACTION_PAYLOAD_MISMATCH"}

            # 7. Replay protection check
            replay_key = f"{subject_addr}:{nonce}"
            if replay_key in self.executed_actions:
                self.counters["rejected_replay"] += 1
                return {"authorized": False, "status_code": 409, "reason": "REPLAY_DETECTED_NONCE_EXPENDED"}

            # 8. Check on-chain acceptability or inclusion proof
            is_acceptable = self.contract.functions.acceptable(window_id, seq).call()
            if not is_acceptable:
                # If window is sealed, check inclusion proof
                if proof_hex_list:
                    proof_bytes_list = [bytes.fromhex(p.replace("0x", "")) for p in proof_hex_list]
                    included = self.contract.functions.verifyInclusion(
                        window_id, seq, leaf_bytes, proof_bytes_list
                    ).call()
                    if not included:
                        self.counters["rejected_bad_receipt"] += 1
                        return {"authorized": False, "status_code": 403, "reason": "INCLUSION_PROOF_REJECTED"}
                else:
                    self.counters["rejected_bad_receipt"] += 1
                    return {"authorized": False, "status_code": 403, "reason": "SLOT_NOT_ACCEPTABLE_OR_EXPIRED"}

            # Action Authorized! Record replay protection key
            self.executed_actions.add(replay_key)
            self.counters["accepted"] += 1

            return {
                "authorized": True,
                "status_code": 200,
                "windowId": window_id,
                "seq": seq,
                "subject": subject_addr,
                "nonce": nonce,
                "outcome": outcome
            }

        except Exception as e:
            self.counters["rejected_bad_receipt"] += 1
            return {"authorized": False, "status_code": 400, "reason": f"VERIFICATION_ERROR: {str(e)}"}
