"""
test/test_cross_conformance.py
Python pytest verifying AC2: Cross-Language Conformance.
Asserts bit-identical leaf computation, ABI encoding, and hashes between Python and Solidity.
"""

import os
import json
import pytest
from eth_abi import encode
from web3 import Web3

from operator.merkle import hash_leaf, build_tree, get_root, get_proof, verify_proof

RECORD_P_TYPES = [
    '(uint16,uint8,uint8,uint32,uint64,bytes4,address,bytes32,bytes32,uint64)'
]

def test_cross_conformance_vectors():
    dir_path = os.path.dirname(os.path.abspath(__file__))
    vectors_path = os.path.join(dir_path, "vectors.json")
    results_path = os.path.join(dir_path, "js_vector_results.json")

    assert os.path.exists(results_path), "Run JS test first to generate js_vector_results.json"

    with open(vectors_path) as f:
        vectors = json.load(f)["vectors"]

    with open(results_path) as f:
        js_results = {r["name"]: r for r in json.load(f)}

    for vec in vectors:
        name = vec["name"]
        js = js_results[name]
        p = vec["recordP"]

        tuple_data = (
            p["ruleId"],
            p["outcome"],
            p["riskBucket"],
            p["routeId"],
            p["blockRef"],
            bytes.fromhex(p["blockHashPrefix"].replace("0x", "")),
            Web3.to_checksum_address(p["subject"]),
            bytes.fromhex(p["actuatorId"].replace("0x", "")),
            bytes.fromhex(p["actionHash"].replace("0x", "")),
            p["nonce"]
        )

        record_p_bytes = encode(RECORD_P_TYPES, [tuple_data])
        record_p_hex = "0x" + record_p_bytes.hex()
        assert record_p_hex.lower() == js["recordPBytes"].lower(), f"RecordP mismatch for {name}"

        record_p_hash = "0x" + Web3.keccak(record_p_bytes).hex()
        assert record_p_hash.lower() == js["recordPHash"].lower(), f"RecordP hash mismatch for {name}"

        priv_commit_bytes = bytes.fromhex(vec["privCommit"].replace("0x", ""))
        py_leaf = hash_leaf(vec["windowId"], vec["seq"], record_p_bytes, priv_commit_bytes)
        py_leaf_hex = "0x" + py_leaf.hex()
        assert py_leaf_hex.lower() == js["leaf"].lower(), f"Leaf mismatch for {name}"

    print("[✓] AC2: Python and Solidity produce 100% bit-identical leaves and encodings!")
