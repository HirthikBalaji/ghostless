"""
operator/merkle.py
Positional Merkle Tree implementation for Ghostless on MST Blockchain.
Exact domain-separation and non-commutative positional hashing matching GhostlessLedger.sol:
- Leaf: keccak256(0x00 || abi.encode(windowId, seq, keccak256(recordP), privCommit))
- Node: keccak256(0x01 || left || right)
- Index determines orientation: (index & 1 == 0) -> hash(0x01 || current || proof_sibling)
"""

import math
from typing import List, Tuple, Optional
from eth_abi import encode
from web3 import Web3

def hash_leaf(
    window_id: int,
    seq: int,
    record_p_bytes: bytes,
    priv_commit: bytes
) -> bytes:
    """
    Computes leaf hash according to Section 2.3 spec:
    keccak256(0x00 || abi.encode(windowId, seq, keccak256(recordP), privCommit))
    """
    record_p_hash = Web3.keccak(record_p_bytes)
    encoded = encode(
        ['uint256', 'uint64', 'bytes32', 'bytes32'],
        [window_id, seq, record_p_hash, priv_commit]
    )
    return Web3.keccak(b'\x00' + encoded)

def hash_node(left: bytes, right: bytes) -> bytes:
    """
    Positional (non-commutative) node hash:
    keccak256(0x01 || left || right)
    """
    return Web3.keccak(b'\x01' + left + right)

def build_tree(leaves: List[bytes]) -> List[List[bytes]]:
    """
    Builds a full positional binary tree from leaves (length must be a power of two).
    Returns layers from leaves (layer 0) up to root (layer depth).
    """
    n = len(leaves)
    if n == 0 or (n & (n - 1)) != 0:
        raise ValueError(f"Number of leaves must be a non-zero power of 2, got {n}")

    layers = [leaves]
    current = leaves
    while len(current) > 1:
        next_layer = []
        for i in range(0, len(current), 2):
            next_layer.append(hash_node(current[i], current[i + 1]))
        layers.append(next_layer)
        current = next_layer

    return layers

def get_root(layers: List[List[bytes]]) -> bytes:
    return layers[-1][0]

def get_proof(layers: List[List[bytes]], index: int) -> List[bytes]:
    """
    Generates positional sibling proof for leaf at `index`.
    Length of proof is strictly log2(size).
    """
    proof = []
    idx = index
    for layer in layers[:-1]:
        sibling_idx = idx ^ 1
        proof.append(layer[sibling_idx])
        idx >>= 1
    return proof

def verify_proof(
    root: bytes,
    leaf: bytes,
    index: int,
    proof: List[bytes],
    size: int
) -> bool:
    """
    Verifies positional inclusion proof matching Solidity _verifyPositionalProof logic.
    """
    expected_depth = int(math.log2(size))
    if len(proof) != expected_depth:
        return False

    h = leaf
    idx = index
    for p in proof:
        if (idx & 1) == 0:
            h = hash_node(h, p)
        else:
            h = hash_node(p, h)
        idx >>= 1

    return h == root
