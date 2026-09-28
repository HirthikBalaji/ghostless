"""
operator/receipts.py
EIP-712 Receipt signing and verification in Python for GhostlessLedger.
Compatible with OpenZeppelin EIP-712 and eth_account.
"""

from typing import Dict, Any, Tuple
from eth_account import Account
from eth_account.messages import encode_typed_data
from web3 import Web3

def get_eip712_domain(chain_id: int, contract_address: str) -> Dict[str, Any]:
    return {
        "name": "GhostlessLedger",
        "version": "1",
        "chainId": chain_id,
        "verifyingContract": Web3.to_checksum_address(contract_address),
    }

def get_eip712_types() -> Dict[str, Any]:
    return {
        "Receipt": [
            {"name": "windowId", "type": "uint256"},
            {"name": "seq", "type": "uint64"},
            {"name": "leaf", "type": "bytes32"},
        ]
    }

def sign_receipt(
    private_key: str,
    chain_id: int,
    contract_address: str,
    window_id: int,
    seq: int,
    leaf: bytes
) -> str:
    """
    Signs a Receipt { windowId, seq, leaf } using EIP-712.
    Returns 65-byte hex signature.
    """
    domain = get_eip712_domain(chain_id, contract_address)
    types = get_eip712_types()
    message = {
        "windowId": window_id,
        "seq": seq,
        "leaf": "0x" + leaf.hex() if isinstance(leaf, bytes) else leaf,
    }

    structured_data = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "Receipt": types["Receipt"],
        },
        "primaryType": "Receipt",
        "domain": domain,
        "message": message,
    }

    signable = encode_typed_data(full_message=structured_data)
    signed = Account.sign_message(signable, private_key=private_key)
    return signed.signature.hex()

def recover_receipt_signer(
    chain_id: int,
    contract_address: str,
    window_id: int,
    seq: int,
    leaf: bytes,
    signature_hex: str
) -> str:
    """
    Recovers the signer address from an EIP-712 Receipt and signature.
    """
    domain = get_eip712_domain(chain_id, contract_address)
    types = get_eip712_types()
    message = {
        "windowId": window_id,
        "seq": seq,
        "leaf": "0x" + leaf.hex() if isinstance(leaf, bytes) else leaf,
    }
    structured_data = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "Receipt": types["Receipt"],
        },
        "primaryType": "Receipt",
        "domain": domain,
        "message": message,
    }
    signable = encode_typed_data(full_message=structured_data)
    recovered = Account.recover_message(signable, signature=signature_hex)
    return Web3.to_checksum_address(recovered)
