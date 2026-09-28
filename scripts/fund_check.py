#!/usr/bin/env python3
"""
fund_check.py - Generates or loads the 3 project keys (OPERATOR, SUBJECT, ATTACKER)
and ensures they are funded with tMSTC on MST Testnet from the official faucet key.
"""
import os
import sys
from eth_account import Account
from web3 import Web3
from dotenv import load_dotenv

# Enable HD wallet / account generation features
Account.enable_unaudited_hdwallet_features()

RPC_URL = os.getenv("RPC_URL", "https://testnetrpc.mstblockchain.com")
w3 = Web3(Web3.HTTPProvider(RPC_URL))

FAUCET_KEY = "0xb944d092c1dadd3b7a7eb9a8769d8b53cf3082ee66a66772118e64c4a526fc74"
TARGET_BALANCE = 15.0  # tMSTC per test wallet

def ensure_env_file():
    env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    if os.path.exists(env_path):
        load_dotenv(env_path)
    
    op_key = os.getenv("OPERATOR_KEY")
    sub_key = os.getenv("SUBJECT_KEY")
    att_key = os.getenv("ATTACKER_KEY")

    created = False
    if not op_key:
        op_key = "0x" + Account.create("ghostless_op_seed_v1").key.hex()
        created = True
    if not sub_key:
        sub_key = "0x" + Account.create("ghostless_sub_seed_v1").key.hex()
        created = True
    if not att_key:
        att_key = "0x" + Account.create("ghostless_att_seed_v1").key.hex()
        created = True

    if created or not os.path.exists(env_path):
        with open(env_path, "w") as f:
            f.write(f"RPC_URL={RPC_URL}\n")
            f.write(f"CHAIN_ID=91562037\n")
            f.write(f"OPERATOR_KEY={op_key}\n")
            f.write(f"SUBJECT_KEY={sub_key}\n")
            f.write(f"ATTACKER_KEY={att_key}\n")
            f.write(f"FAUCET_KEY={FAUCET_KEY}\n")
            f.write(f"EXPLORER_URL=https://mstscan.com\n")
        print(f"[+] Wrote fresh keys to {env_path}")
        load_dotenv(env_path)

    return op_key, sub_key, att_key

def fund_account_if_needed(faucet_acct, target_address, target_amount_ether):
    bal_wei = w3.eth.get_balance(target_address)
    bal_eth = float(w3.from_wei(bal_wei, "ether"))
    print(f"Address {target_address}: current balance = {bal_eth:.4f} tMSTC")
    
    if bal_eth < target_amount_ether:
        needed = target_amount_ether - bal_eth + 1.0  # extra buffer
        print(f"  --> Funding with {needed:.4f} tMSTC from faucet...")
        nonce = w3.eth.get_transaction_count(faucet_acct.address)
        tx = {
            "to": target_address,
            "value": w3.to_wei(needed, "ether"),
            "gas": 25000,
            "gasPrice": int(w3.eth.gas_price * 1.15),
            "nonce": nonce,
            "chainId": w3.eth.chain_id
        }
        signed = faucet_acct.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
        if receipt.status == 1:
            new_bal = float(w3.from_wei(w3.eth.get_balance(target_address), "ether"))
            print(f"  [✓] Funded! New balance: {new_bal:.4f} tMSTC (tx: {tx_hash.hex()})")
        else:
            raise RuntimeError(f"Funding failed for {target_address}")

def main():
    print(f"Checking MST Testnet connection ({RPC_URL})...")
    if not w3.is_connected():
        print(f"[-] Cannot connect to RPC {RPC_URL}")
        sys.exit(1)
    
    chain_id = w3.eth.chain_id
    print(f"[+] Connected to Chain ID: {chain_id} (hex: {hex(chain_id)})")
    
    op_key, sub_key, att_key = ensure_env_file()
    faucet_acct = w3.eth.account.from_key(FAUCET_KEY)
    faucet_bal = float(w3.from_wei(w3.eth.get_balance(faucet_acct.address), "ether"))
    print(f"[+] Faucet balance ({faucet_acct.address}): {faucet_bal:.2f} tMSTC")

    accounts = [
        ("OPERATOR", w3.eth.account.from_key(op_key).address),
        ("SUBJECT", w3.eth.account.from_key(sub_key).address),
        ("ATTACKER", w3.eth.account.from_key(att_key).address),
    ]

    for role, addr in accounts:
        print(f"\nChecking {role} account: {addr}")
        fund_account_if_needed(faucet_acct, addr, TARGET_BALANCE)

    print("\n[✓] All 3 accounts verified and funded successfully!")

if __name__ == "__main__":
    main()
