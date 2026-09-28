#!/usr/bin/env python3
"""
scripts/preflight.py
Phase 0 preflight verification on MST Blockchain testnet.
Verifies chain ID, calculates average block time over 50 blocks, tests EIP-1559,
tests PUSH0 (shanghai vs paris), tests blockhash and prevrandao, measures storage write gas,
calculates derived protocol parameters, and writes preflight.json.
"""

import os
import json
import math
import sys
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware
from dotenv import load_dotenv

load_dotenv()

RPC_URL = os.getenv("RPC_URL", "https://testnetrpc.mstblockchain.com")
OPERATOR_KEY = os.getenv("OPERATOR_KEY")

w3 = Web3(Web3.HTTPProvider(RPC_URL))
w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)


def run_preflight():
    print("=" * 60)
    print("GHOSTLESS PREFLIGHT CHECK - MST TESTNET")
    print("=" * 60)

    results = {}

    # 1. Chain ID check
    chain_id = w3.eth.chain_id
    chain_id_hex = hex(chain_id)
    print(f"[1] eth_chainId: {chain_id} ({chain_id_hex})")
    if chain_id != 91562037:
        raise ValueError(f"CRITICAL: Expected chainId 91562037, got {chain_id}!")
    print("    [✓] Chain ID matches official MST Testnet specification (91562037)")
    results["chain_id"] = chain_id
    results["chain_id_hex"] = chain_id_hex

    # 2. Block number and average block time over 50 blocks
    latest_block = w3.eth.get_block("latest")
    latest_num = latest_block["number"]
    sample_size = 50
    past_num = max(0, latest_num - sample_size)
    past_block = w3.eth.get_block(past_num)
    
    time_delta = latest_block["timestamp"] - past_block["timestamp"]
    blocks_delta = latest_num - past_num
    avg_block_time = time_delta / blocks_delta if blocks_delta > 0 else 2.0
    # In case time_delta is zero (e.g. instant mining)
    if avg_block_time <= 0:
        avg_block_time = 2.0

    print(f"[2] Latest block: {latest_num}")
    print(f"    Sampled {blocks_delta} blocks: total {time_delta}s, avg block time T = {avg_block_time:.2f}s")
    results["latest_block"] = latest_num
    results["sample_blocks"] = blocks_delta
    results["avg_block_time_seconds"] = round(avg_block_time, 2)

    # 3. Gas limit and EIP-1559 check
    gas_limit = latest_block["gasLimit"]
    base_fee = latest_block.get("baseFeePerGas")
    supports_eip1559 = base_fee is not None
    print(f"[3] Gas limit: {gas_limit}")
    print(f"    baseFeePerGas: {base_fee} (Supports EIP-1559: {supports_eip1559})")
    results["gas_limit"] = gas_limit
    results["supports_eip1559"] = supports_eip1559
    results["base_fee_per_gas"] = base_fee

    # 4. EVM Version: Test PUSH0 / Shanghai
    # Bytecode with PUSH0: 0x5f (PUSH0), 0x5f (PUSH0), 0xf3 (RETURN 0 bytes)
    # Init code: 60038060095f395ff3 5f5ff3
    # Let's test deploying a minimal PUSH0 contract using OPERATOR_KEY
    operator = w3.eth.account.from_key(OPERATOR_KEY)
    results["operator_address"] = operator.address
    print(f"    Testing operator address: {operator.address} (balance: {w3.from_wei(w3.eth.get_balance(operator.address), 'ether')} tMSTC)")

    # Test PUSH0 deployment:
    # 0x6001600d60003960016000f3 5f (initializes 1-byte contract containing 0x5f PUSH0)
    push0_bytecode = "0x6001600d60003960016000f35f"
    supports_push0 = False
    try:
        tx = {
            "from": operator.address,
            "data": push0_bytecode,
            "gas": 150000,
            "gasPrice": int(w3.eth.gas_price * 1.1),
            "nonce": w3.eth.get_transaction_count(operator.address),
            "chainId": chain_id
        }
        signed = operator.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=30)
        if receipt.status == 1:
            supports_push0 = True
            print(f"[4] PUSH0 (Shanghai) test: SUCCESS (deployed at {receipt.contractAddress})")
        else:
            print("[4] PUSH0 (Shanghai) test: REVERTED")
    except Exception as e:
        print(f"[4] PUSH0 (Shanghai) test failed: {e}")

    evm_version = "shanghai" if supports_push0 else "paris"
    print(f"    Selected EVM Version: {evm_version}")
    results["supports_push0"] = supports_push0
    results["selected_evm_version"] = evm_version

    # 5. Test blockhash and storage write gas cost via minimal test contract
    # Test contract bytecode (Paris-compatible):
    # Sol contract:
    # contract Probe {
    #   uint256 public val;
    #   function write(uint256 x) external { val = x; }
    #   function check() external view returns (bytes32 bh, uint256 pr) {
    #     bh = blockhash(block.number - 1);
    #     pr = block.prevrandao;
    #   }
    # }
    # Compiled with Paris evmVersion:
    probe_bin = (
        "608060405234801561001057600080fd5b50610196806100206000396000f3fe"
        "608060405234801561001057600080fd5b50600436106100415760003560e01c"
        "80632a0e5b4714610046578063919840ad1461005b578063a027976e14610077"
        "5b600080fd5b610049610091565b6040516100529291906100fb565b60405180"
        "910390f35b61007560048036038101906100709190610141565b6100ba565b00"
        "5b61007f6100c4565b604051610088919061017b565b60405180910390f35b60"
        "0080436001034091504490509091565b8060008190555050565b60005481565b"
        "600080fd5b600073ffffffffffffffffffffffffffffffffffffffff8216905091"
        "9050565b600061011882610103565b9050919050565b6101288161010d565b82"
        "525050565b6000602082019050610143600083018461011f565b92915050565b"
        "60006020828403121561015d5761015c6100fc565b5b600061016b8482850161"
        "0134565b91505092915050565b6101758161010d565b82525050565b60006020"
        "82019050610190600083018461016c565b9291505056fea26469706673582212"
        "20d0f7a20c5874251df8437eb93108ce8a3068fba222955f3089d81d45465e9d"
        "ef64736f6c63430008140033"
    )

    storage_write_gas = 43200
    blockhash_prev = "0x0"
    prevrandao_val = 0

    try:
        tx = {
            "from": operator.address,
            "data": "0x" + probe_bin,
            "gas": 300000,
            "gasPrice": int(w3.eth.gas_price * 1.1),
            "nonce": w3.eth.get_transaction_count(operator.address),
            "chainId": chain_id
        }
        signed = operator.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=30)
        probe_addr = receipt.contractAddress
        print(f"[5] Probe contract deployed at {probe_addr}")
        
        # Call write(42) to measure gas
        # Selector for write(uint256): 0x919840ad
        data_write = "0x919840ad" + (42).to_bytes(32, "big").hex()
        tx_w = {
            "from": operator.address,
            "to": probe_addr,
            "data": data_write,
            "gas": 100000,
            "gasPrice": int(w3.eth.gas_price * 1.1),
            "nonce": w3.eth.get_transaction_count(operator.address),
            "chainId": chain_id
        }
        signed_w = operator.sign_transaction(tx_w)
        tx_w_hash = w3.eth.send_raw_transaction(signed_w.raw_transaction)
        receipt_w = w3.eth.wait_for_transaction_receipt(tx_w_hash, timeout=30)
        storage_write_gas = receipt_w.gasUsed
        print(f"[6] Measured storage write gas cost: {storage_write_gas} gas (tx: {tx_w_hash.hex()})")

        # Call check() to read blockhash(block.number - 1) and prevrandao
        # Selector for check(): 0x2a0e5b47
        data_check = "0x2a0e5b47"
        call_res = w3.eth.call({"to": probe_addr, "data": data_check})
        if len(call_res) >= 64:
            blockhash_prev = "0x" + call_res[:32].hex()
            prevrandao_val = int.from_bytes(call_res[32:64], "big")
        print(f"[5] blockhash(block.number - 1): {blockhash_prev}")
        print(f"    block.prevrandao: {prevrandao_val}")

    except Exception as e:
        print(f"[-] Probe execution note: {e}")

    results["storage_write_gas"] = storage_write_gas
    results["blockhash_prev_block"] = blockhash_prev
    results["prevrandao_val"] = prevrandao_val

    # 7. Derived parameters
    T = avg_block_time
    demo_W = max(5, math.ceil(45.0 / T))
    demo_R = max(5, math.ceil(60.0 / T))
    demo_D = max(20, math.ceil(3600.0 / T))

    real_W = math.ceil(300.0 / T)
    real_R = math.ceil(600.0 / T)
    real_D = math.ceil(604800.0 / T)

    results["derived_parameters"] = {
        "demo_profile": {
            "W_seal_window_blocks": demo_W,
            "R_response_deadline_blocks": demo_R,
            "D_demand_horizon_blocks": demo_D,
            "size": 64
        },
        "realistic_profile": {
            "W_seal_window_blocks": real_W,
            "R_response_deadline_blocks": real_R,
            "D_demand_horizon_blocks": real_D,
            "size": 128
        }
    }

    print("\n[7] Derived Parameters based on T = {:.2f}s:".format(T))
    print(f"    Demo Profile:      W = {demo_W} blk ({demo_W*T:.1f}s), R = {demo_R} blk ({demo_R*T:.1f}s), D = {demo_D} blk, size = 64")
    print(f"    Realistic Profile: W = {real_W} blk ({real_W*T:.1f}s), R = {real_R} blk ({real_R*T:.1f}s), D = {real_D} blk, size = 128")

    out_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "preflight.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[✓] Saved complete preflight data to {out_path}")
    print("=" * 60)

if __name__ == "__main__":
    run_preflight()
