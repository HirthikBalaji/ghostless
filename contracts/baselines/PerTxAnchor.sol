// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title PerTxAnchor (Baseline B0)
 * @notice Traditional per-decision anchoring: writes one leaf hash per transaction.
 * High gas cost (O(N) transactions), no batched aggregation.
 */
contract PerTxAnchor {
    event Anchored(uint256 indexed id, bytes32 indexed leafHash, uint256 timestamp);

    uint256 public totalAnchored;
    mapping(uint256 => bytes32) public leafRecords;

    function anchorDecision(bytes32 leafHash) external returns (uint256 id) {
        id = totalAnchored++;
        leafRecords[id] = leafHash;
        emit Anchored(id, leafHash, block.timestamp);
    }
}
