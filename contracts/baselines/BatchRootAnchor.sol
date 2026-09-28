// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title BatchRootAnchor (Baseline B1)
 * @notice Standard naive Merkle root anchoring: operator batches decisions off-chain
 * and posts Merkle roots without sequence pre-reservation, without bounded seal deadlines,
 * and without on-chain bonded inclusion challenge/response or slashing.
 */
contract BatchRootAnchor {
    struct Batch {
        bytes32 root;
        uint256 count;
        uint256 timestamp;
    }

    event BatchAnchored(uint256 indexed batchId, bytes32 root, uint256 count);

    address public operator;
    Batch[] public batches;

    constructor() {
        operator = msg.sender;
    }

    function anchorBatch(bytes32 root, uint256 count) external returns (uint256 batchId) {
        require(msg.sender == operator, "Only operator");
        batchId = batches.length;
        batches.push(Batch({
            root: root,
            count: count,
            timestamp: block.timestamp
        }));
        emit BatchAnchored(batchId, root, count);
    }

    function verifyProof(
        uint256 batchId,
        bytes32 leaf,
        bytes32[] calldata proof
    ) external view returns (bool) {
        if (batchId >= batches.length) return false;
        bytes32 root = batches[batchId].root;
        bytes32 h = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 p = proof[i];
            h = h < p ? keccak256(abi.encodePacked(h, p)) : keccak256(abi.encodePacked(p, h));
        }
        return h == root;
    }
}
