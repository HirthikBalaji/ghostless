// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./GhostlessLedger.sol";

/**
 * @title OperatorRegistry
 * @notice Trust & Reputation evaluation contract for Ghostless Operators on MST Blockchain.
 * Enables external smart contracts, DAOs, and AI agent networks to verify whether
 * an operator is trusted, check their historical performance score, and inspect
 * active bond collateral before accepting signed decision receipts.
 */
contract OperatorRegistry {
    GhostlessLedger public immutable ledger;

    event OperatorEvaluated(
        address indexed operator,
        bool isTrusted,
        uint256 trustScore,
        uint256 bond
    );

    constructor(address _ledger) {
        require(_ledger != address(0), "Invalid ledger address");
        ledger = GhostlessLedger(_ledger);
    }

    /**
     * @notice Checks if an operator is currently trusted to issue valid, slashable decision receipts.
     * @param op Operator address to inspect.
     * @return trusted True if registered, not frozen, and holds sufficient active bond.
     */
    function isTrusted(address op) external view returns (bool) {
        if (op != ledger.operator() || op == address(0)) {
            return false;
        }
        if (ledger.frozen()) {
            return false;
        }
        if (ledger.bond() < ledger.minBond()) {
            return false;
        }
        return true;
    }

    /**
     * @notice Computes a normalized trust score (0 - 100) based on historical performance and bond backing.
     * @param op Operator address to inspect.
     * @return score Integer between 0 and 100.
     */
    function trustScore(address op) public view returns (uint256) {
        if (op != ledger.operator() || ledger.frozen()) {
            return 0;
        }

        uint256 bond = ledger.bond();
        uint256 minBond = ledger.minBond();

        if (bond < minBond) {
            return 10;
        }

        // Base trust for an active, un-slashed, bonded operator
        uint256 score = 60;

        // Reward for successfully sealed historical windows (+5 points per sealed window, up to +25)
        uint256 sealedWindows = ledger.nextToSeal();
        uint256 windowBonus = sealedWindows * 5;
        if (windowBonus > 25) {
            windowBonus = 25;
        }
        score += windowBonus;

        // Reward for collateral over-collateralization (+15 points for bond >= 2x minBond)
        if (bond >= minBond * 2) {
            score += 15;
        }

        if (score > 100) {
            score = 100;
        }

        return score;
    }

    /**
     * @notice Returns complete profile data for an operator in a single call.
     */
    function getOperatorProfile(address op)
        external
        view
        returns (
            bool trusted,
            uint256 score,
            uint256 activeBond,
            uint256 minRequiredBond,
            bool isFrozen,
            uint256 sealedWindows,
            uint256 openWindows
        )
    {
        trusted = (op == ledger.operator() && !ledger.frozen() && ledger.bond() >= ledger.minBond());
        score = trustScore(op);
        activeBond = (op == ledger.operator()) ? ledger.bond() : 0;
        minRequiredBond = ledger.minBond();
        isFrozen = ledger.frozen();
        sealedWindows = ledger.nextToSeal();
        openWindows = ledger.openCount();
    }
}
