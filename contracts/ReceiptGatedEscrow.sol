// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./GhostlessLedger.sol";
import "./utils/ReentrancyGuard.sol";

/**
 * @title ReceiptGatedEscrow
 * @notice On-chain actuator contract enforcing "No Receipt -> No Effect" on MST Blockchain.
 * Holds funds in escrow that can ONLY be released to the beneficiary upon presenting
 * a cryptographically valid, approved decision receipt issued by the bonded Ghostless operator,
 * verified directly against GhostlessLedger.
 * Enforces an Exposure Cap: total release per window is capped at bond * k by design,
 * making operator malfeasance economically irrational.
 */
contract ReceiptGatedEscrow is ReentrancyGuard {
    GhostlessLedger public immutable ledger;
    bytes32 public immutable actuatorId;
    uint256 public immutable exposureMultiplier; // k factor (e.g. 2 means max 2x bond per window)

    struct EscrowDeposit {
        address depositor;
        address subject;
        uint256 amount;
        bytes32 actionHash;
        uint64 expiryBlock;
        bool released;
        bool refunded;
    }

    // depositId => EscrowDeposit
    mapping(bytes32 => EscrowDeposit) public deposits;

    // keccak256(windowId, seq) => bool (prevents replay across deposits)
    mapping(bytes32 => bool) public executedReceipts;

    // windowId => cumulative released funds
    mapping(uint256 => uint256) public windowExposure;

    event DepositCreated(
        bytes32 indexed depositId,
        address indexed depositor,
        address indexed subject,
        uint256 amount,
        bytes32 actionHash,
        uint64 expiryBlock
    );

    event EscrowReleased(
        bytes32 indexed depositId,
        address indexed subject,
        uint256 amount,
        uint256 windowId,
        uint64 seq
    );

    event DepositRefunded(
        bytes32 indexed depositId,
        address indexed depositor,
        uint256 amount,
        string reason
    );

    constructor(
        address _ledger,
        bytes32 _actuatorId,
        uint256 _exposureMultiplier
    ) {
        require(_ledger != address(0), "Invalid ledger address");
        ledger = GhostlessLedger(_ledger);
        actuatorId = _actuatorId;
        exposureMultiplier = (_exposureMultiplier == 0) ? 2 : _exposureMultiplier;
    }

    /**
     * @notice Locks native MSTC funds into escrow for a specific subject and actionHash.
     * @param depositId Unique identifier for this escrow deposit.
     * @param subject The authorized recipient / beneficiary of the decision.
     * @param actionHash keccak256 hash of the intended action payload.
     * @param expiryBlocks Number of blocks after which depositor can reclaim if unexecuted.
     */
    function createDeposit(
        bytes32 depositId,
        address subject,
        bytes32 actionHash,
        uint64 expiryBlocks
    ) external payable nonReentrant {
        require(msg.value > 0, "Deposit amount must be > 0");
        require(subject != address(0), "Invalid subject address");
        require(actionHash != bytes32(0), "Invalid actionHash");
        require(deposits[depositId].amount == 0, "Deposit ID already exists");
        require(expiryBlocks >= 10, "Expiry blocks too short");

        uint64 expiryBlock = uint64(block.number + expiryBlocks);

        deposits[depositId] = EscrowDeposit({
            depositor: msg.sender,
            subject: subject,
            amount: msg.value,
            actionHash: actionHash,
            expiryBlock: expiryBlock,
            released: false,
            refunded: false
        });

        emit DepositCreated(
            depositId,
            msg.sender,
            subject,
            msg.value,
            actionHash,
            expiryBlock
        );
    }

    function _validateReceipt(
        GhostlessLedger.Receipt calldata receipt,
        bytes calldata signature,
        bytes calldata recordPBytes,
        bytes32 privCommit
    ) internal view returns (bytes32 receiptKey) {
        // 1. Fail-closed: operator must not be frozen
        require(!ledger.frozen(), "Ledger operator is frozen");

        // 2. Signature verification
        address signer = ledger.recoverReceiptSigner(receipt, signature);
        require(signer == ledger.operator(), "Invalid operator signature");

        // 3. Leaf reconstruction & verification
        bytes32 recordPHash = keccak256(recordPBytes);
        bytes32 expectedLeaf = keccak256(
            abi.encodePacked(
                bytes1(0x00),
                abi.encode(receipt.windowId, receipt.seq, recordPHash, privCommit)
            )
        );
        require(receipt.leaf == expectedLeaf, "Receipt leaf mismatch");

        return keccak256(abi.encode(receipt.windowId, receipt.seq));
    }

    function _validatePolicy(
        bytes calldata recordPBytes,
        address expectedSubject,
        bytes32 expectedActionHash
    ) internal view {
        GhostlessLedger.PolicyRecord memory record = abi.decode(
            recordPBytes,
            (GhostlessLedger.PolicyRecord)
        );

        require(record.subject == expectedSubject, "Subject mismatch");
        require(record.actuatorId == actuatorId, "ActuatorId mismatch");
        require(record.actionHash == expectedActionHash, "ActionHash mismatch");
        require(record.outcome == 1, "Decision outcome not approved");
    }

    function _verifyGate(
        uint256 windowId,
        uint64 seq,
        bytes32 leaf,
        bytes32[] calldata merkleProof
    ) internal view {
        bool gatePassed = false;
        if (ledger.acceptable(windowId, seq)) {
            gatePassed = true;
        } else {
            gatePassed = ledger.verifyInclusion(
                windowId,
                seq,
                leaf,
                merkleProof
            );
        }
        require(gatePassed, "Actuator gate check failed on ledger");
    }

    function _checkExposureCap(uint256 windowId, uint256 amount) internal {
        uint256 currentBond = ledger.bond();
        uint256 maxExposure = currentBond * exposureMultiplier;
        require(
            windowExposure[windowId] + amount <= maxExposure,
            "Window exposure cap exceeded (bond * k)"
        );
        windowExposure[windowId] += amount;
    }

    /**
     * @notice Releases escrowed funds to subject upon verification of a valid Ghostless decision receipt.
     * Enforces the "No Receipt -> No Effect" invariant and the Exposure Cap on-chain.
     */
    function releaseWithReceipt(
        bytes32 depositId,
        GhostlessLedger.Receipt calldata receipt,
        bytes calldata signature,
        bytes calldata recordPBytes,
        bytes32 privCommit,
        bytes32[] calldata merkleProof
    ) external nonReentrant {
        EscrowDeposit storage dep = deposits[depositId];
        require(dep.amount > 0, "Deposit does not exist");
        require(!dep.released, "Deposit already released");
        require(!dep.refunded, "Deposit already refunded");
        require(block.number <= dep.expiryBlock, "Deposit expired");

        bytes32 receiptKey = _validateReceipt(
            receipt,
            signature,
            recordPBytes,
            privCommit
        );
        require(!executedReceipts[receiptKey], "Receipt sequence already executed");

        _validatePolicy(recordPBytes, dep.subject, dep.actionHash);
        _verifyGate(receipt.windowId, receipt.seq, receipt.leaf, merkleProof);
        _checkExposureCap(receipt.windowId, dep.amount);

        executedReceipts[receiptKey] = true;
        dep.released = true;

        (bool sent, ) = payable(dep.subject).call{value: dep.amount}("");
        require(sent, "Native transfer to subject failed");

        emit EscrowReleased(
            depositId,
            dep.subject,
            dep.amount,
            receipt.windowId,
            receipt.seq
        );
    }

    /**
     * @notice Refunds escrow deposit back to depositor if expired or if the ledger operator is frozen.
     */
    function refundDeposit(bytes32 depositId) external nonReentrant {
        EscrowDeposit storage dep = deposits[depositId];
        require(dep.amount > 0, "Deposit does not exist");
        require(!dep.released, "Deposit already released");
        require(!dep.refunded, "Deposit already refunded");

        bool isExpired = block.number > dep.expiryBlock;
        bool isOperatorFrozen = ledger.frozen();

        require(
            isExpired || isOperatorFrozen,
            "Refund conditions not met (neither expired nor frozen)"
        );

        dep.refunded = true;
        string memory reason = isOperatorFrozen ? "Operator Frozen" : "Expired";

        (bool sent, ) = payable(dep.depositor).call{value: dep.amount}("");
        require(sent, "Refund transfer failed");

        emit DepositRefunded(depositId, dep.depositor, dep.amount, reason);
    }
}
