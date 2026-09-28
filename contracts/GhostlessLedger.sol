// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "./utils/ReentrancyGuard.sol";

/**
 * @title GhostlessLedger
 * @notice Proof of Non-Omission for Decision Ledgers on MST Blockchain.
 * Guarantees gapless sequence reservation before decisions exist,
 * bonded inclusion challenge response deadlines, equivocation slashing,
 * verifiable policy fraud proofs, and monotonic frozen states.
 */
contract GhostlessLedger is EIP712, ReentrancyGuard {
    using ECDSA for bytes32;

    struct Window {
        uint64 startSeq;
        uint32 size; // power of two, 64..256
        uint64 openedAt; // block.number at openWindow
        uint64 sealDeadline; // openedAt + W
        uint64 sealedAt; // 0 = unsealed
        bytes32 root; // positional Merkle root, 0 until sealed
    }

    struct Receipt {
        uint256 windowId;
        uint64 seq;
        bytes32 leaf;
    }

    struct Demand {
        Receipt r;
        address demander;
        uint64 answerBy;
        uint256 fee;
        bool resolved;
    }

    struct PolicyRecord {
        uint16 ruleId;
        uint8 outcome; // 0 = Denied, 1 = Approved, 255 = Padding
        uint8 riskBucket; // 0..15 quantized
        uint32 routeId;
        uint64 blockRef;
        bytes4 blockHashPrefix;
        address subject;
        bytes32 actuatorId;
        bytes32 actionHash;
        uint64 nonce;
    }

    enum Kind {
        Unsealed,
        Equivocation,
        NoResponse,
        PolicyFraud
    }

    // EIP-712 TypeHash
    bytes32 public constant RECEIPT_TYPEHASH =
        keccak256("Receipt(uint256 windowId,uint64 seq,bytes32 leaf)");

    address public constant BURN_ADDRESS =
        0x000000000000000000000000000000000000dEaD;
    uint32 public constant MAX_OPEN = 2;

    // Configurable protocol parameters
    uint64 public immutable W; // seal window (blocks)
    uint64 public immutable R; // response deadline (blocks)
    uint64 public immutable D; // demand horizon (blocks)
    uint256 public immutable minBond;
    uint256 public immutable demandFee;
    uint16 public immutable slashBps; // 10000 = 100%

    // Operator state
    address public operator;
    uint256 public bond;
    bool public frozen;
    uint32 public openCount;
    uint256 public nextToSeal;
    uint64 public nextSeq;
    bytes32 public headCheckpoint;

    Window[] public windows;
    Demand[] public demands;
    mapping(bytes32 => bool) public demanded; // keccak(windowId, seq) => bool

    event OperatorRegistered(address indexed operator, uint256 bond);
    event BondToppedUp(address indexed operator, uint256 additionalBond, uint256 totalBond);
    event WindowOpened(
        uint256 indexed windowId,
        uint64 startSeq,
        uint32 size,
        uint64 openedAt,
        uint64 sealDeadline
    );
    event WindowSealed(
        uint256 indexed windowId,
        bytes32 root,
        bytes32 headCheckpoint
    );
    event DemandOpened(
        uint256 indexed demandId,
        uint256 indexed windowId,
        uint64 seq,
        address demander,
        uint64 answerBy
    );
    event DemandAnswered(uint256 indexed demandId);
    event Slashed(
        Kind kind,
        uint256 indexed windowId,
        address reporter,
        uint256 amount
    );
    event OperatorWithdrawn(address indexed operator, uint256 amount);

    constructor(
        uint64 _W,
        uint64 _R,
        uint64 _D,
        uint256 _minBond,
        uint256 _demandFee,
        uint16 _slashBps
    ) EIP712("GhostlessLedger", "1") {
        require(_W > 0 && _R > 0 && _D > 0, "Invalid timing windows");
        require(_minBond > 0, "minBond must be > 0");
        require(_slashBps <= 10000, "slashBps > 100%");
        W = _W;
        R = _R;
        D = _D;
        minBond = _minBond;
        demandFee = _demandFee;
        slashBps = _slashBps;
    }

    modifier onlyOperator() {
        require(msg.sender == operator, "Caller is not operator");
        _;
    }

    modifier notFrozen() {
        require(!frozen, "Operator is frozen");
        _;
    }

    // ==========================================
    // OPERATOR LIFECYCLE
    // ==========================================

    function registerOperator() external payable nonReentrant {
        require(operator == address(0), "Operator already registered");
        require(msg.value >= minBond, "Insufficient bond");
        operator = msg.sender;
        bond = msg.value;
        emit OperatorRegistered(msg.sender, msg.value);
    }

    function topUpBond() external payable onlyOperator nonReentrant {
        require(msg.value > 0, "Must send value");
        bond += msg.value;
        emit BondToppedUp(msg.sender, msg.value, bond);
    }

    function openWindow(uint32 size)
        external
        onlyOperator
        notFrozen
        returns (uint256 windowId)
    {
        require(isPow2(size) && size >= 64 && size <= 256, "Invalid size");
        require(openCount < MAX_OPEN, "Exceeds MAX_OPEN");
        require(bond >= minBond, "Bond below minimum");

        windowId = windows.length;
        uint64 curSeq = nextSeq;
        uint64 openedAt = uint64(block.number);
        uint64 sealDeadline = openedAt + W;

        windows.push(
            Window({
                startSeq: curSeq,
                size: size,
                openedAt: openedAt,
                sealDeadline: sealDeadline,
                sealedAt: 0,
                root: bytes32(0)
            })
        );

        nextSeq += size;
        openCount++;

        emit WindowOpened(windowId, curSeq, size, openedAt, sealDeadline);
        return windowId;
    }

    function sealWindow(uint256 windowId, bytes32 root)
        external
        onlyOperator
        notFrozen
    {
        require(windowId < windows.length, "Invalid windowId");
        require(windowId == nextToSeal, "Must seal strictly in order");
        Window storage w = windows[windowId];
        require(w.sealedAt == 0, "Already sealed");
        require(block.number <= w.sealDeadline, "Seal deadline passed");
        require(root != bytes32(0), "Root cannot be zero");

        w.root = root;
        w.sealedAt = uint64(block.number);
        nextToSeal++;
        openCount--;

        headCheckpoint = keccak256(
            abi.encode(headCheckpoint, windowId, w.startSeq, w.size, root)
        );

        emit WindowSealed(windowId, root, headCheckpoint);
    }

    // ==========================================
    // ENFORCEMENT & DISPUTE
    // ==========================================

    function slashUnsealed(uint256 windowId) external nonReentrant {
        require(windowId < windows.length, "Invalid windowId");
        Window storage w = windows[windowId];
        require(w.sealedAt == 0, "Already sealed");
        require(block.number > w.sealDeadline, "Seal deadline not yet passed");

        _slash(Kind.Unsealed, windowId, msg.sender);
    }

    function proveEquivocation(
        Receipt calldata a,
        bytes calldata sigA,
        Receipt calldata b,
        bytes calldata sigB
    ) external nonReentrant {
        require(a.windowId == b.windowId, "Different windows");
        require(a.seq == b.seq, "Different seq");
        require(a.leaf != b.leaf, "Leaves are identical");
        require(a.windowId < windows.length, "Invalid windowId");

        Window storage w = windows[a.windowId];
        require(
            a.seq >= w.startSeq && a.seq < w.startSeq + w.size,
            "Seq out of range"
        );

        address recA = recoverReceiptSigner(a, sigA);
        address recB = recoverReceiptSigner(b, sigB);

        require(recA == operator, "sigA not signed by operator");
        require(recB == operator, "sigB not signed by operator");

        _slash(Kind.Equivocation, a.windowId, msg.sender);
    }

    function demandInclusion(Receipt calldata r, bytes calldata sig)
        external
        payable
        nonReentrant
    {
        require(r.windowId < windows.length, "Invalid windowId");
        Window storage w = windows[r.windowId];
        require(w.sealedAt != 0, "Window not sealed yet");
        require(block.number <= w.sealDeadline + D, "Demand horizon expired");
        require(
            r.seq >= w.startSeq && r.seq < w.startSeq + w.size,
            "Seq out of window range"
        );
        require(msg.value >= demandFee, "Insufficient demand fee");

        bytes32 demandKey = keccak256(abi.encode(r.windowId, r.seq));
        require(!demanded[demandKey], "Slot already demanded");
        demanded[demandKey] = true;

        address recovered = recoverReceiptSigner(r, sig);
        require(recovered == operator, "Receipt not signed by operator");

        uint256 demandId = demands.length;
        uint64 answerBy = uint64(block.number + R);

        demands.push(
            Demand({
                r: r,
                demander: msg.sender,
                answerBy: answerBy,
                fee: msg.value,
                resolved: false
            })
        );

        emit DemandOpened(demandId, r.windowId, r.seq, msg.sender, answerBy);
    }

    function respondInclusion(uint256 demandId, bytes32[] calldata proof)
        external
        onlyOperator
        nonReentrant
    {
        require(demandId < demands.length, "Invalid demandId");
        Demand storage d = demands[demandId];
        require(!d.resolved, "Demand already resolved");
        require(block.number <= d.answerBy, "Response deadline passed");

        Window storage w = windows[d.r.windowId];
        uint64 index = d.r.seq - w.startSeq;

        bool ok = _verifyPositionalProof(
            w.root,
            d.r.leaf,
            index,
            proof,
            w.size
        );
        require(ok, "Invalid inclusion proof");

        d.resolved = true;
        uint256 fee = d.fee;

        // Anti-griefing: fee is paid to operator for successfully answering honest demand
        (bool sent, ) = payable(operator).call{value: fee}("");
        require(sent, "Fee transfer failed");

        emit DemandAnswered(demandId);
    }

    function slashNoResponse(uint256 demandId) external nonReentrant {
        require(demandId < demands.length, "Invalid demandId");
        Demand storage d = demands[demandId];
        require(!d.resolved, "Demand already resolved");
        require(block.number > d.answerBy, "Response deadline not passed");

        d.resolved = true;
        uint256 refundFee = d.fee;
        address demander = d.demander;

        // Refund demand fee to the demander
        (bool sentRefund, ) = payable(demander).call{value: refundFee}("");
        require(sentRefund, "Refund failed");

        _slash(Kind.NoResponse, d.r.windowId, msg.sender);
    }

    /**
     * @notice Proves policy fraud on-chain when an operator commits a leaf whose
     * recordP violates defined policy constraints (e.g. impossible outcome, contradictory risk/rule).
     */
    function provePolicyFraud(
        uint256 windowId,
        uint64 seq,
        bytes calldata recordPBytes,
        bytes32 privCommit,
        bytes32[] calldata proof
    ) external nonReentrant {
        require(windowId < windows.length, "Invalid windowId");
        Window storage w = windows[windowId];
        require(w.sealedAt != 0, "Window not sealed");
        require(
            seq >= w.startSeq && seq < w.startSeq + w.size,
            "Seq out of range"
        );

        // Reconstruct leaf according to Section 2.3 specification
        bytes32 recordPHash = keccak256(recordPBytes);
        bytes32 expectedLeaf = keccak256(
            abi.encodePacked(
                bytes1(0x00),
                abi.encode(windowId, seq, recordPHash, privCommit)
            )
        );

        // Verify leaf is included in the committed window root
        uint64 index = seq - w.startSeq;
        bool included = _verifyPositionalProof(
            w.root,
            expectedLeaf,
            index,
            proof,
            w.size
        );
        require(included, "Leaf not included in window root");

        // Decode recordP fields
        PolicyRecord memory p = abi.decode(recordPBytes, (PolicyRecord));

        // Policy invariants:
        // 1. Outcome must be 0 (Denied), 1 (Approved), or 255 (Padding). Any other value is illegal.
        // 2. Risk bucket must be quantized to 0..15.
        // 3. If outcome == 255 (Padding), then ruleId must be 0, riskBucket must be 0, actionHash must be 0.
        // 4. If ruleId == 999 (Strict Reject Rule), outcome MUST NOT be 1 (Approved).
        // If any invariant is violated in this included leaf, it constitutes demonstrable Policy Fraud.
        bool isFraud = false;

        if (p.outcome != 0 && p.outcome != 1 && p.outcome != 255) {
            isFraud = true;
        } else if (p.riskBucket > 15) {
            isFraud = true;
        } else if (p.ruleId == 999 && p.outcome == 1) {
            // Contradiction: Strict Deny Rule approved
            isFraud = true;
        } else if (p.outcome == 255 && (p.ruleId != 0 || p.actionHash != bytes32(0))) {
            // Falsified padding leaf with non-zero payload
            isFraud = true;
        }

        require(isFraud, "No policy fraud demonstrated");

        _slash(Kind.PolicyFraud, windowId, msg.sender);
    }

    // ==========================================
    // VIEWS FOR ACTUATORS AND WATCHERS
    // ==========================================

    function acceptable(uint256 windowId, uint64 seq)
        external
        view
        returns (bool)
    {
        if (frozen || bond < minBond || windowId >= windows.length) {
            return false;
        }
        Window storage w = windows[windowId];
        return (seq >= w.startSeq &&
            seq < w.startSeq + w.size &&
            w.sealedAt == 0 &&
            block.number <= w.sealDeadline);
    }

    function verifyInclusion(
        uint256 windowId,
        uint64 seq,
        bytes32 leaf,
        bytes32[] calldata proof
    ) external view returns (bool) {
        if (windowId >= windows.length) return false;
        Window storage w = windows[windowId];
        if (w.sealedAt == 0) return false;
        if (seq < w.startSeq || seq >= w.startSeq + w.size) return false;
        uint64 index = seq - w.startSeq;
        return _verifyPositionalProof(w.root, leaf, index, proof, w.size);
    }

    function recoverReceiptSigner(Receipt calldata r, bytes calldata sig)
        public
        view
        returns (address)
    {
        bytes32 structHash = keccak256(
            abi.encode(RECEIPT_TYPEHASH, r.windowId, r.seq, r.leaf)
        );
        bytes32 digest = _hashTypedDataV4(structHash);
        return ECDSA.recover(digest, sig);
    }

    function getReceiptDigest(Receipt calldata r)
        external
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(
            abi.encode(RECEIPT_TYPEHASH, r.windowId, r.seq, r.leaf)
        );
        return _hashTypedDataV4(structHash);
    }

    function windowCount() external view returns (uint256) {
        return windows.length;
    }

    function getWindow(uint256 windowId) external view returns (Window memory) {
        require(windowId < windows.length, "Invalid windowId");
        return windows[windowId];
    }

    function getDemand(uint256 demandId) external view returns (Demand memory) {
        require(demandId < demands.length, "Invalid demandId");
        return demands[demandId];
    }

    function demandCount() external view returns (uint256) {
        return demands.length;
    }

    // ==========================================
    // INTERNAL LOGIC
    // ==========================================

    function _slash(
        Kind kind,
        uint256 windowId,
        address reporter
    ) internal {
        uint256 slashAmount = (bond * slashBps) / 10000;
        bond -= slashAmount;
        frozen = true;

        uint256 reporterBounty = slashAmount / 2;
        uint256 burnAmount = slashAmount - reporterBounty;

        if (reporterBounty > 0) {
            (bool sentReporter, ) = payable(reporter).call{
                value: reporterBounty
            }("");
            require(sentReporter, "Reporter bounty failed");
        }

        if (burnAmount > 0) {
            (bool sentBurn, ) = payable(BURN_ADDRESS).call{value: burnAmount}(
                ""
            );
            require(sentBurn, "Burn transfer failed");
        }

        emit Slashed(kind, windowId, reporter, slashAmount);
    }

    function _verifyPositionalProof(
        bytes32 root,
        bytes32 leaf,
        uint64 index,
        bytes32[] calldata proof,
        uint32 size
    ) internal pure returns (bool) {
        uint256 depth = 0;
        uint32 s = size;
        while (s > 1) {
            depth++;
            s >>= 1;
        }
        if (proof.length != depth) return false;

        bytes32 h = leaf;
        for (uint256 i = 0; i < depth; i++) {
            bytes32 p = proof[i];
            if ((index & 1) == 0) {
                // Leaf is on left: keccak256(0x01 || left || right)
                h = keccak256(abi.encodePacked(bytes1(0x01), h, p));
            } else {
                // Leaf is on right: keccak256(0x01 || left || right)
                h = keccak256(abi.encodePacked(bytes1(0x01), p, h));
            }
            index >>= 1;
        }
        return h == root;
    }

    function isPow2(uint32 x) internal pure returns (bool) {
        return (x != 0) && ((x & (x - 1)) == 0);
    }
}
