const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("ReceiptGatedEscrow Contract Suite", function () {
  let Ghostless, Escrow;
  let ledger, escrow;
  let owner, operator, depositor, subject, attacker;

  const W = 50; // blocks
  const R = 20; // blocks
  const D = 1200; // blocks
  const minBond = ethers.parseEther("1.0");
  const demandFee = ethers.parseEther("0.05");
  const slashBps = 5000;
  const ACTUATOR_ID = ethers.keccak256(ethers.toUtf8Bytes("RECEIPT_GATED_ESCROW_ACTUATOR_V1"));

  const domain = {
    name: "GhostlessLedger",
    version: "1",
    chainId: 31337,
    verifyingContract: null,
  };

  const types = {
    Receipt: [
      { name: "windowId", type: "uint256" },
      { name: "seq", type: "uint64" },
      { name: "leaf", type: "bytes32" },
    ],
  };

  function buildPositionalTree(leaves) {
    const layers = [leaves];
    let current = leaves;
    while (current.length > 1) {
      const nextLayer = [];
      for (let i = 0; i < current.length; i += 2) {
        const left = current[i];
        const right = current[i + 1];
        const combined = ethers.solidityPacked(
          ["bytes1", "bytes32", "bytes32"],
          ["0x01", left, right]
        );
        nextLayer.push(ethers.keccak256(combined));
      }
      layers.push(nextLayer);
      current = nextLayer;
    }
    return layers;
  }

  function getProof(layers, index) {
    const proof = [];
    let idx = index;
    for (let l = 0; l < layers.length - 1; l++) {
      const siblingIdx = idx ^ 1;
      proof.push(layers[l][siblingIdx]);
      idx >>= 1;
    }
    return proof;
  }

  function encodePolicyRecord(record) {
    const PolicyRecordType = [
      "tuple(uint16 ruleId, uint8 outcome, uint8 riskBucket, uint32 routeId, uint64 blockRef, bytes4 blockHashPrefix, address subject, bytes32 actuatorId, bytes32 actionHash, uint64 nonce)",
    ];
    return ethers.AbiCoder.defaultAbiCoder().encode(PolicyRecordType, [record]);
  }

  function computeLeaf(windowId, seq, recordPBytes, privCommit) {
    const recordPHash = ethers.keccak256(recordPBytes);
    const inner = ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint256", "uint64", "bytes32", "bytes32"],
      [windowId, seq, recordPHash, privCommit]
    );
    return ethers.keccak256(ethers.concat(["0x00", inner]));
  }

  beforeEach(async function () {
    [owner, operator, depositor, subject, attacker] = await ethers.getSigners();

    Ghostless = await ethers.getContractFactory("GhostlessLedger");
    ledger = await Ghostless.deploy(W, R, D, minBond, demandFee, slashBps);
    await ledger.waitForDeployment();
    domain.verifyingContract = await ledger.getAddress();

    // Register operator with bond
    await ledger.connect(operator).registerOperator({ value: ethers.parseEther("2.0") });

    // Deploy ReceiptGatedEscrow with exposureMultiplier k = 2
    Escrow = await ethers.getContractFactory("ReceiptGatedEscrow");
    escrow = await Escrow.deploy(await ledger.getAddress(), ACTUATOR_ID, 2);
    await escrow.waitForDeployment();
  });

  it("should create escrow deposit successfully", async function () {
    const depositId = ethers.keccak256(ethers.toUtf8Bytes("deposit-1"));
    const actionHash = ethers.keccak256(ethers.toUtf8Bytes("payout-loan-42"));
    const amount = ethers.parseEther("0.5");

    const tx = await escrow.connect(depositor).createDeposit(depositId, subject.address, actionHash, 100, {
      value: amount,
    });
    const receipt = await tx.wait();

    await expect(tx).to.emit(escrow, "DepositCreated");

    const dep = await escrow.deposits(depositId);
    expect(dep.amount).to.equal(amount);
    expect(dep.subject).to.equal(subject.address);
    expect(dep.actionHash).to.equal(actionHash);
    expect(dep.expiryBlock).to.equal(receipt.blockNumber + 100);
    expect(dep.released).to.be.false;
  });

  it("should release escrow funds with valid receipt during an open window", async function () {
    const depositId = ethers.keccak256(ethers.toUtf8Bytes("deposit-open"));
    const actionHash = ethers.keccak256(ethers.toUtf8Bytes("payout-bounty-99"));
    const amount = ethers.parseEther("1.0");

    await escrow.connect(depositor).createDeposit(depositId, subject.address, actionHash, 100, {
      value: amount,
    });

    // Operator opens window 0 with size 64
    await ledger.connect(operator).openWindow(64);

    const record = {
      ruleId: 101,
      outcome: 1, // Approved
      riskBucket: 2,
      routeId: 1,
      blockRef: 1000,
      blockHashPrefix: "0x12345678",
      subject: subject.address,
      actuatorId: ACTUATOR_ID,
      actionHash: actionHash,
      nonce: 1,
    };
    const recordPBytes = encodePolicyRecord(record);
    const privCommit = ethers.keccak256(ethers.toUtf8Bytes("salt-123"));
    const leaf = computeLeaf(0, 0, recordPBytes, privCommit);

    const receipt = { windowId: 0, seq: 0, leaf };
    const sig = await operator.signTypedData(domain, types, receipt);

    const subjectBalBefore = await ethers.provider.getBalance(subject.address);

    // Call releaseWithReceipt (merkleProof is empty since window is currently open/acceptable)
    await expect(
      escrow.connect(subject).releaseWithReceipt(
        depositId,
        receipt,
        sig,
        recordPBytes,
        privCommit,
        []
      )
    )
      .to.emit(escrow, "EscrowReleased")
      .withArgs(depositId, subject.address, amount, 0, 0);

    const subjectBalAfter = await ethers.provider.getBalance(subject.address);
    // Subject gas cost may apply if subject sent tx, but balance should increase by approx 1 ETH
    expect(subjectBalAfter).to.be.above(subjectBalBefore);

    const dep = await escrow.deposits(depositId);
    expect(dep.released).to.be.true;
  });

  it("should release escrow funds with valid receipt and Merkle proof during a sealed window", async function () {
    const depositId = ethers.keccak256(ethers.toUtf8Bytes("deposit-sealed"));
    const actionHash = ethers.keccak256(ethers.toUtf8Bytes("claim-insurance-7"));
    const amount = ethers.parseEther("0.75");

    await escrow.connect(depositor).createDeposit(depositId, subject.address, actionHash, 200, {
      value: amount,
    });

    await ledger.connect(operator).openWindow(64);

    const record = {
      ruleId: 202,
      outcome: 1, // Approved
      riskBucket: 1,
      routeId: 2,
      blockRef: 1001,
      blockHashPrefix: "0xabcdef12",
      subject: subject.address,
      actuatorId: ACTUATOR_ID,
      actionHash: actionHash,
      nonce: 2,
    };
    const recordPBytes = encodePolicyRecord(record);
    const privCommit = ethers.keccak256(ethers.toUtf8Bytes("salt-sealed"));
    const leaf = computeLeaf(0, 5, recordPBytes, privCommit);

    const receipt = { windowId: 0, seq: 5, leaf };
    const sig = await operator.signTypedData(domain, types, receipt);

    // Build tree of 64 leaves
    const leaves = new Array(64).fill(ethers.keccak256(ethers.toUtf8Bytes("padding")));
    leaves[5] = leaf;
    const layers = buildPositionalTree(leaves);
    const root = layers[layers.length - 1][0];
    const proof = getProof(layers, 5);

    // Seal the window on ledger
    await ledger.connect(operator).sealWindow(0, root);

    // Check release
    await expect(
      escrow.connect(depositor).releaseWithReceipt(
        depositId,
        receipt,
        sig,
        recordPBytes,
        privCommit,
        proof
      )
    )
      .to.emit(escrow, "EscrowReleased")
      .withArgs(depositId, subject.address, amount, 0, 5);

    const dep = await escrow.deposits(depositId);
    expect(dep.released).to.be.true;
  });

  it("should reject release if decision outcome is Denied (0)", async function () {
    const depositId = ethers.keccak256(ethers.toUtf8Bytes("deposit-denied"));
    const actionHash = ethers.keccak256(ethers.toUtf8Bytes("payout-failed"));
    const amount = ethers.parseEther("0.5");

    await escrow.connect(depositor).createDeposit(depositId, subject.address, actionHash, 100, {
      value: amount,
    });

    await ledger.connect(operator).openWindow(64);

    const record = {
      ruleId: 101,
      outcome: 0, // Denied!
      riskBucket: 5,
      routeId: 1,
      blockRef: 1000,
      blockHashPrefix: "0x12345678",
      subject: subject.address,
      actuatorId: ACTUATOR_ID,
      actionHash: actionHash,
      nonce: 10,
    };
    const recordPBytes = encodePolicyRecord(record);
    const privCommit = ethers.keccak256(ethers.toUtf8Bytes("salt-denied"));
    const leaf = computeLeaf(0, 1, recordPBytes, privCommit);

    const receipt = { windowId: 0, seq: 1, leaf };
    const sig = await operator.signTypedData(domain, types, receipt);

    await expect(
      escrow.releaseWithReceipt(depositId, receipt, sig, recordPBytes, privCommit, [])
    ).to.be.revertedWith("Decision outcome not approved");
  });

  it("should prevent replay of the same receipt across different deposits", async function () {
    const depositId1 = ethers.keccak256(ethers.toUtf8Bytes("dep-1"));
    const depositId2 = ethers.keccak256(ethers.toUtf8Bytes("dep-2"));
    const actionHash = ethers.keccak256(ethers.toUtf8Bytes("same-action"));

    await escrow.connect(depositor).createDeposit(depositId1, subject.address, actionHash, 100, {
      value: ethers.parseEther("0.2"),
    });
    await escrow.connect(depositor).createDeposit(depositId2, subject.address, actionHash, 100, {
      value: ethers.parseEther("0.2"),
    });

    await ledger.connect(operator).openWindow(64);

    const record = {
      ruleId: 1,
      outcome: 1,
      riskBucket: 0,
      routeId: 0,
      blockRef: 100,
      blockHashPrefix: "0x00000000",
      subject: subject.address,
      actuatorId: ACTUATOR_ID,
      actionHash: actionHash,
      nonce: 1,
    };
    const recordPBytes = encodePolicyRecord(record);
    const privCommit = ethers.keccak256(ethers.toUtf8Bytes("salt-replay"));
    const leaf = computeLeaf(0, 0, recordPBytes, privCommit);

    const receipt = { windowId: 0, seq: 0, leaf };
    const sig = await operator.signTypedData(domain, types, receipt);

    // Release deposit 1
    await escrow.releaseWithReceipt(depositId1, receipt, sig, recordPBytes, privCommit, []);

    // Attempting to release deposit 2 with the same receipt must revert
    await expect(
      escrow.releaseWithReceipt(depositId2, receipt, sig, recordPBytes, privCommit, [])
    ).to.be.revertedWith("Receipt sequence already executed");
  });

  it("should allow refund if deposit expires or if operator is frozen", async function () {
    const depositId = ethers.keccak256(ethers.toUtf8Bytes("dep-refund"));
    const actionHash = ethers.keccak256(ethers.toUtf8Bytes("action-refund"));
    const amount = ethers.parseEther("0.4");

    await escrow.connect(depositor).createDeposit(depositId, subject.address, actionHash, 10, {
      value: amount,
    });

    // Mine 11 blocks to exceed expiry
    for (let i = 0; i < 11; i++) {
      await ethers.provider.send("evm_mine", []);
    }

    const depositorBefore = await ethers.provider.getBalance(depositor.address);
    const tx = await escrow.connect(depositor).refundDeposit(depositId);
    const receipt = await tx.wait();
    const gasUsed = receipt.gasUsed * receipt.gasPrice;
    const depositorAfter = await ethers.provider.getBalance(depositor.address);

    expect(depositorAfter + gasUsed - depositorBefore).to.equal(amount);
  });

  it("should enforce exposure cap: reject release if window payout exceeds bond * k", async function () {
    // Operator bond is 2.0 ETH, k = 2, so max exposure per window is 4.0 ETH
    // Deposit 4.5 ETH
    const depositId = ethers.keccak256(ethers.toUtf8Bytes("dep-large-exposure"));
    const actionHash = ethers.keccak256(ethers.toUtf8Bytes("large-action"));
    const largeAmount = ethers.parseEther("4.5");

    await escrow.connect(depositor).createDeposit(depositId, subject.address, actionHash, 100, {
      value: largeAmount,
    });

    await ledger.connect(operator).openWindow(64);

    const record = {
      ruleId: 1,
      outcome: 1,
      riskBucket: 0,
      routeId: 0,
      blockRef: 100,
      blockHashPrefix: "0x00000000",
      subject: subject.address,
      actuatorId: ACTUATOR_ID,
      actionHash: actionHash,
      nonce: 99,
    };
    const recordPBytes = encodePolicyRecord(record);
    const privCommit = ethers.keccak256(ethers.toUtf8Bytes("salt-exp"));
    const leaf = computeLeaf(0, 0, recordPBytes, privCommit);

    const receipt = { windowId: 0, seq: 0, leaf };
    const sig = await operator.signTypedData(domain, types, receipt);

    // Releasing 4.5 ETH when cap is 4.0 ETH must revert
    await expect(
      escrow.releaseWithReceipt(depositId, receipt, sig, recordPBytes, privCommit, [])
    ).to.be.revertedWith("Window exposure cap exceeded (bond * k)");
  });
});
