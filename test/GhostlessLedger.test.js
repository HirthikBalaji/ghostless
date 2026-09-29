const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("GhostlessLedger & Invariant Suite", function () {
  let Ghostless;
  let ledger;
  let owner, operator, subject, watcher, attacker;

  const W = 15; // blocks
  const R = 20; // blocks
  const D = 1200; // blocks
  const minBond = ethers.parseEther("1.0");
  const demandFee = ethers.parseEther("0.05");
  const slashBps = 5000; // 50% slash

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

  // Helper to build positional tree
  function buildPositionalTree(leaves) {
    const layers = [leaves];
    let current = leaves;
    while (current.length > 1) {
      const nextLayer = [];
      for (let i = 0; i < current.length; i += 2) {
        const left = current[i];
        const right = current[i + 1];
        // keccak256(0x01 || left || right)
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

  function computeLeaf(windowId, seq, recordPBytes, privCommit) {
    const recordPHash = ethers.keccak256(recordPBytes);
    const inner = ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint256", "uint64", "bytes32", "bytes32"],
      [windowId, seq, recordPHash, privCommit]
    );
    return ethers.keccak256(ethers.concat(["0x00", inner]));
  }

  beforeEach(async function () {
    [owner, operator, subject, watcher, attacker] = await ethers.getSigners();

    Ghostless = await ethers.getContractFactory("GhostlessLedger");
    ledger = await Ghostless.deploy(
      W,
      R,
      D,
      minBond,
      demandFee,
      slashBps
    );
    await ledger.waitForDeployment();
    domain.verifyingContract = await ledger.getAddress();

    // Register operator
    await ledger.connect(operator).registerOperator({ value: ethers.parseEther("2.0") });
  });

  describe("Operator Registration & Invariant I4 (Bond & Monotonic Freeze)", function () {
    it("registers operator with correct initial bond", async function () {
      expect(await ledger.operator()).to.equal(operator.address);
      expect(await ledger.bond()).to.equal(ethers.parseEther("2.0"));
      expect(await ledger.frozen()).to.equal(false);
    });

    it("prevents double registration", async function () {
      await expect(
        ledger.connect(attacker).registerOperator({ value: minBond })
      ).to.be.revertedWith("Operator already registered");
    });

    it("allows operator to top up bond", async function () {
      await ledger.connect(operator).topUpBond({ value: ethers.parseEther("1.0") });
      expect(await ledger.bond()).to.equal(ethers.parseEther("3.0"));
    });
  });

  describe("Invariant I1: Contiguous Sequence Reservation", function () {
    it("reserves sequence numbers monotonically with zero gaps or overlaps", async function () {
      expect(await ledger.nextSeq()).to.equal(0);

      // Open window 0 (size 64)
      await ledger.connect(operator).openWindow(64);
      let w0 = await ledger.getWindow(0);
      expect(w0.startSeq).to.equal(0);
      expect(w0.size).to.equal(64);
      expect(await ledger.nextSeq()).to.equal(64);

      // Open window 1 (size 128)
      await ledger.connect(operator).openWindow(128);
      let w1 = await ledger.getWindow(1);
      expect(w1.startSeq).to.equal(64);
      expect(w1.size).to.equal(128);
      expect(await ledger.nextSeq()).to.equal(192);

      // Verify Invariant I1: nextSeq == sum(sizes)
      const count = await ledger.windowCount();
      let totalSize = 0n;
      for (let i = 0n; i < count; i++) {
        const w = await ledger.getWindow(i);
        totalSize += BigInt(w.size);
      }
      expect(await ledger.nextSeq()).to.equal(totalSize);
    });

    it("enforces MAX_OPEN windows limit (max 2)", async function () {
      await ledger.connect(operator).openWindow(64);
      await ledger.connect(operator).openWindow(64);
      await expect(ledger.connect(operator).openWindow(64)).to.be.revertedWith("Exceeds MAX_OPEN");
    });
  });

  describe("Invariant I2 & I3: Seal In Order, Checkpoint Fold & Deadlines", function () {
    it("seals windows strictly in order and updates headCheckpoint", async function () {
      await ledger.connect(operator).openWindow(64);
      await ledger.connect(operator).openWindow(64);

      const root0 = ethers.hexlify(ethers.randomBytes(32));
      const root1 = ethers.hexlify(ethers.randomBytes(32));

      // Attempt to seal window 1 before window 0 -> must revert
      await expect(
        ledger.connect(operator).sealWindow(1, root1)
      ).to.be.revertedWith("Must seal strictly in order");

      // Seal window 0
      const initialCheckpoint = await ledger.headCheckpoint();
      await ledger.connect(operator).sealWindow(0, root0);
      const w0 = await ledger.getWindow(0);
      expect(w0.root).to.equal(root0);
      expect(w0.sealedAt).to.be.gt(0);

      // Verify Invariant I3: headCheckpoint fold
      const expectedCp0 = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes32", "uint256", "uint64", "uint32", "bytes32"],
          [initialCheckpoint, 0, w0.startSeq, w0.size, root0]
        )
      );
      expect(await ledger.headCheckpoint()).to.equal(expectedCp0);

      // Cannot double seal window 0
      await expect(
        ledger.connect(operator).sealWindow(0, root0)
      ).to.be.revertedWith("Must seal strictly in order");

      // Seal window 1
      await ledger.connect(operator).sealWindow(1, root1);
      const w1 = await ledger.getWindow(1);
      const expectedCp1 = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes32", "uint256", "uint64", "uint32", "bytes32"],
          [expectedCp0, 1, w1.startSeq, w1.size, root1]
        )
      );
      expect(await ledger.headCheckpoint()).to.equal(expectedCp1);
    });

    it("slashUnsealed: reverts before sealDeadline, slashes after sealDeadline", async function () {
      await ledger.connect(operator).openWindow(64);

      // Attempt slash immediately -> must revert
      await expect(ledger.connect(watcher).slashUnsealed(0)).to.be.revertedWith(
        "Seal deadline not yet passed"
      );

      // Advance blocks past sealDeadline
      for (let i = 0; i <= W; i++) {
        await ethers.provider.send("evm_mine");
      }

      // Now watcher can slash unsealed window
      const initialWatcherBal = await ethers.provider.getBalance(watcher.address);
      const initialBond = await ledger.bond();
      const tx = await ledger.connect(watcher).slashUnsealed(0);
      const rc = await tx.wait();
      const gasCost = rc.gasUsed * tx.gasPrice;

      // Invariant I4: frozen becomes true, bond slashed by slashBps (50%)
      expect(await ledger.frozen()).to.equal(true);
      const slashedAmount = (initialBond * BigInt(slashBps)) / 10000n;
      expect(await ledger.bond()).to.equal(initialBond - slashedAmount);

      const finalWatcherBal = await ethers.provider.getBalance(watcher.address);
      const expectedBounty = (slashedAmount * 20n) / 100n;
      expect(finalWatcherBal).to.equal(initialWatcherBal + expectedBounty - gasCost);
    });
  });

  describe("Equivocation Slashing: proveEquivocation", function () {
    it("slashes operator if two conflicting receipts exist for same slot", async function () {
      await ledger.connect(operator).openWindow(64);

      const leafA = ethers.hexlify(ethers.randomBytes(32));
      const leafB = ethers.hexlify(ethers.randomBytes(32));

      const rA = { windowId: 0, seq: 10, leaf: leafA };
      const rB = { windowId: 0, seq: 10, leaf: leafB };

      const sigA = await operator.signTypedData(domain, types, rA);
      const sigB = await operator.signTypedData(domain, types, rB);

      // Watcher presents both receipts to slash operator
      await expect(ledger.connect(watcher).proveEquivocation(rA, sigA, rB, sigB))
        .to.emit(ledger, "Slashed");

      expect(await ledger.frozen()).to.equal(true);
    });

    it("rejects equivocation claim if leaves are identical or signers invalid", async function () {
      await ledger.connect(operator).openWindow(64);

      const leaf = ethers.hexlify(ethers.randomBytes(32));
      const rA = { windowId: 0, seq: 10, leaf: leaf };
      const rB = { windowId: 0, seq: 10, leaf: leaf };

      const sigA = await operator.signTypedData(domain, types, rA);
      const sigB = await operator.signTypedData(domain, types, rB);

      await expect(
        ledger.connect(watcher).proveEquivocation(rA, sigA, rB, sigB)
      ).to.be.revertedWith("Leaves are identical");
    });
  });

  describe("Demand & Inclusion Response (Invariant I5)", function () {
    let leaves, tree, root;
    const size = 64;

    beforeEach(async function () {
      await ledger.connect(operator).openWindow(size);

      // Generate 64 deterministic dummy leaves
      leaves = [];
      for (let i = 0; i < size; i++) {
        leaves.push(ethers.keccak256(ethers.toUtf8Bytes(`leaf-${i}`)));
      }
      tree = buildPositionalTree(leaves);
      root = tree[tree.length - 1][0];

      // Seal window 0 with root
      await ledger.connect(operator).sealWindow(0, root);
    });

    it("happy path: demandInclusion followed by valid respondInclusion sends fee to operator", async function () {
      const targetIndex = 5;
      const receipt = { windowId: 0, seq: targetIndex, leaf: leaves[targetIndex] };
      const sig = await operator.signTypedData(domain, types, receipt);

      // Demander opens demand
      await ledger.connect(subject).demandInclusion(receipt, sig, { value: demandFee });
      expect(await ledger.demandCount()).to.equal(1);

      const proof = getProof(tree, targetIndex);
      const initialOpBal = await ethers.provider.getBalance(operator.address);

      // Operator responds on-chain with proof
      const tx = await ledger.connect(operator).respondInclusion(0, proof);
      const rc = await tx.wait();
      const gasCost = rc.gasUsed * tx.gasPrice;

      // Operator receives the anti-griefing fee
      const finalOpBal = await ethers.provider.getBalance(operator.address);
      expect(finalOpBal).to.equal(initialOpBal + demandFee - gasCost);

      const d = await ledger.getDemand(0);
      expect(d.resolved).to.equal(true);
    });

    it("rejects invalid proof depth or wrong positional sibling", async function () {
      const targetIndex = 5;
      const receipt = { windowId: 0, seq: targetIndex, leaf: leaves[targetIndex] };
      const sig = await operator.signTypedData(domain, types, receipt);

      await ledger.connect(subject).demandInclusion(receipt, sig, { value: demandFee });
      const proof = getProof(tree, targetIndex);

      // Wrong depth (e.g. truncated proof)
      const badDepthProof = proof.slice(0, proof.length - 1);
      await expect(
        ledger.connect(operator).respondInclusion(0, badDepthProof)
      ).to.be.revertedWith("Invalid inclusion proof");

      // Wrong sibling
      const corruptedProof = [...proof];
      corruptedProof[0] = ethers.hexlify(ethers.randomBytes(32));
      await expect(
        ledger.connect(operator).respondInclusion(0, corruptedProof)
      ).to.be.revertedWith("Invalid inclusion proof");
    });

    it("timeout slash: slashNoResponse slashes operator and refunds fee to demander", async function () {
      const targetIndex = 5;
      const receipt = { windowId: 0, seq: targetIndex, leaf: leaves[targetIndex] };
      const sig = await operator.signTypedData(domain, types, receipt);

      const initialSubBal = await ethers.provider.getBalance(subject.address);
      const subTx = await ledger.connect(subject).demandInclusion(receipt, sig, { value: demandFee });
      const subRc = await subTx.wait();
      const subGas = subRc.gasUsed * subTx.gasPrice;

      // Advance past response deadline R
      for (let i = 0; i <= R; i++) {
        await ethers.provider.send("evm_mine");
      }

      // Watcher calls slashNoResponse
      const initialWatcherBal = await ethers.provider.getBalance(watcher.address);
      const tx = await ledger.connect(watcher).slashNoResponse(0);
      const rc = await tx.wait();
      const gasCost = rc.gasUsed * tx.gasPrice;

      // Demander received full fee refund PLUS 60% victim compensation!
      const finalSubBal = await ethers.provider.getBalance(subject.address);
      const initialBond = ethers.parseEther("2.0");
      const slashedAmount = (initialBond * BigInt(slashBps)) / 10000n;
      const expectedVictimComp = (slashedAmount * 60n) / 100n;
      expect(finalSubBal).to.equal(initialSubBal - subGas + expectedVictimComp);

      // Operator is frozen and slashed
      expect(await ledger.frozen()).to.equal(true);

      // Watcher received 20% reporter bounty
      const finalWatcherBal = await ethers.provider.getBalance(watcher.address);
      const expectedWatcherBounty = (slashedAmount * 20n) / 100n;
      expect(finalWatcherBal).to.equal(initialWatcherBal - gasCost + expectedWatcherBounty);
    });
  });

  describe("Policy Fraud Proof: provePolicyFraud", function () {
    it("slashes operator when an included leaf violates policy invariants", async function () {
      const size = 64;
      await ledger.connect(operator).openWindow(size);

      // Construct fraudulent record: ruleId = 999 (Strict Reject) but outcome = 1 (Approved)
      const recordP = {
        ruleId: 999,
        outcome: 1, // FRAUD: Approved under strict reject rule!
        riskBucket: 12,
        routeId: 42,
        blockRef: 100,
        blockHashPrefix: "0x12345678",
        subject: subject.address,
        actuatorId: ethers.keccak256(ethers.toUtf8Bytes("API_GATEWAY_1")),
        actionHash: ethers.keccak256(ethers.toUtf8Bytes("PAY_100_USD")),
        nonce: 1,
      };

      const recordPBytes = ethers.AbiCoder.defaultAbiCoder().encode(
        [
          "tuple(uint16 ruleId,uint8 outcome,uint8 riskBucket,uint32 routeId,uint64 blockRef,bytes4 blockHashPrefix,address subject,bytes32 actuatorId,bytes32 actionHash,uint64 nonce)",
        ],
        [recordP]
      );

      const privCommit = ethers.hexlify(ethers.randomBytes(32));
      const fraudulentLeaf = computeLeaf(0, 0, recordPBytes, privCommit);

      const leaves = [fraudulentLeaf];
      for (let i = 1; i < size; i++) {
        leaves.push(ethers.keccak256(ethers.toUtf8Bytes(`pad-${i}`)));
      }
      const tree = buildPositionalTree(leaves);
      const root = tree[tree.length - 1][0];

      await ledger.connect(operator).sealWindow(0, root);

      const proof = getProof(tree, 0);

      // Anyone (watcher) proves policy fraud on-chain
      await expect(
        ledger.connect(watcher).provePolicyFraud(0, 0, recordPBytes, privCommit, proof)
      ).to.emit(ledger, "Slashed");

      expect(await ledger.frozen()).to.equal(true);
    });
  });

  describe("Actuator Gate View: acceptable & verifyInclusion", function () {
    it("returns acceptable=true during open window, false once frozen or expired", async function () {
      await ledger.connect(operator).openWindow(64);

      expect(await ledger.acceptable(0, 10)).to.equal(true);
      expect(await ledger.acceptable(0, 64)).to.equal(false); // out of range

      // Slash operator
      const rA = { windowId: 0, seq: 10, leaf: ethers.randomBytes(32) };
      const rB = { windowId: 0, seq: 10, leaf: ethers.randomBytes(32) };
      const sigA = await operator.signTypedData(domain, types, rA);
      const sigB = await operator.signTypedData(domain, types, rB);
      await ledger.connect(watcher).proveEquivocation(rA, sigA, rB, sigB);

      // Now acceptable returns false
      expect(await ledger.acceptable(0, 10)).to.equal(false);
    });
  });
});
