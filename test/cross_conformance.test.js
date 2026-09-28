const { expect } = require("chai");
const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

describe("AC2: Cross-Language Conformance (Solidity/JS)", function () {
  let ledger;
  let operator;
  let vectors;

  before(async function () {
    const [deployer, op] = await ethers.getSigners();
    operator = op;

    const Ghostless = await ethers.getContractFactory("GhostlessLedger");
    ledger = await Ghostless.deploy(15, 20, 1200, ethers.parseEther("1.0"), ethers.parseEther("0.01"), 5000);
    await ledger.waitForDeployment();
    await ledger.connect(operator).registerOperator({ value: ethers.parseEther("1.0") });

    const raw = fs.readFileSync(path.join(__dirname, "vectors.json"), "utf8");
    vectors = JSON.parse(raw).vectors;
  });

  it("computes bit-identical recordP, leaf and EIP-712 digests matching Python specification", async function () {
    const computedResults = [];

    for (const vec of vectors) {
      const p = vec.recordP;
      const tuple = [
        p.ruleId,
        p.outcome,
        p.riskBucket,
        p.routeId,
        p.blockRef,
        p.blockHashPrefix,
        ethers.getAddress(p.subject),
        p.actuatorId,
        p.actionHash,
        p.nonce,
      ];

      const recordPBytes = ethers.AbiCoder.defaultAbiCoder().encode(
        [
          "tuple(uint16 ruleId,uint8 outcome,uint8 riskBucket,uint32 routeId,uint64 blockRef,bytes4 blockHashPrefix,address subject,bytes32 actuatorId,bytes32 actionHash,uint64 nonce)",
        ],
        [tuple]
      );
      const recordPHash = ethers.keccak256(recordPBytes);

      // leaf = keccak256(0x00 || abi.encode(windowId, seq, keccak256(recordP), privCommit))
      const inner = ethers.AbiCoder.defaultAbiCoder().encode(
        ["uint256", "uint64", "bytes32", "bytes32"],
        [vec.windowId, vec.seq, recordPHash, vec.privCommit]
      );
      const leaf = ethers.keccak256(ethers.concat(["0x00", inner]));

      // EIP-712 digest from contract
      const receipt = { windowId: vec.windowId, seq: vec.seq, leaf: leaf };
      const contractDigest = await ledger.getReceiptDigest(receipt);

      computedResults.push({
        name: vec.name,
        recordPBytes,
        recordPHash,
        leaf,
        digest: contractDigest,
      });
    }

    // Save JS computed results for Python side assertion
    fs.writeFileSync(
      path.join(__dirname, "js_vector_results.json"),
      JSON.stringify(computedResults, null, 2)
    );
  });
});
