const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("OperatorRegistry & Trust Score Suite", function () {
  let Ghostless, Registry;
  let ledger, registry;
  let owner, operator, randomUser;

  const W = 50;
  const R = 20;
  const D = 1200;
  const minBond = ethers.parseEther("1.0");
  const demandFee = ethers.parseEther("0.05");
  const slashBps = 5000;

  beforeEach(async function () {
    [owner, operator, randomUser] = await ethers.getSigners();

    Ghostless = await ethers.getContractFactory("GhostlessLedger");
    ledger = await Ghostless.deploy(W, R, D, minBond, demandFee, slashBps);
    await ledger.waitForDeployment();

    Registry = await ethers.getContractFactory("OperatorRegistry");
    registry = await Registry.deploy(await ledger.getAddress());
    await registry.waitForDeployment();
  });

  it("should return false for unbonded / non-registered operator", async function () {
    expect(await registry.isTrusted(randomUser.address)).to.be.false;
    expect(await registry.trustScore(randomUser.address)).to.equal(0);
  });

  it("should return true and compute initial trust score for bonded operator", async function () {
    await ledger.connect(operator).registerOperator({ value: ethers.parseEther("2.5") });

    expect(await registry.isTrusted(operator.address)).to.be.true;

    // Base score (60) + over-collateralization bonus (15) = 75
    const score = await registry.trustScore(operator.address);
    expect(score).to.equal(75);

    const profile = await registry.getOperatorProfile(operator.address);
    expect(profile.trusted).to.be.true;
    expect(profile.score).to.equal(75);
    expect(profile.activeBond).to.equal(ethers.parseEther("2.5"));
    expect(profile.isFrozen).to.be.false;
  });

  it("should increase score as windows are sealed on time", async function () {
    await ledger.connect(operator).registerOperator({ value: ethers.parseEther("2.0") });

    // Open and seal 2 windows
    await ledger.connect(operator).openWindow(64);
    await ledger.connect(operator).sealWindow(0, ethers.keccak256(ethers.toUtf8Bytes("root-0")));

    await ledger.connect(operator).openWindow(64);
    await ledger.connect(operator).sealWindow(1, ethers.keccak256(ethers.toUtf8Bytes("root-1")));

    // Base (60) + over-collateralization (15) + 2 sealed windows (10) = 85
    const score = await registry.trustScore(operator.address);
    expect(score).to.equal(85);
  });

  it("should return score 0 and isTrusted=false once operator is slashed / frozen", async function () {
    await ledger.connect(operator).registerOperator({ value: ethers.parseEther("1.0") });
    await ledger.connect(operator).openWindow(64);

    // Mine past deadline
    for (let i = 0; i < 55; i++) {
      await ethers.provider.send("evm_mine", []);
    }

    // Slash unsealed
    await ledger.slashUnsealed(0);

    expect(await registry.isTrusted(operator.address)).to.be.false;
    expect(await registry.trustScore(operator.address)).to.equal(0);

    const profile = await registry.getOperatorProfile(operator.address);
    expect(profile.trusted).to.be.false;
    expect(profile.isFrozen).to.be.true;
    expect(profile.score).to.equal(0);
  });
});
