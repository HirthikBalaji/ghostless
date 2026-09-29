const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  console.log("=================================================");
  console.log("RUNNING LIVE MST TESTNET ESCROW DEMO");
  console.log("=================================================");

  const [operator, subject] = await hre.ethers.getSigners();
  console.log("Operator Address:", operator.address);
  console.log("Subject Address:", subject.address);

  const ledgerAddr = process.env.GHOSTLESS_CONTRACT_ADDRESS;
  const escrowAddr = process.env.ESCROW_CONTRACT_ADDRESS;

  console.log("Ledger:", ledgerAddr);
  console.log("Escrow:", escrowAddr);

  const Ghostless = await hre.ethers.getContractFactory("GhostlessLedger");
  const ledger = Ghostless.attach(ledgerAddr);

  const Escrow = await hre.ethers.getContractFactory("ReceiptGatedEscrow");
  const escrow = Escrow.attach(escrowAddr);

  const actuatorId = await escrow.actuatorId();
  console.log("Actuator ID:", actuatorId);

  // 1. Create Escrow Deposit
  const depositId = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("demo-escrow-" + Date.now()));
  const actionPayload = { purpose: "Hackathon Prize Payout", recipient: subject.address, timestamp: Date.now() };
  const actionHash = hre.ethers.keccak256(hre.ethers.toUtf8Bytes(JSON.stringify(actionPayload)));
  const depositAmount = hre.ethers.parseEther("0.05"); // 0.05 tMSTC

  console.log(`\n1. Creating Escrow Deposit: ${depositId}`);
  const depTx = await escrow.connect(operator).createDeposit(depositId, subject.address, actionHash, 500, {
    value: depositAmount,
  });
  await depTx.wait();
  console.log("[✓] Escrow deposit locked with 0.05 tMSTC! Tx:", depTx.hash);

  // 2. Fetch current active window from GhostlessLedger
  const nextSeq = await ledger.nextSeq();
  const windowsCount = await ledger.nextToSeal();
  console.log(`\n2. Next Seq on Ledger: ${nextSeq}`);

  // We find an open window or open a new one
  let activeWindowId = 0;
  let currentWindow;
  for (let i = 0; i < 5; i++) {
    try {
      const w = await ledger.windows(i);
      const isAcc = await ledger.acceptable(i, Number(w.startSeq));
      if (isAcc) {
        activeWindowId = i;
        currentWindow = w;
        break;
      }
    } catch (e) {
      break;
    }
  }

  if (!currentWindow) {
    console.log("Opening new window for demo...");
    const openTx = await ledger.connect(operator).openWindow(64);
    await openTx.wait();
    activeWindowId = Number(await ledger.nextToSeal()) + Number(await ledger.openCount()) - 1;
    currentWindow = await ledger.windows(activeWindowId);
  }

  const assignedSeq = Number(currentWindow.startSeq);
  console.log(`Using Window #${activeWindowId}, Seq #${assignedSeq}`);

  // 3. Issue Approved EIP-712 Decision Receipt
  const domain = {
    name: "GhostlessLedger",
    version: "1",
    chainId: (await hre.ethers.provider.getNetwork()).chainId,
    verifyingContract: ledgerAddr,
  };

  const types = {
    Receipt: [
      { name: "windowId", type: "uint256" },
      { name: "seq", type: "uint64" },
      { name: "leaf", type: "bytes32" },
    ],
  };

  const PolicyRecordType = [
    "tuple(uint16 ruleId, uint8 outcome, uint8 riskBucket, uint32 routeId, uint64 blockRef, bytes4 blockHashPrefix, address subject, bytes32 actuatorId, bytes32 actionHash, uint64 nonce)",
  ];

  const currentBlock = await hre.ethers.provider.getBlock("latest");
  const blockHashPrefix = currentBlock.hash.slice(0, 10);

  const policyRecord = {
    ruleId: 777,
    outcome: 1, // Approved!
    riskBucket: 1,
    routeId: 10,
    blockRef: currentBlock.number,
    blockHashPrefix: blockHashPrefix,
    subject: subject.address,
    actuatorId: actuatorId,
    actionHash: actionHash,
    nonce: 1,
  };

  const recordPBytes = hre.ethers.AbiCoder.defaultAbiCoder().encode(PolicyRecordType, [policyRecord]);
  const recordPHash = hre.ethers.keccak256(recordPBytes);
  const privCommit = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("demo-priv-salt-" + Date.now()));

  const inner = hre.ethers.AbiCoder.defaultAbiCoder().encode(
    ["uint256", "uint64", "bytes32", "bytes32"],
    [activeWindowId, assignedSeq, recordPHash, privCommit]
  );
  const leaf = hre.ethers.keccak256(hre.ethers.concat(["0x00", inner]));

  const receipt = {
    windowId: activeWindowId,
    seq: assignedSeq,
    leaf: leaf,
  };

  console.log("\n3. Signing EIP-712 Receipt as Operator...");
  const signature = await operator.signTypedData(domain, types, receipt);
  console.log("[✓] Operator Receipt Signature generated");

  // 4. Release Escrow via Receipt
  console.log("\n4. Calling releaseWithReceipt on MST Testnet...");
  const subjectBalBefore = await hre.ethers.provider.getBalance(subject.address);

  const releaseTx = await escrow.connect(subject).releaseWithReceipt(
    depositId,
    receipt,
    signature,
    recordPBytes,
    privCommit,
    []
  );
  const rec = await releaseTx.wait();
  console.log("[✓] ESCROW FUNDS RELEASED LIVE ON MST TESTNET!");
  console.log("Tx Hash:", releaseTx.hash);
  console.log("Gas Used:", rec.gasUsed.toString());

  const subjectBalAfter = await hre.ethers.provider.getBalance(subject.address);
  console.log("Subject Balance Change:", hre.ethers.formatEther(subjectBalAfter - subjectBalBefore), "tMSTC");

  const finalDep = await escrow.deposits(depositId);
  console.log("Deposit Released status:", finalDep.released);
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
