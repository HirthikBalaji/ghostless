const hre = require("hardhat");
const fs = require("fs");
const path = require("path");
const { Constants, Provider } = require("@mstblockchain/mst-sdk");

async function main() {
  console.log("=================================================");
  console.log("DEPLOYING GHOSTLESS SUITE TO MST BLOCKCHAIN TESTNET");
  console.log("=================================================");

  // Verify MST SDK Constants
  console.log("[MST SDK] Target Chain ID:", Constants.CHAINS.TESTNET);
  console.log("[MST SDK] Default RPC:", Constants.DEFAULT_RPC_URL);

  const [operator] = await hre.ethers.getSigners();
  console.log("Deployer / Operator Address:", operator.address);

  const balance = await hre.ethers.provider.getBalance(operator.address);
  console.log("Operator Balance:", hre.ethers.formatEther(balance), "tMSTC");

  // Load preflight parameters
  const preflightPath = path.join(__dirname, "..", "preflight.json");
  let preflight = {};
  if (fs.existsSync(preflightPath)) {
    preflight = JSON.parse(fs.readFileSync(preflightPath, "utf8"));
  }

  // W window for interactive demo and testing: 1000 blocks (~50 min)
  const W = 1000;
  const R = 30; // 30 blocks response deadline
  const D = 1200; // demand horizon
  const minBond = hre.ethers.parseEther("1.0");
  const demandFee = hre.ethers.parseEther("0.01");
  const slashBps = 5000; // 50% slash (60% to victim, 20% to reporter, 20% burned)

  console.log(`\n1. Deploying GhostlessLedger with: W=${W}, R=${R}, D=${D}, minBond=1.0, demandFee=0.01, slashBps=5000...`);
  const Ghostless = await hre.ethers.getContractFactory("GhostlessLedger");
  const ledger = await Ghostless.deploy(W, R, D, minBond, demandFee, slashBps);
  await ledger.waitForDeployment();
  const ledgerAddr = await ledger.getAddress();
  console.log("[✓] GhostlessLedger deployed at:", ledgerAddr);

  // Register operator with 2.0 tMSTC initial bond
  console.log("Registering operator on-chain with 2.0 tMSTC bond...");
  const regTx = await ledger.registerOperator({ value: hre.ethers.parseEther("2.0") });
  await regTx.wait();
  console.log("[✓] Operator registered! Bond:", hre.ethers.formatEther(await ledger.bond()), "tMSTC");

  // Deploy OperatorRegistry
  console.log("\n2. Deploying OperatorRegistry (Trust Score)...");
  const Registry = await hre.ethers.getContractFactory("OperatorRegistry");
  const registry = await Registry.deploy(ledgerAddr);
  await registry.waitForDeployment();
  const registryAddr = await registry.getAddress();
  console.log("[✓] OperatorRegistry deployed at:", registryAddr);

  // Deploy ReceiptGatedEscrow (with exposure cap k = 2)
  console.log("\n3. Deploying ReceiptGatedEscrow (Exposure Cap k = 2)...");
  const actuatorId = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("RECEIPT_GATED_ESCROW_ACTUATOR_V1"));
  const Escrow = await hre.ethers.getContractFactory("ReceiptGatedEscrow");
  const escrow = await Escrow.deploy(ledgerAddr, actuatorId, 2);
  await escrow.waitForDeployment();
  const escrowAddr = await escrow.getAddress();
  console.log("[✓] ReceiptGatedEscrow deployed at:", escrowAddr);

  // Deploy Baseline B0: PerTxAnchor
  console.log("\n4. Deploying Baseline B0 (PerTxAnchor)...");
  const PerTxAnchor = await hre.ethers.getContractFactory("PerTxAnchor");
  const perTx = await PerTxAnchor.deploy();
  await perTx.waitForDeployment();
  const perTxAddr = await perTx.getAddress();
  console.log("[✓] PerTxAnchor deployed at:", perTxAddr);

  // Deploy Baseline B1: BatchRootAnchor
  console.log("\n5. Deploying Baseline B1 (BatchRootAnchor)...");
  const BatchRootAnchor = await hre.ethers.getContractFactory("BatchRootAnchor");
  const batchRoot = await BatchRootAnchor.deploy();
  await batchRoot.waitForDeployment();
  const batchRootAddr = await batchRoot.getAddress();
  console.log("[✓] BatchRootAnchor deployed at:", batchRootAddr);

  // Open first demo window on-chain
  console.log("\n6. Opening Initial Demo Window #0 (size 64)...");
  const openTx = await ledger.openWindow(64);
  await openTx.wait();
  console.log("[✓] Window #0 opened! NextSeq:", (await ledger.nextSeq()).toString());

  const deploymentData = {
    network: hre.network.name,
    chainId: (await hre.ethers.provider.getNetwork()).chainId.toString(),
    operatorAddress: operator.address,
    ghostlessLedgerAddress: ledgerAddr,
    operatorRegistryAddress: registryAddr,
    receiptGatedEscrowAddress: escrowAddr,
    perTxAnchorAddress: perTxAddr,
    batchRootAnchorAddress: batchRootAddr,
    parameters: {
      W,
      R,
      D,
      minBond: "1.0",
      demandFee: "0.01",
      slashBps: 5000,
      victimCompensationBps: 6000,
      reporterBountyBps: 2000,
      burnBps: 2000,
      initialBond: "2.0",
      exposureMultiplier: 2,
    },
    deployedAt: new Date().toISOString(),
  };

  const deployPath = path.join(__dirname, "..", "deployment.json");
  fs.writeFileSync(deployPath, JSON.stringify(deploymentData, null, 2));
  console.log("\n[✓] Saved deployment details to deployment.json");

  // Update .env file
  const envPath = path.join(__dirname, "..", ".env");
  if (fs.existsSync(envPath)) {
    let envContent = fs.readFileSync(envPath, "utf8");
    envContent = envContent.replace(/GHOSTLESS_CONTRACT_ADDRESS=.*/g, `GHOSTLESS_CONTRACT_ADDRESS=${ledgerAddr}`);
    envContent = envContent.replace(/OPERATOR_REGISTRY_ADDRESS=.*/g, `OPERATOR_REGISTRY_ADDRESS=${registryAddr}`);
    envContent = envContent.replace(/ESCROW_CONTRACT_ADDRESS=.*/g, `ESCROW_CONTRACT_ADDRESS=${escrowAddr}`);
    envContent = envContent.replace(/PER_TX_CONTRACT_ADDRESS=.*/g, `PER_TX_CONTRACT_ADDRESS=${perTxAddr}`);
    envContent = envContent.replace(/BATCH_ROOT_CONTRACT_ADDRESS=.*/g, `BATCH_ROOT_CONTRACT_ADDRESS=${batchRootAddr}`);
    if (!envContent.includes("OPERATOR_REGISTRY_ADDRESS")) {
      envContent += `OPERATOR_REGISTRY_ADDRESS=${registryAddr}\n`;
    }
    fs.writeFileSync(envPath, envContent);
    console.log("[✓] Updated .env with deployed contract addresses");
  }

  console.log("=================================================");
  console.log("ALL CONTRACTS DEPLOYED & CONFIGURED SUCCESSFULLY!");
  console.log("=================================================");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
