const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  console.log("=================================================");
  console.log("DEPLOYING GHOSTLESS & BASELINES TO MST TESTNET");
  console.log("=================================================");

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

  const demo = (preflight.derived_parameters && preflight.derived_parameters.demo_profile) || {
    W_seal_window_blocks: 15,
    R_response_deadline_blocks: 20,
    D_demand_horizon_blocks: 1200,
  };

  const W = demo.W_seal_window_blocks;
  const R = demo.R_response_deadline_blocks;
  const D = demo.D_demand_horizon_blocks;
  const minBond = hre.ethers.parseEther("1.0");
  const demandFee = hre.ethers.parseEther("0.01");
  const slashBps = 5000; // 50% slash

  console.log(`\nDeploying GhostlessLedger with: W=${W}, R=${R}, D=${D}, minBond=1.0, demandFee=0.01, slashBps=5000...`);

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

  // Deploy Baseline B0: PerTxAnchor
  console.log("\nDeploying Baseline B0 (PerTxAnchor)...");
  const PerTxAnchor = await hre.ethers.getContractFactory("PerTxAnchor");
  const perTx = await PerTxAnchor.deploy();
  await perTx.waitForDeployment();
  const perTxAddr = await perTx.getAddress();
  console.log("[✓] PerTxAnchor deployed at:", perTxAddr);

  // Deploy Baseline B1: BatchRootAnchor
  console.log("\nDeploying Baseline B1 (BatchRootAnchor)...");
  const BatchRootAnchor = await hre.ethers.getContractFactory("BatchRootAnchor");
  const batchRoot = await BatchRootAnchor.deploy();
  await batchRoot.waitForDeployment();
  const batchRootAddr = await batchRoot.getAddress();
  console.log("[✓] BatchRootAnchor deployed at:", batchRootAddr);

  const deploymentData = {
    network: hre.network.name,
    chainId: (await hre.ethers.provider.getNetwork()).chainId.toString(),
    operatorAddress: operator.address,
    ghostlessLedgerAddress: ledgerAddr,
    perTxAnchorAddress: perTxAddr,
    batchRootAnchorAddress: batchRootAddr,
    parameters: {
      W,
      R,
      D,
      minBond: "1.0",
      demandFee: "0.01",
      slashBps: 5000,
      initialBond: "2.0",
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
    envContent = envContent.replace(/PER_TX_CONTRACT_ADDRESS=.*/g, `PER_TX_CONTRACT_ADDRESS=${perTxAddr}`);
    envContent = envContent.replace(/BATCH_ROOT_CONTRACT_ADDRESS=.*/g, `BATCH_ROOT_CONTRACT_ADDRESS=${batchRootAddr}`);
    if (!envContent.includes("GHOSTLESS_CONTRACT_ADDRESS")) {
      envContent += `\nGHOSTLESS_CONTRACT_ADDRESS=${ledgerAddr}\nPER_TX_CONTRACT_ADDRESS=${perTxAddr}\nBATCH_ROOT_CONTRACT_ADDRESS=${batchRootAddr}\n`;
    }
    fs.writeFileSync(envPath, envContent);
    console.log("[✓] Updated .env with deployed contract addresses");
  }
}

main().catch((error) => {
  console.error("Deployment failed:", error);
  process.exitCode = 1;
});
