const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  console.log("=================================================");
  console.log("DEPLOYING RECEIPT GATED ESCROW TO MST TESTNET");
  console.log("=================================================");

  const [deployer] = await hre.ethers.getSigners();
  console.log("Deployer Address:", deployer.address);

  const balance = await hre.ethers.provider.getBalance(deployer.address);
  console.log("Deployer Balance:", hre.ethers.formatEther(balance), "tMSTC");

  const ledgerAddr = process.env.GHOSTLESS_CONTRACT_ADDRESS || "0x241BEb20dE8a7E7E3cC929159879E07C1602b8fC";
  const actuatorId = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("RECEIPT_GATED_ESCROW_ACTUATOR_V1"));

  console.log(`Connecting to GhostlessLedger at: ${ledgerAddr}`);
  console.log(`Actuator ID: ${actuatorId}`);

  const Escrow = await hre.ethers.getContractFactory("ReceiptGatedEscrow");
  const escrow = await Escrow.deploy(ledgerAddr, actuatorId);
  await escrow.waitForDeployment();
  const escrowAddr = await escrow.getAddress();

  console.log("\n[✓] ReceiptGatedEscrow deployed successfully at:", escrowAddr);

  // Update .env
  const envPath = path.join(__dirname, "..", ".env");
  if (fs.existsSync(envPath)) {
    let envContent = fs.readFileSync(envPath, "utf8");
    if (envContent.includes("ESCROW_CONTRACT_ADDRESS=")) {
      envContent = envContent.replace(/ESCROW_CONTRACT_ADDRESS=.*/g, `ESCROW_CONTRACT_ADDRESS=${escrowAddr}`);
    } else {
      envContent += `ESCROW_CONTRACT_ADDRESS=${escrowAddr}\n`;
    }
    fs.writeFileSync(envPath, envContent);
    console.log("[✓] Updated .env with ESCROW_CONTRACT_ADDRESS");
  }

  // Update deployment.json
  const deployPath = path.join(__dirname, "..", "deployment.json");
  if (fs.existsSync(deployPath)) {
    const deploymentData = JSON.parse(fs.readFileSync(deployPath, "utf8"));
    deploymentData.receiptGatedEscrowAddress = escrowAddr;
    deploymentData.actuatorId = actuatorId;
    fs.writeFileSync(deployPath, JSON.stringify(deploymentData, null, 2));
    console.log("[✓] Updated deployment.json with escrow details");
  }

  return escrowAddr;
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
