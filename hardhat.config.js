require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config();

const OPERATOR_KEY = process.env.OPERATOR_KEY || "0x0000000000000000000000000000000000000000000000000000000000000001";
const SUBJECT_KEY = process.env.SUBJECT_KEY || "0x0000000000000000000000000000000000000000000000000000000000000002";
const ATTACKER_KEY = process.env.ATTACKER_KEY || "0x0000000000000000000000000000000000000000000000000000000000000003";

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.20",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
      evmVersion: "paris", // safe baseline verified by preflight
    },
  },
  networks: {
    hardhat: {
      chainId: 31337,
    },
    mstTestnet: {
      url: process.env.RPC_URL || "https://testnetrpc.mstblockchain.com",
      chainId: 91562037, // 0x5752035
      accounts: [OPERATOR_KEY, SUBJECT_KEY, ATTACKER_KEY],
      gasPrice: "auto",
    },
  },
  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts",
  },
};
