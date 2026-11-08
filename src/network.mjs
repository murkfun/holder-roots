// The deployed holder set on BNB Smart Chain: addresses, deploy blocks and the defaults of the CLI. Everything here is
// public and checkable: the contracts' verified source is on Sourcify / BscScan, and `npm run verify-bytecode`
// compares the code at these addresses with the contracts in contracts/.
import { parseAbi } from "viem";
import { AGENT_ID_BSC } from "./chain.mjs";

export const BSC = Object.freeze({
  chainId: 56,
  /** MurkFunHolderRoots: the holder set. */
  holderRoots: "0xD59867DADC96202284Fa54d016C6d66a0adBaE24",
  holderRootsDeployBlock: 131_973_909,
  /** Its batch proof verifier (contracts/verifiers/BatchVerifier.sol). */
  batchVerifier: "0x3BA574b3d102800c3E08E2F978A4d802C15b8C9E",
  /** SPACE ID Agent ID (HandleRegistry), and its first registration's block. */
  registry: AGENT_ID_BSC,
  registryFromBlock: 127_950_748,
  /** MurkFun's holder-set API (a hint only: every answer is checked against the chain). */
  api: "https://murk.fun",
  /** Default RPC: serves eth_getLogs over the whole history (many free BSC endpoints do not). Pass two or more with
   *  --rpc a,b so every log range is cross-checked. */
  rpcs: ["https://public-bsc.nownodes.io"],
  page: "https://murk.fun/holders",
});

export const ROOTS_VIEWS = parseAbi([
  "function batchCount() view returns (uint256)",
  "function batches(uint256) view returns (uint256 root, bytes32 listHash, uint64 postedAt, uint64 queueStart, uint32 holds, uint32 serial, uint64 usableFrom)",
  "function acceptedRoot() view returns (uint256 root, uint256 id)",
  "function currentRoot() view returns (uint256)",
  "function isKnownRoot(uint256) view returns (bool)",
  "function CHALLENGE_PERIOD() view returns (uint256)",
  "function ROOT_HISTORY() view returns (uint256)",
  "function EMPTY_ROOT() view returns (uint256)",
  "function AGENT_NFT() view returns (address)",
  "function BATCH_VERIFIER() view returns (address)",
  "function operator() view returns (address)",
  "function owner() view returns (address)",
  "function MIN_BOND() view returns (uint256)",
  "function DISPUTE_DEPOSIT() view returns (uint256)",
  "function heldFrom() view returns (uint256)",
  "function queueHead() view returns (uint256)",
  "function queueTail() view returns (uint256)",
  "function queue(uint256) view returns (address)",
  "function queuedTime(uint256) view returns (uint64)",
  "function enqueued(address) view returns (bool)",
  "function provenOrigin(address) view returns (bool)",
  "function openDisputes() view returns (uint256)",
  "function registrationSigner(address addr, uint256 deadline, bytes sig) view returns (address)",
  "function enqueue(address addr, uint256 deadline, bytes sig)",
]);

export const REGISTRY_VIEWS = parseAbi([
  "function balanceOf(address) view returns (uint256)",
  "function ownerOf(uint256) view returns (address)",
  "function handleOf(address) view returns (string)",
]);
