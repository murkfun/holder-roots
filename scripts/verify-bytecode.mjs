#!/usr/bin/env node
// Compile contracts/ (forge, the deployment's settings) and compare the result with the code deployed on BSC.
//
//   npm run verify-bytecode                      forge build, then eth_getCode of MurkFunHolderRoots and BatchVerifier
//                                                and compare (exit 1 on any difference)
//   npm run verify-bytecode -- --offline         forge build, then compare with contracts/bytecode.json (no network)
//   npm run verify-bytecode -- --rpc <url>       another BSC endpoint
//   npm run verify-bytecode -- --write           (maintainers) write contracts/bytecode.json from the build
//
// What is compared: the runtime code without its CBOR metadata tail (the last 2 bytes give its length; it hashes the
// source file names and comments, not the code) and with the immutables (constructor arguments: the Agent ID registry,
// the batch verifier, the registry's EIP-712 domain) zeroed at the positions the compiler reports. The immutables are
// then read from the deployed code and shown, so you can check them too. Everything else must be byte-identical.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { createPublicClient, encodeAbiParameters, http, keccak256, pad, toBytes } from "viem";
import { BSC } from "../src/network.mjs";
import { isMain } from "../src/entry.mjs";

const DIR = path.resolve(import.meta.dirname, "../contracts");
const EXPECTED = path.join(DIR, "bytecode.json");
export const CONTRACTS = [
  { name: "MurkFunHolderRoots", file: "MurkFunHolderRoots.sol", address: BSC.holderRoots },
  { name: "BatchVerifier", file: "BatchVerifier.sol", address: BSC.batchVerifier },
];

/** `code` (0x hex) without the CBOR metadata tail. */
export function stripCbor(code) {
  const hex = code.slice(2);
  if (hex.length < 4) return code;
  const len = parseInt(hex.slice(-4), 16);
  const cut = (len + 2) * 2;
  return cut <= hex.length ? `0x${hex.slice(0, hex.length - cut)}` : code;
}

/** `code` with every immutable reference (byte ranges) zeroed. */
export function maskImmutables(code, refs = {}) {
  const b = Buffer.from(code.slice(2), "hex");
  for (const list of Object.values(refs)) for (const { start, length } of list) b.fill(0, start, start + length);
  return `0x${b.toString("hex")}`;
}

/** The immutables' values in deployed `code` (the first reference of each). */
export function immutableValues(code, refs = {}) {
  const b = Buffer.from(code.slice(2), "hex");
  return Object.values(refs).map((list) => `0x${b.subarray(list[0].start, list[0].start + list[0].length).toString("hex")}`);
}

export const normalized = (code, refs) => stripCbor(maskImmutables(code, refs));

/** What MurkFunHolderRoots' immutables must be, in declaration order (AGENT_NFT, BATCH_VERIFIER, REGISTRY_DOMAIN). The
 *  compiler keys immutableReferences by AST id, which follows the source order, and immutableValues returns them in
 *  ascending key order: the n-th value must be the n-th entry here (a swap is a difference). */
export function expectedRootsImmutables(registry = BSC.registry, verifier = BSC.batchVerifier, chainId = BSC.chainId) {
  const h = (s) => keccak256(toBytes(s));
  const domain = keccak256(encodeAbiParameters(
    [{ type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }, { type: "uint256" }, { type: "address" }],
    [h("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"), h("HandleRegistry"), h("1"), BigInt(chainId), registry],
  ));
  return [["AGENT_NFT (SPACE ID Agent ID)", pad(registry), registry], ["BATCH_VERIFIER", pad(verifier), verifier], ["REGISTRY_DOMAIN (the registry's EIP-712 domain)", domain, domain]];
}

/** Each expected immutable against the value at its position: [label, ok, shown]. */
export function checkImmutables(values, expected = expectedRootsImmutables()) {
  if (values.length !== expected.length) return [[`${values.length} immutables in the code, ${expected.length} expected`, false, ""]];
  return expected.map(([label, want, shown], i) => [label, values[i].toLowerCase() === want.toLowerCase(), shown]);
}

function build() {
  console.error("$ forge build (contracts/)");
  execFileSync("forge", ["build"], { cwd: DIR, stdio: ["ignore", "inherit", "inherit"] });
}

function artifact(c) {
  const j = JSON.parse(fs.readFileSync(path.join(DIR, "out", c.file, `${c.name}.json`), "utf8"));
  return { code: j.deployedBytecode.object, refs: j.deployedBytecode.immutableReferences ?? {} };
}

async function main(argv) {
  const opt = (k) => (argv.includes(k) ? argv[argv.indexOf(k) + 1] : undefined);
  if (!argv.includes("--no-build")) build();
  const built = CONTRACTS.map((c) => {
    const a = artifact(c);
    return { ...c, ...a, hash: keccak256(normalized(a.code, a.refs)), size: (a.code.length - 2) / 2 };
  });
  if (argv.includes("--write")) {
    const out = Object.fromEntries(built.map((c) => [c.name, { address: c.address, runtimeSize: c.size, normalizedKeccak256: c.hash }]));
    fs.writeFileSync(EXPECTED, `${JSON.stringify({ _comment: "keccak256 of the runtime code without the CBOR metadata tail, immutables zeroed (scripts/verify-bytecode.mjs)", ...out }, null, 2)}\n`);
    console.log(`wrote ${path.relative(process.cwd(), EXPECTED)}`);
    return 0;
  }
  let bad = 0;
  if (argv.includes("--offline")) {
    const want = JSON.parse(fs.readFileSync(EXPECTED, "utf8"));
    for (const c of built) {
      const ok = want[c.name]?.normalizedKeccak256 === c.hash;
      if (!ok) bad++;
      console.log(`${ok ? "OK  " : "DIFF"} ${c.name}: build ${c.hash}, contracts/bytecode.json ${want[c.name]?.normalizedKeccak256}`);
    }
    return bad ? 1 : 0;
  }
  const rpc = opt("--rpc") ?? BSC.rpcs[0];
  const pub = createPublicClient({ transport: http(rpc, { timeout: 30_000, retryCount: 2 }) });
  if ((await pub.getChainId()) !== BSC.chainId) throw new Error(`${new URL(rpc).host} is not BNB Smart Chain`);
  for (const c of built) {
    const onchain = await pub.getCode({ address: c.address });
    if (!onchain || onchain === "0x") {
      bad++;
      console.log(`DIFF ${c.name} ${c.address}: no code on chain`);
      continue;
    }
    const h = keccak256(normalized(onchain, c.refs));
    const ok = h === c.hash && (onchain.length - 2) / 2 === c.size;
    if (!ok) bad++;
    console.log(`${ok ? "OK  " : "DIFF"} ${c.name} ${c.address}: chain ${h}, build ${c.hash}`);
    const imm = immutableValues(onchain, c.refs);
    if (imm.length) console.log(`     immutables in the deployed code: ${imm.join(", ")}`);
    if (c.name === "MurkFunHolderRoots") {
      for (const [what, ok, shown] of checkImmutables(imm)) {
        if (!ok) bad++;
        console.log(`     ${ok ? "OK  " : "DIFF"} ${what}${shown ? ` = ${shown}` : ""}`);
      }
    }
  }
  console.log(bad ? `${bad} difference(s)` : "The deployed code is exactly what contracts/ compiles to (metadata tail and immutables aside).");
  return bad ? 1 : 0;
}

if (isMain(import.meta.url)) {
  main(process.argv.slice(2)).then((c) => process.exit(c), (e) => {
    console.error(`error: ${String(e.shortMessage ?? e.message ?? e).split("\n")[0]}`);
    process.exit(1);
  });
}
