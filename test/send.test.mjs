// What `challenge` / `audit --challenge` / `enqueue` may send (src/audit.mjs sendLimits, sendProblem): only on BNB Smart
// Chain, only below the gas price cap, and a disputeOrigin only while the contract's DISPUTE_DEPOSIT is at most
// --max-deposit. No network.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { parseEther, parseGwei } from "viem";
import { DEFAULT_MAX_DEPOSIT, DEFAULT_MAX_GAS_PRICE_GWEI, parseArgs, sendLimits, sendProblem } from "../src/audit.mjs";
import { LOG_BSC_RPCS } from "../src/chain.mjs";

test("defaults: chain 56, 0.05 BNB deposit, 5 gwei", () => {
  assert.deepEqual(sendLimits({}), { maxDepositWei: parseEther(DEFAULT_MAX_DEPOSIT), maxGasPriceWei: parseGwei(DEFAULT_MAX_GAS_PRICE_GWEI), chainId: 56 });
  assert.equal(DEFAULT_MAX_DEPOSIT, "0.05");
  assert.deepEqual(sendLimits({ maxDeposit: "1.5", maxGasPriceGwei: "0.5", chainId: "97" }), { maxDepositWei: parseEther("1.5"), maxGasPriceWei: parseGwei("0.5"), chainId: 97 });
  for (const bad of [{ maxDeposit: "-1" }, { maxDeposit: "lots" }, { maxGasPriceGwei: "1e9" }, { chainId: "0" }, { chainId: "x" }]) assert.throws(() => sendLimits(bad), /must be/, JSON.stringify(bad));
});

test("refused: another chain, a gas price above the cap, a dispute deposit above the cap", () => {
  const lim = sendLimits({});
  assert.equal(sendProblem({ chainId: 56, gasPriceWei: parseGwei("0.1"), depositWei: 0n }, lim), undefined);
  assert.match(sendProblem({ chainId: 1 }, lim), /chain 1, not 56/);
  assert.match(sendProblem({ gasPriceWei: parseGwei("6") }, lim), /gas price 6 gwei is above --max-gas-price-gwei 5/);
  assert.equal(sendProblem({ gasPriceWei: parseGwei("5") }, lim), undefined, "at the cap is fine");
  assert.match(sendProblem({ depositWei: parseEther("0.06") }, lim), /DISPUTE_DEPOSIT is 0.06 BNB, above --max-deposit 0.05 BNB/);
  assert.equal(sendProblem({ depositWei: parseEther("0.06") }, sendLimits({ maxDeposit: "0.1" })), undefined);
});

test("the audit's own argument parser: --report, the send limits checked before any scan, endpoints that serve old logs", () => {
  const o = parseArgs(["--holder-roots", "0x00000000000000000000000000000000000000aa", "--from-block", "1", "--report", "r.json"]);
  assert.equal(o.json, "r.json");
  assert.throws(() => parseArgs(["--holder-roots", "0xaa", "--from-block", "1", "--max-deposit", "x"]), /--max-deposit must be/);
  assert.ok(LOG_BSC_RPCS.length > 0 && !LOG_BSC_RPCS.some((u) => /bsc-dataseed/.test(u)));
  if (!process.env.MURKFUN_HOLDERS_RPC) assert.equal(o.rpc, LOG_BSC_RPCS.join(","));
});

test("node src/audit.mjs --challenge sends fraud proofs, so it needs --yes (refused before any scan)", () => {
  const req = ["--holder-roots", "0x0000000000000000000000000000000000000001", "--from-block", "0"];
  const o = parseArgs(["--challenge", "--yes", "--report", "r.json", ...req]);
  assert.equal(o.yes, true, "--yes takes no value");
  assert.equal(o.json, "r.json");
  const r = spawnSync(process.execPath, [fileURLToPath(new URL("../src/audit.mjs", import.meta.url)), "--challenge", "--holder-roots", "0x0000000000000000000000000000000000000001", "--from-block", "0", "--rpc", "http://127.0.0.1:9"], { encoding: "utf8", timeout: 30_000 });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /--challenge sends fraud proofs: add --yes/);
});
