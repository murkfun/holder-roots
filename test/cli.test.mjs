// src/cli.mjs: the command line (no network): arguments, the audit defaults, the key file rules, help.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { USAGE, UsageError, auditOptions, keyFromFile, main, parseCli } from "../src/cli.mjs";
import { BSC } from "../src/network.mjs";

test("arguments: command, positionals, --flags and --key value pairs", () => {
  assert.deepEqual(parseCli(["lookup", "alice.ai", "--json", "--rpc", "a,b", "--no-api"]), { cmd: "lookup", args: ["alice.ai"], o: { json: true, rpc: "a,b", noApi: true } });
  assert.deepEqual(parseCli(["enqueue", "0xabc", "--key-file", "k", "--yes"]).o, { keyFile: "k", yes: true });
  assert.throws(() => parseCli(["tree", "--rpc"]), UsageError);
});

test("the audit defaults to the deployed holder set and the registry's whole history", () => {
  const o = auditOptions({});
  assert.equal(o.holderRoots, BSC.holderRoots);
  assert.equal(o.fromBlock, BSC.registryFromBlock);
  assert.equal(o.deployBlock, BSC.holderRootsDeployBlock);
  assert.equal(o.rpc, BSC.rpcs.join(","));
  assert.deepEqual([o.confirmations, o.graceS, o.intervalS, o.challenge], [30, 86_400, 0, false]);
  assert.equal(auditOptions({ graceS: "60", rpc: "x,y" }).graceS, 60);
});

test("a key is read from a file only, and must look like one", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "murkfun-holders-cli-"));
  try {
    const good = path.join(dir, "k");
    fs.writeFileSync(good, `0x${"11".repeat(32)}\n`);
    assert.equal(keyFromFile(good), `0x${"11".repeat(32)}`);
    const bad = path.join(dir, "bad");
    fs.writeFileSync(bad, "hunter2");
    assert.throws(() => keyFromFile(bad), /does not hold a key/);
    assert.throws(() => keyFromFile(undefined), /--key-file/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("help and unknown commands", async () => {
  const log = console.log;
  let out = "";
  console.log = (s) => { out += s; };
  try {
    assert.equal(await main(["--help"]), 0);
  } finally {
    console.log = log;
  }
  assert.equal(out, USAGE);
  for (const c of ["status", "tree", "lookup", "audit", "challenge", "enqueue", "--key-file", "--yes", "--no-api"]) assert.ok(USAGE.includes(c), c);
  await assert.rejects(main(["frobnicate"]), UsageError);
  await assert.rejects(main(["lookup"]), /one 0x address/);
});

test("help lists every option the commands take", () => {
  for (const f of ["--api", "--chain-id", "--max-deposit", "--max-gas-price-gwei", "--confirmations", "--grace-s", "--report", "--rps", "--registry", "--from-block", "--deploy-block", "--interval-s", "--challenge-state", "--heartbeat"]) assert.ok(USAGE.includes(f), f);
  assert.match(USAGE, /lookup and enqueue send the address you look up to that API/);
});

test("audit --interval-s --challenge sends without asking, so it needs --yes", async () => {
  await assert.rejects(main(["audit", "--interval-s", "600", "--challenge", "--key-file", "k"]), (e) => e instanceof UsageError && /add --yes/.test(e.message));
});

test("the send limits reach challengeFindings through the audit options", () => {
  const o = auditOptions({ maxDeposit: "0.2", maxGasPriceGwei: "1", chainId: "97" });
  assert.deepEqual([o.maxDeposit, o.maxGasPriceGwei, o.chainId], ["0.2", "1", "97"]);
  assert.deepEqual([auditOptions({}).maxDeposit, auditOptions({}).chainId], [undefined, undefined], "the defaults apply in sendLimits");
});
