// scripts/verify-bytecode.mjs: what is compared (no forge, no network), and the committed expectations.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { CONTRACTS, immutableValues, maskImmutables, normalized, stripCbor } from "../scripts/verify-bytecode.mjs";
import { BSC } from "../src/network.mjs";

test("the CBOR metadata tail is cut by its length (the last two bytes)", () => {
  assert.equal(stripCbor("0x6001600255aabbcc0003"), "0x6001600255");
  assert.equal(stripCbor("0x00"), "0x00");
  assert.equal(stripCbor("0x60ffff"), "0x60ffff", "a length past the start leaves the code alone");
});

test("immutables are zeroed where the compiler says, and read back from deployed code", () => {
  const refs = { 7: [{ start: 1, length: 2 }, { start: 5, length: 2 }] };
  const deployed = "0x60beef6000cafe0002";
  assert.equal(maskImmutables(deployed, refs), "0x600000600000000002");
  assert.deepEqual(immutableValues(deployed, refs), ["0xbeef"]);
  assert.equal(normalized(deployed, refs), "0x6000006000", "masked, then the 2-byte tail and its length field cut");
});

test("contracts/bytecode.json covers the deployed contracts at their addresses", () => {
  const want = JSON.parse(fs.readFileSync(path.resolve(import.meta.dirname, "../contracts/bytecode.json"), "utf8"));
  assert.deepEqual(CONTRACTS.map((c) => c.address), [BSC.holderRoots, BSC.batchVerifier]);
  for (const c of CONTRACTS) {
    assert.equal(want[c.name].address, c.address);
    assert.match(want[c.name].normalizedKeccak256, /^0x[0-9a-f]{64}$/);
  }
});

test("MurkFunHolderRoots' immutables are checked in declaration order: a swap is a difference", async () => {
  const { checkImmutables, expectedRootsImmutables } = await import("../scripts/verify-bytecode.mjs");
  const want = expectedRootsImmutables();
  assert.deepEqual(want.map(([l]) => l.split(" ")[0]), ["AGENT_NFT", "BATCH_VERIFIER", "REGISTRY_DOMAIN"]);
  // the deployed holder set's values (read from its code): the registry, the verifier, the registry's EIP-712 domain
  const deployed = [
    "0x00000000000000000000000060b9262456de011f7d15a54cdd8c48baaa8b022f",
    "0x0000000000000000000000003ba574b3d102800c3e08e2f978a4d802c15b8c9e",
    "0x4b93a6ba8165deb19d779d00513ae88c9f8dcbc866b64522491cec51c6661f73",
  ];
  assert.deepEqual(checkImmutables(deployed).map(([, ok]) => ok), [true, true, true]);
  assert.deepEqual(checkImmutables([deployed[1], deployed[0], deployed[2]]).map(([, ok]) => ok), [false, false, true], "swapped registry / verifier");
  assert.equal(checkImmutables(deployed.slice(0, 2))[0][1], false, "a missing immutable");
});
