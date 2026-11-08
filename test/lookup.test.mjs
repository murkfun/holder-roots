// src/lookup.mjs on synthetic data (no network): the query parser, the list hash, the tree rebuild and the lookup's
// checks of every hint (a wrong API answer is never reported as verified).
import assert from "node:assert/strict";
import { test } from "node:test";
import { concat, getAddress, keccak256, pad, toBytes, toHex } from "viem";
import { HolderSetReader, agentIdOf, listHash, parseQuery } from "../src/lookup.mjs";
import * as zk from "../src/tree.mjs";

// checksummed, like every address the chain readers return (getAddress)
const addr = (i) => getAddress(`0x${(0xa11ce00n + BigInt(i)).toString(16).padStart(40, "0")}`);
const fhex = (x) => toHex(BigInt(x), { size: 32 });
const LISTS = [[addr(1), addr(2), addr(3)], [addr(4), addr(5)], [addr(6)]];

/** A reader whose chain reads come from the synthetic lists: batches 0..accepted are accepted. */
function fake(accepted, { api, holds = true, origin = "register" } = {}) {
  const r = new HolderSetReader({ rpc: "http://127.0.0.1:1", api: api === undefined ? "http://api.invalid" : api });
  const g = new zk.GlobalTree([]);
  const roots = LISTS.map((l, i) => (g.set(i, zk.batchRoot(l)), g.root()));
  const now = 2_000_000_000;
  const infos = LISTS.map((l, i) => ({ id: i, root: roots[i], listHash: listHash(l), postedAt: now - 7200 + i * 3600, queueStart: 0, holds: 0, serial: i + 1, usableFrom: now - 3600 + i * 3600 }));
  r.state = async () => ({ chainId: 56, holderRoots: r.roots, batchCount: LISTS.length, acceptedBatch: accepted, acceptedRoot: accepted === null ? null : fhex(roots[accepted]), currentRoot: fhex(roots.at(-1)), challengePeriodS: 3600, rootHistory: 24, heldFrom: null, queue: { head: 0, tail: 0, length: 0 }, operator: addr(99), openDisputes: 0 });
  r.batchInfo = async (id) => infos[id];
  r.batchList = async (id) => ({ ...infos[id], addrs: LISTS[id], subtreeRoot: zk.batchRoot(LISTS[id]), newRoot: roots[id], block: 1, tx: "0x01" });
  r.allBatches = async () => ({ batches: LISTS.map((l, i) => ({ id: i, addrs: l, newRoot: roots[i], subtreeRoot: zk.batchRoot(l) })), head: 100, endpoints: 1 });
  r.registryOf = async (q) => ({ address: q.kind === "address" ? q.address : addr(2), handle: "alice.ai", holdsAgentId: holds });
  r.read = async (fn) => (fn === "enqueued" ? false : undefined);
  r.originFromTx = async (_a, tx) => ({ origin, tx, block: 5 });
  r.originFromLogs = async () => ({ origin, tx: "0xlogs", block: 5 });
  return { r, roots };
}

/** What MurkFun's API would answer for `a` (accepted batches 0..acc), optionally tampered. */
function apiAnswer(a, acc, tamper) {
  const b = LISTS.findIndex((l) => l.includes(a));
  if (b < 0) return { address: a, status: "pending", batch: null, position: null, accepted: false, proof: null, mint: { tx: "0xmint" } };
  const j = LISTS[b].indexOf(a);
  const accepted = acc !== null && b <= acc;
  let proof = null;
  if (accepted) {
    const p = zk.holderPathFromRoots(LISTS[b], b, LISTS.slice(0, acc + 1).map(zk.batchRoot), a);
    proof = { leaf: fhex(zk.leaf(a)), leafIndex: p.index.toString(), siblings: p.siblings.map(fhex), root: fhex(p.root), rootBatch: acc, batchRoot: fhex(zk.batchRoot(LISTS[b])) };
    if (tamper === "sibling") proof.siblings[3] = fhex(123n);
    if (tamper === "garbage") proof.siblings[0] = "not a number";
  }
  return { address: a, status: "included", batch: b, position: tamper === "position" ? j + 1 : j, accepted, proof, mint: { tx: "0xmint" } };
}

test("queries: address, name, name.ai; anything else is refused", () => {
  const a = "0x00000000000000000000000000000000000000aa";
  assert.deepEqual(parseQuery(` ${a} `), { kind: "address", address: getAddress(a) });
  assert.deepEqual(parseQuery("Alice.ai"), { kind: "name", name: "alice" });
  assert.deepEqual(parseQuery("bob42"), { kind: "name", name: "bob42" });
  for (const bad of ["", "al ice", "a.b.ai", "x".repeat(65)]) assert.throws(() => parseQuery(bad), /not an address or an Agent ID name/);
  assert.throws(() => parseQuery(`0x${"a".repeat(39)}`), /not an address \(0x and 40 hex digits\)/);
  assert.equal(agentIdOf("alice"), BigInt(keccak256(toBytes("alice"))));
});

test("listHash is HolderRoots' _listHash: keccak256 over 32-byte words", () => {
  assert.equal(listHash([addr(1), addr(2)]), keccak256(concat([pad(addr(1)), pad(addr(2))])));
});

test("tree: every root rebuilt from the lists; a wrong contract root is a mismatch", async () => {
  const { r, roots } = fake(1);
  const t = await r.tree();
  assert.equal(t.ok, true, t.mismatches.join("; "));
  assert.equal(t.leaves, 6);
  assert.equal(t.rebuiltCurrentRoot, fhex(roots[2]));
  assert.equal(t.rebuiltAcceptedRoot, fhex(roots[1]));
  assert.deepEqual(t.batches.map((b) => b.accepted), [true, true, false]);
  const bad = fake(1).r;
  const info = bad.batchInfo;
  bad.batchInfo = async (id) => (id === 1 ? { ...(await info(id)), root: 5n } : info(id));
  const t2 = await bad.tree();
  assert.equal(t2.ok, false);
  assert.match(t2.mismatches.join(";"), /batch 1: contractRoot wrong/);
});

test("lookup: an accepted holder gets a path checked against the contract's acceptedRoot", async () => {
  const { r, roots } = fake(1);
  r.apiLookup = async (a) => apiAnswer(a, 1);
  const x = await r.lookup(addr(5));
  assert.equal(x.member, true);
  assert.deepEqual([x.batch, x.position, x.accepted, x.origin], [1, 1, true, "register"]);
  assert.deepEqual(x.verified, { registry: true, origin: true, membership: true, path: true });
  assert.equal(x.path.root, fhex(roots[1]));
  assert.equal(zk.rootFromPath(zk.leaf(addr(5)), BigInt(x.path.leafIndex), x.path.siblings.map(BigInt)), roots[1]);
});

test("lookup: a tampered or garbage proof, or a wrong position, is never reported as verified", async () => {
  for (const tamper of ["sibling", "garbage"]) {
    const { r } = fake(1);
    r.apiLookup = async (a) => apiAnswer(a, 1, tamper);
    const x = await r.lookup(addr(2));
    assert.equal(x.member, true);
    assert.equal(x.path, null, tamper);
    assert.equal(x.verified.path, false);
    assert.match(x.notes.join(";"), /does not verify/);
  }
  const { r } = fake(1);
  r.apiLookup = async (a) => apiAnswer(a, 1, "position");
  const y = await r.lookup(addr(4));
  assert.equal(y.member, false);
  assert.equal(y.verified.membership, false);
  assert.match(y.notes.join(";"), /does not hold this address on chain/);
});

test("lookup: a batch still in its window is a member, not accepted, without a path", async () => {
  const { r } = fake(1);
  r.apiLookup = async (a) => apiAnswer(a, 1);
  const x = await r.lookup(addr(6));
  assert.deepEqual([x.member, x.batch, x.accepted, x.path], [true, 2, false, null]);
  assert.match(x.notes.join(";"), /challenge window/);
});

test("lookup without the API: membership and the path from the chain's Batch events alone", async () => {
  const { r, roots } = fake(2, { api: "" });
  r.apiLookup = async () => assert.fail("the API must not be asked");
  const x = await r.lookup(addr(3));
  assert.equal(x.source, "chain");
  assert.deepEqual([x.member, x.batch, x.position, x.accepted, x.origin], [true, 0, 2, true, "register"]);
  assert.deepEqual(x.verified, { registry: true, origin: true, membership: true, path: true });
  assert.equal(x.path.root, fhex(roots[2]));
  const y = await r.lookup(addr(42));
  assert.deepEqual([y.member, y.verified.membership], [false, true]);
});

test("lookup: an admin-minted Agent ID is never in the set", async () => {
  const { r } = fake(1, { origin: "admin" });
  r.apiLookup = async (a) => ({ ...apiAnswer(a, 1), status: "admin_minted", batch: null, position: null });
  const x = await r.lookup(addr(77));
  assert.deepEqual([x.member, x.origin], [false, "admin"]);
  assert.match(x.notes.join(";"), /adminRegister/);
});

test("status reads who governs the set: owner, operator (and whether they are one key), the bond and the dispute deposit", async () => {
  const r = new HolderSetReader({ rpc: "http://127.0.0.1:1", api: "" });
  const KEY = addr(77);
  const views = {
    batchCount: 3n, acceptedRoot: [5n, 1n], currentRoot: 6n, CHALLENGE_PERIOD: 3600n, ROOT_HISTORY: 24n, heldFrom: (1n << 256n) - 1n,
    queueHead: 0n, queueTail: 0n, operator: KEY, openDisputes: 0n, owner: KEY, MIN_BOND: 0n, DISPUTE_DEPOSIT: 0n,
  };
  r.pub = { getChainId: async () => 56 };
  r.read = async (fn) => views[fn];
  const st = await r.state();
  assert.deepEqual([st.owner, st.operator, st.ownerIsOperator, st.minBondWei, st.disputeDepositWei], [KEY, KEY, true, "0", "0"]);
  views.owner = addr(78);
  views.DISPUTE_DEPOSIT = 10n ** 16n;
  const st2 = await r.state();
  assert.deepEqual([st2.ownerIsOperator, st2.disputeDepositWei], [false, "10000000000000000"]);
});
