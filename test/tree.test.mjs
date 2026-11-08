// src/tree.mjs: paths, roots, the batch witness, and the constants the contract and the circuits hard-code.
import assert from "node:assert/strict";
import { test } from "node:test";
import * as zk from "../src/tree.mjs";

const addr = (i) => `0x${(0xb0b0000n + BigInt(i)).toString(16).padStart(40, "0")}`;

test("the empty tree's root is MurkFunHolderRoots.EMPTY_ROOT; leaf = H(address)", () => {
  assert.equal(zk.DEPTH, 26);
  assert.equal(zk.BATCH_SIZE, 1024);
  assert.equal(zk.ZEROS[zk.DEPTH], 0x1646d6f544ec36df9dc41f778a7ef1690a53c730b501471b6acd202194a7e8e9n);
  assert.equal(zk.rootOfBatches([]), zk.ZEROS[zk.DEPTH]);
  assert.equal(zk.leaf(addr(1)), zk.H([BigInt(addr(1))]));
  assert.equal(zk.leaf(addr(1).toUpperCase().replace("0X", "0x")), zk.leaf(addr(1)), "any letter case");
  for (const z of zk.ZEROS) assert.ok(z < zk.FIELD);
});

test("holder paths reach the root, from the lists and from the batch roots alike", () => {
  const batches = [Array.from({ length: 5 }, (_, i) => addr(i)), Array.from({ length: 3 }, (_, i) => addr(10 + i))];
  const root = zk.rootOfBatches(batches);
  for (const a of [addr(0), addr(4), addr(11)]) {
    const p = zk.holderPath(batches, a);
    assert.equal(p.root, root);
    assert.equal(p.siblings.length, zk.DEPTH);
    assert.equal(zk.rootFromPath(zk.leaf(a), p.index, p.siblings), root);
    const b = a === addr(11) ? 1 : 0;
    const q = zk.holderPathFromRoots(batches[b], b, batches.map(zk.batchRoot), a);
    assert.deepEqual(q, p);
  }
  assert.equal(zk.holderPath(batches, addr(99)), undefined);
  assert.throws(() => zk.holderPathFromRoots(batches[0], 0, [123n, zk.batchRoot(batches[1])], addr(0)), /does not match/);
});

test("batch witnesses chain: each new root is the next old root", () => {
  const lists = [[addr(1), addr(2)], [addr(3)], [addr(4), addr(5), addr(6)]];
  const subs = [];
  let root = zk.ZEROS[zk.DEPTH];
  for (let i = 0; i < lists.length; i++) {
    const w = zk.batchWitness(subs, i, lists[i]);
    assert.equal(w.oldRoot, root);
    root = w.newRoot;
    subs.push(w.subtreeRoot);
  }
  assert.equal(root, zk.rootOfBatches(lists));
  assert.throws(() => zk.batchRoot(Array.from({ length: 1025 }, (_, i) => addr(i))), /too large/);
});
