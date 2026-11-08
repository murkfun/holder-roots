// Stale origin disputes (src/disputes.mjs), no network: which open disputes are stale, what to do with them, which block
// time a batch must not be posted at, and the wait for a later block time (fake scanners).
import assert from "node:assert/strict";
import { test } from "node:test";
import { batchRecord, disputeRecord, isStale, mayPost, openDisputesFrom, postedAtToAvoid, staleAction, waitPast } from "../src/disputes.mjs";

const DISPUTER = "0x00000000000000000000000000000000000000d1";
const ZERO = "0x0000000000000000000000000000000000000000";
const H1 = `0x${"11".repeat(32)}`;
const H2 = `0x${"22".repeat(32)}`;
/** A `disputes(i)` tuple: disputer, openedAt, batchId, addr, postedAt, index, holds, listHash, serial, answerBy, deposit. */
const raw = ({ disputer = DISPUTER, batchId = 5, postedAt = 1_000n, listHash = H1, answerBy = 5_000n } = {}) =>
  [disputer, 1_100n, batchId, "0x00000000000000000000000000000000000000a1", postedAt, 0, true, listHash, 9, answerBy, 10n ** 16n];
/** A `batches(id)` tuple: root, listHash, postedAt, queueStart, holds, serial, usableFrom. */
const batch = ({ listHash = H1, postedAt = 1_000n, serial = 9 } = {}) => [1n, listHash, postedAt, 0n, 0, serial, postedAt + 3_600n];

test("disputes: records, stale or live as resolveOrigin sees it (slot gone, or another batch: postedAt or list differ)", () => {
  const d = disputeRecord(3n, raw());
  assert.deepEqual([d.id, d.open, d.batchId, d.postedAt, d.listHash, d.answerBy], [3n, true, 5, 1_000n, H1, 5_000n]);
  assert.equal(disputeRecord(4, raw({ disputer: ZERO })).open, false);
  assert.deepEqual(batchRecord(batch()), { listHash: H1, postedAt: 1_000n, serial: 9 });
  assert.equal(isStale(d, 5n, undefined), true, "slot 5 dropped (batchCount 5)");
  assert.equal(isStale(d, 6n, batchRecord(batch())), false, "the disputed batch is live");
  assert.equal(isStale(d, 6n, batchRecord(batch({ postedAt: 1_001n }))), true, "a replacement posted at another time");
  assert.equal(isStale(d, 6n, batchRecord(batch({ listHash: H2 }))), true, "a replacement with another list");
  // the hazard the operator avoids: a replacement with the same list in the same second is NOT stale to the contract
  assert.equal(isStale(d, 6n, batchRecord(batch({ serial: 10 }))), false, "a new serial does not help: resolveOrigin ignores it");
  assert.equal(staleAction(d, 5n, undefined, 4_999n), "defend");
  assert.equal(staleAction(d, 5n, undefined, 5_000n), "resolve");
  assert.equal(staleAction(d, 6n, batchRecord(batch()), 9_999n), "live");
  assert.equal(staleAction(disputeRecord(4, raw({ disputer: ZERO })), 5n, undefined, 0n), "closed");
});

test("disputes: a batch is never posted into a slot at the postedAt of the batch dropped from it or of an open dispute of it", () => {
  const open5 = disputeRecord(1, raw({ batchId: 5, postedAt: 1_000n }));
  const open5later = disputeRecord(2, raw({ batchId: 5, postedAt: 1_010n }));
  const open6 = disputeRecord(3, raw({ batchId: 6, postedAt: 2_000n }));
  const closed5 = disputeRecord(4, raw({ batchId: 5, postedAt: 3_000n, disputer: ZERO }));
  assert.equal(postedAtToAvoid(5), 0n, "a slot never used, no dispute");
  assert.equal(postedAtToAvoid(5, { dropped: 990n }), 990n, "the dropped batch's own second");
  assert.equal(postedAtToAvoid(5, { dropped: 990n, disputes: [open5, open5later, open6, closed5] }), 1_010n, "the latest open dispute of that slot; other slots and closed disputes do not count");
  assert.equal(postedAtToAvoid(6, { disputes: [open5, open6] }), 2_000n);
  assert.equal(mayPost(1_010n, 1_010n), false, "the same second: the next block may share it");
  assert.equal(mayPost(1_011n, 1_010n), true);
  assert.equal(mayPost(5n, 0n), true);
});

test("disputes: openDisputesFrom reads from the floor and keeps the open ones it selects", async () => {
  const all = [raw({ batchId: 2 }), raw({ disputer: ZERO }), raw({ batchId: 7 }), raw({ batchId: 8 })];
  const reads = [];
  const readAll = async (fn, args = []) => {
    reads.push(`${fn}(${args.join(",")})`);
    return fn === "disputeCount" ? BigInt(all.length) : all[Number(args[0])];
  };
  const got = await openDisputesFrom(readAll, 1n, (d) => d.batchId >= 7);
  assert.deepEqual(got.map((d) => d.id), [2n, 3n]);
  assert.deepEqual(reads, ["disputeCount()", "disputes(1)", "disputes(2)", "disputes(3)"], "nothing below the floor");
});

test("disputes: waitPast waits until every endpoint's latest block is past the second to avoid, and gives up after maxMs", async () => {
  const scanner = (times) => {
    let k = 0;
    return { _call: async (f) => f({ getBlock: async () => ({ timestamp: times[Math.min(k++, times.length - 1)] }) }) };
  };
  const lines = [];
  // one endpoint is a block behind: the lowest head counts
  const latest = await waitPast([scanner([1_000n, 1_001n, 1_001n]), scanner([1_000n, 1_000n, 1_001n])], 1_000n, { pollMs: 1, log: (l) => lines.push(l), id: 5 });
  assert.equal(latest, 1_001n);
  assert.equal(lines.length, 1, "told once");
  assert.match(lines[0], /^batch 5: .* posted at 1000; waiting for a later block time/);
  assert.equal(await waitPast([scanner([2_000n])], 1_000n, { pollMs: 1 }), 2_000n, "already past: no wait");
  await assert.rejects(waitPast([scanner([1_000n])], 1_000n, { maxMs: 20, pollMs: 5 }), (e) => e.code === "SlotTime" && /did not pass 1000/.test(e.message));
});
