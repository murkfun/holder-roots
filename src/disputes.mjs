// Origin disputes that outlive their batch (README "Security model", stale disputes). A batch dropped by a fraud proof
// (`challenge`, or `resolveOrigin` of another dispute) leaves its open origin disputes open. `resolveOrigin` matches a
// dispute to the batch now at its slot by `postedAt` and `listHash` only (not by the batch's serial), so a stale
// dispute whose slot gets a REPLACEMENT batch with the same list, posted in the same second as the dropped one, would
// drop the replacement when resolved. Two rules keep that from happening, both off chain:
//   - the operator never posts into a slot at a block time equal to the `postedAt` of the batch dropped from it or of
//     any open dispute of that slot (`postedAtToAvoid`; it waits for a later block timestamp);
//   - stale disputes are closed as soon as possible: answered with the holder's registration signature
//     (`defendOrigin`, at any time), or, once their answer window has passed, resolved (`resolveOrigin` of a stale
//     dispute only returns its deposit: `DisputeVoid`).
// Used by the audit (src/audit.mjs) and by MurkFun's operator, which follows both rules.

/** A `disputes(i)` record as a plain object (the view's tuple: disputer, openedAt, batchId, addr, postedAt, index,
 *  holds, listHash, serial, answerBy, deposit). */
export function disputeRecord(id, d) {
  return {
    id: BigInt(id), disputer: d[0], open: BigInt(d[0]) !== 0n, openedAt: BigInt(d[1]), batchId: Number(d[2]), addr: d[3],
    postedAt: BigInt(d[4]), index: Number(d[5]), listHash: d[7], serial: Number(d[8]), answerBy: BigInt(d[9]),
  };
}

/** A `batches(id)` record (root, listHash, postedAt, queueStart, holds, serial, usableFrom). */
export const batchRecord = (b) => ({ listHash: b[1], postedAt: BigInt(b[2]), serial: Number(b[5]) });

/**
 * Whether an open dispute is stale: the batch it disputed is gone. `count` is `batchCount()`, `batchAt` the
 * `batches(d.batchId)` record (`batchRecord`; only needed when the slot is live). Live and with the same postedAt
 * and listHash: not stale (the dispute applies to that batch, as `resolveOrigin` sees it).
 */
export function isStale(d, count, batchAt) {
  if (d.batchId >= Number(count)) return true;
  return !batchAt || batchAt.postedAt !== d.postedAt || batchAt.listHash !== d.listHash;
}

/** What to do with an open dispute `d` at chain time `now`: "live" (a dispute of a live batch: defend it, or the
 *  audit resolves an upheld one), "defend" (stale, inside its answer window: only a defence closes it now) or
 *  "resolve" (stale, past `answerBy`: `resolveOrigin` voids it and returns the deposit to the disputer). */
export function staleAction(d, count, batchAt, now) {
  if (!d.open) return "closed";
  if (!isStale(d, count, batchAt)) return "live";
  return BigInt(now) >= d.answerBy ? "resolve" : "defend";
}

/**
 * The block time a new batch in slot `id` must NOT be posted at, or 0n: the largest of the `postedAt` of the batch
 * last dropped from that slot (`dropped`: `batches(id).postedAt` read while `id >= batchCount`, 0 for a slot never
 * used) and of every open dispute of that slot (`disputes`: `disputeRecord`s). Post only once the chain's latest
 * block time is above it (`mayPost`): every later block then has a later time.
 */
export function postedAtToAvoid(id, { dropped = 0n, disputes = [] } = {}) {
  let t = BigInt(dropped);
  for (const d of disputes) if (d.open && d.batchId === Number(id) && d.postedAt > t) t = d.postedAt;
  return t;
}

/** Whether a batch sent now lands at a block time other than `avoid`: the latest block's time `latest` is above it. */
export const mayPost = (latest, avoid) => BigInt(avoid) === 0n || BigInt(latest) > BigInt(avoid);

/** The open origin disputes from `floor` on that `keep` selects (disputeRecord), read with `readAll` (every
 *  endpoint, must agree). */
export async function openDisputesFrom(readAll, floor, keep = () => true) {
  const n = BigInt(await readAll("disputeCount"));
  const out = [];
  for (let i = floor; i < n; i++) {
    const d = disputeRecord(i, await readAll("disputes", [i]));
    if (d.open && keep(d)) out.push(d);
  }
  return out;
}

/** Wait until the latest block of every scanner in `list` (src/chain.mjs `scanners`) has a timestamp above `avoid`, so
 *  the next transaction lands at a later block time: polls every `pollMs`, at most `maxMs`, then throws (code
 *  SlotTime). Returns that latest block time. */
export async function waitPast(list, avoid, { maxMs = 60_000, pollMs = 1_000, log = () => {}, id = "?" } = {}) {
  const end = Date.now() + maxMs;
  let told = false;
  for (;;) {
    const times = await Promise.all(list.map((sc) => sc._call((c) => c.getBlock({ blockTag: "latest" })).then((b) => b.timestamp)));
    const latest = times.reduce((a, b) => (b < a ? b : a));
    if (mayPost(latest, avoid)) return latest;
    if (!told) {
      log(`batch ${id}: the batch dropped from this slot (or an open dispute of it) was posted at ${avoid}; waiting for a later block time`);
      told = true;
    }
    if (Date.now() >= end) throw Object.assign(new Error(`batch ${id}: the chain's time did not pass ${avoid} within ${maxMs} ms: not posting into that slot this round`), { code: "SlotTime" });
    await new Promise((r) => setTimeout(r, pollMs));
  }
}
