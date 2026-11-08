// The MurkFun holder tree: leaf, node, the empty-subtree roots, batch subtrees, the global tree of batch slots, Merkle
// paths and the batch circuit's witness. MurkFun's own operator tooling uses this same file.
//
// Hash: Poseidon2 over BN254 (Noir's black box, `poseidon::poseidon2::Poseidon2::hash`), sponge IV = len << 64.
// Holder tree: depth 26 = a global tree of 2^16 batch slots, each slot an aligned subtree of 1024 leaves (one
// MurkFunHolderRoots batch, zero-padded). leaf(A) = H(A); an empty leaf is 0. The contract hard-codes the empty root
// (EMPTY_ROOT = ZEROS[26]) and the batch circuit (circuits/batch) proves newRoot = append(oldRoot, addrs).
import { poseidon2Hash } from "@zkpassport/poseidon2";
import { getAddress, toHex } from "viem";

/** The BN254 scalar field (every hash input and output is below it). */
export const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const BATCH_LOG = 10;
export const GLOBAL_LOG = 16;
export const DEPTH = BATCH_LOG + GLOBAL_LOG;
export const BATCH_SIZE = 1 << BATCH_LOG;

export const H = (xs) => poseidon2Hash(xs.map((x) => BigInt(x)));
export const node = (l, r) => H([l, r]);
export const leaf = (addr) => H([BigInt(getAddress(addr))]);

/** zeros[i] = root of an empty subtree of height i. */
export const ZEROS = (() => {
  const z = [0n];
  for (let i = 0; i < DEPTH; i++) z.push(node(z[i], z[i]));
  return z;
})();

/** Root of one batch subtree (1024 leaves, zero-padded) and its levels. */
export function batchLevels(addrs) {
  if (addrs.length > BATCH_SIZE) throw new Error("batch too large");
  let layer = Array.from({ length: BATCH_SIZE }, (_, i) => (i < addrs.length ? leaf(addrs[i]) : 0n));
  const levels = [layer];
  for (let l = 0; l < BATCH_LOG; l++) {
    const next = [];
    for (let i = 0; i < layer.length; i += 2) next.push(node(layer[i], layer[i + 1]));
    levels.push((layer = next));
  }
  return levels;
}
export const batchRoot = (addrs) => batchLevels(addrs)[BATCH_LOG][0];

/** Sparse Merkle path / root over 2^GLOBAL_LOG slots of batch roots (empty slot = ZEROS[BATCH_LOG]). */
export class GlobalTree {
  constructor(batchRoots = []) {
    this.levels = [new Map()];
    batchRoots.forEach((r, i) => this.set(i, r));
  }
  get(level, i) {
    return this.levels[level]?.get(i) ?? ZEROS[BATCH_LOG + level];
  }
  set(index, value) {
    let i = index;
    let v = value;
    for (let l = 0; l <= GLOBAL_LOG; l++) {
      (this.levels[l] ??= new Map()).set(i, v);
      if (l === GLOBAL_LOG) break;
      const sib = this.get(l, i ^ 1);
      v = i & 1 ? node(sib, v) : node(v, sib);
      i >>= 1;
    }
  }
  root() {
    return this.get(GLOBAL_LOG, 0);
  }
  siblings(index) {
    const out = [];
    let i = index;
    for (let l = 0; l < GLOBAL_LOG; l++, i >>= 1) out.push(this.get(l, i ^ 1));
    return out;
  }
}

/** Root after appending `batches` (arrays of addresses) in order, starting from the empty tree. */
export function rootOfBatches(batches) {
  return new GlobalTree(batches.map(batchRoot)).root();
}

/** Membership path of `addr` (first occurrence) given every batch's address list. */
export function holderPath(batches, addr) {
  const a = getAddress(addr);
  for (let b = 0; b < batches.length; b++) {
    const j = batches[b].findIndex((x) => getAddress(x) === a);
    if (j < 0) continue;
    const levels = batchLevels(batches[b]);
    const inner = [];
    for (let l = 0, i = j; l < BATCH_LOG; l++, i >>= 1) inner.push(levels[l][i ^ 1]);
    const tree = new GlobalTree(batches.map((x, k) => (k === b ? levels[BATCH_LOG][0] : batchRoot(x))));
    return { index: BigInt(b) * BigInt(BATCH_SIZE) + BigInt(j), siblings: [...inner, ...tree.siblings(b)], root: tree.root() };
  }
  return undefined;
}

/** Same as holderPath when the batch roots (from the Batch events) are already known: hashes only `addr`'s batch. */
export function holderPathFromRoots(batchAddrs, batchIndex, roots, addr) {
  const a = getAddress(addr);
  const j = batchAddrs.findIndex((x) => getAddress(x) === a);
  if (j < 0) return undefined;
  const levels = batchLevels(batchAddrs);
  if (levels[BATCH_LOG][0] !== BigInt(roots[batchIndex])) throw new Error("batch root does not match its address list");
  const inner = [];
  for (let l = 0, i = j; l < BATCH_LOG; l++, i >>= 1) inner.push(levels[l][i ^ 1]);
  const tree = new GlobalTree(roots.map(BigInt));
  return { index: BigInt(batchIndex) * BigInt(BATCH_SIZE) + BigInt(j), siblings: [...inner, ...tree.siblings(batchIndex)], root: tree.root() };
}

export function rootFromPath(leafValue, index, siblings) {
  let cur = leafValue;
  let i = BigInt(index);
  for (const s of siblings) {
    cur = i & 1n ? node(s, cur) : node(cur, s);
    i >>= 1n;
  }
  return cur;
}

const f = (x) => `"${toHex(BigInt(x))}"`;

/** Batch circuit witness (Prover.toml): append `addrs` as batch `batchIndex` to the tree of `prevRoots` (batch roots
 *  so far). */
export function batchWitness(prevRoots, batchIndex, addrs) {
  const tree = new GlobalTree(prevRoots.map(BigInt));
  const oldRoot = tree.root();
  const siblings = tree.siblings(batchIndex);
  const sub = batchRoot(addrs);
  tree.set(batchIndex, sub);
  const padded = Array.from({ length: BATCH_SIZE }, (_, i) => (i < addrs.length ? BigInt(getAddress(addrs[i])) : 0n));
  const toml = [
    `old_root = ${f(oldRoot)}`,
    `new_root = ${f(tree.root())}`,
    `batch_index = ${f(batchIndex)}`,
    `count = ${addrs.length}`,
    `subtree_root = ${f(sub)}`,
    `addrs = [${padded.map(f).join(", ")}]`,
    `siblings = [${siblings.map(f).join(", ")}]`,
  ].join("\n");
  return { toml, oldRoot, newRoot: tree.root(), subtreeRoot: sub };
}
