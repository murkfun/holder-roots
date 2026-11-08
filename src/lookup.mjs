// Reading the holder set from the chain: the contract's state, one batch's published list, the whole tree rebuilt from
// the Batch events, and a lookup of one holder (address, name or name.ai). Reads only; never signs or sends.
//
// Trust: the chain is the only authority. MurkFun's holder-set API (BSC.api) is used as a hint to avoid a full log
// scan; every fact taken from it is checked on chain or locally before it is reported as verified:
//   - a membership proof: leaf = H(address), the 26 siblings hash up to the proof's root (src/tree.mjs) and that root
//     is the contract's acceptedRoot();
//   - a batch and position: the Batch event of that batch (found from the batch's on-chain postedAt), whose list hashes
//     to the contract's listHash, holds the address at that position;
//   - the origin (register vs adminRegister): the registry's event in the mint transaction's receipt.
// `--no-api` (api: "") skips the API: the batches come from a scan of every Batch event, the origin from a scan of the
// registry's events for that owner (slow on a full history: thousands of eth_getLogs calls).
import { concat, createPublicClient, decodeEventLog, getAddress, http, keccak256, pad, toBytes, toHex } from "viem";
import { ADMIN_REGISTERED, BATCH, REGISTERED, scanners } from "./chain.mjs";
import { BSC, REGISTRY_VIEWS, ROOTS_VIEWS } from "./network.mjs";
import * as tree from "./tree.mjs";

const fhex = (x) => toHex(BigInt(x), { size: 32 });
const num = (x) => (x === undefined || x === null ? null : Number(x));

/** `q`: 0x + 40 hex digits, or an Agent ID name with or without `.ai`. */
export function parseQuery(q) {
  const s = String(q ?? "").trim();
  if (/^0x[0-9a-fA-F]{40}$/.test(s)) return { kind: "address", address: getAddress(s) };
  if (/^0x[0-9a-fA-F]{36,}$/.test(s)) throw new Error(`not an address (0x and 40 hex digits): ${s}`);
  const name = s.toLowerCase().replace(/\.ai$/, "");
  if (/^[a-z0-9]{1,64}$/.test(name)) return { kind: "name", name };
  throw new Error(`not an address or an Agent ID name: ${JSON.stringify(s)} (0x + 40 hex digits, name or name.ai)`);
}

/** The SPACE ID token id of a name (the part before ".ai"). */
export const agentIdOf = (name) => BigInt(keccak256(toBytes(name)));

/** MurkFunHolderRoots' `_listHash`: keccak256 over the addresses as 32-byte words. */
export const listHash = (addrs) => keccak256(addrs.length ? concat(addrs.map((a) => pad(a))) : "0x");

export class HolderSetReader {
  /** @param o {{ rpc?: string, holderRoots?: string, registry?: string, deployBlock?: number|bigint,
   *   registryFromBlock?: number|bigint, api?: string, chunk?: number, rps?: number, log?: (s: string) => void }} */
  constructor(o = {}) {
    this.rpcs = String(o.rpc ?? BSC.rpcs.join(",")).split(",").map((s) => s.trim()).filter(Boolean);
    if (!this.rpcs.length) throw new Error("no RPC endpoint (--rpc url[,url2])");
    this.pub = createPublicClient({ transport: http(this.rpcs[0], { timeout: 30_000, retryCount: 3 }) });
    this.roots = getAddress(o.holderRoots ?? BSC.holderRoots);
    this.registry = getAddress(o.registry ?? BSC.registry);
    this.deployBlock = BigInt(o.deployBlock ?? BSC.holderRootsDeployBlock);
    this.registryFromBlock = BigInt(o.registryFromBlock ?? BSC.registryFromBlock);
    this.api = o.api === undefined ? BSC.api : o.api;
    this.scanOpts = { chunk: o.chunk ?? 5_000, rps: o.rps ?? 4, log: o.log };
    this.log = o.log ?? (() => {});
  }

  read(functionName, args = [], address = this.roots, abi = ROOTS_VIEWS) {
    return this.pub.readContract({ address, abi, functionName, args });
  }

  /** The contract's state: batch count, accepted and current roots, the challenge window, the queue, who governs it
   *  (owner, operator; the same key when `ownerIsOperator`) and the bond / dispute deposit. */
  async state() {
    const [chainId, batchCount, accepted, currentRoot, challengePeriod, rootHistory, heldFrom, queueHead, queueTail, operator, openDisputes, owner, minBond, disputeDeposit] = await Promise.all([
      this.pub.getChainId(), this.read("batchCount"), this.read("acceptedRoot"), this.read("currentRoot"), this.read("CHALLENGE_PERIOD"),
      this.read("ROOT_HISTORY"), this.read("heldFrom"), this.read("queueHead"), this.read("queueTail"), this.read("operator"), this.read("openDisputes"),
      this.read("owner"), this.read("MIN_BOND"), this.read("DISPUTE_DEPOSIT"),
    ]);
    const none = (1n << 256n) - 1n;
    const count = Number(batchCount);
    // acceptedRoot() answers (0, 0) while no batch is accepted yet
    const acceptedBatch = count > 0 && accepted[0] !== 0n ? Number(accepted[1]) : null;
    return {
      chainId, holderRoots: this.roots, batchCount: count, acceptedBatch, acceptedRoot: acceptedBatch === null ? null : fhex(accepted[0]), currentRoot: fhex(currentRoot),
      challengePeriodS: Number(challengePeriod), rootHistory: Number(rootHistory), heldFrom: heldFrom === none ? null : Number(heldFrom),
      queue: { head: Number(queueHead), tail: Number(queueTail), length: Number(queueTail - queueHead) }, operator, openDisputes: Number(openDisputes),
      owner, ownerIsOperator: getAddress(owner) === getAddress(operator), minBondWei: minBond.toString(), disputeDepositWei: disputeDeposit.toString(),
    };
  }

  /** The contract's record of batch `id`. */
  async batchInfo(id) {
    const b = await this.read("batches", [BigInt(id)]);
    return { id: Number(id), root: b[0], listHash: b[1], postedAt: Number(b[2]), queueStart: Number(b[3]), holds: Number(b[4]), serial: Number(b[5]), usableFrom: Number(b[6]) };
  }

  /** Blocks [from, to] whose timestamp is `ts` (BSC puts several blocks in one second). */
  async blocksAt(ts) {
    const latest = await this.pub.getBlockNumber();
    const time = async (n) => (await this.pub.getBlock({ blockNumber: n })).timestamp;
    const after = async (t, lo, hi) => {
      let end = hi + 1n;
      while (lo < end) {
        const mid = (lo + end) / 2n;
        if ((await time(mid)) > t) end = mid;
        else lo = mid + 1n;
      }
      return lo;
    };
    const t = BigInt(ts);
    const from = await after(t - 1n, this.deployBlock, latest);
    let step = 1n;
    while (from + step <= latest && (await time(from + step)) === t) step *= 2n;
    const to = (await after(t, from, from + step > latest ? latest : from + step)) - 1n;
    return { from, to: to < from ? from : to };
  }

  /** Batch `id`'s published list, from its Batch event (found from the batch's on-chain postedAt), checked against the
   *  contract's listHash. Throws if it can not be found or does not match. */
  async batchList(id) {
    const info = await this.batchInfo(id);
    if (!info.postedAt) throw new Error(`batch ${id} does not exist`);
    const { from, to } = await this.blocksAt(info.postedAt);
    const logs = await this.pub.getLogs({ address: this.roots, event: BATCH, args: { id: BigInt(id) }, fromBlock: from, toBlock: to, strict: true });
    // a dropped and re-posted slot has several Batch events: the one whose list matches the contract's is the live one
    for (const l of logs.reverse()) {
      const addrs = l.args.addrs.map((a) => getAddress(a));
      if (listHash(addrs) === info.listHash) return { ...info, addrs, subtreeRoot: l.args.subtreeRoot, newRoot: l.args.newRoot, block: Number(l.blockNumber), tx: l.transactionHash };
    }
    throw new Error(`batch ${id}: no Batch event in blocks ${from}-${to} matches the contract's listHash`);
  }

  /** Every live batch from the Batch events (dropped ones removed), cross-checked over every --rpc endpoint. */
  async allBatches() {
    const list = scanners(this.rpcs.join(","), this.scanOpts);
    const head = await this.pub.getBlockNumber();
    const answers = [];
    for (const s of list) answers.push(await s.batches(this.roots, this.deployBlock, head));
    const key = (bs) => bs.map((b) => `${b.id}:${b.newRoot}:${b.subtreeRoot}:${b.addrs.join(",")}`).join("\n");
    for (let i = 1; i < answers.length; i++) {
      if (key(answers[i]) !== key(answers[0])) throw Object.assign(new Error(`RPC endpoints disagree on the Batch events (${list[0].urls[0]} vs ${list[i].urls[0]})`), { code: "RpcDisagreement" });
    }
    return { batches: answers[0], head: Number(head), endpoints: list.length };
  }

  /**
   * The whole tree rebuilt from the Batch events: every batch's subtree root and tree root recomputed from its published
   * list and compared with the event and the contract, the current root and the accepted root compared with the
   * contract's. `ok` is true when everything matches.
   */
  async tree() {
    const st = await this.state();
    const { batches, head, endpoints } = await this.allBatches();
    const g = new tree.GlobalTree([]);
    const rows = [];
    const mismatches = [];
    let acceptedRoot = null;
    if (batches.length !== st.batchCount) mismatches.push(`the Batch events give ${batches.length} live batches, the contract has batchCount ${st.batchCount}`);
    for (const b of batches) {
      const sub = tree.batchRoot(b.addrs);
      g.set(b.id, sub);
      const info = b.id < st.batchCount ? await this.batchInfo(b.id) : undefined;
      const row = {
        id: b.id, count: b.addrs.length, subtreeRoot: fhex(sub), root: fhex(g.root()),
        subtreeOk: sub === b.subtreeRoot, eventRootOk: g.root() === b.newRoot,
        contractRootOk: info ? g.root() === info.root : false, listHashOk: info ? listHash(b.addrs) === info.listHash : false,
        postedAt: info?.postedAt ?? null, usableFrom: info?.usableFrom ?? null, accepted: st.acceptedBatch !== null && b.id <= st.acceptedBatch,
      };
      if (!row.subtreeOk || !row.eventRootOk || !row.contractRootOk || !row.listHashOk) mismatches.push(`batch ${b.id}: ${["subtreeOk", "eventRootOk", "contractRootOk", "listHashOk"].filter((k) => !row[k]).map((k) => k.replace(/Ok$/, "")).join(", ")} wrong`);
      if (row.accepted && b.id === st.acceptedBatch) acceptedRoot = row.root;
      rows.push(row);
    }
    const currentRoot = fhex(g.root());
    if (currentRoot !== st.currentRoot) mismatches.push(`rebuilt current root ${currentRoot} != contract currentRoot() ${st.currentRoot}`);
    if (acceptedRoot !== st.acceptedRoot) mismatches.push(`rebuilt accepted root ${acceptedRoot} != contract acceptedRoot() ${st.acceptedRoot}`);
    const leaves = rows.reduce((n, r) => n + r.count, 0);
    return { ok: mismatches.length === 0, head, endpoints, ...st, leaves, rebuiltCurrentRoot: currentRoot, rebuiltAcceptedRoot: acceptedRoot, mismatches, batches: rows, list: batches };
  }

  /** The SPACE ID side of a query: { address, handle, holdsAgentId }. */
  async registryOf(q) {
    if (q.kind === "name") {
      const owner = await this.read("ownerOf", [agentIdOf(q.name)], this.registry, REGISTRY_VIEWS).catch(() => null);
      if (!owner) return { address: null, handle: null, holdsAgentId: false };
      return { address: getAddress(owner), handle: `${q.name}.ai`, holdsAgentId: true };
    }
    const [handle, balance] = await Promise.all([
      this.read("handleOf", [q.address], this.registry, REGISTRY_VIEWS).catch(() => ""),
      this.read("balanceOf", [q.address], this.registry, REGISTRY_VIEWS).catch(() => 0n),
    ]);
    return { address: q.address, handle: handle ? `${handle}.ai` : null, holdsAgentId: balance > 0n };
  }

  /** `register` (the user path, in the holder set) or `admin` (adminRegister, never in it), from the mint
   *  transaction's receipt; undefined when the receipt has no registration of `addr`. */
  async originFromTx(addr, txHash) {
    const rc = await this.pub.getTransactionReceipt({ hash: txHash });
    for (const l of rc.logs) {
      if (getAddress(l.address) !== this.registry) continue;
      try {
        const ev = decodeEventLog({ abi: [REGISTERED, ADMIN_REGISTERED], data: l.data, topics: l.topics });
        if (getAddress(ev.args.owner) === addr) return { origin: ev.eventName === "Registered" ? "register" : "admin", tx: txHash, block: Number(rc.blockNumber) };
      } catch {
        // another event of the registry
      }
    }
    return undefined;
  }

  /** The origin from a scan of the registry's events for `addr` (slow: the whole registry history). */
  async originFromLogs(addr) {
    const [s] = scanners(this.rpcs[0], this.scanOpts);
    const head = await this.pub.getBlockNumber();
    const logs = await s.logs({ address: this.registry, events: [REGISTERED, ADMIN_REGISTERED], args: { owner: addr } }, this.registryFromBlock, head);
    const l = logs[0];
    return l ? { origin: l.eventName === "Registered" ? "register" : "admin", tx: l.transactionHash, block: Number(l.blockNumber) } : undefined;
  }

  /** GET <api>/v1/holders/lookup?q=<address> (a hint), or undefined if the API is off, down or answers garbage. */
  async apiLookup(addr) {
    if (!this.api) return undefined;
    try {
      const r = await fetch(`${this.api.replace(/\/+$/, "")}/v1/holders/lookup?q=${addr}`, { signal: AbortSignal.timeout(15_000), headers: { accept: "application/json" } });
      if (!r.ok) return undefined;
      const j = await r.json();
      return j && typeof j === "object" ? j : undefined;
    } catch {
      return undefined;
    }
  }

  /**
   * One holder: who it is on the registry (owner, handle, origin), where it is in the tree (batch, position, accepted,
   * usableFrom) and, when its batch is accepted, its Merkle path against the accepted root (checked here). Every field
   * says whether it was verified on chain (`verified`); `source` says where the hints came from (`api` or `chain`).
   */
  async lookup(query) {
    const q = parseQuery(query);
    const reg = await this.registryOf(q);
    const st = await this.state();
    const out = {
      query: String(query).trim(), address: reg.address, handle: reg.handle, holdsAgentId: reg.holdsAgentId, origin: null, mint: null,
      member: false, batch: null, position: null, postedAt: null, usableFrom: null, accepted: false, acceptedBatch: st.acceptedBatch,
      acceptedRoot: st.acceptedRoot, queued: false, path: null, source: this.api ? "api" : "chain", verified: { registry: true, origin: false, membership: false, path: false }, notes: [],
    };
    if (!reg.address) {
      out.notes.push("no Agent ID with this name");
      return out;
    }
    const a = reg.address;
    out.queued = await this.read("enqueued", [a]);
    const hint = this.api ? await this.apiLookup(a) : undefined;
    if (this.api && !hint) {
      out.notes.push("the holder-set API did not answer: chain only");
      out.source = "chain";
    }

    // origin
    if (hint?.mint?.tx) {
      const o = await this.originFromTx(a, hint.mint.tx).catch(() => undefined);
      if (o) Object.assign(out, { origin: o.origin, mint: { tx: o.tx, block: o.block } }, { verified: { ...out.verified, origin: true } });
      else out.notes.push("the API's mint transaction holds no registration of this address");
    }
    if (!out.verified.origin && (!this.api || !hint)) {
      const o = await this.originFromLogs(a).catch((e) => void out.notes.push(`origin scan failed: ${e.shortMessage ?? e.message}`));
      if (o) Object.assign(out, { origin: o.origin, mint: { tx: o.tx, block: o.block } }, { verified: { ...out.verified, origin: true } });
    }

    // membership + path
    if (hint && typeof hint.batch === "number" && typeof hint.position === "number") {
      const b = await this.batchList(hint.batch).catch((e) => void out.notes.push(`batch ${hint.batch}: ${e.message}`));
      if (b && b.addrs[hint.position] === a) {
        Object.assign(out, { member: true, batch: b.id, position: hint.position, postedAt: b.postedAt, usableFrom: b.usableFrom });
        out.verified.membership = true;
      } else if (b) out.notes.push(`the API's batch ${hint.batch} / position ${hint.position} does not hold this address on chain`);
      out.accepted = out.member && st.acceptedBatch !== null && out.batch <= st.acceptedBatch;
      if (out.accepted && hint.proof) {
        const p = hint.proof;
        let siblings = [];
        let index = -1n;
        let ok = false;
        try {
          siblings = (p.siblings ?? []).map((x) => BigInt(x));
          index = BigInt(p.leafIndex ?? -1);
          ok = siblings.length === tree.DEPTH && siblings.every((x) => x >= 0n && x < tree.FIELD) &&
            index === BigInt(out.batch) * BigInt(tree.BATCH_SIZE) + BigInt(out.position) &&
            BigInt(p.leaf) === tree.leaf(a) && tree.rootFromPath(tree.leaf(a), index, siblings) === BigInt(st.acceptedRoot);
        } catch {
          ok = false; // not numbers: garbage
        }
        if (ok) {
          out.path = { leaf: fhex(tree.leaf(a)), leafIndex: index.toString(), siblings: siblings.map(fhex), root: st.acceptedRoot };
          out.verified.path = true;
        } else out.notes.push("the API's proof does not verify against the contract's acceptedRoot(): ignored");
      }
    }
    if (!out.verified.membership && (!this.api || !hint || hint.batch === null || hint.batch === undefined)) {
      // chain only: every Batch event (also when the API says "not in the tree": a claim of absence is checked too)
      if (!this.api || !hint) {
        const { batches } = await this.allBatches();
        for (const b of batches) {
          const j = b.addrs.indexOf(a);
          if (j < 0) continue;
          const info = await this.batchInfo(b.id);
          Object.assign(out, { member: true, batch: b.id, position: j, postedAt: info.postedAt, usableFrom: info.usableFrom });
          break;
        }
        out.verified.membership = true; // present or absent, from the chain's own events
        out.accepted = out.member && st.acceptedBatch !== null && out.batch <= st.acceptedBatch;
        if (out.accepted) {
          const live = batches.slice(0, st.acceptedBatch + 1);
          const p = tree.holderPathFromRoots(live[out.batch].addrs, out.batch, live.map((b) => tree.batchRoot(b.addrs)), a);
          if (p && fhex(p.root) === st.acceptedRoot) {
            out.path = { leaf: fhex(tree.leaf(a)), leafIndex: p.index.toString(), siblings: p.siblings.map(fhex), root: fhex(p.root) };
            out.verified.path = true;
          } else out.notes.push("the path rebuilt from the Batch events does not reach the contract's acceptedRoot()");
        }
      } else out.notes.push("the API says this address is in no batch (not checked: run with --no-api to scan every Batch event)");
    }
    if (!out.member && out.origin === "admin") out.notes.push("minted with adminRegister: never part of the holder set");
    else if (!out.member && reg.holdsAgentId) out.notes.push(out.queued ? "enqueued: the operator's next batches must include it once QUEUE_GRACE (1 h) passed" : "not in the tree yet: the operator adds new holders in hourly batches (or anyone can force it in: murkfun-holders enqueue)");
    else if (out.member && !out.accepted) out.notes.push(`in batch ${out.batch}, still in its challenge window (usable from ${new Date(out.usableFrom * 1000).toISOString()})`);
    return out;
  }
}

/** Remove the batch lists from a tree() result (they are large) and make it JSON-friendly. */
export function treeSummary(t) {
  const { list: _list, ...rest } = t;
  return rest;
}
