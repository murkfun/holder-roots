// Public-RPC log scanning for the holder set: Agent ID registrations and MurkFunHolderRoots batches. Chunked block
// ranges that shrink on "range too large" answers, a request-rate limit, retries with backoff and several endpoints in
// turn. Used by the audit (src/audit.mjs) and the lookup. Reads only; never signs or sends.
//
// Trust: one RPC endpoint is not trusted. `scanners(rpcs)` gives one scanner PINNED to each endpoint (no
// rotation), `crossChecked` asks two or more of them for the same range and throws on any difference, and
// `balances` reads `balanceOf` at a fixed block over a JSON-RPC batch, so the caller can check each endpoint.
import { createPublicClient, decodeEventLog, encodeFunctionData, getAddress, http, parseAbi, parseAbiItem } from "viem";

/** SPACE ID Agent ID registry on BSC (HandleRegistry, soulbound ERC-721, verified source on Sourcify). */
export const AGENT_ID_BSC = "0x60B9262456dE011F7d15a54CdD8c48bAaa8B022F";
/** Free public BSC endpoints (no key). Override with --rpc / MURKFUN_HOLDERS_RPC (comma-separated). */
export const PUBLIC_BSC_RPCS = ["https://bsc-rpc.publicnode.com", "https://bsc.drpc.org", "https://1rpc.io/bnb", "https://bsc-dataseed.bnbchain.org"];
/** The audit's default endpoints: PUBLIC_BSC_RPCS without the bsc-dataseed ones (they refuse eth_getLogs over old
 *  blocks, so a full scan could never finish on them). */
export const LOG_BSC_RPCS = PUBLIC_BSC_RPCS.filter((u) => !/bsc-dataseed/.test(u));

/** HandleRegistry: the user path (backend-signed `register`) and the owner path (`adminRegister`, any address). */
export const REGISTERED = parseAbiItem("event Registered(bytes32 indexed labelhash, address indexed owner, string handle)");
export const ADMIN_REGISTERED = parseAbiItem("event AdminRegistered(bytes32 indexed labelhash, address indexed owner, string handle)");
export const REGISTER_FN = parseAbiItem("function register(string handle, uint256 deadline, bytes sig)");
export const BATCH = parseAbiItem("event Batch(uint256 indexed id, uint256 fromRoot, uint256 newRoot, uint256 subtreeRoot, address[] addrs, uint64 fromBlock, uint64 toBlock)");
export const CHALLENGED = parseAbiItem("event Challenged(uint256 indexed id, uint256 index, address addr, address challenger, uint256 reward, uint256 dropped)");
export const ORIGIN_DISPUTED = parseAbiItem("event OriginDisputed(uint256 indexed dispute, uint256 indexed id, uint256 index, address addr, address disputer)");
const BALANCE_OF = parseAbi(["function balanceOf(address) view returns (uint256)"]);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export class LogScanner {
  /** @param o {{ rpcs: string[], chunk?: number, minChunk?: number, rps?: number, retries?: number, timeoutMs?: number, log?: (s: string) => void }} */
  constructor(o) {
    this.timeoutMs = o.timeoutMs ?? 30_000;
    this.clients = o.rpcs.map((url) => createPublicClient({ transport: http(url, { timeout: this.timeoutMs, retryCount: 0 }) }));
    this.urls = o.rpcs;
    this.chunk = o.chunk ?? 5_000;
    this.minChunk = o.minChunk ?? 50;
    this.gap = 1000 / (o.rps ?? 4);
    this.retries = o.retries ?? 6;
    this.balanceBatch = o.balanceBatch ?? 100;
    this.log = o.log ?? (() => {});
    this.next = 0;
    this.rpc = 0;
    this.requests = 0;
  }

  async _call(fn) {
    let err;
    for (let attempt = 0; attempt <= this.retries; attempt++) {
      // each call takes the next free slot before it waits, so concurrent calls keep the rate too
      const at = Math.max(Date.now(), this.next);
      this.next = at + this.gap;
      if (at > Date.now()) await sleep(at - Date.now());
      this.requests++;
      try {
        return await fn(this.clients[this.rpc], this.urls[this.rpc]);
      } catch (e) {
        err = e;
        const msg = String(e?.details ?? e?.shortMessage ?? e?.message ?? e);
        // a rate limit ("rate limit", HTTP 429 "Too Many Requests") is retried, not a range to split
        if (/range|limit|too many|too large|exceed|10000|block range/i.test(msg) && !/rate|too many requests/i.test(msg)) throw Object.assign(e, { rangeError: true });
        this.rpc = (this.rpc + 1) % this.clients.length; // next endpoint (a pinned scanner has one)
        await sleep(Math.min(30_000, 500 * 2 ** attempt));
      }
    }
    throw err;
  }

  blockNumber() {
    return this._call((c) => c.getBlockNumber({ cacheTime: 0 }));
  }

  /** All logs of `filter` in [from, to], in order. */
  async logs(filter, from, to, onProgress) {
    const out = [];
    let start = BigInt(from);
    const end = BigInt(to);
    let size = BigInt(this.chunk);
    while (start <= end) {
      const stop = start + size - 1n < end ? start + size - 1n : end;
      try {
        const got = await this._call((c) => c.getLogs({ ...filter, fromBlock: start, toBlock: stop, strict: true }));
        out.push(...got);
        onProgress?.(stop, out.length);
        start = stop + 1n;
        if (size < BigInt(this.chunk)) size = size * 2n > BigInt(this.chunk) ? BigInt(this.chunk) : size * 2n;
      } catch (e) {
        if (!e.rangeError || size <= BigInt(this.minChunk)) throw e;
        size /= 2n;
        this.log(`range too large at ${start}: chunk -> ${size}`);
      }
    }
    return out;
  }

  /**
   * HandleRegistry registrations in [from, to], in chain order: [{ kind: "user" | "admin", owner, label, handle,
   * block, logIndex, tx }]. Only "user" (`Registered`) addresses belong in the holder set.
   */
  async registrations(registry, from, to, onProgress) {
    const logs = await this.logs({ address: registry, events: [REGISTERED, ADMIN_REGISTERED] }, from, to, onProgress);
    return logs
      .map((l) => ({ kind: l.eventName === "Registered" ? "user" : "admin", owner: getAddress(l.args.owner), label: l.args.labelhash, handle: l.args.handle, block: l.blockNumber, logIndex: l.logIndex, tx: l.transactionHash }))
      .sort((a, b) => (a.block === b.block ? a.logIndex - b.logIndex : a.block < b.block ? -1 : 1));
  }

  /** Live MurkFunHolderRoots batches (dropped ones removed), in id order: [{ id, addrs, newRoot, subtreeRoot, fromBlock, toBlock, block }].
   *  `initial`: the live batches up to `from - 1` (a persisted scan), so a round only reads the new blocks. */
  async batches(holderRoots, from, to, initial = []) {
    const logs = await this.logs({ address: holderRoots }, from, to);
    const live = [...initial];
    for (const l of logs) {
      let ev;
      try {
        ev = decodeEventLog({ abi: [BATCH, CHALLENGED], data: l.data, topics: l.topics });
      } catch {
        continue;
      }
      if (ev.eventName === "Batch") {
        live.length = Number(ev.args.id); // a re-posted slot replaces a dropped one
        live.push({ id: Number(ev.args.id), addrs: ev.args.addrs.map((a) => getAddress(a)), newRoot: ev.args.newRoot, subtreeRoot: ev.args.subtreeRoot, fromBlock: ev.args.fromBlock, toBlock: ev.args.toBlock, block: l.blockNumber });
      } else if (ev.eventName === "Challenged") {
        live.length = Number(ev.args.id);
      }
    }
    return live;
  }

  /** `registry.balanceOf(a)` for every address at `block`, in JSON-RPC batches of `size`: Map(address -> bigint). */
  async balances(registry, addrs, block, size = this.balanceBatch) {
    const out = new Map();
    const tag = `0x${BigInt(block).toString(16)}`;
    for (let i = 0; i < addrs.length; i += size) {
      const part = addrs.slice(i, i + size);
      const body = part.map((a, k) => ({ jsonrpc: "2.0", id: k, method: "eth_call", params: [{ to: registry, data: encodeFunctionData({ abi: BALANCE_OF, functionName: "balanceOf", args: [a] }) }, tag] }));
      const res = await this._call(async (_, url) => {
        const r = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body), signal: AbortSignal.timeout(this.timeoutMs) });
        const j = await r.json();
        if (!Array.isArray(j) || j.length !== part.length) throw new Error(`balanceOf batch: bad answer from ${url}`);
        // only an execution revert is an answer (no Agent ID); any other per-item error (rate limit, missing state,
        // a timeout inside the batch) is a failed read, retried like a failed request
        for (const x of j) {
          if (!Number.isInteger(x?.id) || x.id < 0 || x.id >= part.length) throw new Error(`balanceOf batch: bad answer from ${url}`);
          if (x.error ? !isRevert(x.error) : typeof x.result !== "string" || !/^0x[0-9a-fA-F]*$/.test(x.result)) {
            // "rate" in the message: retried, never taken for a range error (whatever the node's message says)
            throw new Error(`balanceOf batch: ${url} failed a read (${String(x.error?.message ?? "no result").slice(0, 120)}); retried like a rate limit`);
          }
        }
        return j;
      });
      for (const x of res) {
        // a reverting balanceOf (OZ ERC721 for address 0) counts as no Agent ID, as on chain; so does no code ("0x")
        out.set(part[x.id], x.error || x.result === "0x" ? 0n : BigInt(x.result));
      }
    }
    return out;
  }
}

/** A JSON-RPC error object that is the call reverting (geth / erigon: code 3, or "execution reverted"), not a failure
 *  to answer. */
export function isRevert(err) {
  return err?.code === 3 || /revert/i.test(String(err?.message ?? ""));
}

/** One scanner pinned to each endpoint (no rotation between them: every answer is attributable). */
export function scanners(rpcs, o = {}) {
  const urls = [...new Set(String(rpcs).split(",").map((s) => s.trim()).filter(Boolean))];
  return urls.map((url) => new LogScanner({ ...o, rpcs: [url] }));
}

const key = (r) => `${r.block}:${r.logIndex}:${r.tx}:${r.kind}:${r.owner}:${r.label}`;

/**
 * `fn(scanner)` on every scanner (at least `min`); throws `RpcDisagreement` unless all answers are equal (compared
 * with `keyOf`). Returns the first answer.
 */
export async function crossChecked(list, fn, keyOf = key, min = 2) {
  if (list.length < min) throw Object.assign(new Error(`need ${min} independent RPC endpoints (--rpc a,b), got ${list.length}`), { code: "RpcCount" });
  const answers = [];
  for (const s of list) answers.push(await fn(s));
  const ref = answers[0].map(keyOf).join("\n");
  for (let i = 1; i < answers.length; i++) {
    const other = answers[i].map(keyOf);
    if (other.join("\n") !== ref) {
      const a = new Set(answers[0].map(keyOf));
      const b = new Set(other);
      const onlyA = [...a].filter((x) => !b.has(x));
      const onlyB = [...b].filter((x) => !a.has(x));
      throw Object.assign(new Error(`RPC endpoints disagree (${list[0].urls[0]} vs ${list[i].urls[0]}): ${onlyA.length} vs ${onlyB.length} different entries, e.g. ${onlyA[0] ?? onlyB[0]}`), { code: "RpcDisagreement", onlyA, onlyB });
    }
  }
  return answers[0];
}

/** The lowest head over the endpoints minus `confirmations`, and never past any endpoint's `finalized` block when it
 *  reports one (confirmations alone are seconds of BSC blocks; finality is what makes a log permanent). */
export async function confirmedHead(list, confirmations, { finalized = confirmations > 0 } = {}) {
  let head;
  for (const s of list) {
    let b = await s.blockNumber();
    if (finalized) {
      const f = await s._call((c) => c.getBlock({ blockTag: "finalized" })).then((x) => x.number, () => undefined);
      if (f !== undefined && f !== null && f + BigInt(confirmations) < b) b = f + BigInt(confirmations);
    }
    if (head === undefined || b < head) head = b;
  }
  const h = head - BigInt(confirmations);
  return h < 0n ? 0n : h;
}

/**
 * `balanceOf > 0` for every address at `block`, on every endpoint. Returns the addresses some endpoint reports as
 * non-holders, and throws `RpcDisagreement` if the endpoints disagree.
 */
export async function nonHolders(list, registry, addrs, block) {
  const views = [];
  for (const s of list) views.push(await s.balances(registry, addrs, block));
  const bad = [];
  for (const a of addrs) {
    const vals = views.map((v) => v.get(a) > 0n);
    if (vals.some((x) => x !== vals[0])) throw Object.assign(new Error(`RPC endpoints disagree on balanceOf(${a}) at ${block}`), { code: "RpcDisagreement" });
    if (!vals[0]) bad.push(a);
  }
  return bad;
}
