#!/usr/bin/env node
// MurkFun holders audit: anyone can run this (`murkfun-holders audit`). Rescans the SPACE ID Agent ID registrations
// (HandleRegistry `Registered` / `AdminRegistered`) and the MurkFunHolderRoots `Batch` events over
// public RPC and checks:
//   - every batch: its subtree root and the tree root after it, recomputed from the published list (the batch proof
//     already forces this on chain; this checks the event data and the JS mirror);
//   - every listed address holds an Agent ID (`balanceOf` at the latest block, for EVERY listed address): "extra"
//     entries can be removed with `challenge` at any time (the report prints the arguments);
//   - no listed address was minted with `adminRegister`: "adminMinted" entries can be removed with `disputeOrigin`
//     while their batch is in its challenge window (no registration signature exists for them, so nobody can answer
//     the dispute); after the window a dispute can no longer be opened;
//   - every user-registered holder up to the audit's OWN head (the lowest endpoint head minus --confirmations, minus
//     --grace-s seconds of blocks, 24 h by default: well past the operator's hourly posting cadence) is in the tree: "missing" ones can be forced in with `enqueue`. The operator's `toBlock` is
//     never used for this; batches whose `toBlock` goes backwards or lies before their own registrations
//     are reported under "suspiciousToBlock".
// With two or more --rpc endpoints every log range and every balance is read from each and compared (an endpoint
// that disagrees is reported under "rpcDisagreement", exit 1).
// Exit code: 0 clean, 1 extra / admin-minted entries, a root mismatch or an RPC disagreement, 2 missing holders only.
// Reads only, unless --challenge (below).
//
//   node src/audit.mjs --holder-roots 0x.. --from-block N [--deploy-block N] [--rpc url,..]
//        [--registry 0x60B9..] [--confirmations 30] [--grace-s 86400 | --grace-blocks N] [--report report.json]
//        [--interval-s N] [--challenge --yes] [--challenge-state cache/holders-challenges.json] [--heartbeat file]
//        [--max-deposit 0.05] [--max-gas-price-gwei 5]
// (--report: also write the report to that file; `--json file` is the older spelling of the same.)
// --interval-s N: repeat every N seconds and alert (src/alerts.mjs: holders_audit_failed; also when a round itself
// fails) instead of exiting (600 s is a good interval for the 1 h window: DEFAULT_INTERVAL_S). A round must come well inside the challenge window (an admin-minted entry can be disputed only while its batch is in
// it): an interval of half of CHALLENGE_PERIOD (read from the chain) or more is refused at start, and alerted
// (holders_audit_interval_too_long) if the holder-set owner shortens the window later.
// --challenge --yes (with MURKFUN_CHALLENGER_KEY or MURKFUN_CHALLENGER_KEY_FILE; any funded key; --challenge without
// --yes is refused before anything runs): send the fraud proofs the
// report finds, without a human in the challenge window (1 h): for an "extra" entry commit, then `challenge`; for an
// "adminMinted" entry commit, then `disputeOrigin` (only while its batch is in its challenge window: run the audit
// more often than the challenge period; past it the alert holders_dispute_too_late fires), and `resolveOrigin` once
// its answer window has passed; an admin-minted entry someone else disputed already is adopted and resolved the same
// way (disputes are read from the contract; --challenge-state keeps only the scan floor). Each step is isolated. Only
// entries cross-checked on two or more endpoints are challenged. Before anything is sent: the endpoint must be BNB Smart
// Chain (chain id 56, --chain-id for a test chain), its gas price at most --max-gas-price-gwei (default 5) and the
// contract's DISPUTE_DEPOSIT (sent with each disputeOrigin; the owner can raise it) at most --max-deposit BNB (default
// 0.05); otherwise nothing is sent.
import fs from "fs";
import path from "path";
import { concat, createPublicClient, createWalletClient, encodeAbiParameters, formatEther, formatGwei, getAddress, http, keccak256, pad, parseAbi, parseEther, parseGwei } from "viem";
import { privateKeyToAccount, generatePrivateKey } from "viem/accounts";
import { AGENT_ID_BSC, LOG_BSC_RPCS, confirmedHead, crossChecked, nonHolders, scanners } from "./chain.mjs";
import * as zk from "./tree.mjs";
import { Alerts } from "./alerts.mjs";
import { batchRecord, disputeRecord, isStale } from "./disputes.mjs";
import { isMain } from "./entry.mjs";

export function parseArgs(argv) {
  const o = { rpc: process.env.MURKFUN_HOLDERS_RPC ?? LOG_BSC_RPCS.join(","), registry: AGENT_ID_BSC, confirmations: 30, graceS: 86_400, chunk: 5_000, rps: 4, challengeState: "cache/holders-challenges.json" };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i].replace(/^--/, "").replace(/-([a-z])/g, (_, c) => c.toUpperCase());
    o[k] = k === "challenge" || k === "yes" ? true : argv[++i];
  }
  for (const k of ["confirmations", "graceS", "chunk", "rps"]) o[k] = Number(o[k]);
  if (o.graceBlocks !== undefined) o.graceBlocks = Number(o.graceBlocks);
  o.intervalS = o.intervalS === undefined ? 0 : Number(o.intervalS);
  if (o.report !== undefined) o.json = o.report;
  sendLimits(o); // a bad --max-deposit / --max-gas-price-gwei / --chain-id fails here, before any scan
  if (!o.holderRoots || o.fromBlock === undefined) throw new Error("--holder-roots and --from-block are required");
  return o;
}

const regKey = (r) => `${r.block}:${r.logIndex}:${r.tx}:${r.kind}:${r.owner}:${r.label}`;
const batchKey = (b) => `${b.id}:${b.newRoot}:${b.subtreeRoot}:${b.toBlock}:${b.addrs.join(",")}`;

export async function audit(o) {
  const list = scanners(o.rpc, { chunk: o.chunk, rps: o.rps });
  const roots = getAddress(o.holderRoots);
  const registry = getAddress(o.registry);
  const head = await confirmedHead(list, o.confirmations ?? 30); // registrations are expected up to here
  const latest = await confirmedHead(list, 0); // batches: everything posted so far
  const report = { head: Number(head), endpoints: list.length, batches: 0, holdersRegistered: 0, adminRegistered: 0, addressesListed: 0, rootMismatches: [], extra: [], adminMinted: [], missing: [], duplicates: 0, suspiciousToBlock: [], rpcDisagreement: [] };
  const checked = async (fn, keyOf) => {
    if (list.length < 2) return fn(list[0]);
    try {
      return await crossChecked(list, fn, keyOf, 2);
    } catch (e) {
      if (e.code !== "RpcDisagreement") throw e;
      report.rpcDisagreement.push(e.message);
      return fn(list[0]);
    }
  };
  const live = await checked((s) => s.batches(roots, BigInt(o.deployBlock ?? o.fromBlock), latest), batchKey);
  const regs = await checked((s) => s.registrations(registry, BigInt(o.fromBlock), head), regKey);
  const user = new Map();
  const admin = new Map();
  for (const r of regs) {
    const m = r.kind === "user" ? user : admin;
    if (!m.has(r.owner)) m.set(r.owner, Number(r.block));
  }
  report.batches = live.length;
  report.holdersRegistered = user.size;
  report.adminRegistered = admin.size;

  const tree = new zk.GlobalTree([]);
  const listed = new Set();
  let prevTo = 0;
  for (const b of live) {
    const sub = zk.batchRoot(b.addrs);
    tree.set(b.id, sub);
    if (sub !== b.subtreeRoot || tree.root() !== b.newRoot) report.rootMismatches.push({ id: b.id, subtreeOk: sub === b.subtreeRoot, rootOk: tree.root() === b.newRoot });
    const to = Number(b.toBlock);
    const lastReg = Math.max(0, ...b.addrs.map((a) => user.get(a) ?? 0));
    if (to < prevTo || to < lastReg) report.suspiciousToBlock.push({ batch: b.id, toBlock: to, previousToBlock: prevTo, lastRegistrationListed: lastReg });
    prevTo = Math.max(prevTo, to);
    for (let i = 0; i < b.addrs.length; i++) {
      const a = b.addrs[i];
      report.addressesListed++;
      if (listed.has(a)) report.duplicates++;
      listed.add(a);
      if (admin.has(a)) report.adminMinted.push({ batch: b.id, index: i, address: a, dispute: { id: b.id, index: i, addrs: `${b.addrs.length} addresses from Batch event ${b.id}` } });
    }
  }

  // every listed address must hold an Agent ID now (balanceOf at `latest`, on every endpoint; soulbound: a holder
  // stays one)
  const all = [...listed];
  let bad;
  try {
    bad = new Set(await nonHolders(list.length < 2 ? list : list.slice(0, 2), registry, all, latest));
  } catch (e) {
    if (e.code !== "RpcDisagreement") throw e;
    report.rpcDisagreement.push(e.message);
    bad = new Set(await nonHolders(list.slice(0, 1), registry, all, latest));
  }
  for (const b of live) {
    b.addrs.forEach((a, i) => {
      if (bad.has(a)) report.extra.push({ batch: b.id, index: i, address: a, challengeable: true, challenge: { id: b.id, index: i, addrs: `${b.addrs.length} addresses from Batch event ${b.id}` } });
    });
  }

  // missing: user-registered up to the audit's own head (minus grace), not listed
  const cutoff = Number(head) - (o.graceBlocks ?? await blocksIn(list[0], head, o.graceS));
  for (const [a, block] of user) if (block <= cutoff && !listed.has(a)) report.missing.push({ address: a, registeredAt: block });
  Object.defineProperty(report, "live", { value: live, enumerable: false }); // for --challenge (not in the JSON)
  report.ok = report.rootMismatches.length === 0 && report.extra.length === 0 && report.adminMinted.length === 0 && report.missing.length === 0 && report.rpcDisagreement.length === 0;
  return report;
}

/** About how many blocks `seconds` are at `head` (the average block time of the last 10,000 blocks). */
async function blocksIn(s, head, seconds) {
  const back = head > 10_000n ? 10_000n : head;
  if (back === 0n) return 0;
  const [a, b] = [await s._call((c) => c.getBlock({ blockNumber: head - back })), await s._call((c) => c.getBlock({ blockNumber: head }))];
  const per = Number(b.timestamp - a.timestamp) / Number(back);
  return per > 0 ? Math.ceil(seconds / per) : 0;
}

/** What --challenge may spend unless told otherwise: the dispute deposit per disputeOrigin (BNB) and the gas price. */
export const DEFAULT_MAX_DEPOSIT = "0.05";
export const DEFAULT_MAX_GAS_PRICE_GWEI = "5";

/** The send limits of --challenge from the options: --max-deposit (BNB), --max-gas-price-gwei, --chain-id (56). */
export function sendLimits(o) {
  const num = (v, what) => {
    if (!/^\d+(\.\d+)?$/.test(String(v))) throw new Error(`${what} must be a non-negative number, got ${JSON.stringify(v)}`);
    return String(v);
  };
  const chainId = Number(o.chainId ?? 56);
  if (!Number.isSafeInteger(chainId) || chainId <= 0) throw new Error(`--chain-id must be a chain id, got ${JSON.stringify(o.chainId)}`);
  return {
    maxDepositWei: parseEther(num(o.maxDeposit ?? DEFAULT_MAX_DEPOSIT, "--max-deposit")),
    maxGasPriceWei: parseGwei(num(o.maxGasPriceGwei ?? DEFAULT_MAX_GAS_PRICE_GWEI, "--max-gas-price-gwei")),
    chainId,
  };
}

/** Why a transaction must not be sent (another chain, a gas price or a dispute deposit above the limits), or
 *  undefined. `depositWei`: only for a step that pays the deposit. */
export function sendProblem({ chainId, gasPriceWei, depositWei }, lim) {
  if (chainId !== undefined && chainId !== lim.chainId) return `the sending endpoint is chain ${chainId}, not ${lim.chainId} (--chain-id)`;
  if (gasPriceWei !== undefined && gasPriceWei > lim.maxGasPriceWei) return `its gas price ${formatGwei(gasPriceWei)} gwei is above --max-gas-price-gwei ${formatGwei(lim.maxGasPriceWei)}`;
  if (depositWei !== undefined && depositWei > lim.maxDepositWei) return `the contract's DISPUTE_DEPOSIT is ${formatEther(depositWei)} BNB, above --max-deposit ${formatEther(lim.maxDepositWei)} BNB`;
  return undefined;
}

/** A watch-mode interval well inside the 1 h challenge window. */
export const DEFAULT_INTERVAL_S = 600;

/** Why `intervalS` is too long for a challenge window of `periodS` seconds (a round at least every half window), or
 *  undefined. */
export function intervalProblem(intervalS, periodS) {
  const half = Number(periodS) / 2;
  if (Number(intervalS) < half) return undefined;
  return `--interval-s ${intervalS} is not well inside the holder set's challenge window (CHALLENGE_PERIOD ${periodS} s): ` +
    `an admin-minted entry can be disputed only inside its batch's window, so rounds must come more often than every ${half} s ` +
    `(--interval-s; ${DEFAULT_INTERVAL_S} s suits the 1 h window)`;
}

/** CHALLENGE_PERIOD of the holder set, from the first endpoint. */
async function challengePeriod(o) {
  const [s] = scanners(o.rpc, { chunk: o.chunk, rps: o.rps });
  return s._call((c) => c.readContract({ address: getAddress(o.holderRoots), abi: ROOTS_ABI, functionName: "CHALLENGE_PERIOD" }));
}

const ROOTS_ABI = parseAbi([
  "function CHALLENGE_PERIOD() view returns (uint256)",
  "function commit(bytes32 commitment)",
  "function commitHash(address challenger, uint256 id, uint256 index, bytes32 salt) pure returns (bytes32)",
  "function challenge(uint256 id, uint256 index, address[] addrs, bytes32 salt)",
  "function disputeOrigin(uint256 id, uint256 index, address[] addrs, bytes32 salt) payable returns (uint256)",
  "function resolveOrigin(uint256 dispute)",
  "function disputes(uint256) view returns (address disputer, uint64 openedAt, uint32 batchId, address addr, uint64 postedAt, uint16 index, bool holds, bytes32 listHash, uint32 serial, uint64 answerBy, uint96 deposit)",
  "function disputeCount() view returns (uint256)",
  "function disputeOpen(bytes32) view returns (bool)",
  "function provenOrigin(address) view returns (bool)",
  "function batchCount() view returns (uint256)",
  "function batches(uint256) view returns (uint256 root, bytes32 listHash, uint64 postedAt, uint64 queueStart, uint32 holds, uint32 serial, uint64 usableFrom)",
  "function DISPUTE_DEPOSIT() view returns (uint256)",
  "function batches(uint256) view returns (uint256 root, bytes32 listHash, uint64 postedAt, uint64 queueStart, uint32 holds, uint32 serial, uint64 usableFrom)",
  "event OriginDisputed(uint256 indexed dispute, uint256 indexed id, uint256 index, address addr, address disputer)",
]);
const BALANCE_OF = parseAbi(["function balanceOf(address) view returns (uint256)"]);
/** HolderRoots' `_listHash`: keccak256 over the addresses as 32-byte words. */
const listHash = (addrs) => keccak256(concat(addrs.map((a) => pad(a))));

/**
 * Send the fraud proofs report `r` calls for, each on its own (one failure is reported in `errors` and
 * never skips the rest):
 *   1. every open dispute of an admin-minted entry, ANYONE's (found on chain from `disputeCount` / `disputes(i)`, not
 *      only the ones this audit opened or kept in its state file), is resolved with `resolveOrigin` once its answer
 *      window has passed (someone else's dispute of the same entry makes ours revert
 *      `AlreadyDisputed`, so the audit adopts it; resolving is permissionless);
 *   2. `challenge` the first extra entry (then stop: it drops that batch and every later one; re-audit first);
 *   3. `disputeOrigin` every admin-minted entry nobody disputes yet, while its batch is in its challenge window
 *      (`WindowClosed` after it: such entries are returned in `tooLate`, nothing can remove them any more).
 * Before 1, any open dispute whose batch was dropped (stale, src/disputes.mjs), whoever opened it, is resolved once its
 * answer window has passed (`resolveOrigin` voids it), and listed in `stale` until then.
 * Before any `commit`, the views the reveal depends on are checked (live list, holder or not, dispute already open,
 * origin proven), so a reveal that would revert costs nothing. Only with two or more agreeing endpoints.
 * Returns { sent, adopted, errors, tooLate, stale }.
 */
export async function challengeFindings(o, r, live) {
  if (r.endpoints < 2 || r.rpcDisagreement.length) return { sent: [], adopted: [], errors: [], skipped: "needs two or more agreeing endpoints" };
  const f = process.env.MURKFUN_CHALLENGER_KEY_FILE;
  const key = (f ? fs.readFileSync(f, "utf8") : process.env.MURKFUN_CHALLENGER_KEY ?? "").trim();
  if (!/^0x[0-9a-fA-F]{64}$/.test(key)) throw new Error("--challenge needs MURKFUN_CHALLENGER_KEY (0x + 64 hex) or MURKFUN_CHALLENGER_KEY_FILE");
  const rpcUrl = o.txRpc ?? String(o.rpc).split(",")[0].trim();
  const pub = createPublicClient({ transport: http(rpcUrl) });
  const chain = { id: await pub.getChainId(), name: "bsc", nativeCurrency: { name: "BNB", symbol: "BNB", decimals: 18 }, rpcUrls: { default: { http: [rpcUrl] } } };
  const lim = sendLimits(o);
  const wrongChain = sendProblem({ chainId: chain.id }, lim);
  if (wrongChain) return { sent: [], adopted: [], errors: [`nothing sent: ${wrongChain}`], refused: wrongChain };
  const w = createWalletClient({ account: privateKeyToAccount(key), transport: http(rpcUrl), chain });
  const roots = getAddress(o.holderRoots);
  const registry = getAddress(o.registry ?? AGENT_ID_BSC);
  const read = (functionName, args = [], blockTag) => pub.readContract({ address: roots, abi: ROOTS_ABI, functionName, args, ...(blockTag ? { blockTag } : {}) });
  const tx = async (functionName, args, value = 0n) => {
    // every transaction at the endpoint's gas price, and only below the cap
    const gasPrice = await pub.getGasPrice();
    const p = sendProblem({ gasPriceWei: gasPrice }, lim);
    if (p) throw new Error(`${functionName} not sent: ${p}`);
    const hash = await w.writeContract({ address: roots, abi: ROOTS_ABI, functionName, args, value, gasPrice });
    const rc = await pub.waitForTransactionReceipt({ hash });
    if (rc.status !== "success") throw new Error(`${functionName} reverted (${hash})`);
    return rc;
  };
  const st0 = fs.existsSync(o.challengeState) ? JSON.parse(fs.readFileSync(o.challengeState, "utf8")) : {};
  const st = { disputeFloor: "0", ...st0 };
  const save = () => {
    fs.mkdirSync(path.dirname(o.challengeState), { recursive: true });
    fs.writeFileSync(`${o.challengeState}.tmp`, JSON.stringify(st));
    fs.renameSync(`${o.challengeState}.tmp`, o.challengeState);
  };
  const sent = [];
  const adopted = [];
  const errors = [];
  const each = async (what, fn) => {
    try {
      return await fn();
    } catch (e) {
      errors.push(`${what}: ${String(e.shortMessage ?? e.message).split("\n")[0].slice(0, 200)}`);
      return undefined;
    }
  };
  const reveal = async (fn, b, i, value) => {
    const salt = generatePrivateKey();
    await tx("commit", [await read("commitHash", [w.account.address, BigInt(b), BigInt(i), salt])]);
    // the commit is mined: the reveal lands in a later block
    return tx(fn, [BigInt(b), BigInt(i), live[b].addrs, salt], value);
  };
  /** The views `challenge` / `disputeOrigin` check, read before the commit: the live list and its serial. */
  const liveBatch = async (b) => {
    if (BigInt(b) >= (await read("batchCount"))) throw new Error(`batch ${b} is not live any more`);
    const info = await read("batches", [BigInt(b)]);
    if (info[1] !== listHash(live[b].addrs)) throw new Error(`batch ${b}: the list from its Batch event does not match the contract's (re-posted slot?)`);
    return info;
  };
  const holds = async (a) => (await pub.readContract({ address: registry, abi: BALANCE_OF, functionName: "balanceOf", args: [a] }).catch(() => 0n)) > 0n;
  const admin = new Map(r.adminMinted.map((e) => [`${e.batch}:${e.address}`, e]));

  // 1. every open dispute of an admin-minted entry, whoever opened it: resolved once ripe. Disputes are read from the
  // contract (a dispute once closed stays closed; `disputeFloor` moves only past disputes closed at the finalized
  // block, so a reorg never hides one)
  const now = (await pub.getBlock()).timestamp;
  const count = await read("disputeCount");
  const pendingAdmin = new Set(); // findings with an open dispute already (theirs or ours)
  const stale = []; // open disputes of dropped batches, not yet resolvable
  await each("dispute scan", async () => {
    let floor = BigInt(st.disputeFloor);
    const finalCount = await read("disputeCount", [], "finalized").catch(() => 0n);
    let movable = true;
    for (let i = floor; i < count; i++) {
      const d = await read("disputes", [i]);
      if (BigInt(d[0]) === 0n) {
        if (movable && i < finalCount && BigInt((await read("disputes", [i], "finalized").catch(() => [1n]))[0]) === 0n) floor = i + 1n;
        else movable = false;
        continue;
      }
      movable = false;
      // a stale dispute (its batch was dropped: src/disputes.mjs), anyone's: resolved once its answer window has
      // passed (void: only the deposit goes back to its disputer), so it can never meet a replacement batch
      const rec = disputeRecord(i, d);
      const bc = await read("batchCount");
      if (isStale(rec, bc, BigInt(rec.batchId) < bc ? batchRecord(await read("batches", [BigInt(rec.batchId)])) : undefined)) {
        if (BigInt(now) < rec.answerBy) {
          stale.push(`dispute ${i} of ${rec.batchId}:${getAddress(rec.addr)}: stale (batch dropped), resolved once its window ends`);
          continue;
        }
        await each(`resolveOrigin ${i}`, async () => {
          await tx("resolveOrigin", [i]);
          sent.push(`resolveOrigin ${i} (stale)`);
        });
        continue;
      }
      const k = `${d[2]}:${getAddress(d[3])}`;
      // a dispute of a listed holder is the operator's to defend: resolved here only if it is an admin-minted entry or
      // this audit opened it
      if (!admin.has(k) && getAddress(d[0]) !== w.account.address) continue;
      pendingAdmin.add(k);
      if (BigInt(now) < d[9]) { // answerBy: fixed when the dispute was opened
        if (getAddress(d[0]) !== w.account.address) adopted.push(`dispute ${i} of ${k} by ${getAddress(d[0])}: resolved once its window ends`);
        continue;
      }
      await each(`resolveOrigin ${i}`, async () => {
        await tx("resolveOrigin", [i]);
        sent.push(`resolveOrigin ${i}`);
      });
    }
    st.disputeFloor = floor.toString();
    save();
  });

  // 2. a listed non-holder: challenge (the first one; it drops that batch and every later one)
  for (const e of r.extra) {
    const ok = await each(`challenge ${e.batch}/${e.index}`, async () => {
      await liveBatch(e.batch);
      if (await holds(e.address)) throw new Error(`${e.address} holds an Agent ID now: nothing to challenge`);
      await reveal("challenge", e.batch, e.index);
      sent.push(`challenge ${e.batch}/${e.index} ${e.address}`);
      return true;
    });
    if (ok) return { sent, adopted, errors, stale }; // re-audit before the next
  }

  // 3. admin-minted entries nobody disputes yet
  const deposit = await read("DISPUTE_DEPOSIT");
  const tooLate = [];
  for (const e of r.adminMinted) {
    const k = `${e.batch}:${e.address}`;
    if (pendingAdmin.has(k)) continue;
    await each(`disputeOrigin ${e.batch}/${e.index}`, async () => {
      const p = sendProblem({ depositWei: deposit }, lim);
      if (p) throw new Error(`not sent: ${p}`);
      const info = await liveBatch(e.batch);
      // disputes open only inside the batch's challenge window; the commit lands a block before the reveal: margin
      if ((await pub.getBlock()).timestamp + 60n >= info[6]) {
        tooLate.push(`${e.batch}/${e.index} ${e.address}`);
        return;
      }
      if (await read("provenOrigin", [e.address])) throw new Error(`${e.address}: its registration signature was verified on chain (provenOrigin); it can not be disputed`);
      if (!(await holds(e.address))) throw new Error(`${e.address} holds no Agent ID: the challenge path applies`);
      if (await read("disputeOpen", [keccak256(encodeAbiParameters([{ type: "uint32" }, { type: "address" }], [info[5], e.address]))])) {
        // opened after the scan above (or on a block it did not see): adopted next round
        adopted.push(`${k}: already disputed, adopted next round`);
        return;
      }
      await reveal("disputeOrigin", e.batch, e.index, deposit);
      sent.push(`disputeOrigin ${e.batch}/${e.index} ${e.address}`);
    });
  }
  return { sent, adopted, errors, tooLate, stale };
}

export function exitCode(r) {
  return r.rootMismatches.length || r.extra.length || r.adminMinted.length || r.rpcDisagreement.length ? 1 : r.missing.length ? 2 : 0;
}

/** Repeat the audit every `intervalS` seconds and alert on its outcome. */
export async function watch(o) {
  const alerts = new Alerts("holders-audit");
  const tooLong = intervalProblem(o.intervalS, await challengePeriod(o));
  if (tooLong) {
    console.error(`REFUSED: ${tooLong}`);
    await alerts.event("holders_audit_interval_too_long", "critical", `holder-set audit refused to start: ${tooLong}`);
    process.exit(1);
  }
  for (;;) {
    try {
      // the holder-set owner can shorten the window (setParams): alert, keep auditing
      const p = intervalProblem(o.intervalS, await challengePeriod(o));
      await alerts.level("holders_audit_interval_too_long", !!p, "critical", p ? `holder-set audit: ${p}` : "the audit interval is inside the challenge window again");
      const r = await audit(o);
      const code = exitCode(r);
      const summary = `extra ${r.extra.length}, admin-minted ${r.adminMinted.length}, root mismatches ${r.rootMismatches.length}, RPC disagreements ${r.rpcDisagreement.length}, missing ${r.missing.length}`;
      console.log(`audit: ${summary}`);
      if (o.json) fs.writeFileSync(o.json, JSON.stringify(r, (_, v) => (typeof v === "bigint" ? v.toString() : v), 2));
      await alerts.level("holders_audit_failed", code !== 0, code === 1 ? "critical" : "warning", code === 0 ? "the holder set matches the registry again"
        : code === 1 ? `holder-set audit: ${summary}. Extra / admin-minted entries can be removed with a fraud proof (the report lists the arguments; murkfun-holders challenge sends them)`
        : `holder-set audit: ${r.missing.length} registered holder(s) missing past the grace period; the operator should post them (or anyone can enqueue them)`);
      let failed = [];
      if (o.challenge) {
        const c = await challengeFindings(o, r, r.live);
        for (const x of c.sent) await alerts.event("holders_fraud_proof_sent", "critical", `holder-set audit sent ${x}`);
        failed = c.errors ?? [];
        for (const x of failed) console.error(`challenge: ${x}`);
        for (const x of c.tooLate ?? []) await alerts.event("holders_dispute_too_late", "critical", `holder-set audit: admin-minted entry ${x} is past its batch's challenge window, no dispute can remove it any more`);
      }
      await alerts.level("holders_audit_round_failed", failed.length > 0, "critical", failed.length
        ? `holder-set audit: ${failed.length} fraud-proof step(s) failed (${failed[0]}); the others went on`
        : "audit rounds run again");
    } catch (e) {
      console.error(`audit failed: ${e.message}`);
      await alerts.level("holders_audit_round_failed", true, "critical", `a holder-set audit round failed: ${String(e.message).slice(0, 500)}. Fraud detection is not running`);
    }
    if (o.heartbeat) {
      fs.mkdirSync(path.dirname(o.heartbeat), { recursive: true });
      fs.writeFileSync(o.heartbeat, new Date().toISOString());
    }
    await new Promise((res) => setTimeout(res, o.intervalS * 1000));
  }
}

if (isMain(import.meta.url)) {
  const o = parseArgs(process.argv.slice(2));
  if (o.challenge && !o.yes) throw new Error("--challenge sends fraud proofs: add --yes");
  if (o.intervalS) await watch(o);
  const r = await audit(o);
  if (o.challenge) console.error(JSON.stringify(await challengeFindings(o, r, r.live)));
  const s = JSON.stringify(r, (_, v) => (typeof v === "bigint" ? v.toString() : v), 2);
  if (o.json) fs.writeFileSync(o.json, s);
  console.log(s);
  process.exit(exitCode(r));
}
