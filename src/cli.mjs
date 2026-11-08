#!/usr/bin/env node
// murkfun-holders: check MurkFun's holder set yourself. Read-only by default; nothing is sent without --key-file AND
// --yes: challenge and enqueue only simulate without them, and `audit --interval-s N --challenge` refuses to start.
import fs from "node:fs";
import { createPublicClient, createWalletClient, formatEther, getAddress, http } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { DEFAULT_MAX_DEPOSIT, DEFAULT_MAX_GAS_PRICE_GWEI, audit, challengeFindings, exitCode, sendLimits, sendProblem, watch } from "./audit.mjs";
import { scanners } from "./chain.mjs";
import { HolderSetReader, parseQuery, treeSummary } from "./lookup.mjs";
import { BSC, ROOTS_VIEWS } from "./network.mjs";
import { registrationSignatures } from "./registration.mjs";
import { isMain } from "./entry.mjs";

export const USAGE = `murkfun-holders: check MurkFun's holder set (MurkFunHolderRoots on BNB Smart Chain) yourself.

  murkfun-holders status                      the contract's state: batches, accepted / current root, queue
  murkfun-holders tree                        rebuild the whole tree from the Batch events; compare every root with
                                              the contract's (exit 1 on any mismatch)
  murkfun-holders lookup <0xaddress|name|name.ai>
                                              one holder: Agent ID owner / handle, origin, batch, position, accepted,
                                              usableFrom and its verified Merkle path
  murkfun-holders audit                       diff the tree with the SPACE ID registry: listed non-holders, admin-
                                              minted entries, missing holders (exit 1 / 2, see README)
  murkfun-holders challenge                   audit, then remove what it finds with fraud proofs (needs two --rpc)
  murkfun-holders enqueue <0xaddress|name>    force a registered holder into the next batches (forced inclusion)

Options:
  --rpc url[,url2]     BSC JSON-RPC endpoints (default ${BSC.rpcs.join(",")}); with two or more every log range is
                       cross-checked. They must serve eth_getLogs over old blocks.
  --no-api             never ask MurkFun's holder-set API (${BSC.api}); everything from the chain (slower). Without
                       it, lookup and enqueue send the address you look up to that API (a hint only, checked on
                       chain), so MurkFun's server sees it with your IP address
  --api url            another holder-set API (default ${BSC.api})
  --holder-roots 0x..  another MurkFunHolderRoots (default ${BSC.holderRoots})
  --json               machine-readable output
  --key-file <file>    challenge / enqueue: a file holding the sending key (0x + 64 hex; any funded key)
  --yes                challenge / enqueue: really send (without it: a dry run that sends nothing)
  --tx-rpc url         challenge / enqueue: the endpoint that sends (default the first --rpc)
  --chain-id N         challenge / enqueue: the chain the sending endpoint must be (default 56); nothing is sent
                       on another
  --max-deposit BNB    challenge: the most DISPUTE_DEPOSIT a disputeOrigin may send (default ${DEFAULT_MAX_DEPOSIT})
  --max-gas-price-gwei N  challenge / enqueue: nothing is sent above this gas price (default ${DEFAULT_MAX_GAS_PRICE_GWEI})

Audit options (audit, challenge):
  --confirmations N    blocks below the head the audit stops at (default 30)
  --grace-s N          a registered holder counts as missing only after N seconds (default 86400) (or --grace-blocks N)
  --report file        also write the report as JSON to this file
  --rps N, --chunk N   requests per second per endpoint (default 4), blocks per eth_getLogs (default 5000)
  --registry 0x..      the Agent ID registry (default ${BSC.registry})
  --from-block N       first registry block scanned (default ${BSC.registryFromBlock})
  --deploy-block N     the holder set's deploy block (default ${BSC.holderRootsDeployBlock})
  --interval-s N       repeat every N seconds and alert through ALERT_WEBHOOK_URL / ALERT_DISCORD_WEBHOOK_URL
  --challenge          with --interval-s: send the fraud proofs each round finds (needs --key-file and --yes)
  --challenge-state f  where --challenge keeps its scan floor (default .murkfun-holders/challenges.json)
  --heartbeat file     with --interval-s: touched after every round

Install or update: npm install -g https://github.com/murkfun/holder-roots/releases/latest/download/murkfun-holders.tgz
`;

export class UsageError extends Error {}

/** argv → { cmd, args: positional[], o: options }. */
export function parseCli(argv) {
  const o = {};
  const args = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) {
      args.push(a);
      continue;
    }
    const k = a.slice(2).replace(/-([a-z])/g, (_, c) => c.toUpperCase());
    if (["json", "yes", "noApi", "help", "challenge"].includes(k)) o[k] = true;
    else {
      if (i + 1 >= argv.length) throw new UsageError(`${a} needs a value`);
      o[k] = argv[++i];
    }
  }
  const cmd = args.shift();
  return { cmd, args, o };
}

/** The sending account from --key-file (the key is never printed). */
export function keyFromFile(file) {
  if (!file) throw new UsageError("--key-file <file> is required to send");
  const k = fs.readFileSync(file, "utf8").trim();
  if (!/^0x[0-9a-fA-F]{64}$/.test(k)) throw new UsageError(`${file} does not hold a key (0x + 64 hex digits)`);
  return k;
}

/** The audit's options with this network's defaults. */
export function auditOptions(o) {
  return {
    rpc: o.rpc ?? BSC.rpcs.join(","), registry: o.registry ?? BSC.registry, confirmations: Number(o.confirmations ?? 30),
    graceS: Number(o.graceS ?? 86_400), chunk: Number(o.chunk ?? 5_000), rps: Number(o.rps ?? 4),
    graceBlocks: o.graceBlocks === undefined ? undefined : Number(o.graceBlocks), intervalS: Number(o.intervalS ?? 0),
    holderRoots: o.holderRoots ?? BSC.holderRoots, fromBlock: o.fromBlock ?? BSC.registryFromBlock,
    deployBlock: o.deployBlock ?? BSC.holderRootsDeployBlock, challengeState: o.challengeState ?? ".murkfun-holders/challenges.json",
    txRpc: o.txRpc, json: o.report, challenge: !!o.challenge, heartbeat: o.heartbeat,
    maxDeposit: o.maxDeposit, maxGasPriceGwei: o.maxGasPriceGwei, chainId: o.chainId,
  };
}

const json = (x) => JSON.stringify(x, (_, v) => (typeof v === "bigint" ? v.toString() : v), 2);

function reader(o) {
  return new HolderSetReader({ rpc: o.rpc, holderRoots: o.holderRoots, api: o.noApi ? "" : o.api, log: o.json ? undefined : (s) => console.error(s) });
}

function printTree(t) {
  console.log(`MurkFunHolderRoots ${t.holderRoots} (chain ${t.chainId}), Batch events up to block ${t.head}, ${t.endpoints} endpoint(s)`);
  console.log(`batches ${t.batchCount}, leaves ${t.leaves}, accepted batch ${t.acceptedBatch ?? "none yet"}`);
  for (const b of t.batches) console.log(`  batch ${b.id}: ${b.count} addresses, root ${b.root} ${b.accepted ? "accepted" : `usable from ${b.usableFrom ? new Date(b.usableFrom * 1000).toISOString() : "?"}`}${b.subtreeOk && b.eventRootOk && b.contractRootOk && b.listHashOk ? "" : "  MISMATCH"}`);
  console.log(`current root  rebuilt ${t.rebuiltCurrentRoot}\n              contract ${t.currentRoot}`);
  console.log(`accepted root rebuilt ${t.rebuiltAcceptedRoot}\n              contract ${t.acceptedRoot}`);
  console.log(t.ok ? "OK: every root recomputed from the published lists equals the contract's." : `MISMATCH:\n  ${t.mismatches.join("\n  ")}`);
}

async function enqueue(o, target) {
  const r = reader(o);
  const q = parseQuery(target);
  const reg = await r.registryOf(q);
  if (!reg.address) throw new UsageError(`${target}: no Agent ID with this name`);
  const a = reg.address;
  if (await r.read("enqueued", [a])) return { address: a, sent: false, reason: "already enqueued (each address once, ever)" };
  const hint = await r.apiLookup(a);
  const list = scanners(r.rpcs.join(","), { chunk: 5_000, rps: 4 });
  const check = async (deadline, sig) => Promise.all(list.map((s) => s._call((c) => c.readContract({ address: r.roots, abi: ROOTS_VIEWS, functionName: "registrationSigner", args: [a, deadline, sig] }))));
  const [c] = await registrationSignatures(list, r.registry, a, { txHash: hint?.mint?.tx, fromBlock: r.registryFromBlock, check });
  if (!c) return { address: a, sent: false, reason: "no registration signature the contract accepts (minted with adminRegister, or by a signer it never recorded)" };
  const key = o.keyFile ? keyFromFile(o.keyFile) : undefined;
  const account = key ? privateKeyToAccount(key) : undefined;
  const url = o.txRpc ?? r.rpcs[0];
  const pub = createPublicClient({ transport: http(url) });
  const req = { address: r.roots, abi: ROOTS_VIEWS, functionName: "enqueue", args: [a, c.deadline, c.sig], account: account?.address ?? "0x0000000000000000000000000000000000000001" };
  await pub.simulateContract(req); // throws with the revert reason
  if (!o.yes || !account) return { address: a, sent: false, dryRun: true, simulated: "ok", deadline: c.deadline.toString(), next: "add --key-file <file> --yes to send it" };
  const lim = sendLimits(o);
  const [chainId, gasPrice] = await Promise.all([pub.getChainId(), pub.getGasPrice()]);
  const p = sendProblem({ chainId, gasPriceWei: gasPrice }, lim);
  if (p) throw new Error(`enqueue not sent: ${p}`);
  const chain = { id: chainId, name: "bsc", nativeCurrency: { name: "BNB", symbol: "BNB", decimals: 18 }, rpcUrls: { default: { http: [url] } } };
  const w = createWalletClient({ account, transport: http(url), chain });
  const hash = await w.writeContract({ address: r.roots, abi: ROOTS_VIEWS, functionName: "enqueue", args: [a, c.deadline, c.sig], gasPrice });
  const rc = await pub.waitForTransactionReceipt({ hash });
  return { address: a, sent: true, tx: hash, status: rc.status };
}

async function challenge(o) {
  const ao = auditOptions(o);
  const rep = await audit(ao);
  const findings = { extra: rep.extra, adminMinted: rep.adminMinted, rpcDisagreement: rep.rpcDisagreement };
  if (!rep.extra.length && !rep.adminMinted.length) return { ...findings, sent: [], note: "nothing to challenge" };
  if (!o.yes || !o.keyFile) {
    // what a real run would send: commit + reveal for the first extra entry and for each admin-minted one, each
    // disputeOrigin with the contract's DISPUTE_DEPOSIT (plus resolveOrigin for disputes whose answer window passed)
    const deposit = await reader(o).read("DISPUTE_DEPOSIT");
    const lim = sendLimits(o);
    const plan = {
      transactions: (rep.extra.length ? 2 : 0) + 2 * rep.adminMinted.length,
      disputeDepositBnb: formatEther(deposit), totalDepositBnb: formatEther(deposit * BigInt(rep.adminMinted.length)),
      maxDepositBnb: formatEther(lim.maxDepositWei),
      ...(rep.adminMinted.length && deposit > lim.maxDepositWei ? { refused: `DISPUTE_DEPOSIT is above --max-deposit: the disputes would not be sent` } : {}),
    };
    return { ...findings, sent: [], dryRun: true, plan, next: "add --key-file <file> --yes to send the fraud proofs (two or more agreeing --rpc endpoints are required)" };
  }
  keyFromFile(o.keyFile); // checked here, read again by challengeFindings
  process.env.MURKFUN_CHALLENGER_KEY_FILE = o.keyFile;
  delete process.env.MURKFUN_CHALLENGER_KEY;
  return { ...findings, ...(await challengeFindings(ao, rep, rep.live)) };
}

export async function main(argv) {
  const { cmd, args, o } = parseCli(argv);
  if (!cmd || o.help || cmd === "help") {
    console.log(USAGE);
    return 0;
  }
  if (o.holderRoots) o.holderRoots = getAddress(o.holderRoots);
  switch (cmd) {
    case "status": {
      const st = await reader(o).state();
      console.log(o.json ? json(st) : Object.entries(st).map(([k, v]) => `${k}: ${typeof v === "object" && v ? JSON.stringify(v) : v}`).join("\n"));
      return 0;
    }
    case "tree": {
      const t = await reader(o).tree();
      if (o.json) console.log(json(treeSummary(t)));
      else printTree(t);
      return t.ok ? 0 : 1;
    }
    case "lookup": {
      if (args.length !== 1) throw new UsageError("lookup takes one 0x address, name or name.ai");
      const r = await reader(o).lookup(args[0]);
      console.log(json(r));
      return 0;
    }
    case "audit": {
      const ao = auditOptions(o);
      if (ao.intervalS) {
        if (ao.challenge && !o.yes) throw new UsageError("audit --interval-s --challenge sends fraud proofs without asking: add --yes (and --key-file <file>)");
        if (ao.challenge) keyFromFile(o.keyFile ?? process.env.MURKFUN_CHALLENGER_KEY_FILE);
        if (o.keyFile) process.env.MURKFUN_CHALLENGER_KEY_FILE = o.keyFile;
        await watch(ao); // never returns
      }
      const r = await audit(ao);
      if (ao.json) fs.writeFileSync(ao.json, json(r));
      console.log(json(r));
      return exitCode(r);
    }
    case "challenge": {
      const c = await challenge(o);
      console.log(json(c));
      // a step that failed (or a refusal: another chain, the gas price or deposit above the limits) is not a success
      return c.errors?.length || c.skipped ? 1 : 0;
    }
    case "enqueue": {
      if (args.length !== 1) throw new UsageError("enqueue takes one 0x address or name");
      console.log(json(await enqueue(o, args[0])));
      return 0;
    }
    default:
      throw new UsageError(`unknown command ${cmd}`);
  }
}

if (isMain(import.meta.url)) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e) => {
      console.error(e instanceof UsageError ? `${e.message}\n\n${USAGE}` : `error: ${String(e.shortMessage ?? e.message ?? e).split("\n")[0]}`);
      process.exit(e instanceof UsageError ? 2 : 1);
    },
  );
}
