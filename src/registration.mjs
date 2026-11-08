// A holder's SPACE ID registration signature: the (deadline, sig) of its `HandleRegistry.register` call, read from the
// transaction of its `Registered` event. Forced inclusion (`enqueue`) and the answer to an origin dispute
// (`defendOrigin`) both take it; MurkFunHolderRoots checks it against the registry's known signers
// (`registrationSigner`). Reads only.
import { decodeFunctionData, toFunctionSelector } from "viem";
import { REGISTERED, REGISTER_FN } from "./chain.mjs";

/**
 * Every candidate (deadline, sig) of `addr`'s `HandleRegistry.register` call, from each endpoint in turn: the
 * transaction of its `Registered` event (`txHash` when known, else found from `fromBlock` on), decoded as a top-level
 * call and at every occurrence of the selector in the calldata (embedded calls, e.g. through a smart account). With
 * `check(deadline, sig)` (answers of the `registrationSigner` view, one per endpoint) only candidates some endpoint
 * accepts are returned, those every answering endpoint accepts first. Endpoints that fail or have nothing are
 * skipped; the result has no duplicates.
 */
export async function registrationSignatures(list, registry, addr, { txHash, fromBlock = 0n, check } = {}) {
  const seen = new Set();
  const all = [];
  const ok = [];
  const want = toFunctionSelector(REGISTER_FN).slice(2);
  const tryDecode = (data) => {
    try {
      const { args } = decodeFunctionData({ abi: [REGISTER_FN], data });
      return { deadline: args[1], sig: args[2] };
    } catch {
      return undefined;
    }
  };
  for (const sc of list) {
    const before = all.length;
    const fromTx = async (tx) => {
      const { input } = await sc._call((c) => c.getTransaction({ hash: tx }));
      const found = [tryDecode(input)];
      const hex = input.slice(2);
      for (let i = hex.indexOf(want); i >= 0; i = hex.indexOf(want, i + 1)) if (i % 2 === 0) found.push(tryDecode(`0x${hex.slice(i)}`));
      for (const c of found) {
        if (!c) continue;
        const k = `${c.deadline}:${c.sig.toLowerCase()}`;
        if (seen.has(k)) continue;
        seen.add(k);
        all.push(c);
      }
    };
    // the known transaction first; without one, or when it gives nothing here (a reorg moved it?), the logs
    if (txHash) await fromTx(txHash).catch(() => {});
    if (all.length === before) {
      try {
        const logs = await sc.logs({ address: registry, event: REGISTERED, args: { owner: addr } }, fromBlock, await sc.blockNumber());
        for (const l of logs) await fromTx(l.transactionHash).catch(() => {});
      } catch {
        // this endpoint failed: the next one may have it
      }
    }
    if (!check) {
      if (all.length) break;
      continue;
    }
    for (const c of all.slice(before)) {
      const signers = await check(c.deadline, c.sig).catch(() => []);
      const good = signers.filter((x) => BigInt(x) !== 0n).length;
      if (good) ok.push({ ...c, all: good === signers.length });
    }
    if (ok.some((c) => c.all)) break; // every endpoint accepts one: no need to ask the others
  }
  if (!check) return all;
  return ok.sort((x, y) => Number(y.all) - Number(x.all)).map(({ all: _a, ...c }) => c);
}

/** The first candidate of `registrationSignatures` (unchecked), or undefined. */
export async function registrationSignature(list, registry, addr, txHash) {
  return (await registrationSignatures(list, registry, addr, { txHash }))[0];
}
