// src/chain.mjs against a stub JSON-RPC endpoint (no chain, nothing leaves the machine).
import assert from "node:assert/strict";
import http from "node:http";
import { test } from "node:test";
import { LogScanner, nonHolders } from "../src/chain.mjs";

const A = "0x00000000000000000000000000000000000000a1";
const B = "0x00000000000000000000000000000000000000b2";
const REG = "0x60B9262456dE011F7d15a54CdD8c48bAaa8B022F";

/** An endpoint answering every balanceOf batch item with `answer(address, n)` (n: the request count so far). */
async function stub(answer) {
  let n = 0;
  const srv = http.createServer(async (req, res) => {
    let body = "";
    for await (const c of req) body += c;
    n++;
    const items = JSON.parse(body).map((m) => ({ jsonrpc: "2.0", id: m.id, ...answer(`0x${m.params[0].data.slice(-40)}`, n) }));
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify(items));
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${srv.address().port}`, close: () => new Promise((r) => srv.close(r)), requests: () => n };
}
const one = `0x${"1".padStart(64, "0")}`;

test("balanceOf: only an execution revert reads as no Agent ID; a rate limit or any other item error is a failed read", async () => {
  const revert = await stub((a) => (a === B ? { error: { code: 3, message: "execution reverted: ERC721: address zero is not a valid owner" } } : { result: one }));
  const limited = await stub((a) => (a === B ? { error: { code: -32005, message: "rate limit exceeded" } } : { result: one }));
  const missing = await stub((a) => (a === B ? { error: { code: -32000, message: "missing trie node" } } : { result: one }));
  const recovers = await stub((a, n) => (a === B && n === 1 ? { error: { code: -32005, message: "too many requests" } } : { result: one }));
  try {
    const s = (url, retries = 0) => new LogScanner({ rpcs: [url], rps: 1000, retries });
    assert.deepEqual(await nonHolders([s(revert.url)], REG, [A, B], 1n), [B], "a revert is an answer: no Agent ID");
    await assert.rejects(nonHolders([s(limited.url)], REG, [A, B], 1n), /failed a read \(rate limit exceeded\)/);
    await assert.rejects(nonHolders([s(missing.url)], REG, [A, B], 1n), /failed a read \(missing trie node\)/);
    // a failed read is retried like a failed request
    assert.deepEqual(await nonHolders([s(recovers.url, 1)], REG, [A, B], 1n), []);
    assert.equal(recovers.requests(), 2);
  } finally {
    for (const x of [revert, limited, missing, recovers]) await x.close();
  }
});
