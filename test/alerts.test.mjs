// src/alerts.mjs: level alerts once per transition, events, both payloads.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Alerts } from "../src/alerts.mjs";

test("level alerts fire once, repeat only after ALERT_REPEAT_MINUTES, resolve once; events always go out; Discord + generic payloads", async () => {
  const got = [];
  const fakeFetch = async (url, init) => { got.push({ url, body: JSON.parse(init.body) }); return new Response(null, { status: 204 }); };
  const a = new Alerts("holders-audit", { ALERT_DISCORD_WEBHOOK_URL: "http://discord.invalid/x", ALERT_WEBHOOK_URL: "http://hook.invalid/y", ALERT_DISCORD_MENTION: "@here", ALERT_ENV: "test" }, fakeFetch);
  await a.level("holders_audit_failed", true, "critical", "round failed");
  await a.level("holders_audit_failed", true, "critical", "round failed");
  assert.equal(got.length, 2, "one firing notification to each webhook");
  const discord = got.find((g) => g.url.startsWith("http://discord")).body;
  assert.match(discord.embeds[0].title, /\[CRITICAL\] test holders-audit: holders_audit_failed/);
  assert.equal(discord.content, "@here");
  const generic = got.find((g) => g.url.startsWith("http://hook")).body;
  assert.deepEqual([generic.service, generic.alert, generic.severity, generic.status], ["holders-audit", "holders_audit_failed", "critical", "firing"]);
  await a.level("holders_audit_failed", false, "critical", "ok again");
  await a.level("holders_audit_failed", false, "critical", "ok again");
  assert.equal(got.filter((g) => g.url.startsWith("http://hook") && g.body.status === "resolved").length, 1, "resolved once");
  assert.equal(got.length, 4);
  await a.event("holders_fraud_proof_sent", "info", "challenge 3/7 sent");
  assert.equal(got.find((g) => g.url.startsWith("http://hook") && g.body.alert === "holders_fraud_proof_sent").body.status, "event");
  assert.equal(new Alerts("x", {}, fakeFetch).discord, undefined, "no URL: only logged");
});
