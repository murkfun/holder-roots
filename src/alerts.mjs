// Alerts of the audit's --interval-s mode (and any other long-running holder-set service): a Discord embed
// (ALERT_DISCORD_WEBHOOK_URL, posted as ALERT_DISCORD_USERNAME, default "murkfun-holders"; ALERT_DISCORD_MENTION pinged
// on critical firing alerts) and a generic JSON webhook (ALERT_WEBHOOK_URL). Level alerts go out once per transition (firing / resolved) and again every
// ALERT_REPEAT_MINUTES (60) while firing. Without a URL they are only logged. Messages never contain keys, and URLs in
// them are cut to their host (RPC endpoints carry API keys).
//
// The audit's alerts:
//   holders_audit_failed     critical  extra / admin-minted entries, a root mismatch or an RPC disagreement (exit 1);
//                                      warning: holders missing past the grace period (exit 2)
//   holders_audit_interval_too_long critical  --interval-s is half the challenge window or more (refused at start;
//                                      level alert if the window is shortened later)
//   holders_audit_round_failed critical  a round, or one of its fraud-proof steps, failed
//   holders_fraud_proof_sent critical  event: --challenge sent a fraud proof
//   holders_dispute_too_late critical  event: an admin-minted entry is past its batch's challenge window

const COLOR = { critical: 0xdc2626, warning: 0xf59e0b, info: 0x3b82f6, resolved: 0x16a34a };
const ICON = { critical: "🔴", warning: "🟠", info: "🔵", resolved: "✅" };
const clip = (s, n) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);
/** URLs (RPC endpoints carry API keys in their paths and queries) replaced by their host. */
export const redact = (s) => String(s).replace(/\b(https?|wss?):\/\/([^/\s"'?#]+)[^\s"']*/g, "$1://$2/…");

export class Alerts {
  constructor(service, env = process.env, fetchFn = fetch) {
    this.service = service;
    this.discord = env.ALERT_DISCORD_WEBHOOK_URL || undefined;
    this.generic = env.ALERT_WEBHOOK_URL || undefined;
    this.mention = env.ALERT_DISCORD_MENTION || undefined;
    this.username = env.ALERT_DISCORD_USERNAME || "murkfun-holders";
    this.envName = env.ALERT_ENV ?? env.MURKFUN_ENV ?? null;
    this.repeatMs = Number(env.ALERT_REPEAT_MINUTES ?? 60) * 60_000;
    this.fetch = fetchFn;
    this.active = new Map(); // alert -> { since, sentAt }
    this.sent = [];
  }

  /** A level alert: `on` true fires (or repeats), false resolves a firing one. */
  async level(alert, on, severity, message, labels = {}) {
    const a = this.active.get(alert);
    if (on) {
      const now = Date.now();
      if (a && (this.repeatMs === 0 || now - a.sentAt < this.repeatMs)) return;
      const since = a?.since ?? new Date(now).toISOString();
      this.active.set(alert, { since, sentAt: now });
      return this.post({ alert, severity, status: "firing", message, labels, startsAt: since });
    }
    if (!a) return;
    this.active.delete(alert);
    return this.post({ alert, severity, status: "resolved", message, labels, startsAt: a.since });
  }

  /** A one-off event. */
  event(alert, severity, message, labels = {}) {
    return this.post({ alert, severity, status: "event", message, labels, startsAt: new Date().toISOString() });
  }

  async post(p) {
    p = { ...p, message: redact(p.message) };
    const ts = new Date().toISOString();
    const body = { service: this.service, env: this.envName, ...p, ts, text: `[${p.severity}] ${p.alert}: ${p.message}`, content: `[${p.severity}] ${p.alert}: ${p.message}` };
    this.sent.push(body);
    console.error(`alert ${p.status} ${p.alert} (${p.severity}): ${p.message}`);
    const kind = p.status === "resolved" ? "resolved" : p.severity;
    const state = p.status === "resolved" ? "RESOLVED" : p.status === "event" ? `${p.severity.toUpperCase()} event` : p.severity.toUpperCase();
    const ping = this.mention && p.status === "firing" && p.severity === "critical";
    const discord = {
      username: this.username,
      ...(ping ? { content: this.mention } : {}),
      allowed_mentions: ping ? { parse: ["everyone", "roles", "users"] } : { parse: [] },
      embeds: [{
        title: clip(`${ICON[kind]} [${state}] ${this.envName ? `${this.envName} ` : ""}${this.service}: ${p.alert}`, 256),
        description: clip(p.message, 4096),
        color: COLOR[kind],
        fields: Object.entries(p.labels).slice(0, 20).map(([name, value]) => ({ name: clip(name, 256), value: clip(String(value), 1024), inline: true })),
        timestamp: ts,
      }],
    };
    const send = (url, b) => this.fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(b), signal: AbortSignal.timeout(10_000) })
      .catch((e) => console.error(`alert delivery failed: ${String(e.message ?? e).slice(0, 200)}`));
    await Promise.all([this.discord && send(this.discord, discord), this.generic && send(this.generic, body)]);
  }
}
