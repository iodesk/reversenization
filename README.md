# VibesWAF

A reverse proxy and WAF built for personal use and experimentation. Not production-hardened, not battle-tested — just a fun project to learn how WAFs work from the inside.

Built in Go. Uses [Coraza](https://github.com/corazawaf/coraza) + OWASP CRS for managed rules, PostgreSQL for config, ClickHouse for logs, Redis for state.

---

## What it does

Sits in front of your apps (via OpenResty/nginx), runs each request through a 4-phase pipeline, and decides: block, challenge, or allow.

```
Request → Phase 1 (Hard Rules) → Phase 2 (Scoring) → Phase 3 (Decision) → Phase 4 (Response)
```

---

## Highlights

### Predictable scoring pipeline

Every request produces a numeric score (0–100) from five independent categories. The final decision is always `score ≥ block_threshold → block`, `score ≥ challenge_threshold → challenge`, else allow. No magic, no hidden rules.

```
ip_reputation   +20  →  ×1.0  →  cap 25  →  20
bot_detection   +45  →  ×1.0  →  cap 35  →  35
waf_anomaly      +5  →  ×1.5  →  cap 40  →   7
protocol_anomaly  0
trust             0
─────────────────────────────────────────────
total: 62  →  CHALLENGE (threshold: 50)
```

All weights, caps, and thresholds are configurable from the dashboard. Nothing is hardcoded.

---

### Full pipeline trace as raw JSON

Every request carries a `PipelineTrace` that records exactly what happened at each stage — which rule fired, raw score, multiplier, final score after cap, and the decision.

```json
{
  "phase": "scoring",
  "decision": "challenge",
  "score": 62,
  "stages": [
    {
      "stage": "ip_reputation",
      "score": 20,
      "multiplier": 1.0,
      "final_score": 20,
      "reason": "manual_asn:9009"
    },
    {
      "stage": "bot_detection",
      "score": 45,
      "multiplier": 1.0,
      "final_score": 35,
      "reason": "missing_sec_fetch:15,chromium_missing_sec_ch_ua:15,chromium_missing_sec_fetch:15",
      "evidence": "capped at 35"
    },
    {
      "stage": "waf_anomaly",
      "score": 5,
      "multiplier": 1.5,
      "final_score": 7,
      "rule_id": "920280"
    }
  ]
}
```

Stored in ClickHouse. Queryable from the dashboard log viewer.

---

### Early-exit hard rules (Phase 1)

Before any scoring happens, deterministic checks run in order and exit immediately on match:

```
ChallengeValidator → IPAccess → Flood → RateLimit → Cache → Custom Rules
```

- **ChallengeValidator** — validates the `ok` cookie (HMAC-SHA256, includes trust level)
- **IPAccess** — per-app allow/block/challenge by CIDR or single IP
- **Flood** — 256-shard in-memory flood detector with penalty period
- **RateLimit** — token bucket per IP+UA, no Redis on hot path
- **Cache** — replays cached decisions for repeat fingerprints
- **Custom Rules** — expression-based rules (IP, path, UA, headers, geo, ASN) with `skip` support for per-module bypass

Hard decision → skip Phase 2 entirely. Target: < 3ms.

---

### Challenge with trajectory analysis

The slider challenge collects raw mouse trajectory data (position + timing) and sends it to the backend on solve. The server analyzes it and assigns a trust level (0–3) based on:

- Speed variance (human: irregular, bot: constant)
- Straightness (human: 0.85–0.98, bot: ~1.0)
- Y-axis jitter
- Direction changes
- Timing regularity

Trust level feeds back into Phase 2 as a negative score (0 to −15), so a high-confidence human solve can bring a borderline request below the challenge threshold on the next request.

---

### Trust history

IPs with N consecutive clean requests (no block/challenge) accumulate a trust score over time. Configurable threshold and reduction value from the dashboard.

---

### Zero DB queries on the request path

All config (scoring weights, app config, rate limits, IP reputation) is preloaded into memory via atomic swap with a background refresh. PostgreSQL is only hit by the config loader goroutine, never by the request handler.

---

### Async logging to ClickHouse

All requests are logged regardless of decision. Logging is a side effect — it happens via a buffered channel and batch worker. The request handler never waits for a log write.

---

## Stack

| Component | Role |
|-----------|------|
| Go | Core proxy + pipeline |
| OpenResty (nginx + Lua) | TLS termination, JA4 fingerprinting, dynamic cert via `ssl_certificate_by_lua` |
| Coraza + OWASP CRS | Managed WAF rules |
| PostgreSQL | Config storage |
| ClickHouse | Request logs + analytics |
| Redis | Rate limit state, challenge store |
| React + Vite | Dashboard frontend |
| MaxMind GeoIP2 | Geo lookup + datacenter detection |

---

## Dashboard

Web UI to manage everything without touching config files:

- **Applications** — proxy targets, per-app overrides
- **Security Rules** — expression-based custom rules
- **Rate Limiter** — flood + token bucket profiles
- **Bot Detector** — per-rule scores, UA patterns, trust level config
- **WAF Settings** — paranoia level, disabled rules, custom SecRules
- **IP Reputation** — manual IP/ASN scores
- **Scoring Engine** — per-category multiplier, cap, thresholds
- **Logs** — request log viewer with raw JSON trace
- **Analytics** — traffic overview, threat breakdown

---

## Requirements

- Go 1.25+
- PostgreSQL
- ClickHouse
- Redis
- OpenResty (for TLS + JA4)

---

## Setup

```sh
cp .env.example .env
# edit .env

# run migrations
./wafer migrate

# start
./wafer
```

Frontend:

```sh
cd frontend
cp .env.example .env
npm install
npm run build
```

See `config/` for nginx, systemd service, and ACME scripts.

---

## Caveats

- Personal project. No guarantees, no SLA, no support.
- Test coverage is partial.
- Some features assume OpenResty is in front (JA4 header, dynamic SSL).
- Not designed for multi-tenant.
