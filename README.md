# VibesWAF

A reverse proxy and WAF built for personal use and experimentation. Not production-hardened, not battle-tested: just a project to learn how WAFs work from the inside.

![Pipeline Trace](screenshot/11.%20Pipeline-trace.png)

Built in Go. Uses [Coraza](https://github.com/corazawaf/coraza) + OWASP CRS for managed rules, PostgreSQL for config, ClickHouse for logs, Redis for state.

---

## What it does

Sits in front of your apps (behind OpenResty/nginx), runs each request through a 4-phase pipeline, and decides: block, challenge, or allow. Everything passes through.

```
Request -> Phase 1 (Hard Rules) -> Phase 2 (Scoring) -> Phase 3 (Decision) -> Phase 4 (Response)
```

---

## Pipeline

### Phase 1: Hard Rules (deterministic, early exit)

Runs in order. If any handler makes a decision (block/challenge), the pipeline stops immediately.

```
ChallengeValidator -> IPAccess -> Flood -> RateLimit -> Cache -> Custom Rules
```

- **ChallengeValidator**: validates the `ok` cookie (HMAC-SHA256 with IP + UA + timestamp + trust level). If valid, the request carries a trust level into Phase 2.
- **IPAccess**: per-app allow/block/challenge by CIDR or single IP. Match is terminal.
- **Flood**: 256-shard in-memory detector with configurable penalty period. Handles basic, attack, and error flood profiles.
- **RateLimit**: token bucket per IP+UA. No Redis on the hot path.
- **Cache**: replays cached decisions for repeat request fingerprints.
- **Custom Rules**: expression-based rules (IP, path, UA, headers, geo, ASN). Supports `skip` action to bypass specific Phase 2 modules.

If any Phase 1 handler issues a terminal decision, Phases 2 and 3 are skipped and the pipeline jumps directly to Phase 4.

### Phase 2: Scoring (cumulative)

All handlers run. Each contributes points to five independent categories:

```
IPReputation -> BotDetection -> WAFEngine -> ProtocolAnomaly -> TrustedHistory -> StableSession -> Trust
```

| Category | Source | Typical signals |
|---|---|---|
| `ip_reputation` | MaxMind, Spamhaus, manual entries | Datacenter IP, known bad ASN |
| `bot_detection` | UA analysis, header consistency, timing | Missing Sec-Fetch, bot UA pattern, burst rate |
| `waf_anomaly` | Coraza + OWASP CRS | SQLi, XSS, LFI, RCE rule matches |
| `protocol_anomaly` | HTTP header analysis, JA4 fingerprinting | Content-Type on GET, TE/CL conflict, old TLS + browser UA |
| `trust` | Challenge result, history, known good bots | Negative score (reduction) for verified users |

After all handlers run, each category score is clamped to its `max_score` and multiplied by its configured multiplier. Categories can be disabled from the dashboard (score resets to 0).

### Phase 3: Decision

One rule: the total score determines the outcome.

```
score >= block_threshold     -> block
score >= challenge_threshold -> challenge
score <  challenge_threshold -> allow
```

All thresholds, weights, caps, and multipliers are stored in PostgreSQL and live in memory via atomic pointer swap. Nothing is hardcoded.

### Phase 4: Response

- **Block**: 403 page with the reason and a Ray ID.
- **Challenge**: slider page (see below).
- **Allow**: proxy to upstream.

---

## Challenge System

When a request hits the challenge threshold, the client is served a slider page. The slider collects raw mouse trajectory data (position + timing per sample point) and sends it to the backend.

The server validates three things:

1. **Position**: slider position within tolerance (4 percentage points) of the server-generated target.
2. **Duration**: total interaction time >= 1.5 seconds.
3. **Trajectory analysis**: the raw mouse path is scored across seven metrics:

| Metric | Human | Bot |
|---|---|---|
| Speed variance | Irregular | Uniform |
| Straightness | 0.85..0.98 | ~1.0 |
| Y-axis jitter | Present | Flat line |
| Direction changes | >= 1 X reversal | None |
| Timing variance | Variable intervals | Constant intervals |
| Acceleration variance | Phased (accel, cruise, decel) | Flat |
| Micro-pauses | Present before release | None |

Trajectory score (70%) + browser signals score (30%) combine into a confidence value (0.0..1.0), which maps to a trust level:

| Trust Level | Confidence | Score Reduction |
|---|---|---|
| 0 | 0.00..0.39 | 0 (solved but suspicious) |
| 1 | 0.40..0.59 | -5 |
| 2 | 0.60..0.79 | -10 |
| 3 | 0.80..1.00 | -15 |

The trust level is embedded in the `ok` cookie (HMAC-protected) and applied as a negative score on the next request. A high-confidence human solve can bring a borderline request below the challenge threshold.

Maximum 3 attempts per challenge. Challenge store has a configurable TTL. Challenge solve requests are rate-limited per IP.

---

## Trust History

IPs with N consecutive clean requests (no block or challenge) accumulate a trust reduction score. Both the threshold (N) and reduction value are configurable from the dashboard. Stored in Redis with a 24-hour TTL.

---

## Config

DB -> preload -> memory -> runtime via atomic swap. Background refresh every 10 seconds. Zero DB queries on the request path.

---

## Logging

All requests are logged regardless of decision. Logging is a side effect: it happens via a buffered channel and batch worker. The request handler never waits for a log write. Destination: ClickHouse.

Each log entry includes the full pipeline trace (per-stage scores, reasons, multipliers, final scores).

---

## Stack

| Component | Role |
|---|---|
| Go | Core proxy + pipeline |
| OpenResty (nginx + Lua) | TLS termination, JA4 fingerprinting, dynamic SSL |
| Coraza + OWASP CRS | Managed WAF rules |
| PostgreSQL | Config storage, migrations |
| ClickHouse | Request logs + analytics |
| Redis | Rate limit state, challenge store, trust history |
| React + Vite | Dashboard frontend |
| MaxMind GeoIP2 | Geo lookup + datacenter detection |

---

## Dashboard

Web UI for managing all configuration:

- **Applications**: domain, upstreams, load balancing, per-app overrides, trusted proxies.
- **Security Rules**: expression-based custom rules (IP, path, UA, headers, geo, ASN) with block/challenge/allow/log/skip actions.
- **Rate Limiter**: flood profiles (basic, attack, error) and token bucket per-app rate limits.
- **Bot Detector**: per-rule UA/referer scores, bot IP ranges, trust level thresholds.
- **WAF Engine**: Coraza paranoia level, anomaly thresholds, allowed methods, disabled rules, custom SecRules.
- **IP Reputation**: manual IP and ASN scoring.
- **Scoring Engine**: per-category multiplier, max score cap, enable/disable toggle, block and challenge thresholds.
- **Logs**: request log viewer with raw JSON pipeline trace.
- **Analytics**: traffic charts, threat breakdown, score distribution.

---

## Requirements

- Go 1.25+
- PostgreSQL 14+
- ClickHouse
- Redis
- OpenResty (for TLS termination and JA4 fingerprinting)

---

## Setup

```sh
cp .env.example .env
# edit .env

# run migrations (auto by default, set AUTO_MIGRATE=false to skip)
./wafer
```

Frontend:

```sh
cd frontend
cp .env.example .env
npm install
npm run build
```

See `config/` for nginx configuration, systemd service, and ACME scripts.

---

## Caveats

- Personal project. No guarantees, no SLA.
- Test coverage is partial.
- Some features assume OpenResty is in front (JA4 headers, dynamic SSL).
- Not designed for multi-tenant.
