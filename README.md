## Won Main "Security" Track from IBM & AWS Mini-Track

# ClawGuard

Security middleware for OpenClaw agents. Defends against prompt injection attacks across text, images, PDFs, and audio. Shares threat intel on-chain via Base Sepolia..

Built for a hackathon demo. Parts are production-grade (detection pipeline,
migrations, CSP, Prometheus, admin-auth on audit + metrics); parts are
explicitly scaffolds (adversarial learning loop, ZK proof generation). See
[Project Honesty](#project-honesty) for the exact state of each subsystem.

## Architecture

```
Inbound Content → Extraction → Detection Pipeline → Verdict
                      |              |
              OCR / PDF / Whisper    Rules → Classifier → LLM Judge
              HTML / Email parse          |
                                    On-chain threat cache (instant block)
                                          |
                                    Base Sepolia registry (shared intel)
```

**Detection pipeline** short-circuits: if regex rules are confident (severity
≥ 0.9), we block without calling the classifier or LLM judge. The ML
classifier (`protectai/deberta-v3-base-prompt-injection-v2`, see
`detector/classifier.py`) handles cases rules miss. The LLM judge (Claude
Haiku, see `skill/detectors/judge.py`) resolves ambiguous cases only, and
**fails closed** — a transient API error yields a `sanitize` verdict, not a
silent `pass`.

## Quick Start

```bash
cd clawguard

# 1. Install dependencies
make setup

# 2. Configure secrets (see docs/SECRETS.md for the full list)
cp .env.example .env
# Fill in ANTHROPIC_API_KEY at minimum. For admin endpoints, also set
# ADMIN_API_TOKEN (protects /api/audit and /metrics).

# 3. Generate attack fixtures
make fixtures

# 4. Run database migrations
make migrate

# 5. Run the demo
make demo
```

### Full demo with dashboard

```bash
# Terminal 1: API server
make api

# Terminal 2: Dashboard
make dashboard

# Terminal 3: Run demo agent
make demo

# Open http://localhost:5175
```

## Environment Variables

Key ones (see `docs/SECRETS.md` for the authoritative list):

| Variable | Required | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | For judge | LLM judge (Claude Haiku) and vision model |
| `ADMIN_API_TOKEN` | For admin | Required by `/api/audit`; also gates `/metrics` by default |
| `METRICS_BEARER_TOKEN` | Optional | If set, scrape `/metrics` with `Authorization: Bearer ...`; falls back to `ADMIN_API_TOKEN` |
| `WS_BEARER_TOKEN` | For WS | Bearer token required by `/ws/updates` from non-loopback origins |
| `REQUIRE_ADMIN_TOKEN` | Optional | `false` disables admin auth (dev only — do NOT in prod) |
| `REQUIRE_METRICS_TOKEN` | Optional | `false` disables metrics auth (dev only) |
| `BASE_SEPOLIA_RPC_URL` | No | Default: `https://sepolia.base.org` |
| `CLAWGUARD_PRIVATE_KEY` | No | For publishing to on-chain registry |
| `CLAWGUARD_REGISTRY_ADDRESS` | No | Deployed `ThreatRegistry` address |
| `DEFENSE_PROTOCOL_ADDRESS` | No | Deployed `DefenseProtocol` address (learning publisher) |
| `SLACK_WEBHOOK_URL` | No | Critical alerts (RPC failures, learning-round errors) |
| `LOG_FORMAT` | No | `plain` (default) or `json` for structured logs |
| `CORS_ORIGINS` | No | Comma-separated allowlist for the FastAPI server |
| `EXPOSE_OPENAPI` | No | Set `false` to hide `/docs`, `/redoc`, and `/openapi.json` in production |
| `ENABLE_HSTS` | No | Set `true` behind TLS-terminating proxies to emit `Strict-Transport-Security` |
| `HSTS_MAX_AGE_SEC` | No | Max-age for HSTS (default one year) |

### Health checks

- **`GET /api/health`** — liveness: process is up, cheap snapshot of chain config and cached-threat count (does not start chain polling).
- **`GET /api/ready`** — readiness: `PRAGMA quick_check` + Alembic at head; returns **503** until the database is migrated and intact. Use this for load balancers and orchestrators; keep **`/api/health`** for simple process probes.

The demo runs without on-chain, without Slack, and without the admin token
(flip `REQUIRE_ADMIN_TOKEN=false` for local dev). Every optional integration
degrades gracefully.

## Contract Deployment (Optional)

```bash
curl -L https://foundry.paradigm.xyz | bash && foundryup
make contracts
# Copy the deployed address to .env as CLAWGUARD_REGISTRY_ADDRESS
```

## Staged Attacks

Three attack fixtures in `demo/attacks/`:

1. **`bloomberg_email.eml`** — Fake Bloomberg earnings alert with injection in an HTML comment and a `display:none` div. Both tell the agent to sell all positions.
2. **`chart_injection.png`** — Stock chart with white-on-white text ("SELL ALL AAPL") nearly invisible to human readers but caught by inverted OCR and vision model.
3. **`earnings_report.pdf`** — Earnings report PDF with a hidden text layer (white text, 1pt font) and injection in PDF metadata fields.

## Detection Rules

30 regex rules in `skill/detectors/rules.py` across categories:

- Instruction override ("ignore previous", "new instructions")
- Role manipulation ("you are now", "act as", DAN/jailbreak)
- System prompt markers (`<system>`, `[INST]`, prompt boundaries)
- Obfuscation (base64 blobs, hex/unicode escapes)
- Steganographic (zero-width chars, homoglyph mixed scripts)
- Markup injection (HTML comments, hidden divs, script tags)
- Financial-specific ("sell all positions", urgency+trade combos)
- Context manipulation (fake errors, fake user messages, separators)
- Delimiter abuse (backtick system tags, XML tag injection)
- Exfiltration (markdown image data exfil)

## Design Decisions

- **Short-circuit pipeline**. Rules are fast and free. Classifier needs a
  ~700MB model download but runs locally. LLM judge costs API calls — only
  invoked when uncertain.
- **Fail-closed judge**. If Claude errors mid-call we return `sanitize` with
  low confidence instead of letting the attack through.
- **Multipass OCR**. Standard OCR misses white-on-white text. Inverted and
  edge-detect passes catch adversarial text at the cost of some false
  positives in normal images (acceptable for security).
- **Hash-first cache check**. Before running any detection we SHA-256 the
  extracted text and check against the local SQLite cache of on-chain
  threats. Known attacks block in microseconds.
- **Graceful degradation**. Every heavy component (Whisper, Tesseract,
  transformers, web3, Alpaca) is optional. The skill works with just
  `anthropic` installed.
- **Admin auth**. `/api/audit` requires `X-Admin-Token`; `/metrics` requires
  `Authorization: Bearer ...` (or `X-Metrics-Token`). Both fall back to
  `ADMIN_API_TOKEN` when no dedicated token is set.
- **SQLite with WAL**. `journal_mode=WAL`, `synchronous=NORMAL`,
  `busy_timeout=5000ms`. Good enough for demo throughput. Cursor pagination
  on detections/threats/audit (see `X-Next-Cursor` response header).

## Project Honesty

What this repo is and isn't, per subsystem:

| Area | State | Notes |
|---|---|---|
| Detection pipeline (`skill/detectors`) | Works | 30 rules + classifier + fail-closed judge, tested |
| Multimodal extractors (`extractor/`, `skill/extractors/`) | Works | Real OCR / PDF / email / HTML / audio with graceful fallbacks |
| Threat registry cache (SQLite) | Works | WAL, Alembic migrations, indexes, cursor pagination |
| Audit log | Works | Admin-gated, filterable, cursor-paginated |
| FastAPI server (`skill/api.py`) | Works | CSP + security headers, optional HSTS, `/api/ready`, rate limits (per-process; see below), request IDs, admin/metrics auth, WS auth |
| Vercel serverless (`api/index.py`) | Works | Now a thin re-export of `skill.api:app` (full parity) |
| On-chain publish — threat registry (`skill/chain/client.py`) | Works when env set | Real web3 writes to Base Sepolia |
| On-chain publish — defense updates (`learning/publisher.py`) | Works when env set | Real `DefenseProtocol.publishDefenseUpdate` |
| Async RPC client (`blockchain/async_client.py`) | Works | Dedupe + severity-aware alerts |
| AWS KMS signer (`skill/chain/kms_signer.py`) | Works | Non-exportable ECC_SECG_P256K1 keys; drop-in replacement for `eth_account.sign_transaction`. Set `CLAWGUARD_KMS_KEY_ID` to activate |
| AWS envelope cipher (`skill/chain/envelope.py`) | Works | AES-256-GCM via `kms:GenerateDataKey` under the envelope CMK |
| AWS Secrets Manager backend (`skill/config/secrets.py`) | Works | `CLAWGUARD_SECRETS_SOURCE=aws`; 5-min TTL cache; falls back to env on miss |
| Bedrock judge (`skill/detectors/bedrock_judge.py`) | Works | Claude Haiku 4.5 via Bedrock Converse; fail-closed to `sanitize` |
| AWS infrastructure (`infrastructure/envs/prod`) | Works | Full Terraform: KMS + Secrets Manager + Bedrock + API Gateway + ECS Fargate. `enable_compute=false` by default to keep costs off. See [`docs/AWS_ARCHITECTURE.md`](docs/AWS_ARCHITECTURE.md) |
| Learning loop (`learning/`) | **Scaffold** | Red agent is a stub, blue agent is real MLP but trained on hardcoded features; see `learning/README.md` for the honest story |
| ZK proofs (`zk/`) | **Mock** | `prover_host.py` returns deterministic fake Groth16 JSON; real RISC Zero flow is documented under `zk/INTEGRATION.md` |
| On-chain anomaly detection (`detector/on_chain/`) | Exploratory | IsolationForest + state machine; benchmarks under `detector/bench/` |
| Prometheus metrics (`/metrics`) | Works | Auth-gated; scrape with bearer token |
| OpenTelemetry tracing | Works when OTLP set | HTTP exporter |
| Slack alerting | Works | TTL dedupe, severity-aware, thread-safe `alert_sync` |
| API rate limiting | Per-process | Keys clients by `X-Forwarded-For` when present; for many replicas, enforce limits at the edge (nginx) or add a shared store (Redis is wired in compose for future use) |

## Project Structure

```
clawguard/
  skill/                  # OpenClaw entrypoints + FastAPI app + detection pipeline
    api.py                # FastAPI server (admin auth, CSP, WS, /metrics)
    handler.py            # intercept() — the OpenClaw hook entrypoint
    detectors/            # rules.py, judge.py, pipeline.py
    extractors/           # thin wrappers that delegate to extractor/
    chain/                # ChainClient (threat registry — canonical)
    observability/        # metrics, tracing, alerts, JSON logging
    config/               # settings (non-secret knobs) + secrets (SecretsManager)
    migrations/           # Alembic (001 init, 002 audit_log, 003 indexes)
  extractor/              # Multimodal text extraction (text/html/pdf/image/audio)
  detector/               # ML classifier + on-chain tx anomaly detection
  blockchain/             # async_client, mempool_monitor, preemptive_strike, defense_agent
  learning/               # Red/Blue loop scaffold, rule_extractor, publisher
  network/                # poller + applier for cross-node defense sync
  zk/                     # RISC Zero host (currently mock) + guests
  store/                  # SQLite + Redis Streams helpers
  api/                    # Vercel serverless entrypoint (re-exports skill.api:app)
  contracts/              # Foundry: ThreatRegistry, DefenseProtocol, Consensus
  demo/ dashboard/        # Demo trading agent + React UI
  docs/                   # SECRETS.md, OBSERVABILITY.md, MIGRATIONS.md
```
