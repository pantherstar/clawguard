# ClawGuardian API-First Architecture

ClawGuardian should move from a chain-backed shared registry to an API-first
control plane with local enforcement at the edge. Base Sepolia can remain a
temporary compatibility backend during migration, but it should no longer be
the primary source of truth or the default architecture story.

Related docs:

- [API migration plan](API_MIGRATION_PLAN.md)
- [API surfaces](API_SURFACES.md)

## Why shift off Base Sepolia

The current chain-backed design proved the shared-intel concept, but it is not
the best long-term backend for the product.

- The hot path should optimize for low-latency lookups, controlled operations,
  and straightforward failure handling.
- Operational ownership matters more than public verifiability for the core
  product.
- Shared threat intelligence needs replay, idempotency, node lifecycle, and
  controlled rollout behavior that fit a service backend better than a public
  testnet.
- The chain can still be used later for export, anchoring, or audit proofs if
  that becomes strategically useful, but not in the request path.

## Current state

Today the product is centered on a local scan pipeline with a local SQLite
cache and optional Base Sepolia publishing.

High-level flow today:

`agent input -> extract -> hash -> local cache / chain-backed cache -> rules -> classifier -> judge -> optional publish`

Important properties worth preserving:

- Content extraction and verdicting run locally.
- Known threats can be blocked from a local cache without remote work.
- The system degrades gracefully when optional integrations are unavailable.

## Target state

The target architecture keeps enforcement on each node and moves shared
coordination into a ClawGuardian API.

```text
agent / node
  -> local extraction + detection
  -> local cache lookup
  -> shared ClawGuardian API
       -> threat lookup
       -> threat publish
       -> incremental updates
       -> node heartbeat / topology
       -> append-only audit/event log
```

The key design rule is simple:

**scan locally, share centrally, cache everywhere.**

## Responsibilities split

### Edge node

The edge node remains the enforcement point.

- Extract text from inbound content.
- Compute canonical content hashes from extracted text.
- Check local cache first.
- Run rules, classifier, and judge locally when the cache misses.
- Publish confirmed threats asynchronously.
- Consume shared updates and hydrate the local cache.
- Continue operating in degraded mode when the shared API is unavailable.

### Shared ClawGuardian API

The shared API becomes the control plane and source of truth for shared intel.

- Serve threat-hash lookups.
- Accept idempotent threat publishes.
- Provide snapshot + incremental update feeds.
- Track node identity, heartbeats, regions, and capabilities.
- Persist an append-only event history for replay and audit.
- Coordinate defense bundle distribution separately from threat-hash sharing.

## Recommended backend shape

Use conventional service infrastructure instead of blockchain as the default
backend.

- Postgres as the canonical store for threats, events, node state, and replay.
- Redis for short-TTL hot cache and fanout, not as the source of truth.
- SSE or WebSocket streams for incremental updates, with pull fallback.
- Object storage only for larger redacted artifacts or defense bundles, not for
  request-path lookups.

The API should be fast to read, easy to replay, and explicit about ownership.

## Trust model and best practices

Moving off-chain removes public immutability from the default path, so the API
design must make trust explicit.

- Keep scan enforcement local. The API distributes intelligence; it does not
  become the primary scan engine.
- Require per-node authentication instead of one shared token.
- Make publish endpoints idempotent and signed.
- Persist an append-only event log with stable event IDs and monotonic
  sequencing.
- Store redacted samples and metadata centrally by default, not raw payloads.
- Treat defense updates as a stricter workflow than simple threat-hash sharing.
- Make replay a first-class feature so any node can rebuild state from
  snapshot plus updates.

## What blockchain becomes

Blockchain should become optional and out-of-band.

- Compatibility adapter during migration.
- Optional export or anchoring target for audit proofs.
- Never the required hot-path lookup backend for the product.

That keeps the product architecture operationally simple while preserving room
for later verifiability features if they become valuable.

## Implementation direction

The migration should introduce a backend-agnostic shared-intel interface and
have the request path depend on that abstraction instead of on chain-specific
code.

The desired end state is:

- edge scan code depends on a `ThreatFeedClient`-style interface
- the HTTP-backed implementation is primary
- the Base Sepolia implementation is optional and transitional

For the concrete rollout path, see [API migration plan](API_MIGRATION_PLAN.md).
For the proposed control-plane contract, see [API surfaces](API_SURFACES.md).
