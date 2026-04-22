# ClawGuardian API Surfaces

This document outlines the shared-intel interface and control-plane endpoints
for an API-first ClawGuardian deployment.

Related docs:

- [API-first architecture](API_ARCHITECTURE.md)
- [API migration plan](API_MIGRATION_PLAN.md)

## Design intent

The shared API should replace Base Sepolia as the default shared backend while
preserving local scan enforcement on each node.

The API contract should support three behaviors:

- fast shared-hash lookup
- idempotent publish of newly confirmed threats
- reliable snapshot + incremental sync for local caches

## Internal interface boundary

Request-path code should depend on one neutral shared-intel client instead of
on chain-specific code.

Illustrative shape:

```python
class ThreatFeedClient:
    def lookup_hash(self, content_hash: str) -> dict | None: ...
    def publish_threat(self, threat: dict) -> dict: ...
    def list_updates(self, cursor: str | None = None) -> dict: ...
    def publish_defense_update(self, bundle: dict) -> dict: ...
```

Implementations can include:

- HTTP-backed API client as primary
- Base Sepolia adapter during migration
- dual-write wrapper for cutover periods

The request path should not care which backend is active.

## External control-plane endpoints

These are the recommended minimum API surfaces for v1.

### `POST /v1/threats/lookup`

Purpose:

- check whether one or more content hashes are already known

Behavior:

- accepts canonical hashes
- returns zero or more matches with category and source metadata
- safe to call in the request path when the local cache misses

### `POST /v1/threats`

Purpose:

- publish a newly confirmed threat

Behavior:

- accepts an idempotency key
- records a canonical event
- returns accepted status plus canonical event ID
- should be invoked asynchronously from the local verdict path

### `GET /v1/threats/snapshot`

Purpose:

- bootstrap a node cache from a point-in-time snapshot

Behavior:

- returns a bounded snapshot of active threat records
- should support a cursor, watermark, or version marker for follow-on sync

### `GET /v1/threats/updates`

Purpose:

- replay incremental changes after snapshot bootstrap

Behavior:

- ordered by monotonic sequence
- idempotent for duplicates
- suitable for polling or stream recovery

### `POST /v1/nodes/heartbeat`

Purpose:

- register that a node is alive and describe its current capabilities

Behavior:

- records version, region, and feature flags
- supports operator visibility and topology views

### `GET /v1/network/topology`

Purpose:

- expose a backend-neutral view of participating nodes

Behavior:

- returns nodes, roles, and connectivity metadata needed by the operator UI
- should not depend on blockchain concepts to be meaningful

### `POST /v1/defense-updates`

Purpose:

- publish validated defense bundles separately from simple threat hashes

Behavior:

- stricter provenance and approval rules than a normal threat publish
- may later fan out rule updates or model deltas to nodes

## Event record requirements

Each shared threat event should carry stable replay fields.

Recommended fields:

- `event_id`
- `sequence`
- `content_hash`
- `category`
- `reason_family`
- `sample_redacted`
- `reported_by`
- `reported_at`
- `schema_version`
- optional `signature`
- optional `source_backend`

The important properties are:

- event IDs are stable
- sequence is monotonic
- records are append-only
- new fields are additive

## Node sync model

Recommended sync pattern:

1. node loads a snapshot
2. node stores the returned watermark or cursor
3. node consumes ordered updates after that point
4. node falls back to pull if streaming disconnects

This avoids full-resync behavior for normal operations and gives nodes a clear
recovery path after downtime.

## Auth and integrity expectations

The API-first model needs explicit integrity controls.

- every node gets its own credentials
- publish requests should be signed or HMAC-protected
- publish endpoints must support idempotency
- records should preserve provenance instead of relying on implicit trust
- deletes should be modeled as status transitions, not hard removal

## Non-goals for v1

These API surfaces do not require the following on day one:

- central storage of full raw payloads by default
- synchronous publish inside the user-facing scan path
- blockchain-backed verification in the hot path
- model-serving centralization for rules, classifier, or judge execution

## Acceptance shape

The API surface is good enough for implementation when:

- the edge node can look up known hashes without knowing the backend type
- new threats can be published safely more than once
- a node can rebuild local state from snapshot plus updates
- topology and health views no longer need chain-specific language to make
  sense

The architectural reasoning lives in [API-first architecture](API_ARCHITECTURE.md),
and the rollout order lives in [API migration plan](API_MIGRATION_PLAN.md).
