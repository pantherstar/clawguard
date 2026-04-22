# ClawGuardian API-First Migration Plan

This document describes how to move ClawGuardian off Base Sepolia and onto a
shared ClawGuardian API without breaking the current edge-enforcement model.

Related docs:

- [API-first architecture](API_ARCHITECTURE.md)
- [API surfaces](API_SURFACES.md)

## Goal

Make the ClawGuardian API the primary source of truth for shared threat
intelligence while keeping extraction, detection, and local cache enforcement
on each node.

The migration should preserve these guarantees:

- local cache hits remain fast
- scans still work when the shared backend is degraded
- threat publishes do not block the verdict path
- state can be rebuilt from snapshot plus ordered updates

## Phase 1: decouple the request path

Introduce a backend-agnostic shared-intel interface and stop calling
chain-specific code directly from request-path logic.

Required outcome:

- request-path code depends on a neutral `ThreatFeedClient`-style abstraction
- Base Sepolia is wrapped behind an adapter
- health and dashboard wiring stop assuming that `chain` is the canonical
  backend concept

This phase is complete when the edge node can swap shared backends without
changing detection logic.

## Phase 2: stand up the HTTP control plane

Build the first API-backed shared-intel backend.

Recommended components:

- Postgres for canonical threats, events, and node state
- Redis for short-lived cache and fanout
- threat lookup API
- threat publish API
- snapshot endpoint
- incremental update feed
- node heartbeat / topology endpoints
- append-only event history

Important rule:

The API is a coordination plane, not the primary scan engine. Detection stays
local.

## Phase 3: dual-run

Run the API backend alongside Base Sepolia until behavior is proven.

Recommended dual-run behavior:

- read from API first
- optionally fall back to chain-backed state for parity checks
- publish to both backends
- compare hit rates, publish success, update lag, and duplicate handling

This phase should expose mismatches before cutover instead of after it.

## Phase 4: cut over

Promote the API to source of truth.

Required changes:

- edge nodes read from the API-backed feed by default
- chain publishing is disabled by default
- operator and health narratives describe the shared API, not Base Sepolia, as
  the primary backend

Rollback should still be possible during this phase by switching the edge node
back to the compatibility adapter.

## Phase 5: retire chain-first product surfaces

After the API backend is stable:

- retire chain-first naming from docs and operator views
- deprecate chain-only operator endpoints from the primary workflow
- move any remaining blockchain functionality to optional compatibility or
  audit/export paths

This is where product framing fully catches up with backend reality.

## Migration safeguards

### Keep local enforcement

Do not centralize the scan pipeline in the first migration.

- extraction stays local
- rules stay local
- classifier stays local
- judge stays local
- only shared intelligence and coordination move centrally

### Publish asynchronously

A blocked verdict must not wait on central persistence.

- publish after local decision
- retry safely with idempotency keys
- tolerate duplicate delivery

### Replicate with replay

Nodes should rebuild state deterministically.

- bootstrap from snapshot
- continue from a sequence-based updates feed
- ignore duplicated events safely
- recover cleanly after disconnection

## Operational best practices

- Use Postgres as the canonical source of truth.
- Use Redis only for cache and fanout.
- Use sequence numbers for replication, not timestamp-only sync.
- Support SSE or WebSocket updates plus polling fallback.
- Give every node its own credentials and identity.
- Store redacted samples by default.
- Keep defense-bundle workflows separate from simple threat-hash sharing.

## Cutover metrics

Before the API becomes authoritative, track at least:

- lookup latency
- publish acknowledgement latency
- update replication lag
- local cache hit ratio
- duplicate publish rate
- snapshot rebuild time
- degraded-mode behavior when the shared API is unavailable

## Success criteria

The migration is complete when:

- edge nodes can operate with the API as the only shared backend
- local cache behavior remains intact
- replay and rebuild are proven
- request-path dependency on Base Sepolia is removed
- blockchain is no longer required for the default product architecture

For the target architecture, see [API-first architecture](API_ARCHITECTURE.md).
For the interface and endpoint contract, see [API surfaces](API_SURFACES.md).
