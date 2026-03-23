# Workspace Architecture

## Overview

The workspace is organized so the protocol state machines stay distinct from the wire contract,
transport implementation, runtime orchestration, and PoC supervisors.

The current supported path is intentionally layered:

- core/domain crates own protocol rules and state transitions
- network crates own framing and transport delivery
- runtime crates own manifests, process startup, routing, and supervision
- `poc-runtime` owns the supported local 41-process operator workflow

## Layered Structure

### `crates/core`

This layer contains the protocol entities and shared domain support.

- role crates
  - `wt`
  - `sar`
  - `peer`
  - `niso`
  - `iso`
  - `boomlet`
  - `phone`
  - `st`
- shared domain support
  - `protocol`
  - `cryptography`
  - `descriptor`
  - `bitcoin_utils`
  - `tracing_utils`

Core crates remain the policy boundary. Runtime and transport code may drive them, but they should
not need to know about manifests, Tokio tasks, or PoC supervision.

### `crates/network`

This layer owns inter-process communication.

- `protocol-wire`
  - stable wire framing, message tags, control payload wrappers, and typed encode/decode helpers
- `boomerang-transport`
  - the transport abstraction
  - the current Tokio/TCP backend
  - handshake logic
  - frame I/O
  - delay-injection seams for future timing experiments

### `crates/runtime`

This layer owns application/runtime behavior.

- `boomerang-config`
  - process manifests
  - cluster manifests
  - PoC defaults
  - load/save and validation
  - published WT/SAR public-identity artifact shape
- `boomerang-runtime`
  - per-process runtime bootstrap
  - role-runtime construction
  - runtime context and routing
  - async cluster launcher seams
- `boomerang-node`
  - the standalone CLI host for one role process or one manifest-defined cluster
- `boomerang-scenarios`
  - deterministic scenario builders used by PoC supervision and tests

### `poc`

This area contains operator-facing and reference PoC runners.

- `poc-runtime`
  - the supported local multi-process supervisor
- `poc-networked`
  - legacy concurrent actor/channel runner
- `poc-steps`
  - legacy linear walkthrough runner

## Runtime Model

The workspace keeps the 41-process topology. The async refactor changed the inside of each process,
not the process count.

- one OS process per role instance
- one Tokio runtime host inside each process
- one dedicated blocking protocol-driver task per process
- async sockets, timers, and supervision outside the core state machines

That allows async transport and supervision without forcing the core protocol crates themselves to
become async.

## WT/SAR Identity Boundary

WT and SAR now own private identity creation internally. Outside core:

- manifests never contain WT/SAR private identity material
- WT/SAR manifests do not carry `wt_id` or `sar_id`
- runtime and supervisors consume only `identity-public.toml`

This keeps the non-core layers from becoming secret carriers for WT/SAR key material.

## Run-Artifact Layout

The default PoC run-artifact base is now [`poc-runs/`](/Users/bedlam/Desktop/getting_rusty/boomerang/poc-runs/README.md)
under the repository root. `poc-runtime` creates one ephemeral child run directory there by
default, which makes logs and generated manifests easy to find when persistence is explicitly
enabled while still keeping default runs self-cleaning.

## Dependency Direction

Dependency flow remains intentionally inward:

- support crates -> domain crates
- network/runtime crates -> domain and protocol contracts
- PoC runners -> runtime/config/scenario crates
- outer layers depend on inner policy crates, not the reverse

## Supported And Reference Paths

`boomerang-node` plus `poc-runtime` are the maintained operator path.

`poc-networked` and `poc-steps` remain in the workspace because they still provide reference value,
regression coverage, and alternate views of the protocol, but they are not the primary path for
new runtime work.
