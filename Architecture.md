# Architecture

This document explains how the repository is organized and how the proof-of-concept runners are layered around the core Boomerang protocol entities. It does not try to restate the protocol design itself.

## Goals

The workspace is organized around a few constraints:

- Keep the core protocol entities independent from any specific transport.
- Preserve the protocol's message-in / message-out structure.
- Support both a deterministic step runner and a networked runner without forking core logic.
- Make orchestration changes happen in PoC crates, not in the core entity crates.

## Layers

### Core protocol crates

The crates `peer`, `phone`, `iso`, `niso`, `boomlet`, `wt`, `sar`, and `st` contain the protocol entities. They are responsible for protocol state transitions and message production/consumption.

Shared protocol types live in:

- `protocol`
  - Message types and shared constructs such as identifiers and parcels.
- `cryptography`
  - Shared cryptographic primitives and helpers.

These crates are transport-agnostic. They do not know whether the orchestration is step-by-step or networked.

### `poc_steps`

`poc_steps` is the linear, explicit runner. It executes setup and withdrawal by calling `produce_*` and `consume_*` methods directly in the same order as the design diagrams.

Key files:

- `poc_steps/src/config.rs`
  - Static configuration for the runner.
- `poc_steps/src/setup.rs`
  - Explicit setup sequence.
- `poc_steps/src/withdrawal.rs`
  - Explicit withdrawal sequence.

Use `poc_steps` when the goal is to inspect the exact protocol sequence in a human-readable order.

### `poc_networked`

`poc_networked` is the automated runner. It wraps the same core entities in an independent orchestration layer built on Tokio channels and actors.

Key files:

- `poc_networked/src/config.rs`
  - Static network and withdrawal configuration.
- `poc_networked/src/actors/peer_actor.rs`
  - Drives one peer and its local entities.
- `poc_networked/src/actors/wt_actor.rs`
  - Drives the watchtower.
- `poc_networked/src/actors/sar_actor.rs`
  - Drives each SAR.
- `poc_networked/src/transport.rs`
  - Inter-actor mailbox primitives and peer directory.
- `poc_networked/src/local_actor.rs`
  - Channel-backed worker handles for peer-local entities.
- `poc_networked/src/envelopes.rs`
  - Transport envelopes used between orchestration actors.

Use `poc_networked` when the goal is to exercise the protocol as a concurrent, automatically progressing system.

## Configuration

Both runnable PoCs now use dedicated config modules:

- `poc_steps/src/config.rs`
- `poc_networked/src/config.rs`

This keeps runtime parameters, milestone blocks, withdrawal constants, and `bitcoind` path resolution out of the runner entrypoint logic.

The config layer is intentionally separate from the protocol entities. Changing environment defaults or orchestration parameters should not require modifying the core protocol crates.

## Message Model

The protocol follows a message-in / message-out model:

- `consume_*` methods apply incoming protocol messages to entity state.
- `produce_*` methods create outgoing protocol messages from current entity state.

This separation is deliberate. It keeps state transitions explicit and makes orchestration, retries, and alternative transport layers easier to build around the same entities.

Shared messages and message collections are represented in `protocol`, including parcelized multi-recipient exchanges.

## Transport and Isolation

### In `poc_steps`

There is no independent transport layer. The runner directly invokes entity methods in the required order. This keeps the protocol steps visible and easy to trace back to the design diagrams.

### In `poc_networked`

There are two transport boundaries:

- Inter-actor transport
  - Peer <-> WT, Peer <-> SAR, WT <-> SAR, and peer out-of-band communication all use Tokio `mpsc` channels.
- Peer-local transport
  - Each peer-local entity (`Peer`, `Iso`, `Niso`, `Boomlet`, `Boomletwo`, `Phone`, `St`) runs behind a channel-backed worker in `local_actor.rs`.

This means the networked runner's orchestration is independent from the protocol logic. The runner sends typed envelopes and local worker requests; the entity crates still only know about protocol messages and state transitions.

## Logging and Tracing

The repository uses `tracing` for runtime visibility.

- Core protocol methods emit spans and events around protocol state transitions.
- Runner crates use higher-level orchestration logs to narrate setup, withdrawal, actor roles, and major milestones.

In practice:

- `poc_steps` is best for step-by-step protocol inspection.
- `poc_networked` is best for actor-level and transport-level tracing of an automated run.

## Why Two PoCs Exist

The two runners solve different problems:

- `poc_steps`
  - Optimizes for protocol readability and direct correspondence with the message diagrams.
- `poc_networked`
  - Optimizes for concurrency, automatic execution, and separation between orchestration and core protocol logic.

Keeping both is intentional. The step runner is the clearest reference implementation of the flow, while the networked runner is the clearest reference implementation of a channel-based orchestration layer around the same protocol.
