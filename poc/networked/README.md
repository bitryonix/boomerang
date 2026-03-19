# `poc-networked`

`poc-networked` is the automated, channel-based Boomerang proof-of-concept runner. It executes the protocol concurrently across one WT, five SARs, and five peers.

## Purpose

Use this crate when you want to:

- run the protocol automatically end-to-end,
- exercise an independent networking/orchestration layer around the core entities,
- inspect actor-level tracing for setup, withdrawal, SAR checks, and the digging game.

## Architecture

The crate is split into a small orchestration stack:

- `src/main.rs`
  - Boots the network, creates actors, and starts the run.
- `src/config.rs`
  - Static network, topology, and withdrawal configuration.
- `src/actors/`
  - `peer_actor.rs`, `wt_actor.rs`, and `sar_actor.rs`.
- `src/transport.rs`
  - Tokio `mpsc` mailbox primitives and peer directory for out-of-band peer messaging.
- `src/local_actor.rs`
  - Channel-backed workers for peer-local entities such as `Niso`, `Iso`, `Boomlet`, `Phone`, and `St`.
- `src/envelopes.rs`
  - Typed envelopes passed between orchestration actors.

## Communication Model

- Inter-peer, peer-to-WT, peer-to-SAR, WT-to-SAR, and SAR-to-WT communication all use Tokio channels.
- Peer-local entity interactions are also routed through Tokio channels via `local_actor.rs`.
- The protocol entity crates remain transport-agnostic; the networking layer is independent from their core logic.

## Run

From the workspace root:

```bash
cargo run -p poc-networked
```

## Notes

- The default run boots exactly five peers, five SARs, and one WT.
- The crate emits INFO-level tracing that narrates the protocol phases from setup through final broadcast.
- This is the right runner when you want to validate concurrent orchestration rather than read the protocol step-by-step.
