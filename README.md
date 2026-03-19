# Boomerang Proof of Concept

Boomerang is a Bitcoin cold-storage protocol with built-in coercion resistance. This repository is the Rust proof-of-concept implementation of the protocol and its execution environments.

For the protocol design itself, see the [boomerang design repository](https://github.com/bitryonix/boomerang_design).

## Workspace Overview

This workspace contains two runnable proof-of-concept binaries and a set of core protocol crates:

- `poc_steps`
  - A deterministic, step-by-step runner that follows the setup and withdrawal message diagrams directly.
  - Useful when you want to inspect the protocol flow in a linear, explicit way.
- `poc_networked`
  - A networked runner that executes the protocol automatically across one WT, five SARs, and five peers.
  - Uses an independent Tokio-channel transport/orchestration layer around the core protocol entities.
- Core crates
  - `peer`, `phone`, `iso`, `niso`, `boomlet`, `wt`, `sar`, `st`, `protocol`, `cryptography`, and supporting utilities.

## Runners

### `poc-steps`

`poc-steps` executes the protocol in the same order as the design diagrams, with the orchestration written out explicitly.

- Entry point: `poc_steps/src/main.rs`
- Config: `poc_steps/src/config.rs`
- Detailed docs: [poc_steps/README.md](poc_steps/README.md)

Run it with:

```bash
cargo run -p poc-steps
```

### `poc-networked`

`poc-networked` runs the same protocol automatically through an independent actor/transport layer. Cross-entity communication uses Tokio channels, and peer-local entities are also isolated behind channel-backed workers.

- Entry point: `poc_networked/src/main.rs`
- Config: `poc_networked/src/config.rs`
- Detailed docs: [poc_networked/README.md](poc_networked/README.md)

Run it with:

```bash
cargo run -p poc-networked
```

## Repository Layout

- `poc_steps/`
  - Step-by-step PoC runner.
- `poc_networked/`
  - Networked PoC runner.
- `protocol/`
  - Shared protocol messages and constructs.
- `peer/`, `phone/`, `iso/`, `niso/`, `boomlet/`, `wt/`, `sar/`, `st/`
  - Core protocol entities.
- `cryptography/`
  - Shared cryptographic primitives and helpers.
- `bitcoin-29.0/`
  - Bundled `bitcoind` binaries used by the PoC runners on supported platforms.

## Platform Support

The PoC runners currently support Linux and macOS through the bundled `bitcoind` binaries in `bitcoin-29.0/`.

## Architecture

Architectural decisions are documented in [Architecture.md](Architecture.md).

## Roadmap

- [x] Core PoC implementation in Rust
- [x] Step-by-step execution runner
- [x] Networked execution runner with independent Tokio-channel transport layer
- [ ] Dynamic simulation for parameter tuning under realistic delays and non-linearity
- [ ] Java Card Boomlet implementation
- [ ] ST software and hardware implementation
- [ ] Ancillary services and operational tooling
- [ ] Robust error handling and fallback flows
- [ ] CLI and GUI layers
