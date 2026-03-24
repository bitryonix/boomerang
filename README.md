# Boomerang Rust Workspace

This repository contains the Rust proof-of-concept implementation of the Boomerang cold-storage
protocol together with the transport, runtime, configuration, and supervisor layers needed to run
the protocol as independent processes.

For the protocol design itself, see the [boomerang design repository](https://github.com/bitryonix/boomerang_design).

- [Boomerang Rust Workspace](#boomerang-rust-workspace)
  - [What This Workspace Contains](#what-this-workspace-contains)
  - [Supported Runtime Path](#supported-runtime-path)
  - [Current Execution Model](#current-execution-model)
  - [Workspace Layout](#workspace-layout)
  - [Run Artifacts](#run-artifacts)
  - [Common Commands](#common-commands)
  - [WT/SAR Identity Contract](#wtsar-identity-contract)
  - [Logging And Operator Experience](#logging-and-operator-experience)
  - [Quality Gates](#quality-gates)
  - [Documentation Map](#documentation-map)
  - [Roadmap](#roadmap)

## What This Workspace Contains

The workspace is split into four top-level concerns:

- `crates/core`
  - Protocol entities and domain support crates.
  - This is where the protocol state machines live.
- `crates/network`
  - The wire contract and the transport implementation.
  - Today that means `protocol-wire` plus the Tokio/TCP-backed `boomerang-transport`.
- `crates/runtime`
  - Configuration, manifest loading, runtime orchestration, the standalone node host, and
    deterministic scenario builders.
- `poc`
  - Human-facing proof-of-concept runners.
  - `poc-runtime` is the supported operator path.
  - `poc-networked` and `poc-steps` remain available as legacy/reference runners.

The repository also vendors a local Bitcoin Core fixture under `bitcoin-29.0/` for PoC-oriented
development flows.

## Supported Runtime Path

The supported runtime stack is:

- `boomerang-node`
  - Runs one configured role process from a TOML manifest.
- `poc-runtime`
  - Launches the full 41-process local topology, stages WT/SAR identity publication, writes the
    generated cluster manifest, supervises child processes, and prints a curated terminal narrative.

`poc-networked` and `poc-steps` are still runnable, but they are reference surfaces rather than the
preferred path for new work.

One important operational detail is that `poc-runtime` launches `boomerang-node` as a separate
child executable by path. Because of that, `cargo run -p poc-runtime` now performs its own
freshness preflight for the workspace-managed `target/debug/boomerang-node` and automatically runs
`cargo build -p boomerang-node` when the managed child binary is missing or stale. Explicit
external `--node-bin` paths remain operator-managed and are never rebuilt automatically.

## Current Execution Model

- The system still runs as 41 independent OS processes in the main PoC flow.
- Each `boomerang-node` process now hosts an async Tokio runtime for sockets, timers, and
  supervision work.
- The core protocol workflow itself remains synchronous and runs inside one dedicated blocking
  driver task per process.
- WT and SAR create their private identity material internally inside the core entities.
- Nothing outside core is allowed to put WT/SAR private identity material into manifests.
- The only WT/SAR identity artifact that leaves the process boundary is `identity-public.toml`.

## Workspace Layout

```text
crates/
  core/
  network/
  runtime/
poc/
  poc-runtime/
  poc-networked/
  poc-steps/
poc-runs/
docs/
bitcoin-29.0/
```

## Run Artifacts

The default PoC run-artifact base is now [`poc-runs/`](/Users/bedlam/Desktop/getting_rusty/boomerang/poc-runs/README.md)
in the workspace root so operators can find generated manifests, per-process state directories, and
logs without digging through the system temp directory.

By default, `poc-runtime` creates one fresh `run-*` child directory under that base and keeps it
after the run completes. Exact-directory persistence and reuse are still explicit:

- default
  - `cargo run -p poc-runtime`
  - creates `poc-runs/run-...`
  - keeps that run directory afterward
- keep a specific run directory
  - `cargo run -p poc-runtime -- --state-root /path/to/run --persist-state-root`
- reuse an existing persistent run directory
  - `cargo run -p poc-runtime -- --state-root /path/to/run --persist-state-root --reuse-state-root`

## Common Commands

Run one standalone role:

```bash
cargo run -p boomerang-node -- wt run --config /path/to/wt.toml
```

Run the supported 41-process PoC supervisor:

```bash
cargo run -p poc-runtime
```

Generate the deterministic 41-process manifest example:

```bash
cargo run -p poc-runtime --example local_poc_manifest
```

Run the legacy reference runners:

```bash
cargo run -p poc-networked
cargo run -p poc-steps
```

## WT/SAR Identity Contract

The workspace now enforces one clear rule:

- WT/SAR manifests never contain WT/SAR private keys or Tor secret keys.
- WT/SAR manifests also no longer contain `wt_id` or `sar_id` in their own bootstrap payloads.
- WT/SAR `run` creates identity internally.
- Supervisors and peers consume only `identity-public.toml`.

That rule applies to the supported path and to custom WT/SAR manifests loaded through
`boomerang-config`.

## Logging And Operator Experience

`poc-runtime` intentionally separates high-signal terminal output from low-level log artifacts:

- terminal output
  - curated supervisor narrative
  - color-coded phase labels and protocol event types in interactive terminals
  - identity staging
  - setup milestones
  - full peer duress-check steps
  - full digging-game ping-pong steps
  - withdrawal completion
  - child-failure summaries
- on-disk artifacts
  - `node.log`
  - `progress.log`
  - generated manifest files
  - WT/SAR `identity-public.toml`

The terminal output is meant to show the protocol dynamic at a glance. The per-process files are
the place to go for deep debugging.

## Quality Gates

The strongest repository-level checks currently used for this workspace are:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --no-deps
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items
```

## Documentation Map

- Workspace architecture: [Architecture.md](/Users/bedlam/Desktop/getting_rusty/boomerang/Architecture.md)
- Workspace design decisions: [DesignDecisions.md](/Users/bedlam/Desktop/getting_rusty/boomerang/DesignDecisions.md)
- Workspace limitations: [Limitations.md](/Users/bedlam/Desktop/getting_rusty/boomerang/Limitations.md)
- Operational notes: [docs/operations.md](/Users/bedlam/Desktop/getting_rusty/boomerang/docs/operations.md)
- Repository ADR baseline: [docs/adr/0001-repository-compliance-baseline.md](/Users/bedlam/Desktop/getting_rusty/boomerang/docs/adr/0001-repository-compliance-baseline.md)
- PoC area overview: [poc/README.md](/Users/bedlam/Desktop/getting_rusty/boomerang/poc/README.md)
- Supported PoC runner: [poc/poc-runtime/README.md](/Users/bedlam/Desktop/getting_rusty/boomerang/poc/poc-runtime/README.md)

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
