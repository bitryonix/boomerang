# Workspace Operations

This document centralizes the operator-facing commands, artifact locations, and runtime
expectations for the current workspace.

## Supported Commands

- `cargo run -p boomerang-node -- <role> run --config <path>`
  - Run one standalone role process from a TOML process manifest.
- `cargo run -p boomerang-node -- cluster up --manifest <path>`
  - Launch a manifest-defined cluster through the shared node host.
- `cargo run -p poc-runtime`
  - Launch the supported local 41-process PoC supervisor.
- `cargo run -p poc-runtime --example local_poc_manifest`
  - Print the deterministic 41-process manifest summary.
- `cargo run -p poc-networked`
  - Run the legacy concurrent reference surface.
- `cargo run -p poc-steps`
  - Run the legacy step-by-step reference surface.

## Default PoC Artifact Location

The default PoC artifact base is now [`poc-runs/`](/Users/bedlam/Desktop/getting_rusty/boomerang/poc-runs/README.md)
at the workspace root.

By default, `poc-runtime` treats `--state-root` as a base directory for one fresh child run
directory:

- `cargo run -p poc-runtime`
  - creates `poc-runs/run-...`
  - keeps that run directory after the run ends
- `cargo run -p poc-runtime -- --state-root /path/to/base`
  - creates `/path/to/base/run-...`
  - keeps that run directory after the run ends

Persistence is explicit:

- `--persist-state-root`
  - keep one exact run directory on disk
- `--persist-state-root --reuse-state-root`
  - intentionally reuse an existing persistent run directory

## Operational Artifacts

Within one kept run directory, the important files are:

- `cluster.toml`
  - the generated final 41-process manifest
- `<process>/node.log`
  - raw stdout/stderr from each child `boomerang-node`
- `<process>/progress.log`
  - runtime lifecycle and protocol-stage markers
- `<process>/identity-public.toml`
  - WT/SAR public identity artifacts

## WT/SAR Identity Flow

WT and SAR now follow one strict operator contract:

- WT/SAR manifests never contain `private_key` or `tor_secret_key`
- WT/SAR manifests never contain `wt_id` or `sar_id` in their own bootstrap payloads
- `boomerang-node <wt|sar> run --config ...` creates identity internally
- the only cross-process WT/SAR identity artifact is `identity-public.toml`

`poc-runtime` automates that flow:

1. start WT and SAR first
2. wait for their `identity-public.toml` files
3. build the final 41-process manifest using only those public ids
4. launch the remaining roles

## Logging

`poc-runtime` intentionally does not mirror child stdout/stderr into the main terminal. The
operator experience is split:

- terminal
  - curated supervisor narrative
  - setup milestones
  - digging-game checkpoints
  - withdrawal progress
  - concise failure summaries
- per-process files
  - `node.log`
  - `progress.log`

That keeps the main terminal readable while preserving the full low-level trace on disk.

## Environment Variables

- `RUST_LOG`
  - controls tracing verbosity for the supported binaries and the reference runners

## Quality Gates

The repository-level compliance script currently runs:

```bash
cargo +stable fmt --all --check
cargo +stable clippy --workspace --all-targets --all-features -- -D warnings
cargo +stable clippy --workspace --all-targets --all-features -- -W clippy::missing_docs_in_private_items
cargo +stable test --workspace --all-features
cargo +stable test --workspace --doc
RUSTDOCFLAGS="-D warnings" cargo +stable doc --workspace --no-deps
RUSTDOCFLAGS="-D warnings" cargo +stable doc --workspace --no-deps --document-private-items
cargo +stable check --workspace
cargo +stable tree -d
cargo +stable tree -e features
```
