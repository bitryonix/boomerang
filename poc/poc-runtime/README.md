# poc-runtime

`poc-runtime` is the supported operator-facing crate for the local Boomerang proof-of-concept
flow.

## What It Does

`poc-runtime` owns the full supported local workflow:

- rebuild the workspace-managed `boomerang-node` automatically when the launcher detects that the
  managed binary is missing or older than the relevant workspace sources
- validate the default PoC configuration
- start a local Bitcoin Core fixture
- start WT and SAR first
- wait for WT/SAR `identity-public.toml`
- build the final deterministic 41-process manifest
- launch the remaining 35 `boomerang-node` children
- supervise the whole cluster until completion or failure

## Runtime Model

Each managed `boomerang-node` child now hosts an async runtime internally:

- Tokio owns sockets, timers, and transport supervision
- the protocol workflow still runs synchronously inside one blocking driver task

That gives the PoC real async transport and supervision behavior without rewriting the core
protocol crates as async code.

## Terminal Narrative

The default terminal output is intentionally curated.

`poc-runtime` tails each child `progress.log` and promotes important milestones into a readable
narrative, including:

- identity staging
- setup progress
- full peer duress-check steps
- full digging-game ping-pong steps
- withdrawal completion
- concise failure summaries with exact `node.log` and `progress.log` paths

When the output is attached to a real terminal, `poc-runtime` color-codes both the phase label and
the protocol event itself so the viewer can distinguish things like approvals, duress checks,
ping-pongs, commitment-path milestones, signing, completion, failure, and artifact notices more
easily. Non-interactive output stays plain, and `NO_COLOR` disables the styling explicitly.

Raw child stdout/stderr still stays in each process `node.log`.

## Common Commands

```bash
cargo run -p poc-runtime
cargo run -p poc-runtime --example local_poc_manifest
```

When `poc-runtime` is using the workspace-managed `target/debug/boomerang-node`, it now checks
that executable before launch and runs `cargo build -p boomerang-node` automatically if the child
binary is missing or stale.

If you pass an explicit external `--node-bin`, `poc-runtime` treats that executable as
operator-managed and does not rebuild it.

## State Root Behavior

The default artifact base is the visible repository-root
[`poc-runs/`](../../poc-runs/README.md) directory.

By default, `poc-runtime` treats `--state-root` as a base directory and creates one fresh
child run directory under it. That child run directory is kept after the run finishes.

Keep one exact run directory on disk:

```bash
cargo run -p poc-runtime -- --state-root /path/to/run --persist-state-root
```

Reuse an existing persistent run directory intentionally:

```bash
cargo run -p poc-runtime -- --state-root /path/to/old-run --persist-state-root --reuse-state-root
```
