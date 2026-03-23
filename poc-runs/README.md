# PoC Run Artifacts

This directory is the default visible home for `poc-runtime` run artifacts.

What appears here depends on the flags you use:

- default `cargo run -p poc-runtime`
  - creates one ephemeral `run-...` child directory here
  - keeps that child directory after the run finishes
- `--persist-state-root`
  - keeps the chosen run directory on disk
- `--persist-state-root --reuse-state-root`
  - intentionally reuses an existing persistent run directory

When persistence is enabled, a run directory typically contains:

- `cluster.toml`
- one state directory per managed process
- each process `node.log`
- each process `progress.log`
- WT/SAR `identity-public.toml`
