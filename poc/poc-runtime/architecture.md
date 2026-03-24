# poc-runtime Architecture

`poc-runtime` is the operator-facing entrypoint for the supported local multi-process Boomerang
flow.

## Dependencies

It sits above:

- `boomerang-scenarios`
- `boomerang-config`
- `boomerang-runtime`
- `boomerang-node`

## Launcher Phases

The launcher runs in two phases:

1. check whether the workspace-managed `boomerang-node` child binary is missing or stale and
   rebuild it automatically when needed
1. start WT/SAR with real `boomerang-node <role> run --config ...` processes
2. wait for WT/SAR `identity-public.toml`
3. build the final 41-process manifest
4. launch the remaining roles around the already-running WT/SAR hosts
5. supervise all managed children until they exit or one fails

## Operator Output Model

The crate intentionally separates:

- full ping-pong and duress-step supervisor narrative in the terminal
- low-level raw detail in per-process `node.log` and `progress.log`

The default artifact base is the visible repository-root `poc-runs/` directory, and each default
launch creates a fresh `run-*` child directory there and keeps it for inspection.
