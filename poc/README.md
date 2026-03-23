# PoC Area

The top-level `poc/` area collects every human-facing Boomerang proof-of-concept runner that still
lives in the workspace.

## Crates

- `poc-runtime`
  - The supported local 41-process supervisor.
- `poc-networked`
  - Legacy concurrent reference runner.
- `poc-steps`
  - Legacy linear walkthrough runner.

## Which One To Use

Use `poc-runtime` for active operator and regression work:

```bash
cargo run -p poc-runtime
```

Use the other two only when you intentionally want their alternate perspectives:

- `poc-networked`
  - compare the protocol against a channel/actor orchestration model
- `poc-steps`
  - read the protocol in a direct linear flow

## Run Artifacts

The PoC area now works with a visible workspace-root artifact base:

- default base
  - [`poc-runs/`](/Users/bedlam/Desktop/getting_rusty/boomerang/poc-runs/README.md)
- default behavior
  - fresh child `run-*` directory
  - kept after the run
- explicit persistence
  - `--persist-state-root`
- explicit reuse
  - `--persist-state-root --reuse-state-root`
