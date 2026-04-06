# boomerang-scenarios

Provides deterministic scenario builders used by `poc-runtime`, runtime-facing tests, and future
supervisors. The current primary scenario is the 41-process local Boomerang cluster.

The local POC builder now consumes a WT public id plus one SAR public id per SAR instance. A
separate helper builds the WT/SAR identity-publication configs that `poc-runtime` runs before the final
cluster manifest is assembled.

The default run-artifact base returned by `default_state_root()` is now the visible workspace-root
[`poc-runs/`](../../../poc-runs/README.md) directory.
