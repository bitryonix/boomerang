# poc-runtime Design Decisions

- The reusable 41-process topology builder stays in `boomerang-scenarios`.
- The human-facing PoC CLI and examples live in `poc/poc-runtime`.
- The top-level `poc/` directory is an umbrella area again, not a package root.
- Redundant launcher aliases such as `run_local_poc` and `run_binary` were removed so the crate
  matches the same thin bootstrap pattern as `boomerang-node`.
- WT and SAR now publish only public ids back to the PoC supervisor. `poc-runtime` stages the real WT/SAR
  processes first and never owns a non-core WT/SAR private-identity artifact.
- The default terminal view is a curated supervisor narrative derived from runtime `progress.log`
  files, while raw child logs remain on disk for postmortem inspection.
- The default run-artifact base is the visible repository-root `poc-runs/` directory.
- Reusing a persistent run directory is explicit opt-in through `--reuse-state-root`.
- `poc-runtime` auto-refreshes only the workspace-managed `target/debug/boomerang-node` path.
  Explicit external `--node-bin` paths stay operator-managed and are never rebuilt automatically.
