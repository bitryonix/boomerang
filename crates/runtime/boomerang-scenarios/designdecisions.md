# boomerang-scenarios Design Decisions

- Scenario construction was pulled out of the PoC launcher so topology logic can be reused and
  tested independently.
- The operator-facing PoC flow now lives in `poc-runtime`, while `boomerang-scenarios` stays focused on
  reusable manifest construction.
- WT/SAR identities are no longer pre-generated inside the final manifest builder. The scenario
  crate now expects published public ids as inputs and leaves identity generation to runtime hosts.
- The shared default state-root base points at the visible workspace-root `poc-runs/` directory.
