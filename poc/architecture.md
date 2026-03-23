# PoC Area Architecture

The `poc/` area keeps three different ways of looking at the Boomerang protocol close together
without mixing them into the reusable runtime crates.

- `poc/poc-runtime`
  - supported supervisor
  - launches real `boomerang-node` processes
  - stages WT/SAR identity publication
  - generates the final 41-process manifest
  - supervises children and narrates progress
- `poc/poc-networked`
  - reference concurrent runner with actor/channel orchestration
- `poc/poc-steps`
  - reference linear runner that mirrors the protocol diagrams

The default run-artifact base for this area is the visible repository-root
[`poc-runs/`](/Users/bedlam/Desktop/getting_rusty/boomerang/poc-runs/README.md) directory.
