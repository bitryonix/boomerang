# `poc-steps` Architecture

`poc-steps` is the legacy linear Boomerang reference runner. It exists to preserve a direct,
diagram-like walkthrough of setup and withdrawal without an intermediate transport abstraction.

## Why This Crate Exists

This crate is kept so maintainers can:

- read the protocol in a linear order,
- compare domain behavior against design diagrams,
- debug a precise `produce_*` / `consume_*` sequence without actor or TCP orchestration.

## Main Components

- `src/main.rs`
  - Thin binary bootstrap that delegates to focused modules.
- `src/app.rs`
  - Config loading, milestone printing, and sequential workflow orchestration.
- `src/tracing_setup.rs`
  - Legacy tracing subscriber bootstrap.
- `src/setup.rs`
  - Linear setup walk-through.
- `src/withdrawal.rs`
  - Linear withdrawal walk-through.

## Relationship to the Supported Runtime

`poc-steps` is a legacy/reference crate, not the preferred runtime path. It remains in the
workspace so the explicit protocol walkthrough stays buildable, testable, and documented beside
`poc-runtime`.
