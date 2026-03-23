# `poc-networked` Architecture

`poc-networked` is the legacy concurrent Boomerang reference runner. It exists to preserve the
actor-and-channel orchestration model that predates the newer `ProtocolFrame` transport stack.

## Why This Crate Exists

This crate is kept as a reference surface for:

- actor-based concurrency experiments,
- transport-agnostic protocol orchestration ideas,
- regression comparison against the supported multi-process runtime.

## Main Components

- `src/main.rs`
  - Thin binary bootstrap that delegates to focused modules.
- `src/app.rs`
  - Legacy startup validation, actor wiring, and task orchestration.
- `src/tracing_setup.rs`
  - Legacy tracing subscriber bootstrap.
- `src/actors/`
  - Peer, WT, and SAR orchestration actors.
- `src/local_actor.rs`
  - Channel-backed wrappers for peer-local entities.
- `src/transport.rs`
  - Tokio mailboxes and routing helpers.
- `src/envelopes.rs`
  - Typed message envelopes passed across actors.

## Relationship to the Supported Runtime

`poc-networked` is not the preferred execution path for new work. The supported path is
`boomerang-node` plus `poc-runtime`, but this crate remains in the workspace so the older design
continues to compile, test, and document cleanly.
