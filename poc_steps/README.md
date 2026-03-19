# `poc-steps`

`poc-steps` is the step-by-step Boomerang proof-of-concept runner. It executes setup and withdrawal in a direct, linear order that mirrors the design diagrams.

## Purpose

Use this crate when you want to:

- inspect the protocol flow without an extra transport layer,
- compare the implementation with the setup and withdrawal diagrams,
- debug the exact order of `produce_*` and `consume_*` calls.

## Important Files

- `src/main.rs`
  - Runner entrypoint and tracing initialization.
- `src/config.rs`
  - Static configuration for milestone blocks, tolerances, withdrawal settings, and bundled `bitcoind` path resolution.
- `src/setup.rs`
  - Full setup sequence.
- `src/withdrawal.rs`
  - Full withdrawal sequence.

## Run

From the workspace root:

```bash
cargo run -p poc-steps
```

## Notes

- This runner is explicit rather than abstract. The setup and withdrawal flows are intentionally written out in detail.
- The default config resolves the bundled `bitcoind` binary from the workspace root.
- This crate is the best place to read the protocol flow in diagram order.
