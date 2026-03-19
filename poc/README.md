# PoCs

This directory groups the runnable proof-of-concept environments around the shared Boomerang core crates.

## Subdirectories

- `steps/`
  - The `poc-steps` package.
  - Runs the protocol linearly and explicitly for diagram-level inspection.
- `networked/`
  - The `poc-networked` package.
  - Runs the protocol automatically through an independent Tokio-channel orchestration layer.

## Run Commands

```bash
cargo run -p poc-steps
cargo run -p poc-networked
```
