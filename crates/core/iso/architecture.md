# iso Architecture

`iso` is a domain crate that owns ISO state and message transitions only.

Its setup flow is organized as staged modules under `src/setup/` so the duress path, backup bootstrap, backup request, backup transfer, and backup completion phases can evolve independently while keeping `setup/mod.rs` wiring-only.
