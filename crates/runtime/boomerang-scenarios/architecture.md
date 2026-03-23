# boomerang-scenarios Architecture

Scenario generation lives outside binaries so topology creation is reusable from tests and
supervisor tools. The local POC area is now split between:

- preflight WT/SAR identity-publication configs
- final cluster manifest generation from published WT/SAR public ids

The crate also owns the shared defaults that PoC-facing tools use for the node binary path and the
default workspace-root run-artifact base.
