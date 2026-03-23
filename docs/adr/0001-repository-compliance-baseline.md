# ADR 0001: Whole-Repository Compliance Baseline

## Status

Accepted

## Context

The repository contains both the supported runtime stack and older proof-of-concept runners.
The Boomerang workspace also spans many crates, which makes it easy for documentation, manifest
metadata, and lint policy to drift if the repository does not enforce a single baseline.

## Decision

- Keep the active runtime path as `boomerang-node` plus `poc-runtime`.
- Keep `poc/poc-networked` and `poc/poc-steps` in the workspace as legacy/reference crates.
- Apply the same workspace metadata and quality gates to legacy crates that apply to active crates.
- Keep crate roots thin and move orchestration, validation, parsing, and tests into focused leaf modules.
- Keep PoC run artifacts discoverable under the repository root instead of hiding them in the
  system temp directory by default.

## Consequences

- Legacy crates continue to compile and document cleanly instead of silently decaying.
- Workspace-level checks can catch drift earlier because they operate over the full repository.
- Some compliance work remains incremental because the strongest private-item documentation and panic-removal goals still require crate-by-crate refactoring.
