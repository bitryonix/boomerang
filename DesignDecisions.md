# Design Decisions

## Current Decisions

- The supported runtime path is `boomerang-node` plus `poc-runtime`.
- The repository keeps one crate per core entity rather than merging the domain layer into one
  large crate.
- Wire framing and transport-control wrappers live in `protocol-wire`, outside the core `protocol`
  crate.
- Process and cluster manifests live in `boomerang-config`, outside `boomerang-runtime`.
- Deterministic local-topology construction lives in `boomerang-scenarios`, outside the binaries.
- `boomerang-transport` exposes backend-neutral transport interfaces while keeping Tokio/TCP as the
  current supported backend.
- `boomerang-runtime` exposes transport and launcher seams while keeping the local child-process
  launcher as the current supported host.
- The node host and PoC supervisor are async at the transport/supervision layer, but the core
  protocol workflows remain synchronous inside dedicated blocking driver tasks.
- WT and SAR create private identity material internally; non-core layers consume only
  `identity-public.toml`.
- PoC run artifacts have a visible home in `poc-runs/` at the workspace root.

## Reference-Surface Decisions

- `poc-networked` and `poc-steps` remain in the repository as reference runners.
- They stay in workspace membership so build, lint, test, and doc gates keep applying to them.
- They are intentionally not treated as the preferred operator path.

## Operator-Facing Decisions

- `poc-runtime` prints a curated supervisor narrative to the terminal instead of streaming raw
  child stdout/stderr.
- Raw `node.log` and `progress.log` files remain on disk for deep debugging.
- `--state-root` defaults to an ephemeral child directory under the visible repo-root
  `poc-runs/` base.
- Persistence and reuse are explicit:
  - `--persist-state-root` keeps one exact run directory
  - `--persist-state-root --reuse-state-root` is required to reuse an existing persistent run
    directory

## Migration Notes

- Compatibility-only package surfaces were removed.
  - Replace `cargo run -p poc` with `cargo run -p poc-runtime`.
  - Replace `poc_config::...` imports with `boomerang_config::...`.
- The old empty top-level `legacy/` staging area was removed after the active legacy crates were
  moved under `poc/`.
- WT/SAR manifests no longer accept bootstrap secret or self-public-id fields.
  - Remove `private_key`, `tor_secret_key`, `wt_id`, and `sar_id` from WT/SAR bootstrap payloads.
  - Start WT/SAR with `boomerang-node <wt|sar> run --config ...`.
  - Learn WT/SAR public ids from `identity-public.toml`.
