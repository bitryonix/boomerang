# PoC Area Design Decisions

- All proof-of-concept runners live under top-level `poc/`.
- `poc-runtime` is the supported PoC launcher command.
- `poc-networked` and `poc-steps` remain intentionally as reference runners.
- `poc-runtime` favors a curated supervisor narrative in the terminal.
- Raw per-process detail stays in `node.log` and `progress.log`.
- The default artifact base is the visible repository-root `poc-runs/` directory.
