# Limitations

- The supported stack is still PoC-oriented.
  - It is designed for local development and protocol exploration rather than for a hardened
    multi-host production deployment.
- The transport trust model is still local/trusted-environment oriented.
  - The current TCP handshake verifies self-reported role, instance, and link metadata but does
    not yet provide strong cryptographic peer authentication.
- Several core entity crates still contain very large setup or withdrawal modules.
  - The boundary split is better than before, but some flows remain difficult to review and evolve.
- Some older non-test paths in the wider workspace still rely on panic-style control flow or
  `unwrap`/`expect`.
- Operator-facing backend selection is intentionally still fixed.
  - The runtime and transport crates now have extension seams, but the supported path is still
    Tokio/TCP plus the local child-process launcher.
- Repository-wide documentation is much stronger than it was, but the strictest private-item
  documentation posture is still incremental work.
- `poc-networked` and `poc-steps` remain in the workspace on purpose.
  - That keeps useful reference runners available, but it also means some logic is still duplicated
    across the PoC area.

## Planned Follow-Ups

- Continue decomposing the largest entity and runtime modules.
- Continue replacing panic-style runtime paths with typed errors.
- Strengthen transport authentication and timeout policy for less-trusted environments.
- Keep tightening the docs and review surface around trust boundaries and operational assumptions.
