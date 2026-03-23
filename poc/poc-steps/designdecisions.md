# `poc-steps` Design Decisions

- The crate remains in the workspace as a legacy/reference runner.
- The flow is intentionally explicit rather than abstract so readers can trace the protocol in diagram order.
- New operational capabilities should target `boomerang-node` and `poc-runtime` first, with this crate
  updated only to preserve reference value and regression confidence.
