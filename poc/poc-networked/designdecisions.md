# `poc-networked` Design Decisions

- The crate remains in the workspace as a legacy/reference runner.
- Channel-based actor orchestration is preserved here for comparison with the supported process-per-role runtime.
- New runtime behavior should land in the supported stack first unless the change is specifically about historical comparison.
