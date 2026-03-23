# `poc-steps` Limitations

- The crate duplicates protocol flow knowledge that also exists in the domain crates and the supported runtime stack.
- `setup.rs` and `withdrawal.rs` are still very large and need decomposition if they are changed further.
- The crate is useful for protocol reading and regression comparison, but not as the main operational runtime surface.

## Follow-Up

- Keep the walkthrough accurate as the protocol evolves.
- Continue extracting reusable fixtures and regression scenarios out of this crate when they become stable.
