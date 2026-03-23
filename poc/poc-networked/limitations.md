# `poc-networked` Limitations

- This crate models networking with Tokio channels rather than the `ProtocolFrame` TCP transport used by the supported runtime stack.
- Large actor files still need finer decomposition if this crate is going to evolve further.
- The crate is retained for reference and regression comparison, so feature work should generally
  target `boomerang-node` and `poc-runtime` first.

## Follow-Up

- Keep the crate building and documented while equivalent regression coverage is harvested into the supported runtime stack.
- Continue shrinking large actor modules when changes are required there.
