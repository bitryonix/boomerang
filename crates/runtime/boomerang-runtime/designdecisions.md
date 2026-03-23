# boomerang-runtime Design Decisions

- Runtime-specific dispatch and lifecycle handling stay here instead of leaking into `boomerang-node` or `boomerang-transport`.
- Large role runtimes are split first by role, then by flow phase or helper concern, so `mod.rs` stays wiring-only and future changes remain locally reviewable.
- WT/SAR identity generation is owned by the runtime host, not by the supervisor manifest. The
  runtime persists local private identity artifacts and publishes only public ids back outward.
