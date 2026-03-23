# protocol-wire Design Decisions

- The wire-facing API was given its own crate first so runtime and transport code could stop depending directly on `protocol` internals.
- The crate owns both the general protocol frame contract and the wire-only control messages so the tag registry stays centralized and cycle-free.
