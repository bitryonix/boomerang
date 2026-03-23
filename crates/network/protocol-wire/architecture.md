# protocol-wire Architecture

`protocol-wire` is the dedicated wire-facing boundary for the workspace.

It owns:
- frame headers and payload framing
- message tag registry
- wire encode/decode helpers
- the `WireMessage` / `TaggedMessage` traits
- wire-only control payloads used during transport/runtime coordination

It depends on `protocol` for domain message types, but the dependency direction does not go back the other way: the domain layer no longer owns or re-exports wire code.
