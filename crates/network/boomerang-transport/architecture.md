# boomerang-transport Architecture

## Mission

This crate owns the smallest transport surface that can:

- validate named links,
- establish TCP sockets,
- prove peer identity with a control handshake,
- expose frame-level readers and writers to the runtime.

It deliberately avoids owning business protocol state, role dispatch, or manifest loading.

## Internal structure

- `src/lib.rs`
  - thin crate root with docs and re-exports.
- `src/transport.rs`
  - thin transport façade.
- `src/transport/model.rs`
  - transport-facing data models such as `LinkConfig` and `OutboundFrame`.
- `src/transport/io.rs`
  - frame read/write helpers and progress-log output.
- `src/transport/handshake.rs`
  - outbound retry policy plus the `TransportHello` / `TransportReady` handshake.
- `src/transport/service.rs`
  - runtime-facing orchestration for establishing links and spawning reader threads.
- `src/error.rs`
  - typed transport errors that callers can surface without losing meaning.

## Responsibilities

This crate owns:

- link configuration validation
- listener/connect lifecycle
- handshake execution over `protocol-wire`
- framed reader/writer utilities

## Dependency direction

`boomerang-transport` depends inward on `protocol-wire` for the wire contract.
`boomerang-runtime` depends outward on this crate for transport services.

## Relationship to the supported runtime

It does not own the wire contract itself. `ProtocolFrame`, `MessageTag`, and the control payload
types live in `protocol-wire`, while `boomerang-runtime` owns role orchestration on top of those
transport primitives.
