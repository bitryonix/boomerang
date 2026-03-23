# boomerang-transport

`boomerang-transport` owns the transport layer for standalone Boomerang processes.

## Why this crate exists

The workspace needs one crate that handles:

- backend-neutral transport ports for runtime composition,
- transport identities and link configuration,
- the current Tokio TCP connect/bind policy,
- control-message handshakes,
- framed socket I/O over `protocol-wire`,
- bounded inbound and outbound transport queues,
- optional non-core delay injection for future latency experiments.

Those concerns are operational and transport-specific. They do not belong in `protocol`, and they
should not be duplicated across `boomerang-runtime`, `boomerang-node`, or `poc-runtime`.

## Main entry points

- `TransportInterface` / `TransportSession`
  - backend-neutral ports used by the runtime crate, with async session establishment and a
    blocking bridge for the synchronous role driver.
- `tcp::TcpTransportInterface`
  - the supported concrete backend for today’s runtime path.
- `LinkDelayPolicy`
  - optional transport-edge delay hooks for future tests and PoC timing experiments.
- `LocalProcessIdentity`
  - identifies the current process during the transport handshake.
- `LinkConfig`
  - defines one named bind-or-connect link and validates its invariants.
- `establish_links`
  - turns validated link configs into one established async session.
- `write_outbound_frame`
  - enqueues one framed message for the writer selected by manifest route name.
- `read_frame` / `write_frame`
  - raw frame helpers for the wire boundary.

The transport session now also supports explicit shutdown so final queued outbound frames can be
flushed before a process exits.

## Module layout

- `src/transport/model.rs`
  - link and frame wrapper types.
- `src/transport/io.rs`
  - frame and progress-log I/O.
- `src/transport/handshake.rs`
  - control handshake and connect retry policy.
- `src/transport/service.rs`
  - runtime-facing orchestration helpers.

## Example

A process runtime uses this crate during bootstrap:

```text
let session = transport
    .establish_session(&local_identity, &links, progress_path)
    .await?;
```

## Where to look next

- `protocol-wire` for the wire contract itself
- `boomerang-runtime` for role orchestration built on top of these transport primitives
