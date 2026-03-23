# `boomerang-node`

`boomerang-node` is the shared standalone host for Boomerang protocol entities.

## Commands

Run a single role process:

```bash
cargo run -p boomerang-node -- st run --config boomerang-node/examples/minimal-process.toml
```

Run WT directly and let it publish its public identity artifact:

```bash
cargo run -p boomerang-node -- wt run --config /tmp/wt.toml
```

Launch a small cluster from one manifest:

```bash
cargo run -p boomerang-node -- cluster up --manifest boomerang-node/examples/minimal-cluster.toml
```

## Config Shape

Each process config contains:

- `role`
- `instance_id`
- `state_dir`
- `bootstrap`
- `routes`
- `links`
- `boomerang`
- `withdrawal`

For WT and SAR, the bootstrap section now carries only the runtime inputs needed for internal
initialization. WT/SAR create identity during `run` and publish only `identity-public.toml` into
`state_dir`. Peer/phone-facing manifests consume those public ids, but WT/SAR manifests
themselves no longer carry `wt_id`, `sar_id`, or any WT/SAR secret identity material.

The checked-in starter files are:

- `boomerang-node/examples/minimal-process.toml` for one `st` process
- `boomerang-node/examples/minimal-cluster.toml` for one tiny `st`/`iso` cluster

Each link contains:

- `name`
- `peer_role`
- `peer_instance_id`
- exactly one of `bind_addr` or `connect_addr`

## Status

The current runtime owns real entity instances, performs `TransportHello` / `TransportReady`
handshakes over `ProtocolFrame`, validates manifests, and enforces per-role accepted tag sets.

Each `boomerang-node` process now hosts a Tokio runtime for sockets, timers, and supervision, but
the role workflow itself still runs in one dedicated blocking driver task so the synchronous core
protocol entities remain unchanged.

Role-specific protocol dispatch is intentionally scaffolded for expansion and still needs to be
filled in beyond the transport/bootstrap layer.
