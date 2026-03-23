# boomerang-runtime Architecture

`boomerang-runtime` is the application/service layer above the domain and transport crates.

It depends inward on domain crates, config models, transport abstractions, and the wire contract.
It does not own CLI parsing or manifest serialization.

WT/SAR private identity generation does not live here anymore. The runtime layer now treats that as
core-owned behavior and only persists the public identity artifact that supervisors consume.

The runtime role logic is split into dedicated modules under `src/roles/`:
- `api` for the public runtime trait and builder
- `config` for runtime construction from manifests
- `shared` for cross-role helpers
- one module or module tree per role for live orchestration
- `tags` for accepted-tag declarations

The heaviest roles are further decomposed into role-local submodules so setup, withdrawal, and shared state helpers can evolve independently without reopening a single monolithic file.

At process runtime, this crate now sits between:

- an async transport/session layer
- a synchronous core protocol workflow

It bridges those worlds with a blocking runtime context so the protocol code can stay synchronous
while sockets, timers, and supervision are async.
