# boomerang-transport Design Decisions

- Transport control and handshake messages were moved out of `protocol` so business protocol
  messages do not own runtime transport semantics.
- The crate uses a façade-plus-leaf-module layout so link models, handshake policy, frame I/O, and
  runtime-facing orchestration can evolve independently.
- The transport remains blocking and thread-based for now so it stays decoupled from any specific
  async runtime.
