# boomerang-node Architecture

`boomerang-node` is CLI-only. It validates boundary inputs, loads config/manifests, initializes tracing, and invokes runtime services.

## Module Layout

- `src/main.rs`
  - Thin bootstrap that initializes tracing, parses clap arguments, and delegates into the app layer.
- `src/cli.rs`
  - Clap command model for role execution and cluster launch.
- `src/app.rs`
  - Boundary orchestration that loads manifests and invokes runtime services.
- `src/tracing_setup.rs`
  - Subscriber initialization for the binary.
