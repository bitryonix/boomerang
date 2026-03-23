# boomerang-config Architecture

`boomerang-config` sits at the configuration boundary. It exposes serializable config types,
identity-artifact types, and validation logic, but it does not own transport I/O or runtime
orchestration.
