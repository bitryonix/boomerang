# boomerang-runtime

Hosts the service-layer runtime for Boomerang roles.

It now exposes:

- async-first process execution via `run_process_async`,
- transport-neutral process execution via `run_process_with_transport`,
- async-first cluster supervision via `launch_cluster_async`,
- launcher-neutral cluster supervision via `launch_cluster_with_launcher`,
- the current supported defaults on top of those seams:
  - `boomerang-transport::tcp::TcpTransportInterface`
  - `LocalChildLauncher`

This keeps today’s supported operator path stable while making room for future hosts and
interfaces.

The current node host is now an async process shell: Tokio owns sockets, timers, and child
supervision, while one dedicated blocking driver task still runs the existing synchronous role
workflow so core protocol code does not need an async rewrite.

WT/SAR runtime startup now relies on core-owned internal identity creation and publishes only
`identity-public.toml` immediately after internal initialization. That lets staged supervisors such
as `poc-runtime` learn WT/SAR public ids before the rest of the cluster is online, while the
runtime layer still owns no WT/SAR private identity artifact format.

The runtime now also performs explicit transport-session shutdown after the role workflow returns
so final outbound frames are flushed before a process exits.
