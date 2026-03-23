//! Top-level process bootstrap for one configured runtime process.

use boomerang_config::ProcessConfig;
use boomerang_transport::{LocalProcessIdentity, TransportInterface, tcp::TcpTransportInterface};
use tracing::{info, warn};

use crate::{error::RuntimeError, roles::build_role_runtime};

use super::{
    context::RuntimeContext,
    identity::persist_runtime_published_identity,
    progress::{append_progress, progress_log_path, reset_progress_log},
};

/// Runs one fully-configured Boomerang process from manifest validation through completion.
///
/// # Why this exists
/// `boomerang-node` and `poc-runtime` both need one shared process bootstrap path so they launch
/// the same runtime behavior regardless of whether the process was started directly or as a child.
///
/// # Role in the system
/// This sync compatibility wrapper exists for non-async callers. The supported async host path is
/// [`run_process_async`].
pub fn run_process(config: ProcessConfig) -> Result<(), RuntimeError> {
    block_on_runtime(run_process_async(config))
}

/// Runs one fully-configured Boomerang process using the default async TCP transport backend.
///
/// # Why this exists
/// Each standalone `boomerang-node` process now hosts an async runtime for sockets and timers
/// while still delegating the protocol workflow itself to one dedicated blocking driver task.
///
/// # Role in the system
/// This is the primary process entrypoint behind `boomerang-node <role> run --config ...`.
pub async fn run_process_async(config: ProcessConfig) -> Result<(), RuntimeError> {
    run_process_async_with_transport(config, &TcpTransportInterface::default()).await
}

/// Runs one fully-configured Boomerang process using an explicit transport backend.
///
/// # Why this exists
/// Tests and future hosts need a way to reuse the runtime orchestration with transport backends
/// other than the default Tokio TCP implementation.
pub fn run_process_with_transport(
    config: ProcessConfig,
    transport: &dyn TransportInterface,
) -> Result<(), RuntimeError> {
    block_on_runtime(run_process_async_with_transport(config, transport))
}

/// Async process bootstrap that uses an explicit transport backend.
///
/// # Why this exists
/// This is the async-first variant used by the supported node host and by transport-focused
/// tests.
pub async fn run_process_async_with_transport(
    config: ProcessConfig,
    transport: &dyn TransportInterface,
) -> Result<(), RuntimeError> {
    config.validate()?;
    reset_progress_log(&config)?;
    append_progress(
        &config,
        &format!(
            "stage=process_start role={} instance_id={}",
            config.role.as_str(),
            config.instance_id
        ),
    )?;

    let mut runtime = build_role_runtime(&config)?;
    append_progress(
        &config,
        &format!(
            "stage=runtime_built role={} instance_id={}",
            config.role.as_str(),
            config.instance_id
        ),
    )?;

    // WT/SAR must publish their public ids immediately after internal initialization so staged
    // launchers such as `poc-runtime` can learn those ids before the rest of the cluster exists.
    if persist_runtime_published_identity(&config, runtime.as_ref())? {
        append_progress(
            &config,
            &format!(
                "stage=identity_published role={} instance_id={}",
                config.role.as_str(),
                config.instance_id
            ),
        )?;
    }

    let session = transport
        .establish_session(
            &LocalProcessIdentity::new(config.role, config.instance_id.clone()),
            &config.links,
            &progress_log_path(&config),
        )
        .await?;
    append_progress(
        &config,
        &format!(
            "stage=links_established role={} instance_id={}",
            config.role.as_str(),
            config.instance_id
        ),
    )?;

    info!(
        role = config.role.as_str(),
        instance_id = config.instance_id,
        num_links = config.links.len(),
        "boomerang role runtime started"
    );

    let role = runtime.role();
    let accepted_tags = runtime.accepted_tags();
    let progress_path = progress_log_path(&config);
    let runtime_handle = tokio::runtime::Handle::current();
    append_progress(
        &config,
        &format!(
            "stage=runtime_start role={} instance_id={}",
            config.role.as_str(),
            config.instance_id
        ),
    )?;

    let result = tokio::task::spawn_blocking(move || {
        let mut context =
            RuntimeContext::with_transport_session(role, accepted_tags, session, progress_path);
        let result = runtime.run(&mut context);
        let shutdown_result = context.shutdown(&runtime_handle);

        match (result, shutdown_result) {
            (Ok(()), Ok(())) => Ok(()),
            (Ok(()), Err(error)) => Err(error),
            (Err(error), Ok(())) => Err(error),
            (Err(error), Err(shutdown_error)) => {
                warn!(
                    role = role.as_str(),
                    "runtime shutdown also failed after a protocol error: {}", shutdown_error
                );
                Err(error)
            }
        }
    })
    .await
    .map_err(|error| RuntimeError::BackgroundTaskFailed {
        detail: error.to_string(),
    })?;

    if result.is_ok() {
        append_progress(
            &config,
            &format!(
                "stage=process_complete role={} instance_id={}",
                config.role.as_str(),
                config.instance_id
            ),
        )?;
    }

    result
}

fn block_on_runtime<F>(future: F) -> Result<(), RuntimeError>
where
    F: std::future::Future<Output = Result<(), RuntimeError>>,
{
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        tokio::task::block_in_place(|| handle.block_on(future))
    } else {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(future)
    }
}
