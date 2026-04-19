//! Link-establishment and runtime-facing transport services.
//!
//! # Why this exists
//! Higher layers need one orchestration surface that turns validated link configs into a ready
//! async transport session without taking ownership of raw socket details.
//!
//! # Role in the system
//! This module is the primary runtime-facing surface of the crate.

use std::{collections::BTreeMap, path::Path, sync::Arc, time::Duration};

use protocol_wire::{ProtocolFrame, control::TransportRole};
use tokio::{
    net::{TcpListener, tcp::OwnedReadHalf, tcp::OwnedWriteHalf},
    sync::mpsc,
    time::{sleep, timeout},
};

use crate::{
    delay::{LinkDelayPolicy, NoDelayLinkDelayPolicy},
    error::TransportError,
    transport::{
        handshake::{accept_with_timeout, connect_with_retry, perform_handshake},
        io::{append_progress_line_async, read_frame_async, write_frame_async},
        model::{
            EstablishedLinks, InboundFrame, LinkConfig, LinkWriters, LocalProcessIdentity,
            OutboundFrame,
        },
    },
};

/// Capacity of the per-process inbound frame queue.
const INBOUND_FRAME_CAPACITY: usize = 256;
/// Capacity of each per-link outbound queue.
const OUTBOUND_FRAME_CAPACITY: usize = 64;
/// Timeout budget for one framed read after startup completes.
const READ_TIMEOUT: Duration = Duration::from_secs(300);
/// Timeout budget for one framed write after startup completes.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Establishes every configured transport link for the local process using the default no-delay
/// policy.
pub async fn establish_links(
    local: &LocalProcessIdentity,
    links: &[LinkConfig],
    progress_path: &Path,
) -> Result<EstablishedLinks, TransportError> {
    establish_links_with_delay(
        local,
        links,
        progress_path,
        Arc::new(NoDelayLinkDelayPolicy),
    )
    .await
}

/// Establishes every configured transport link for the local process using an explicit delay
/// policy.
pub(crate) async fn establish_links_with_delay(
    local: &LocalProcessIdentity,
    links: &[LinkConfig],
    progress_path: &Path,
    delay_policy: Arc<dyn LinkDelayPolicy>,
) -> Result<EstablishedLinks, TransportError> {
    append_progress_line_async(
        progress_path,
        &format!("transport_start total_links={}", links.len()),
    )
    .await?;

    let mut listeners = BTreeMap::new();
    for link in links {
        link.validate()?;
        if let Some(bind_addr) = link.bind_addr {
            listeners.insert(link.name.clone(), TcpListener::bind(bind_addr).await?);
            append_progress_line_async(
                progress_path,
                &format!("listener_bound link={} addr={bind_addr}", link.name),
            )
            .await?;
        }
    }

    let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_FRAME_CAPACITY);
    let mut writers = LinkWriters::new();
    let mut task_handles = Vec::with_capacity(links.len() * 2);

    for link in links {
        let mode = if link.connect_addr.is_some() {
            "connect"
        } else {
            "accept"
        };
        append_progress_line_async(
            progress_path,
            &format!("link_start link={} mode={mode}", link.name),
        )
        .await?;

        let stream = if let Some(connect_addr) = link.connect_addr {
            connect_with_retry(connect_addr, link, delay_policy.as_ref()).await?
        } else {
            let listener =
                listeners
                    .get(&link.name)
                    .ok_or_else(|| TransportError::InvalidLinkConfig {
                        link_name: link.name.clone(),
                        reason: "missing listener for bind-mode link".to_owned(),
                    })?;
            accept_with_timeout(listener, link, delay_policy.as_ref()).await?
        };

        let stream = perform_handshake(local, link, stream, delay_policy.as_ref()).await?;
        append_progress_line_async(progress_path, &format!("link_ready link={}", link.name))
            .await?;

        let (reader, writer) = stream.into_split();
        let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_FRAME_CAPACITY);
        writers.insert(link.name.clone(), outbound_tx);

        task_handles.push(tokio::spawn(read_loop(
            link.name.clone(),
            reader,
            inbound_tx.clone(),
            Arc::clone(&delay_policy),
        )));
        task_handles.push(tokio::spawn(write_loop(
            link.name.clone(),
            writer,
            outbound_rx,
            Arc::clone(&delay_policy),
        )));
    }

    Ok(EstablishedLinks {
        inbound_rx,
        writers,
        task_handles,
    })
}

/// Writes one outbound frame to the writer queue associated with its named route.
///
/// # Why this exists
/// The runtime drives role code through a synchronous transport bridge, so outbound routing needs
/// one small helper that resolves the manifest link name and hands the frame to that link's
/// bounded writer queue.
///
/// # Blocking
/// This function may block while waiting for queue capacity. Callers should keep it on the
/// runtime's blocking side rather than invoking it directly on an async executor thread.
///
/// # Errors
/// Returns [`TransportError::UnknownLink`] when the named route was never established and
/// [`TransportError::OutboundChannelClosed`] when the writer task has already shut down.
pub fn write_outbound_frame(
    writers: &LinkWriters,
    outbound: &OutboundFrame,
    local_role: TransportRole,
) -> Result<(), TransportError> {
    let writer = writers
        .get(&outbound.link_name)
        .ok_or_else(|| TransportError::UnknownLink(outbound.link_name.clone(), local_role))?;
    writer.blocking_send(outbound.frame.clone()).map_err(|_| {
        TransportError::OutboundChannelClosed {
            link_name: outbound.link_name.clone(),
        }
    })
}

async fn read_loop(
    link_name: String,
    mut reader: OwnedReadHalf,
    inbound_tx: mpsc::Sender<InboundFrame>,
    delay_policy: Arc<dyn LinkDelayPolicy>,
) {
    loop {
        let frame = match timeout(READ_TIMEOUT, read_frame_async(&mut reader)).await {
            Ok(Ok(frame)) => frame,
            Ok(Err(_)) | Err(_) => break,
        };

        sleep_if_nonzero(delay_policy.inbound_delivery_delay(&link_name, &frame)).await;
        if inbound_tx
            .send(InboundFrame {
                link_name: link_name.clone(),
                frame,
            })
            .await
            .is_err()
        {
            break;
        }
    }
}

async fn write_loop(
    link_name: String,
    mut writer: OwnedWriteHalf,
    mut outbound_rx: mpsc::Receiver<ProtocolFrame>,
    delay_policy: Arc<dyn LinkDelayPolicy>,
) {
    while let Some(frame) = outbound_rx.recv().await {
        sleep_if_nonzero(delay_policy.outbound_delivery_delay(&link_name, &frame)).await;
        match timeout(WRITE_TIMEOUT, write_frame_async(&mut writer, &frame)).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) | Err(_) => break,
        }
    }
}

async fn sleep_if_nonzero(delay: Duration) {
    if !delay.is_zero() {
        sleep(delay).await;
    }
}
