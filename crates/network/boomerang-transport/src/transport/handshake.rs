//! Transport handshake and connection policy helpers.
//!
//! # Why this exists
//! TCP sockets alone do not prove that the peer process is the one the manifest described. This
//! module owns the identity handshake, retry loop, and timeout policy for outbound and inbound
//! link establishment.
//!
//! # Role in the system
//! Used internally by [`crate::establish_links`].

use std::{net::SocketAddr, time::Duration};

use protocol_wire::control::{TransportHello, TransportReady};
use tokio::{
    net::{TcpListener, TcpStream},
    time::{sleep, timeout},
};

use crate::{
    delay::LinkDelayPolicy,
    error::TransportError,
    transport::{
        io::{read_message_async, write_message_async},
        model::{LinkConfig, LocalProcessIdentity},
    },
};

/// Maximum outbound connect attempts for one transport link.
const MAX_CONNECT_ATTEMPTS: usize = 50;
/// Delay between outbound connect attempts.
const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(100);
/// Timeout budget for one individual connect attempt.
const CONNECT_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(1);
/// Timeout budget for one bind-mode accept.
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);
/// Timeout budget for each handshake read/write step.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Performs the identity handshake for one already-connected TCP stream.
pub(crate) async fn perform_handshake(
    local: &LocalProcessIdentity,
    link: &LinkConfig,
    mut stream: TcpStream,
    delay_policy: &dyn LinkDelayPolicy,
) -> Result<TcpStream, TransportError> {
    sleep_if_nonzero(delay_policy.handshake_delay(link)).await;
    write_with_timeout(
        &mut stream,
        &TransportHello::new(local.role, local.instance_id.clone(), link.name.clone()),
        link,
        "handshake_write_hello",
    )
    .await?;
    let hello =
        read_with_timeout::<TransportHello, _>(&mut stream, link, "handshake_read_hello").await?;

    if hello.role() != link.peer_role {
        return Err(TransportError::UnexpectedHelloRole {
            link_name: link.name.clone(),
            expected: link.peer_role,
            actual: hello.role(),
        });
    }
    if hello.instance_id() != link.peer_instance_id {
        return Err(TransportError::UnexpectedHelloInstance {
            link_name: link.name.clone(),
            expected: link.peer_instance_id.clone(),
            actual: hello.instance_id().to_owned(),
        });
    }
    if hello.link_name() != link.name {
        return Err(TransportError::UnexpectedHelloLinkName {
            link_name: link.name.clone(),
            expected: link.name.clone(),
            actual: hello.link_name().to_owned(),
        });
    }

    sleep_if_nonzero(delay_policy.handshake_delay(link)).await;
    write_with_timeout(&mut stream, &TransportReady, link, "handshake_write_ready").await?;
    let _ =
        read_with_timeout::<TransportReady, _>(&mut stream, link, "handshake_read_ready").await?;
    Ok(stream)
}

/// Accepts one inbound transport peer using the production timeout policy.
pub(crate) async fn accept_with_timeout(
    listener: &TcpListener,
    link: &LinkConfig,
    delay_policy: &dyn LinkDelayPolicy,
) -> Result<TcpStream, TransportError> {
    sleep_if_nonzero(delay_policy.accept_delay(link)).await;
    let accept = timeout(ACCEPT_TIMEOUT, listener.accept())
        .await
        .map_err(|_| TransportError::OperationTimedOut {
            link_name: link.name.clone(),
            operation: "accept",
        })?;
    let (stream, _) = accept?;
    Ok(stream)
}

/// Connects to one remote address using the production retry policy.
pub(crate) async fn connect_with_retry(
    addr: SocketAddr,
    link: &LinkConfig,
    delay_policy: &dyn LinkDelayPolicy,
) -> Result<TcpStream, TransportError> {
    connect_with_retry_using_policy(
        addr,
        link,
        delay_policy,
        MAX_CONNECT_ATTEMPTS,
        CONNECT_RETRY_DELAY,
    )
    .await
}

/// Connects to one remote address using an explicit retry budget.
pub(crate) async fn connect_with_retry_using_policy(
    addr: SocketAddr,
    link: &LinkConfig,
    delay_policy: &dyn LinkDelayPolicy,
    attempts: usize,
    retry_delay: Duration,
) -> Result<TcpStream, TransportError> {
    let mut last_error = None;

    for _ in 0..attempts {
        sleep_if_nonzero(delay_policy.connect_delay(link)).await;
        match timeout(CONNECT_ATTEMPT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(error)) => {
                last_error = Some(error);
            }
            Err(_) => {
                return Err(TransportError::OperationTimedOut {
                    link_name: link.name.clone(),
                    operation: "connect",
                });
            }
        }

        if !retry_delay.is_zero() {
            sleep(retry_delay).await;
        }
    }

    match last_error {
        Some(error) => Err(error.into()),
        None => Err(TransportError::InvalidLinkConfig {
            link_name: link.name.clone(),
            reason: "connect retry loop finished without recording an error".to_owned(),
        }),
    }
}

async fn read_with_timeout<M, R>(
    reader: &mut R,
    link: &LinkConfig,
    operation: &'static str,
) -> Result<M, TransportError>
where
    M: protocol_wire::WireMessage,
    R: tokio::io::AsyncRead + Unpin,
{
    timeout(HANDSHAKE_TIMEOUT, read_message_async(reader))
        .await
        .map_err(|_| TransportError::OperationTimedOut {
            link_name: link.name.clone(),
            operation,
        })?
}

async fn write_with_timeout<M, W>(
    writer: &mut W,
    message: &M,
    link: &LinkConfig,
    operation: &'static str,
) -> Result<(), TransportError>
where
    M: protocol_wire::WireMessage,
    W: tokio::io::AsyncWrite + Unpin,
{
    timeout(HANDSHAKE_TIMEOUT, write_message_async(writer, message))
        .await
        .map_err(|_| TransportError::OperationTimedOut {
            link_name: link.name.clone(),
            operation,
        })?
}

async fn sleep_if_nonzero(delay: Duration) {
    if !delay.is_zero() {
        sleep(delay).await;
    }
}
