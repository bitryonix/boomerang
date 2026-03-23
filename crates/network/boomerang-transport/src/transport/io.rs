//! Frame and progress-log I/O helpers.
//!
//! # Why this exists
//! Raw byte I/O and filesystem progress logging change for different reasons than link validation
//! or handshake semantics, so this module keeps those details contained.
//!
//! # Role in the system
//! Used internally by link establishment and reader/writer orchestration, and re-exported for the
//! public frame helpers.

use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::Path,
};

use protocol_wire::{PROTOCOL_FRAME_HEADER_LEN, ProtocolFrame, ProtocolFrameHeader, WireMessage};
use tokio::{
    fs::OpenOptions as AsyncOpenOptions,
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
};

use crate::error::TransportError;

/// Reads one complete [`ProtocolFrame`] from a blocking reader.
///
/// # Why this exists
/// The transport layer needs a deterministic framing boundary before higher layers can decode
/// typed messages or enforce route-specific expectations.
///
/// # Role in the system
/// Used by blocking bridge tests and by typed handshake helpers.
///
/// # Errors
/// Returns a transport error when header bytes are truncated, header decoding fails, the payload
/// length does not fit on the current target, or the payload body is truncated.
///
/// # Examples
/// The transport reader loop repeatedly calls this on a cloned TCP stream:
///
/// ```text
/// let frame = read_frame(&mut stream)?;
/// ```
pub fn read_frame<R>(reader: &mut R) -> Result<ProtocolFrame, TransportError>
where
    R: Read,
{
    let mut header_bytes = [0u8; PROTOCOL_FRAME_HEADER_LEN];
    reader.read_exact(&mut header_bytes)?;
    let header = ProtocolFrameHeader::decode(&header_bytes)?;
    let payload_len =
        usize::try_from(header.payload_len).map_err(|_| TransportError::InvalidLinkConfig {
            link_name: "<frame>".to_owned(),
            reason: "frame payload length does not fit on this target".to_owned(),
        })?;

    // The length comes from the validated frame header, so allocating exactly that many bytes keeps
    // the read boundary aligned with the sender's framing contract.
    let mut payload = vec![0u8; payload_len];
    reader.read_exact(&mut payload)?;
    Ok(ProtocolFrame { header, payload })
}

/// Reads one complete [`ProtocolFrame`] from an async reader.
///
/// # Why this exists
/// The async TCP backend needs the same deterministic frame boundary as the legacy blocking
/// helpers, but without parking a thread on every socket read.
pub async fn read_frame_async<R>(reader: &mut R) -> Result<ProtocolFrame, TransportError>
where
    R: AsyncRead + Unpin,
{
    let mut header_bytes = [0u8; PROTOCOL_FRAME_HEADER_LEN];
    reader.read_exact(&mut header_bytes).await?;
    let header = ProtocolFrameHeader::decode(&header_bytes)?;
    let payload_len =
        usize::try_from(header.payload_len).map_err(|_| TransportError::InvalidLinkConfig {
            link_name: "<frame>".to_owned(),
            reason: "frame payload length does not fit on this target".to_owned(),
        })?;

    let mut payload = vec![0u8; payload_len];
    reader.read_exact(&mut payload).await?;
    Ok(ProtocolFrame { header, payload })
}

/// Writes one complete [`ProtocolFrame`] to a blocking writer and flushes it.
///
/// # Why this exists
/// Frame encoding should stay transport-local so callers do not need to duplicate byte assembly or
/// forget to flush after writing a complete transport unit.
///
/// # Role in the system
/// Used by outbound dispatch and the typed handshake helpers.
///
/// # Errors
/// Returns a transport error if frame encoding fails or if the writer rejects the bytes.
pub fn write_frame<W>(writer: &mut W, frame: &ProtocolFrame) -> Result<(), TransportError>
where
    W: Write,
{
    let bytes = frame.encode()?;
    writer.write_all(&bytes)?;

    // Flushing after a complete frame prevents control-handshake traffic from being buffered
    // indefinitely on small exchanges where the peer is waiting synchronously for the next step.
    writer.flush()?;
    Ok(())
}

/// Writes one complete [`ProtocolFrame`] to an async writer and flushes it.
///
/// # Why this exists
/// The async TCP backend must preserve the exact same frame contract while writing through Tokio
/// socket halves.
pub async fn write_frame_async<W>(
    writer: &mut W,
    frame: &ProtocolFrame,
) -> Result<(), TransportError>
where
    W: AsyncWrite + Unpin,
{
    let bytes = frame.encode()?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

/// Reads one typed wire message from a blocking reader.
///
/// # Why this exists
/// Handshake code works with typed control messages rather than raw frames, so it needs a helper
/// that composes frame reading with typed decode in one place.
///
/// # Errors
/// Returns a transport error when frame reading or typed decode fails.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn read_message<M, R>(reader: &mut R) -> Result<M, TransportError>
where
    M: WireMessage,
    R: Read,
{
    let frame = read_frame(reader)?;

    // Re-encoding the parsed frame lets us reuse the wire contract's checked typed-decode path
    // without duplicating tag/version validation logic in the transport crate.
    let bytes = frame.encode()?;
    Ok(M::decode_frame_checked(&bytes)?)
}

/// Reads one typed wire message from an async reader.
pub(crate) async fn read_message_async<M, R>(reader: &mut R) -> Result<M, TransportError>
where
    M: WireMessage,
    R: AsyncRead + Unpin,
{
    let frame = read_frame_async(reader).await?;
    let bytes = frame.encode()?;
    Ok(M::decode_frame_checked(&bytes)?)
}

/// Writes one typed wire message to a blocking writer.
///
/// # Why this exists
/// Handshake code starts from typed control messages, so this helper keeps their frame encoding at
/// the transport boundary instead of spreading it across socket code.
///
/// # Errors
/// Returns a transport error when message encoding or writing fails.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn write_message<M, W>(writer: &mut W, message: &M) -> Result<(), TransportError>
where
    M: WireMessage,
    W: Write,
{
    let bytes = message.encode_frame()?;
    writer.write_all(&bytes)?;
    writer.flush()?;
    Ok(())
}

/// Writes one typed wire message to an async writer.
pub(crate) async fn write_message_async<M, W>(
    writer: &mut W,
    message: &M,
) -> Result<(), TransportError>
where
    M: WireMessage,
    W: AsyncWrite + Unpin,
{
    let bytes = message.encode_frame()?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

/// Appends one operational progress line to a log file, creating parent directories as needed.
///
/// # Why this exists
/// Startup and handshake progress is valuable when operators debug multi-process bootstrapping, so
/// transport initialization records coarse milestones even before higher-level logging is wired.
///
/// # Errors
/// Returns a transport error when directories cannot be created or the log file cannot be opened
/// or appended.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn append_progress_line(path: &Path, line: &str) -> Result<(), TransportError> {
    if let Some(parent) = path.parent() {
        // Creating the parent directory on demand keeps per-process state roots from requiring a
        // separate provisioning step before transport startup can begin.
        std::fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{line}")?;
    Ok(())
}

/// Appends one operational progress line using async filesystem helpers.
pub(crate) async fn append_progress_line_async(
    path: &Path,
    line: &str,
) -> Result<(), TransportError> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let mut file = AsyncOpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;
    file.write_all(format!("{line}\n").as_bytes()).await?;
    file.flush().await?;
    Ok(())
}
