//! Tests for transport leaf modules.

use std::{
    io::{Cursor, ErrorKind},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use protocol_wire::{
    MessageTag, ProtocolFrame,
    control::{TransportReady, TransportRole},
};

use crate::{
    NoDelayLinkDelayPolicy,
    transport::{
        handshake::{connect_with_retry_using_policy, perform_handshake},
        io::{append_progress_line, read_message, write_message},
        model::{LinkConfig, LinkWriters, LocalProcessIdentity, OutboundFrame},
        service::{establish_links, write_outbound_frame},
    },
};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime should build")
}

async fn bind_ephemeral_listener() -> Option<tokio::net::TcpListener> {
    match tokio::net::TcpListener::bind(localhost_addr(0)).await {
        Ok(listener) => Some(listener),
        Err(error) if error.kind() == ErrorKind::PermissionDenied => None,
        Err(error) => panic!("ephemeral localhost listener should bind in tests: {error}"),
    }
}

/// Creates a local identity for tests.
fn sample_local(role: TransportRole, instance_id: &str) -> LocalProcessIdentity {
    LocalProcessIdentity::new(role, instance_id)
}

/// Creates one link config for tests.
fn sample_link(
    link_name: &str,
    peer_role: TransportRole,
    peer_instance_id: &str,
    bind_addr: Option<SocketAddr>,
    connect_addr: Option<SocketAddr>,
) -> LinkConfig {
    LinkConfig {
        name: link_name.to_owned(),
        peer_role,
        peer_instance_id: peer_instance_id.to_owned(),
        bind_addr,
        connect_addr,
    }
}

/// Returns a unique temporary path under the system temp directory.
fn unique_temp_path(stem: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{stem}-{nanos}.log"))
}

#[test]
fn local_process_identity_new_preserves_fields() {
    let local = sample_local(TransportRole::Wt, "wt-1");
    assert_eq!(local.role, TransportRole::Wt);
    assert_eq!(local.instance_id, "wt-1");
}

#[test]
fn link_config_rejects_empty_name() {
    let link = sample_link(
        "",
        TransportRole::Peer,
        "peer-1",
        None,
        Some(localhost_addr(1)),
    );
    assert!(link.validate().is_err());
}

#[test]
fn link_config_rejects_missing_address_mode() {
    let link = sample_link("link-1", TransportRole::Peer, "peer-1", None, None);
    assert!(link.validate().is_err());
}

#[test]
fn link_config_rejects_empty_peer_instance() {
    let link = sample_link(
        "link-1",
        TransportRole::Peer,
        "",
        None,
        Some(localhost_addr(1)),
    );
    assert!(link.validate().is_err());
}

#[test]
fn outbound_frame_new_preserves_fields() {
    let frame = ProtocolFrame::new(MessageTag::TransportReady, Vec::new())
        .expect("transport-ready frame should encode");
    let outbound = OutboundFrame::new("link-1", frame.clone());
    assert_eq!(outbound.link_name, "link-1");
    assert_eq!(outbound.frame, frame);
}

#[test]
fn outbound_frame_from_message_encodes_control_message() {
    let outbound =
        OutboundFrame::from_message("link-1", &TransportReady).expect("control message encodes");
    assert_eq!(outbound.link_name, "link-1");
    assert_eq!(
        outbound
            .frame
            .message_tag()
            .expect("message tag should decode from frame"),
        MessageTag::TransportReady
    );
}

#[test]
fn append_progress_line_appends_lines() {
    let path = unique_temp_path("boomerang-transport-progress");
    append_progress_line(&path, "line-1").expect("first line should append");
    append_progress_line(&path, "line-2").expect("second line should append");

    let text = std::fs::read_to_string(&path).expect("progress log should be readable");
    assert!(text.contains("line-1"));
    assert!(text.contains("line-2"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn read_and_write_frame_round_trip() {
    let mut buffer = Vec::new();
    let frame = ProtocolFrame::new(MessageTag::TransportReady, Vec::new())
        .expect("transport-ready frame should encode");
    crate::transport::write_frame(&mut buffer, &frame).expect("frame should write");

    let mut cursor = Cursor::new(buffer);
    let received = crate::transport::read_frame(&mut cursor).expect("frame should read");
    assert_eq!(
        received.message_tag().expect("tag should decode"),
        MessageTag::TransportReady
    );
}

#[test]
fn read_and_write_message_round_trip() {
    let mut buffer = Vec::new();
    write_message(&mut buffer, &TransportReady).expect("typed control message should write");

    let mut cursor = Cursor::new(buffer);
    let received =
        read_message::<TransportReady, _>(&mut cursor).expect("typed control message should read");
    assert_eq!(received, TransportReady);
}

#[test]
fn connect_with_retry_using_policy_establishes_connection() {
    let runtime = runtime();
    runtime.block_on(async {
        let Some(listener) = bind_ephemeral_listener().await else {
            return;
        };
        let addr = listener
            .local_addr()
            .expect("listener should have an address");
        let link = sample_link("wt-peer-1", TransportRole::Peer, "peer-1", None, Some(addr));

        let accept = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.expect("listener should accept");
        });

        let stream = connect_with_retry_using_policy(
            addr,
            &link,
            &NoDelayLinkDelayPolicy,
            1,
            Duration::ZERO,
        )
        .await
        .expect("connect should succeed while listener is active");
        drop(stream);
        accept.await.expect("accept task should finish");
    });
}

#[test]
fn connect_with_retry_using_policy_returns_error_when_peer_is_absent() {
    let runtime = runtime();
    runtime.block_on(async {
        let Some(listener) = bind_ephemeral_listener().await else {
            return;
        };
        let addr = listener
            .local_addr()
            .expect("listener should have an address");
        drop(listener);
        let link = sample_link("wt-peer-1", TransportRole::Peer, "peer-1", None, Some(addr));

        let error = connect_with_retry_using_policy(
            addr,
            &link,
            &NoDelayLinkDelayPolicy,
            1,
            Duration::ZERO,
        )
        .await
        .expect_err("connect should fail after listener is dropped");
        assert!(matches!(error, crate::TransportError::Io(_)));
    });
}

#[test]
fn perform_handshake_round_trips_expected_identity() {
    let runtime = runtime();
    runtime.block_on(async {
        let Some(listener) = bind_ephemeral_listener().await else {
            return;
        };
        let addr = listener
            .local_addr()
            .expect("listener should have an address");

        let left_local = sample_local(TransportRole::Wt, "wt-1");
        let right_local = sample_local(TransportRole::Peer, "peer-1");
        let left_link = sample_link("wt-peer-1", TransportRole::Peer, "peer-1", Some(addr), None);
        let right_link = sample_link("wt-peer-1", TransportRole::Wt, "wt-1", None, Some(addr));

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("listener should accept");
            perform_handshake(&left_local, &left_link, stream, &NoDelayLinkDelayPolicy)
                .await
                .expect("handshake should succeed")
        });

        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("client should connect to listener");
        let right_stream =
            perform_handshake(&right_local, &right_link, stream, &NoDelayLinkDelayPolicy)
                .await
                .expect("handshake should succeed");
        drop(right_stream);
        drop(server.await.expect("server handshake task should finish"));
    });
}

#[test]
fn write_outbound_frame_rejects_unknown_link() {
    let writers = LinkWriters::new();
    let frame = ProtocolFrame::new(MessageTag::TransportReady, Vec::new())
        .expect("transport-ready frame should encode");
    let outbound = OutboundFrame::new("missing-link", frame);

    let error = write_outbound_frame(&writers, &outbound, TransportRole::Wt)
        .expect_err("unknown routes should fail");
    assert!(matches!(error, crate::TransportError::UnknownLink(_, _)));
}

#[test]
fn write_outbound_frame_sends_bytes_to_registered_writer() {
    let runtime = runtime();
    runtime.block_on(async {
        let Some(listener) = bind_ephemeral_listener().await else {
            return;
        };
        let addr = listener
            .local_addr()
            .expect("listener should have an address");

        let reader = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("listener should accept");
            let mut bytes = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut bytes)
                .await
                .expect("reader should collect outbound bytes");
            bytes
        });

        let mut writers = LinkWriters::new();
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        writers.insert("link-1".to_owned(), tx);
        let mut stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("client should connect to listener");
        let writer = tokio::spawn(async move {
            if let Some(frame) = rx.recv().await {
                crate::transport::io::write_frame_async(&mut stream, &frame)
                    .await
                    .expect("frame should write");
            }
        });

        let frame = ProtocolFrame::new(MessageTag::TransportReady, Vec::new())
            .expect("transport-ready frame should encode");
        let outbound = OutboundFrame::new("link-1", frame.clone());
        write_outbound_frame(&writers, &outbound, TransportRole::Wt)
            .expect("registered route should write");
        drop(writers);
        writer.await.expect("writer task should finish");

        let bytes = reader.await.expect("reader task should finish");
        let mut cursor = Cursor::new(bytes);
        let received = crate::transport::read_frame(&mut cursor).expect("frame should decode");
        assert_eq!(received, frame);
    });
}

#[test]
fn establish_links_performs_bidirectional_handshake() {
    let runtime = runtime();
    runtime.block_on(async {
        let Some(listener) = bind_ephemeral_listener().await else {
            return;
        };
        let addr = listener
            .local_addr()
            .expect("listener should have an address");
        drop(listener);

        let progress_root = unique_temp_path("boomerang-transport-establish");
        let wt_local = sample_local(TransportRole::Wt, "wt-1");
        let peer_local = sample_local(TransportRole::Peer, "peer-1");
        let wt_links = vec![sample_link(
            "wt-peer-1",
            TransportRole::Peer,
            "peer-1",
            Some(addr),
            None,
        )];
        let peer_links = vec![sample_link(
            "wt-peer-1",
            TransportRole::Wt,
            "wt-1",
            None,
            Some(addr),
        )];

        let wt_progress = progress_root.clone();
        let wt_task = tokio::spawn(async move {
            establish_links(&wt_local, &wt_links, wt_progress.as_path()).await
        });
        let peer_links = establish_links(&peer_local, &peer_links, progress_root.as_path())
            .await
            .expect("peer links should establish");
        let wt_links = wt_task
            .await
            .expect("wt link task should finish")
            .expect("wt links should establish");

        assert_eq!(wt_links.writers.len(), 1);
        assert_eq!(peer_links.writers.len(), 1);

        let _ = std::fs::remove_file(progress_root);
    });
}

fn localhost_addr(offset: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 20_000 + offset))
}
