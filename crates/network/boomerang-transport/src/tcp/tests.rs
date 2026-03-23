//! Tests for the TCP transport adapter layer.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use protocol_wire::{
    MessageTag, ProtocolFrame, WireMessage,
    control::{TransportReady, TransportRole},
};

use crate::{TransportError, TransportSession, tcp::TcpTransportSession};

#[test]
fn tcp_transport_session_receives_from_its_inbound_queue() {
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    let mut session = TcpTransportSession::new(rx, crate::LinkWriters::new());
    tx.blocking_send(crate::InboundFrame {
        link_name: "peer-link".to_owned(),
        frame: ProtocolFrame::new(
            MessageTag::TransportReady,
            TransportReady
                .encode_payload()
                .expect("payload should encode"),
        )
        .expect("transport-ready frame should encode"),
    })
    .expect("test sender should stay connected");

    let inbound = session.recv().expect("session should receive queued frame");
    assert_eq!(inbound.link_name, "peer-link");
    assert_eq!(
        inbound
            .frame
            .message_tag()
            .expect("message tag should decode"),
        MessageTag::TransportReady
    );
}

#[test]
fn tcp_transport_session_reports_closed_inbound_queue() {
    let (tx, rx) = tokio::sync::mpsc::channel::<crate::InboundFrame>(1);
    let mut session = TcpTransportSession::new(rx, crate::LinkWriters::new());
    drop(tx);

    let error = session
        .recv()
        .expect_err("closed channels should map to a transport error");
    assert!(matches!(error, TransportError::InboundChannelClosed));
}

#[test]
fn tcp_transport_session_reuses_compatibility_send_logic() {
    let outbound = crate::OutboundFrame::new(
        "missing-link",
        ProtocolFrame::new(MessageTag::TransportReady, Vec::new())
            .expect("transport-ready frame should encode"),
    );
    let session = TcpTransportSession::new(
        tokio::sync::mpsc::channel::<crate::InboundFrame>(1).1,
        crate::LinkWriters::new(),
    );

    let error = session
        .send(&outbound, TransportRole::Wt)
        .expect_err("unknown routes should still use the compatibility error path");
    assert!(matches!(
        error,
        TransportError::UnknownLink(link_name, TransportRole::Wt) if link_name == "missing-link"
    ));
}

#[test]
fn tcp_transport_session_shutdown_flushes_queued_outbound_frames() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime should build");

    runtime.block_on(async {
        let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel::<crate::InboundFrame>(1);
        drop(inbound_tx);

        let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::channel(1);
        let flushed = Arc::new(AtomicBool::new(false));
        let flushed_for_task = Arc::clone(&flushed);
        let task_handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if outbound_rx.recv().await.is_some() {
                flushed_for_task.store(true, Ordering::SeqCst);
            }
        });

        let mut writers = crate::LinkWriters::new();
        writers.insert("link-1".to_owned(), outbound_tx);
        let session = TcpTransportSession::from_established(crate::EstablishedLinks {
            inbound_rx,
            writers,
            task_handles: vec![task_handle],
        });

        let handle = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            let outbound = crate::OutboundFrame::new(
                "link-1",
                ProtocolFrame::new(MessageTag::TransportReady, Vec::new())
                    .expect("transport-ready frame should encode"),
            );
            session
                .send(&outbound, TransportRole::Wt)
                .expect("queued outbound frame should send");
            Box::new(session)
                .shutdown(&handle)
                .expect("shutdown should wait for the writer task to drain");
        })
        .await
        .expect("blocking transport task should finish");

        assert!(
            flushed.load(Ordering::SeqCst),
            "queued outbound frames should flush before shutdown returns"
        );
    });
}
