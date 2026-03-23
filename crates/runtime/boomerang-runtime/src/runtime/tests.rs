//! Unit tests for runtime helpers that do not need the full process graph.

use std::{
    fs,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::PathBuf,
    sync::{Arc, Mutex},
};

use boomerang_config::{
    BoomerangNetworkConfig, ProcessBootstrap, ProcessConfig, ProcessRoutes, WithdrawalConfig,
    load_published_process_identity, published_identity_path,
};
use boomerang_transport::{
    InboundFrame, LinkConfig, LinkWriters, OutboundFrame, TransportError, TransportInterface,
    TransportSession, TransportSessionFuture,
};
use protocol::constructs::BitcoinCoreAuth;
use protocol::magic::SETUP_NISO_OUTPUT_2_MAGIC;
use protocol::messages::setup::from_niso::to_user::SetupNisoOutput2;
use protocol_wire::{MessageTag, ProtocolFrame, WireMessage, control::TransportRole};

use crate::roles::build_role_runtime;

use super::{
    codec::decode_frame, context::RuntimeContext, identity::persist_runtime_published_identity,
    progress::append_progress_line, service::run_process_with_transport,
};

type RecordedEstablishCall = (TransportRole, String, usize, PathBuf);

struct ClosedSession;

impl TransportSession for ClosedSession {
    fn send(
        &self,
        _outbound: &OutboundFrame,
        _local_role: TransportRole,
    ) -> Result<(), TransportError> {
        Err(TransportError::InboundChannelClosed)
    }

    fn recv(&mut self) -> Result<InboundFrame, TransportError> {
        Err(TransportError::InboundChannelClosed)
    }

    fn shutdown(
        self: Box<Self>,
        _runtime_handle: &tokio::runtime::Handle,
    ) -> Result<(), TransportError> {
        Ok(())
    }
}

struct RecordingTransport {
    established: Arc<Mutex<Vec<RecordedEstablishCall>>>,
}

impl TransportInterface for RecordingTransport {
    fn establish_session<'a>(
        &'a self,
        local: &'a boomerang_transport::LocalProcessIdentity,
        links: &'a [LinkConfig],
        progress_path: &'a std::path::Path,
    ) -> TransportSessionFuture<'a, Result<Box<dyn TransportSession>, TransportError>> {
        Box::pin(async move {
            self.established
                .lock()
                .expect("recording transport mutex should not be poisoned")
                .push((
                    local.role,
                    local.instance_id.clone(),
                    links.len(),
                    progress_path.to_path_buf(),
                ));
            Ok::<Box<dyn TransportSession>, TransportError>(Box::new(ClosedSession))
        })
    }
}

struct IdentityCheckingTransport {
    expected_identity_path: PathBuf,
}

impl TransportInterface for IdentityCheckingTransport {
    fn establish_session<'a>(
        &'a self,
        _local: &'a boomerang_transport::LocalProcessIdentity,
        _links: &'a [LinkConfig],
        _progress_path: &'a std::path::Path,
    ) -> TransportSessionFuture<'a, Result<Box<dyn TransportSession>, TransportError>> {
        Box::pin(async move {
            if !self.expected_identity_path.exists() {
                return Err(TransportError::InvalidLinkConfig {
                    link_name: "__identity-check__".to_owned(),
                    reason: "published identity artifact was missing before transport startup"
                        .to_owned(),
                });
            }

            Err(TransportError::InvalidLinkConfig {
                link_name: "__identity-check__".to_owned(),
                reason: "stop after verifying identity publication order".to_owned(),
            })
        })
    }
}

fn sample_niso_process_config(state_dir: PathBuf) -> ProcessConfig {
    ProcessConfig {
        role: TransportRole::Niso,
        instance_id: "niso-1".to_owned(),
        state_dir,
        bootstrap: ProcessBootstrap::Niso {},
        routes: ProcessRoutes::Niso {
            peer_link: "niso-peer".to_owned(),
        },
        links: vec![LinkConfig {
            name: "niso-peer".to_owned(),
            peer_role: TransportRole::Peer,
            peer_instance_id: "peer-1".to_owned(),
            bind_addr: None,
            connect_addr: Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1))),
        }],
        boomerang: BoomerangNetworkConfig::default(),
        withdrawal: WithdrawalConfig::default(),
    }
}

fn sample_wt_process_config(state_dir: PathBuf) -> ProcessConfig {
    ProcessConfig {
        role: TransportRole::Wt,
        instance_id: "wt-1".to_owned(),
        state_dir,
        bootstrap: ProcessBootstrap::Wt {
            rpc_client_url: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 18443),
            rpc_client_auth: BitcoinCoreAuth::None,
        },
        routes: ProcessRoutes::Wt {
            peer_links: std::collections::BTreeMap::new(),
            sar_links: std::collections::BTreeMap::new(),
        },
        links: Vec::new(),
        boomerang: BoomerangNetworkConfig::default(),
        withdrawal: WithdrawalConfig::default(),
    }
}

fn sample_sar_process_config(state_dir: PathBuf) -> ProcessConfig {
    ProcessConfig {
        role: TransportRole::Sar,
        instance_id: "sar-1".to_owned(),
        state_dir,
        bootstrap: ProcessBootstrap::Sar {},
        routes: ProcessRoutes::Sar {
            peer_link: "sar-peer".to_owned(),
            wt_link: "sar-wt".to_owned(),
        },
        links: Vec::new(),
        boomerang: BoomerangNetworkConfig::default(),
        withdrawal: WithdrawalConfig::default(),
    }
}

#[test]
fn decode_frame_rejects_wrong_tag() {
    let frame = ProtocolFrame::new(
        MessageTag::SetupNisoOutput2,
        SetupNisoOutput2::new(SETUP_NISO_OUTPUT_2_MAGIC)
            .encode_payload()
            .expect("setup output payload should encode"),
    )
    .expect("frame construction should succeed");

    let error = decode_frame::<
        protocol::messages::withdrawal::from_niso::to_user::WithdrawalNisoOutput1,
    >(&frame)
    .expect_err("decoding the wrong tag should fail");

    assert!(matches!(
        error,
        crate::error::RuntimeError::WireDecode(
            protocol_wire::WireDecodeError::UnexpectedMessageTag { .. }
        )
    ));
}

#[test]
fn recv_any_uses_buffered_frames_before_channel() {
    let (_tx, rx) = tokio::sync::mpsc::channel(1);
    let mut context = RuntimeContext::new(
        TransportRole::Peer,
        &[MessageTag::SetupNisoOutput2],
        rx,
        LinkWriters::new(),
        std::env::temp_dir().join("runtime-context-progress.log"),
    );
    context.push_pending_for_test(InboundFrame {
        link_name: "peer-1".to_owned(),
        frame: ProtocolFrame::new(
            MessageTag::SetupNisoOutput2,
            SetupNisoOutput2::new(SETUP_NISO_OUTPUT_2_MAGIC)
                .encode_payload()
                .expect("setup output payload should encode"),
        )
        .expect("frame construction should succeed"),
    });

    let inbound = context
        .recv_any()
        .expect("pending frame should be returned");
    assert_eq!(inbound.link_name, "peer-1");
}

#[test]
fn append_progress_line_creates_parent_directories() {
    let path = std::env::temp_dir()
        .join("boomerang-runtime-progress-tests")
        .join("nested")
        .join("progress.log");
    append_progress_line(&path, "stage=test").expect("progress helper should create parents");

    let written = std::fs::read_to_string(path).expect("progress log should be readable");
    assert!(written.contains("stage=test"));
}

#[test]
fn run_process_with_transport_uses_supplied_transport_interface() {
    let state_dir = std::env::temp_dir().join("boomerang-runtime-transport-interface");
    let config = sample_niso_process_config(state_dir.clone());
    let established = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        established: Arc::clone(&established),
    };

    run_process_with_transport(config, &transport)
        .expect("closed transport sessions should end the default role loop cleanly");

    let established = established
        .lock()
        .expect("recording transport mutex should not be poisoned");
    assert_eq!(established.len(), 1);
    assert_eq!(established[0].0, TransportRole::Niso);
    assert_eq!(established[0].1, "niso-1");
    assert_eq!(established[0].2, 1);
    assert!(established[0].3.ends_with("progress.log"));

    let _ = std::fs::remove_dir_all(state_dir);
}

#[test]
fn wt_runtime_persists_only_public_identity_artifact() {
    let state_dir = std::env::temp_dir().join("boomerang-runtime-wt-public-identity");
    let config = sample_wt_process_config(state_dir.clone());
    let runtime =
        build_role_runtime(&config).expect("WT runtime should build without external ids");

    let published = persist_runtime_published_identity(&config, runtime.as_ref())
        .expect("WT runtime should publish a public identity artifact");
    assert!(published);

    let published = load_published_process_identity(&published_identity_path(&state_dir))
        .expect("WT public identity artifact should load");
    assert_eq!(published.role(), TransportRole::Wt);

    let _ = fs::remove_dir_all(state_dir);
}

#[test]
fn sar_runtime_persists_only_public_identity_artifact() {
    let state_dir = std::env::temp_dir().join("boomerang-runtime-sar-public-identity");
    let config = sample_sar_process_config(state_dir.clone());
    let runtime =
        build_role_runtime(&config).expect("SAR runtime should build without external ids");

    let published = persist_runtime_published_identity(&config, runtime.as_ref())
        .expect("SAR runtime should publish a public identity artifact");
    assert!(published);

    let published = load_published_process_identity(&published_identity_path(&state_dir))
        .expect("SAR public identity artifact should load");
    assert_eq!(published.role(), TransportRole::Sar);

    let _ = fs::remove_dir_all(state_dir);
}

#[test]
fn non_identity_roles_do_not_publish_identity_artifacts() {
    let state_dir = std::env::temp_dir().join("boomerang-runtime-niso-public-identity");
    let config = sample_niso_process_config(state_dir.clone());
    let runtime =
        build_role_runtime(&config).expect("NISO runtime should build without identity artifacts");

    let published = persist_runtime_published_identity(&config, runtime.as_ref())
        .expect("non-identity roles should skip publication cleanly");
    assert!(!published);
    assert!(!published_identity_path(&state_dir).exists());

    let _ = fs::remove_dir_all(state_dir);
}

#[test]
fn wt_run_publishes_public_identity_before_transport_startup() {
    let state_dir = std::env::temp_dir().join("boomerang-runtime-wt-identity-order");
    let config = sample_wt_process_config(state_dir.clone());
    let published_path = published_identity_path(&state_dir);
    let transport = IdentityCheckingTransport {
        expected_identity_path: published_path.clone(),
    };

    let error = run_process_with_transport(config, &transport)
        .expect_err("test transport should stop once publication order is verified");

    assert!(matches!(
        error,
        crate::error::RuntimeError::Transport(TransportError::InvalidLinkConfig { reason, .. })
            if reason == "stop after verifying identity publication order"
    ));

    let published = load_published_process_identity(&published_path)
        .expect("WT public identity artifact should already exist before transport starts");
    assert_eq!(published.role(), TransportRole::Wt);

    let _ = fs::remove_dir_all(state_dir);
}
