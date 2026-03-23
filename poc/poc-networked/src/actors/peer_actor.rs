use std::{collections::BTreeSet, net::SocketAddrV4, path::PathBuf, str::FromStr, sync::Arc};

use bitcoin::{
    Address, Amount, PublicKey, XOnlyPublicKey,
    key::{Keypair, Secp256k1, rand::thread_rng},
};
use bitcoincore_rpc::{Auth, Client, RpcApi, json::AddressType};
use boomerang_config::{BoomerangNetworkConfig, WithdrawalConfig};
use boomlet::Boomlet;
use iso::Iso;
use miniscript::descriptor::Tr;
use niso::Niso;
use peer::Peer;
use phone::Phone;
use protocol::{
    constructs::{PeerId, SarId, WtPeerId},
    messages::{BranchingMessage2, Message, MetadataAttachedMessage, Parcel},
    messages::{
        setup::from_user::to_user::SetupUserPeersOutOfBandMessage1,
        withdrawal::from_wt::{
            to_niso::{WithdrawalWtNisoMessage1, WithdrawalWtNisoMessage2},
            to_non_initiator_niso::{
                WithdrawalWtNonInitiatorNisoMessage1, WithdrawalWtNonInitiatorNisoMessage2,
                WithdrawalWtNonInitiatorNisoMessage3,
            },
        },
    },
};
use st::St;
use tokio::{
    sync::{Barrier, mpsc},
    task::JoinHandle,
    time::{Duration, sleep},
};
use tracing::{debug, info};

use crate::{
    envelopes::{
        PeerToPeerEnvelope, PeerToSarEnvelope, PeerToWtEnvelope, SarToPeerEnvelope,
        WtToPeerEnvelope,
    },
    local_actor::{EntityHandle, spawn_entity},
    transport::PeerDirectory,
};

const LOCAL_ENTITY_CHANNEL_CAPACITY: usize = 64;

pub struct PeerEntities {
    pub peer: Peer,
    pub iso: Iso,
    pub niso: Niso,
    pub boomlet: Boomlet,
    pub boomletwo: Boomlet,
    pub phone: Phone,
    pub st: St,
}

pub struct PeerPorts {
    pub peer_to_wt_tx: mpsc::Sender<PeerToWtEnvelope>,
    pub wt_to_peer_rx: mpsc::Receiver<WtToPeerEnvelope>,
    pub peer_to_sar_tx: mpsc::Sender<PeerToSarEnvelope>,
    pub sar_to_peer_rx: mpsc::Receiver<SarToPeerEnvelope>,
    pub peer_to_peer_tx: mpsc::Sender<PeerToPeerEnvelope>,
    pub peer_to_peer_rx: mpsc::Receiver<PeerToPeerEnvelope>,
}

pub struct InitiatorRuntime {
    pub rpc_address: SocketAddrV4,
    pub cookie_path: PathBuf,
}

pub struct PeerActor {
    index: usize,
    total_peers: usize,
    sar_id: SarId,
    boomerang_config: BoomerangNetworkConfig,
    withdrawal_config: WithdrawalConfig,
    peer: EntityHandle<Peer>,
    iso: EntityHandle<Iso>,
    niso: EntityHandle<Niso>,
    boomlet: EntityHandle<Boomlet>,
    boomletwo: EntityHandle<Boomlet>,
    phone: EntityHandle<Phone>,
    st: EntityHandle<St>,
    peer_to_wt_tx: mpsc::Sender<PeerToWtEnvelope>,
    wt_to_peer_rx: mpsc::Receiver<WtToPeerEnvelope>,
    peer_to_sar_tx: mpsc::Sender<PeerToSarEnvelope>,
    sar_to_peer_rx: mpsc::Receiver<SarToPeerEnvelope>,
    peer_to_peer_tx: mpsc::Sender<PeerToPeerEnvelope>,
    peer_to_peer_rx: mpsc::Receiver<PeerToPeerEnvelope>,
    peer_directory: PeerDirectory,
    peer_registration_barrier: Arc<Barrier>,
    setup_barrier: Arc<Barrier>,
    initiator_runtime: Option<InitiatorRuntime>,
}

impl PeerActor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        index: usize,
        total_peers: usize,
        sar_id: SarId,
        boomerang_config: BoomerangNetworkConfig,
        withdrawal_config: WithdrawalConfig,
        entities: PeerEntities,
        ports: PeerPorts,
        peer_directory: PeerDirectory,
        peer_registration_barrier: Arc<Barrier>,
        setup_barrier: Arc<Barrier>,
        initiator_runtime: Option<InitiatorRuntime>,
    ) -> Self {
        let PeerEntities {
            peer,
            iso,
            niso,
            boomlet,
            boomletwo,
            phone,
            st,
        } = entities;
        let PeerPorts {
            peer_to_wt_tx,
            wt_to_peer_rx,
            peer_to_sar_tx,
            sar_to_peer_rx,
            peer_to_peer_tx,
            peer_to_peer_rx,
        } = ports;
        Self {
            index,
            total_peers,
            sar_id,
            boomerang_config,
            withdrawal_config,
            peer: spawn_entity("peer", peer, LOCAL_ENTITY_CHANNEL_CAPACITY),
            iso: spawn_entity("iso", iso, LOCAL_ENTITY_CHANNEL_CAPACITY),
            niso: spawn_entity("niso", niso, LOCAL_ENTITY_CHANNEL_CAPACITY),
            boomlet: spawn_entity("boomlet", boomlet, LOCAL_ENTITY_CHANNEL_CAPACITY),
            boomletwo: spawn_entity("boomletwo", boomletwo, LOCAL_ENTITY_CHANNEL_CAPACITY),
            phone: spawn_entity("phone", phone, LOCAL_ENTITY_CHANNEL_CAPACITY),
            st: spawn_entity("st", st, LOCAL_ENTITY_CHANNEL_CAPACITY),
            peer_to_wt_tx,
            wt_to_peer_rx,
            peer_to_sar_tx,
            sar_to_peer_rx,
            peer_to_peer_tx,
            peer_to_peer_rx,
            peer_directory,
            peer_registration_barrier,
            setup_barrier,
            initiator_runtime,
        }
    }

    pub async fn run(mut self) {
        self.run_setup().await;
        self.setup_barrier.wait().await;
        self.run_withdrawal().await;
    }

    fn peer_number(&self) -> usize {
        self.index + 1
    }

    fn other_peer_count(&self) -> usize {
        self.total_peers - 1
    }

    fn role_name(&self) -> &'static str {
        if self.initiator_runtime.is_some() {
            "initiator"
        } else {
            "non-initiator"
        }
    }

    fn log_setup_step(&self, step: &str) {
        info!("PeerActor {}: setup - {step}", self.peer_number());
    }

    fn log_withdrawal_step(&self, step: &str) {
        info!("PeerActor {}: withdrawal - {step}", self.peer_number());
    }

    async fn own_peer_id(&self) -> PeerId {
        self.niso
            .call(|entity| {
                entity
                    .get_peer_id()
                    .expect("PeerActor: missing local peer id")
            })
            .await
    }

    async fn own_wt_peer_id(&self) -> WtPeerId {
        self.niso
            .call(|entity| {
                entity
                    .get_wt_peer_id()
                    .expect("PeerActor: missing local wt peer id")
            })
            .await
    }

    fn single_sar_parcel<M: Message>(&self, message: M) -> Parcel<SarId, M> {
        Parcel::new(vec![MetadataAttachedMessage::new(
            self.sar_id.clone(),
            message,
        )])
    }

    async fn send_to_wt(&self, envelope: PeerToWtEnvelope) {
        self.peer_to_wt_tx
            .send(envelope)
            .await
            .expect("PeerActor: WT channel closed");
    }

    async fn recv_from_wt(&mut self) -> WtToPeerEnvelope {
        self.wt_to_peer_rx
            .recv()
            .await
            .expect("PeerActor: WT channel closed")
    }

    async fn send_to_sar(&self, envelope: PeerToSarEnvelope) {
        self.peer_to_sar_tx
            .send(envelope)
            .await
            .expect("PeerActor: SAR channel closed");
    }

    async fn recv_from_sar(&mut self) -> SarToPeerEnvelope {
        self.sar_to_peer_rx
            .recv()
            .await
            .expect("PeerActor: SAR channel closed")
    }

    async fn register_in_peer_directory(&self) {
        let own_peer_id = self.own_peer_id().await;
        self.peer_directory
            .register(own_peer_id, self.peer_to_peer_tx.clone())
            .await;
        self.peer_registration_barrier.wait().await;
    }

    async fn broadcast_out_of_band_message(&self, message: SetupUserPeersOutOfBandMessage1) {
        let own_peer_id = self.own_peer_id().await;
        let inboxes = self.peer_directory.snapshot().await;
        for (peer_id, sender) in inboxes {
            if peer_id == own_peer_id {
                continue;
            }

            sender
                .send(PeerToPeerEnvelope::SetupUserPeersOutOfBandMessage1 {
                    sender_peer_id: own_peer_id.clone(),
                    msg: message.clone(),
                })
                .await
                .expect("PeerActor: peer out-of-band channel closed");
        }
    }

    async fn recv_merged_out_of_band_message(&mut self) -> SetupUserPeersOutOfBandMessage1 {
        let mut received = Vec::with_capacity(self.other_peer_count());
        let mut senders = BTreeSet::new();
        while received.len() < self.other_peer_count() {
            match self
                .peer_to_peer_rx
                .recv()
                .await
                .expect("PeerActor: peer inbox closed")
            {
                PeerToPeerEnvelope::SetupUserPeersOutOfBandMessage1 {
                    sender_peer_id,
                    msg,
                } => {
                    assert!(
                        senders.insert(sender_peer_id),
                        "PeerActor: duplicate out-of-band sender"
                    );
                    received.push(msg);
                }
                _ => panic!("PeerActor: unexpected peer envelope during out-of-band exchange"),
            }
        }

        let mut iter = received.into_iter();
        let mut merged = iter
            .next()
            .expect("PeerActor: expected at least one out-of-band message");
        merged.merge(iter.collect());
        merged
    }

    async fn send_peer_parcel<M, F>(&self, parcel: Parcel<PeerId, M>, wrap: F)
    where
        M: Message,
        F: Fn(PeerId, M) -> PeerToPeerEnvelope,
    {
        let sender_peer_id = self.own_peer_id().await;
        for item in parcel.open() {
            let (target_peer_id, message) = item.into_parts();
            self.peer_directory
                .send(&target_peer_id, wrap(sender_peer_id.clone(), message))
                .await;
        }
    }

    async fn recv_peer_parcel<M, F>(&mut self, unwrap: F) -> Parcel<PeerId, M>
    where
        M: Message,
        F: Fn(PeerToPeerEnvelope) -> Option<(PeerId, M)>,
    {
        let mut messages = Vec::with_capacity(self.other_peer_count());
        while messages.len() < self.other_peer_count() {
            let envelope = self
                .peer_to_peer_rx
                .recv()
                .await
                .expect("PeerActor: peer inbox closed");
            let (sender_peer_id, message) =
                unwrap(envelope).expect("PeerActor: unexpected peer envelope for current phase");
            messages.push(MetadataAttachedMessage::new(sender_peer_id, message));
        }

        Parcel::new(messages)
    }

    async fn run_setup(&mut self) {
        let peer_number = self.peer_number();
        self.log_setup_step("starting phone and SAR handshake");

        let setup_phone_input_1 = self
            .peer
            .call(|entity| entity.produce_setup_phone_input_1().unwrap())
            .await;
        self.phone
            .call(|entity| {
                entity
                    .consume_setup_phone_input_1(setup_phone_input_1)
                    .unwrap()
            })
            .await;
        let setup_phone_sar_message_1 = self
            .phone
            .call(|entity| entity.produce_setup_phone_sar_message_1().unwrap())
            .await
            .look_for_message(&self.sar_id)
            .unwrap()
            .clone();
        self.send_to_sar(PeerToSarEnvelope::SetupPhoneSarMessage1(
            setup_phone_sar_message_1,
        ))
        .await;

        let setup_sar_phone_message_1 = match self.recv_from_sar().await {
            SarToPeerEnvelope::SetupSarPhoneMessage1(msg) => msg,
            _ => panic!("PeerActor: expected SetupSarPhoneMessage1"),
        };
        let setup_sar_phone_message_1 = self.single_sar_parcel(setup_sar_phone_message_1);
        self.phone
            .call(|entity| {
                entity
                    .consume_setup_sar_phone_message_1(setup_sar_phone_message_1)
                    .unwrap()
            })
            .await;
        let setup_phone_output_1 = self
            .phone
            .call(|entity| entity.produce_setup_phone_output_1().unwrap())
            .await;
        self.peer
            .call(|entity| {
                entity
                    .consume_setup_phone_output_1(setup_phone_output_1)
                    .unwrap()
            })
            .await;

        let setup_phone_input_2 = self
            .peer
            .call(|entity| entity.produce_setup_phone_input_2().unwrap())
            .await;
        self.phone
            .call(|entity| {
                entity
                    .consume_setup_phone_input_2(setup_phone_input_2)
                    .unwrap()
            })
            .await;
        let setup_phone_sar_message_2 = self
            .phone
            .call(|entity| entity.produce_setup_phone_sar_message_2().unwrap())
            .await
            .look_for_message(&self.sar_id)
            .unwrap()
            .clone();
        self.send_to_sar(PeerToSarEnvelope::SetupPhoneSarMessage2(
            setup_phone_sar_message_2,
        ))
        .await;

        let setup_sar_phone_message_2 = match self.recv_from_sar().await {
            SarToPeerEnvelope::SetupSarPhoneMessage2(msg) => msg,
            _ => panic!("PeerActor: expected SetupSarPhoneMessage2"),
        };
        let setup_sar_phone_message_2 = self.single_sar_parcel(setup_sar_phone_message_2);
        self.phone
            .call(|entity| {
                entity
                    .consume_setup_sar_phone_message_2(setup_sar_phone_message_2)
                    .unwrap()
            })
            .await;
        let setup_phone_output_2 = self
            .phone
            .call(|entity| entity.produce_setup_phone_output_2().unwrap())
            .await;
        self.peer
            .call(|entity| {
                entity
                    .consume_setup_phone_output_2(setup_phone_output_2)
                    .unwrap()
            })
            .await;
        self.log_setup_step("phone/SAR handshake complete; preparing local ISO/ST/Boomlet state");

        let setup_iso_input_1 = self
            .peer
            .call(|entity| entity.produce_setup_iso_input_1().unwrap())
            .await;
        self.iso
            .call(|entity| entity.consume_setup_iso_input_1(setup_iso_input_1).unwrap())
            .await;
        let setup_iso_boomlet_message_1 = self
            .iso
            .call(|entity| entity.produce_setup_iso_boomlet_message_1().unwrap())
            .await;
        self.boomlet
            .call(|entity| {
                entity
                    .consume_setup_iso_boomlet_message_1(setup_iso_boomlet_message_1)
                    .unwrap()
            })
            .await;
        let setup_boomlet_iso_message_1 = self
            .boomlet
            .call(|entity| entity.produce_setup_boomlet_iso_message_1().unwrap())
            .await;
        self.iso
            .call(|entity| {
                entity
                    .consume_setup_boomlet_iso_message_1(setup_boomlet_iso_message_1)
                    .unwrap()
            })
            .await;
        let setup_iso_st_message_1 = self
            .iso
            .call(|entity| entity.produce_setup_iso_st_message_1().unwrap())
            .await;
        self.st
            .call(|entity| {
                entity
                    .consume_setup_iso_st_message_1(setup_iso_st_message_1)
                    .unwrap()
            })
            .await;
        let setup_st_iso_message_1 = self
            .st
            .call(|entity| entity.produce_setup_st_iso_message_1().unwrap())
            .await;
        self.iso
            .call(|entity| {
                entity
                    .consume_setup_st_iso_message_1(setup_st_iso_message_1)
                    .unwrap()
            })
            .await;
        let setup_iso_boomlet_message_2 = self
            .iso
            .call(|entity| entity.produce_setup_iso_boomlet_message_2().unwrap())
            .await;
        self.boomlet
            .call(|entity| {
                entity
                    .consume_setup_iso_boomlet_message_2(setup_iso_boomlet_message_2)
                    .unwrap()
            })
            .await;
        let setup_boomlet_iso_message_2 = self
            .boomlet
            .call(|entity| entity.produce_setup_boomlet_iso_message_2().unwrap())
            .await;
        self.iso
            .call(|entity| {
                entity
                    .consume_setup_boomlet_iso_message_2(setup_boomlet_iso_message_2)
                    .unwrap()
            })
            .await;
        let setup_iso_st_message_2 = self
            .iso
            .call(|entity| entity.produce_setup_iso_st_message_2().unwrap())
            .await;
        self.st
            .call(|entity| {
                entity
                    .consume_setup_iso_st_message_2(setup_iso_st_message_2)
                    .unwrap()
            })
            .await;
        let setup_st_output_1 = self
            .st
            .call(|entity| entity.produce_setup_st_output_1().unwrap())
            .await;
        self.peer
            .call(|entity| entity.consume_setup_st_output_1(setup_st_output_1).unwrap())
            .await;
        let setup_st_input_1 = self
            .peer
            .call(|entity| entity.produce_setup_st_input_1().unwrap())
            .await;
        self.st
            .call(|entity| entity.consume_setup_st_input_1(setup_st_input_1).unwrap())
            .await;
        let setup_st_iso_message_2 = self
            .st
            .call(|entity| entity.produce_setup_st_iso_message_2().unwrap())
            .await;
        self.iso
            .call(|entity| {
                entity
                    .consume_setup_st_iso_message_2(setup_st_iso_message_2)
                    .unwrap()
            })
            .await;
        let setup_iso_boomlet_message_3 = self
            .iso
            .call(|entity| entity.produce_setup_iso_boomlet_message_3().unwrap())
            .await;
        self.boomlet
            .call(|entity| {
                entity
                    .consume_setup_iso_boomlet_message_3(setup_iso_boomlet_message_3)
                    .unwrap()
            })
            .await;
        let setup_boomlet_iso_message_3 = self
            .boomlet
            .call(|entity| entity.produce_setup_boomlet_iso_message_3().unwrap())
            .await;
        self.iso
            .call(|entity| {
                entity
                    .consume_setup_boomlet_iso_message_3(setup_boomlet_iso_message_3)
                    .unwrap()
            })
            .await;
        let setup_iso_st_message_3 = self
            .iso
            .call(|entity| entity.produce_setup_iso_st_message_3().unwrap())
            .await;
        self.st
            .call(|entity| {
                entity
                    .consume_setup_iso_st_message_3(setup_iso_st_message_3)
                    .unwrap()
            })
            .await;
        let setup_st_output_2 = self
            .st
            .call(|entity| entity.produce_setup_st_output_2().unwrap())
            .await;
        self.peer
            .call(|entity| entity.consume_setup_st_output_2(setup_st_output_2).unwrap())
            .await;
        let setup_st_input_2 = self
            .peer
            .call(|entity| entity.produce_setup_st_input_2().unwrap())
            .await;
        self.st
            .call(|entity| entity.consume_setup_st_input_2(setup_st_input_2).unwrap())
            .await;
        let setup_st_iso_message_3 = self
            .st
            .call(|entity| entity.produce_setup_st_iso_message_3().unwrap())
            .await;
        self.iso
            .call(|entity| {
                entity
                    .consume_setup_st_iso_message_3(setup_st_iso_message_3)
                    .unwrap()
            })
            .await;
        let setup_iso_boomlet_message_4 = self
            .iso
            .call(|entity| entity.produce_setup_iso_boomlet_message_4().unwrap())
            .await;
        self.boomlet
            .call(|entity| {
                entity
                    .consume_setup_iso_boomlet_message_4(setup_iso_boomlet_message_4)
                    .unwrap()
            })
            .await;
        let setup_boomlet_iso_message_4 = self
            .boomlet
            .call(|entity| entity.produce_setup_boomlet_iso_message_4().unwrap())
            .await;
        self.iso
            .call(|entity| {
                entity
                    .consume_setup_boomlet_iso_message_4(setup_boomlet_iso_message_4)
                    .unwrap()
            })
            .await;
        let setup_iso_output_1 = self
            .iso
            .call(|entity| entity.produce_setup_iso_output_1().unwrap())
            .await;
        self.peer
            .call(|entity| {
                entity
                    .consume_setup_iso_output_1(setup_iso_output_1)
                    .unwrap()
            })
            .await;

        let setup_niso_input_1 = self
            .peer
            .call(|entity| entity.produce_setup_niso_input_1().unwrap())
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_setup_niso_input_1(setup_niso_input_1)
                    .unwrap()
            })
            .await;
        let setup_niso_boomlet_message_1 = self
            .niso
            .call(|entity| entity.produce_setup_niso_boomlet_message_1().unwrap())
            .await;
        self.boomlet
            .call(|entity| {
                entity
                    .consume_setup_niso_boomlet_message_1(setup_niso_boomlet_message_1)
                    .unwrap()
            })
            .await;
        let setup_boomlet_niso_message_1 = self
            .boomlet
            .call(|entity| entity.produce_setup_boomlet_niso_message_1().unwrap())
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_setup_boomlet_niso_message_1(setup_boomlet_niso_message_1)
                    .unwrap()
            })
            .await;
        let setup_niso_st_message_1 = self
            .niso
            .call(|entity| entity.produce_setup_niso_st_message_1().unwrap())
            .await;
        self.st
            .call(|entity| {
                entity
                    .consume_setup_niso_st_message_1(setup_niso_st_message_1)
                    .unwrap()
            })
            .await;
        let setup_st_output_3 = self
            .st
            .call(|entity| entity.produce_setup_st_output_3().unwrap())
            .await;
        self.peer
            .call(|entity| entity.consume_setup_st_output_3(setup_st_output_3).unwrap())
            .await;

        self.log_setup_step("local NISO state prepared; registering peer out-of-band inboxes");
        self.register_in_peer_directory().await;

        let out_of_band_message = self
            .peer
            .call(|entity| {
                entity
                    .produce_setup_user_peers_out_of_band_message_1()
                    .unwrap()
            })
            .await;
        self.broadcast_out_of_band_message(out_of_band_message)
            .await;
        let merged_out_of_band_message = self.recv_merged_out_of_band_message().await;
        self.peer
            .call(|entity| {
                entity
                    .consume_setup_user_peers_out_of_band_message_1(merged_out_of_band_message)
                    .unwrap()
            })
            .await;
        self.log_setup_step("peer out-of-band exchange complete; continuing WT registration");

        let setup_niso_input_2 = self
            .peer
            .call(|entity| entity.produce_setup_niso_input_2().unwrap())
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_setup_niso_input_2(setup_niso_input_2)
                    .unwrap()
            })
            .await;
        let setup_niso_boomlet_message_2 = self
            .niso
            .call(|entity| entity.produce_setup_niso_boomlet_message_2().unwrap())
            .await;
        self.boomlet
            .call(|entity| {
                entity
                    .consume_setup_niso_boomlet_message_2(setup_niso_boomlet_message_2)
                    .unwrap()
            })
            .await;
        let setup_boomlet_niso_message_2 = self
            .boomlet
            .call(|entity| entity.produce_setup_boomlet_niso_message_2().unwrap())
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_setup_boomlet_niso_message_2(setup_boomlet_niso_message_2)
                    .unwrap()
            })
            .await;
        let setup_niso_st_message_2 = self
            .niso
            .call(|entity| entity.produce_setup_niso_st_message_2().unwrap())
            .await;
        self.st
            .call(|entity| {
                entity
                    .consume_setup_niso_st_message_2(setup_niso_st_message_2)
                    .unwrap()
            })
            .await;
        let setup_st_output_4 = self
            .st
            .call(|entity| entity.produce_setup_st_output_4().unwrap())
            .await;
        self.peer
            .call(|entity| entity.consume_setup_st_output_4(setup_st_output_4).unwrap())
            .await;
        let setup_st_input_3 = self
            .peer
            .call(|entity| entity.produce_setup_st_input_3().unwrap())
            .await;
        self.st
            .call(|entity| entity.consume_setup_st_input_3(setup_st_input_3).unwrap())
            .await;
        let setup_st_niso_message_1 = self
            .st
            .call(|entity| entity.produce_setup_st_niso_message_1().unwrap())
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_setup_st_niso_message_1(setup_st_niso_message_1)
                    .unwrap()
            })
            .await;
        let setup_niso_boomlet_message_3 = self
            .niso
            .call(|entity| entity.produce_setup_niso_boomlet_message_3().unwrap())
            .await;
        self.boomlet
            .call(|entity| {
                entity
                    .consume_setup_niso_boomlet_message_3(setup_niso_boomlet_message_3)
                    .unwrap()
            })
            .await;
        let setup_boomlet_niso_message_3 = self
            .boomlet
            .call(|entity| entity.produce_setup_boomlet_niso_message_3().unwrap())
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_setup_boomlet_niso_message_3(setup_boomlet_niso_message_3)
                    .unwrap()
            })
            .await;

        let setup_niso_peer_niso_message_1 = self
            .niso
            .call(|entity| entity.produce_setup_niso_peer_niso_message_1().unwrap())
            .await;
        self.send_peer_parcel(setup_niso_peer_niso_message_1, |sender_peer_id, msg| {
            PeerToPeerEnvelope::SetupNisoPeerNisoMessage1 {
                sender_peer_id,
                msg,
            }
        })
        .await;
        let setup_niso_peer_niso_message_1 = self
            .recv_peer_parcel(|envelope| match envelope {
                PeerToPeerEnvelope::SetupNisoPeerNisoMessage1 {
                    sender_peer_id,
                    msg,
                } => Some((sender_peer_id, msg)),
                _ => None,
            })
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_setup_niso_peer_niso_message_1(setup_niso_peer_niso_message_1)
                    .unwrap()
            })
            .await;
        let setup_niso_boomlet_message_4 = self
            .niso
            .call(|entity| entity.produce_setup_niso_boomlet_message_4().unwrap())
            .await;
        self.boomlet
            .call(|entity| {
                entity
                    .consume_setup_niso_boomlet_message_4(setup_niso_boomlet_message_4)
                    .unwrap()
            })
            .await;
        let setup_boomlet_niso_message_4 = self
            .boomlet
            .call(|entity| entity.produce_setup_boomlet_niso_message_4().unwrap())
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_setup_boomlet_niso_message_4(setup_boomlet_niso_message_4)
                    .unwrap()
            })
            .await;
        let setup_niso_boomlet_message_5 = self
            .niso
            .call(|entity| entity.produce_setup_niso_boomlet_message_5().unwrap())
            .await;
        self.boomlet
            .call(|entity| {
                entity
                    .consume_setup_niso_boomlet_message_5(setup_niso_boomlet_message_5)
                    .unwrap()
            })
            .await;
        let setup_boomlet_niso_message_5 = self
            .boomlet
            .call(|entity| entity.produce_setup_boomlet_niso_message_5().unwrap())
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_setup_boomlet_niso_message_5(setup_boomlet_niso_message_5)
                    .unwrap()
            })
            .await;

        let setup_niso_wt_message_1 = self
            .niso
            .call(|entity| entity.produce_setup_niso_wt_message_1().unwrap())
            .await;
        let own_peer_id = self.own_peer_id().await;
        self.send_to_wt(PeerToWtEnvelope::SetupNisoWtMessage1 {
            boomlet_identity_pubkey: *own_peer_id.get_boomlet_identity_pubkey(),
            msg: setup_niso_wt_message_1,
        })
        .await;

        let setup_wt_niso_message_1 = match self.recv_from_wt().await {
            WtToPeerEnvelope::SetupWtNisoMessage1(msg) => msg,
            _ => panic!("PeerActor: expected SetupWtNisoMessage1"),
        };
        self.niso
            .call(|entity| {
                entity
                    .consume_setup_wt_niso_message_1(setup_wt_niso_message_1)
                    .unwrap()
            })
            .await;
        let setup_niso_output_1 = self
            .niso
            .call(|entity| entity.produce_setup_niso_output_1().unwrap())
            .await;
        self.peer
            .call(|entity| {
                entity
                    .consume_setup_niso_output_1(setup_niso_output_1)
                    .unwrap()
            })
            .await;
        let setup_niso_input_3 = self
            .peer
            .call(|entity| entity.produce_setup_niso_input_3().unwrap())
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_setup_niso_input_3(setup_niso_input_3)
                    .unwrap()
            })
            .await;
        let setup_niso_wt_message_2 = self
            .niso
            .call(|entity| entity.produce_setup_niso_wt_message_2().unwrap())
            .await;
        let own_wt_peer_id = self.own_wt_peer_id().await;
        self.send_to_wt(PeerToWtEnvelope::SetupNisoWtMessage2 {
            wt_peer_id: own_wt_peer_id,
            msg: setup_niso_wt_message_2,
        })
        .await;

        let setup_wt_niso_message_2 = match self.recv_from_wt().await {
            WtToPeerEnvelope::SetupWtNisoMessage2(msg) => msg,
            _ => panic!("PeerActor: expected SetupWtNisoMessage2"),
        };
        self.niso
            .call(|entity| {
                entity
                    .consume_setup_wt_niso_message_2(setup_wt_niso_message_2)
                    .unwrap()
            })
            .await;
        let setup_niso_boomlet_message_6 = self
            .niso
            .call(|entity| entity.produce_setup_niso_boomlet_message_6().unwrap())
            .await;
        self.boomlet
            .call(|entity| {
                entity
                    .consume_setup_niso_boomlet_message_6(setup_niso_boomlet_message_6)
                    .unwrap()
            })
            .await;
        let setup_boomlet_niso_message_6 = self
            .boomlet
            .call(|entity| entity.produce_setup_boomlet_niso_message_6().unwrap())
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_setup_boomlet_niso_message_6(setup_boomlet_niso_message_6)
                    .unwrap()
            })
            .await;

        let setup_niso_peer_niso_message_2 = self
            .niso
            .call(|entity| entity.produce_setup_niso_peer_niso_message_2().unwrap())
            .await;
        self.send_peer_parcel(setup_niso_peer_niso_message_2, |sender_peer_id, msg| {
            PeerToPeerEnvelope::SetupNisoPeerNisoMessage2 {
                sender_peer_id,
                msg,
            }
        })
        .await;
        let setup_niso_peer_niso_message_2 = self
            .recv_peer_parcel(|envelope| match envelope {
                PeerToPeerEnvelope::SetupNisoPeerNisoMessage2 {
                    sender_peer_id,
                    msg,
                } => Some((sender_peer_id, msg)),
                _ => None,
            })
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_setup_niso_peer_niso_message_2(setup_niso_peer_niso_message_2)
                    .unwrap()
            })
            .await;
        let setup_niso_boomlet_message_7 = self
            .niso
            .call(|entity| entity.produce_setup_niso_boomlet_message_7().unwrap())
            .await;
        self.boomlet
            .call(|entity| {
                entity
                    .consume_setup_niso_boomlet_message_7(setup_niso_boomlet_message_7)
                    .unwrap()
            })
            .await;
        let setup_boomlet_niso_message_7 = self
            .boomlet
            .call(|entity| entity.produce_setup_boomlet_niso_message_7().unwrap())
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_setup_boomlet_niso_message_7(setup_boomlet_niso_message_7)
                    .unwrap()
            })
            .await;
        let setup_niso_boomlet_message_8 = self
            .niso
            .call(|entity| entity.produce_setup_niso_boomlet_message_8().unwrap())
            .await;
        self.boomlet
            .call(|entity| {
                entity
                    .consume_setup_niso_boomlet_message_8(setup_niso_boomlet_message_8)
                    .unwrap()
            })
            .await;
        let setup_boomlet_niso_message_8 = self
            .boomlet
            .call(|entity| entity.produce_setup_boomlet_niso_message_8().unwrap())
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_setup_boomlet_niso_message_8(setup_boomlet_niso_message_8)
                    .unwrap()
            })
            .await;

        let setup_niso_wt_message_3 = self
            .niso
            .call(|entity| entity.produce_setup_niso_wt_message_3().unwrap())
            .await;
        let own_wt_peer_id = self.own_wt_peer_id().await;
        self.send_to_wt(PeerToWtEnvelope::SetupNisoWtMessage3 {
            wt_peer_id: own_wt_peer_id,
            msg: setup_niso_wt_message_3,
        })
        .await;

        let setup_wt_niso_message_3 = match self.recv_from_wt().await {
            WtToPeerEnvelope::SetupWtNisoMessage3(msg) => msg,
            _ => panic!("PeerActor: expected SetupWtNisoMessage3"),
        };
        self.niso
            .call(|entity| {
                entity
                    .consume_setup_wt_niso_message_3(setup_wt_niso_message_3)
                    .unwrap()
            })
            .await;
        self.log_setup_step("WT registration complete; finalizing peer graph");
        let setup_niso_boomlet_message_9 = self
            .niso
            .call(|entity| entity.produce_setup_niso_boomlet_message_9().unwrap())
            .await;
        self.boomlet
            .call(|entity| {
                entity
                    .consume_setup_niso_boomlet_message_9(setup_niso_boomlet_message_9)
                    .unwrap()
            })
            .await;
        let setup_boomlet_niso_message_9 = self
            .boomlet
            .call(|entity| entity.produce_setup_boomlet_niso_message_9().unwrap())
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_setup_boomlet_niso_message_9(setup_boomlet_niso_message_9)
                    .unwrap()
            })
            .await;

        let setup_niso_peer_niso_message_3 = self
            .niso
            .call(|entity| entity.produce_setup_niso_peer_niso_message_3().unwrap())
            .await;
        self.send_peer_parcel(setup_niso_peer_niso_message_3, |sender_peer_id, msg| {
            PeerToPeerEnvelope::SetupNisoPeerNisoMessage3 {
                sender_peer_id,
                msg,
            }
        })
        .await;
        let setup_niso_peer_niso_message_3 = self
            .recv_peer_parcel(|envelope| match envelope {
                PeerToPeerEnvelope::SetupNisoPeerNisoMessage3 {
                    sender_peer_id,
                    msg,
                } => Some((sender_peer_id, msg)),
                _ => None,
            })
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_setup_niso_peer_niso_message_3(setup_niso_peer_niso_message_3)
                    .unwrap()
            })
            .await;
        let setup_niso_boomlet_message_10 = self
            .niso
            .call(|entity| entity.produce_setup_niso_boomlet_message_10().unwrap())
            .await;
        self.boomlet
            .call(|entity| {
                entity
                    .consume_setup_niso_boomlet_message_10(setup_niso_boomlet_message_10)
                    .unwrap()
            })
            .await;
        let setup_boomlet_niso_message_10 = self
            .boomlet
            .call(|entity| entity.produce_setup_boomlet_niso_message_10().unwrap())
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_setup_boomlet_niso_message_10(setup_boomlet_niso_message_10)
                    .unwrap()
            })
            .await;
        let setup_niso_output_2 = self
            .niso
            .call(|entity| entity.produce_setup_niso_output_2().unwrap())
            .await;
        self.peer
            .call(|entity| {
                entity
                    .consume_setup_niso_output_2(setup_niso_output_2)
                    .unwrap()
            })
            .await;

        let setup_iso_input_2 = self
            .peer
            .call(|entity| entity.produce_setup_iso_input_2().unwrap())
            .await;
        self.iso
            .call(|entity| entity.consume_setup_iso_input_2(setup_iso_input_2).unwrap())
            .await;
        let setup_iso_boomletwo_message_1 = self
            .iso
            .call(|entity| entity.produce_setup_iso_boomletwo_message_1().unwrap())
            .await;
        self.boomletwo
            .call(|entity| {
                entity
                    .consume_setup_iso_boomletwo_message_1(setup_iso_boomletwo_message_1)
                    .unwrap()
            })
            .await;
        let setup_boomletwo_iso_message_1 = self
            .boomletwo
            .call(|entity| entity.produce_setup_boomletwo_iso_message_1().unwrap())
            .await;
        self.iso
            .call(|entity| {
                entity
                    .consume_setup_boomletwo_iso_message_1(setup_boomletwo_iso_message_1)
                    .unwrap()
            })
            .await;
        let setup_iso_output_2 = self
            .iso
            .call(|entity| entity.produce_setup_iso_output_2().unwrap())
            .await;
        self.peer
            .call(|entity| {
                entity
                    .consume_setup_iso_output_2(setup_iso_output_2)
                    .unwrap()
            })
            .await;
        let setup_iso_input_3 = self
            .peer
            .call(|entity| entity.produce_setup_iso_input_3().unwrap())
            .await;
        self.iso
            .call(|entity| entity.consume_setup_iso_input_3(setup_iso_input_3).unwrap())
            .await;
        let setup_iso_boomlet_message_5 = self
            .iso
            .call(|entity| entity.produce_setup_iso_boomlet_message_5().unwrap())
            .await;
        self.boomlet
            .call(|entity| {
                entity
                    .consume_setup_iso_boomlet_message_5(setup_iso_boomlet_message_5)
                    .unwrap()
            })
            .await;
        let setup_boomlet_iso_message_5 = self
            .boomlet
            .call(|entity| entity.produce_setup_boomlet_iso_message_5().unwrap())
            .await;
        self.iso
            .call(|entity| {
                entity
                    .consume_setup_boomlet_iso_message_5(setup_boomlet_iso_message_5)
                    .unwrap()
            })
            .await;
        let setup_iso_output_3 = self
            .iso
            .call(|entity| entity.produce_setup_iso_output_3().unwrap())
            .await;
        self.peer
            .call(|entity| {
                entity
                    .consume_setup_iso_output_3(setup_iso_output_3)
                    .unwrap()
            })
            .await;
        let setup_iso_input_4 = self
            .peer
            .call(|entity| entity.produce_setup_iso_input_4().unwrap())
            .await;
        self.iso
            .call(|entity| entity.consume_setup_iso_input_4(setup_iso_input_4).unwrap())
            .await;
        let setup_iso_boomletwo_message_2 = self
            .iso
            .call(|entity| entity.produce_setup_iso_boomletwo_message_2().unwrap())
            .await;
        self.boomletwo
            .call(|entity| {
                entity
                    .consume_setup_iso_boomletwo_message_2(setup_iso_boomletwo_message_2)
                    .unwrap()
            })
            .await;
        let setup_boomletwo_iso_message_2 = self
            .boomletwo
            .call(|entity| entity.produce_setup_boomletwo_iso_message_2().unwrap())
            .await;
        self.iso
            .call(|entity| {
                entity
                    .consume_setup_boomletwo_iso_message_2(setup_boomletwo_iso_message_2)
                    .unwrap()
            })
            .await;
        let setup_iso_output_4 = self
            .iso
            .call(|entity| entity.produce_setup_iso_output_4().unwrap())
            .await;
        self.peer
            .call(|entity| {
                entity
                    .consume_setup_iso_output_4(setup_iso_output_4)
                    .unwrap()
            })
            .await;
        let setup_iso_input_5 = self
            .peer
            .call(|entity| entity.produce_setup_iso_input_5().unwrap())
            .await;
        self.iso
            .call(|entity| entity.consume_setup_iso_input_5(setup_iso_input_5).unwrap())
            .await;
        let setup_iso_boomlet_message_6 = self
            .iso
            .call(|entity| entity.produce_setup_iso_boomlet_message_6().unwrap())
            .await;
        self.boomlet
            .call(|entity| {
                entity
                    .consume_setup_iso_boomlet_message_6(setup_iso_boomlet_message_6)
                    .unwrap()
            })
            .await;
        let setup_boomlet_iso_message_6 = self
            .boomlet
            .call(|entity| entity.produce_setup_boomlet_iso_message_6().unwrap())
            .await;
        self.iso
            .call(|entity| {
                entity
                    .consume_setup_boomlet_iso_message_6(setup_boomlet_iso_message_6)
                    .unwrap()
            })
            .await;
        let setup_iso_output_5 = self
            .iso
            .call(|entity| entity.produce_setup_iso_output_5().unwrap())
            .await;
        self.peer
            .call(|entity| {
                entity
                    .consume_setup_iso_output_5(setup_iso_output_5)
                    .unwrap()
            })
            .await;
        let setup_niso_input_4 = self
            .peer
            .call(|entity| entity.produce_setup_niso_input_4().unwrap())
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_setup_niso_input_4(setup_niso_input_4)
                    .unwrap()
            })
            .await;
        let setup_niso_boomlet_message_11 = self
            .niso
            .call(|entity| entity.produce_setup_niso_boomlet_message_11().unwrap())
            .await;
        self.boomlet
            .call(|entity| {
                entity
                    .consume_setup_niso_boomlet_message_11(setup_niso_boomlet_message_11)
                    .unwrap()
            })
            .await;
        let setup_boomlet_niso_message_11 = self
            .boomlet
            .call(|entity| entity.produce_setup_boomlet_niso_message_11().unwrap())
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_setup_boomlet_niso_message_11(setup_boomlet_niso_message_11)
                    .unwrap()
            })
            .await;

        let setup_niso_peer_niso_message_4 = self
            .niso
            .call(|entity| entity.produce_setup_niso_peer_niso_message_4().unwrap())
            .await;
        self.send_peer_parcel(setup_niso_peer_niso_message_4, |sender_peer_id, msg| {
            PeerToPeerEnvelope::SetupNisoPeerNisoMessage4 {
                sender_peer_id,
                msg,
            }
        })
        .await;
        let setup_niso_peer_niso_message_4 = self
            .recv_peer_parcel(|envelope| match envelope {
                PeerToPeerEnvelope::SetupNisoPeerNisoMessage4 {
                    sender_peer_id,
                    msg,
                } => Some((sender_peer_id, msg)),
                _ => None,
            })
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_setup_niso_peer_niso_message_4(setup_niso_peer_niso_message_4)
                    .unwrap()
            })
            .await;
        let setup_niso_boomlet_message_12 = self
            .niso
            .call(|entity| entity.produce_setup_niso_boomlet_message_12().unwrap())
            .await;
        self.boomlet
            .call(|entity| {
                entity
                    .consume_setup_niso_boomlet_message_12(setup_niso_boomlet_message_12)
                    .unwrap()
            })
            .await;
        let setup_boomlet_niso_message_12 = self
            .boomlet
            .call(|entity| entity.produce_setup_boomlet_niso_message_12().unwrap())
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_setup_boomlet_niso_message_12(setup_boomlet_niso_message_12)
                    .unwrap()
            })
            .await;
        let setup_niso_output_3 = self
            .niso
            .call(|entity| entity.produce_setup_niso_output_3().unwrap())
            .await;
        self.peer
            .call(|entity| {
                entity
                    .consume_setup_niso_output_3(setup_niso_output_3)
                    .unwrap()
            })
            .await;

        self.iso.call(|entity| entity.reset_state()).await;
        self.log_setup_step("local setup finalization complete");
        info!("PeerActor {peer_number}: setup complete.");
    }

    async fn run_withdrawal(&mut self) {
        let peer_number = self.peer_number();
        let mut miner_task_handle = None;
        self.log_withdrawal_step(&format!("starting as {}", self.role_name()));

        if self.initiator_runtime.is_some() {
            self.log_withdrawal_step(
                "preparing funding transaction and initial withdrawal request",
            );
            miner_task_handle = Some(self.start_initiator_withdrawal().await);

            let initiator_reply = match self.recv_from_wt().await {
                WtToPeerEnvelope::WithdrawalWtNisoMessage1(msg) => msg,
                _ => panic!("PeerActor: expected WithdrawalWtNisoMessage1"),
            };
            self.handle_initiator_tx_aggregation(initiator_reply).await;
        } else {
            self.log_withdrawal_step("waiting for WT approval, ack, and commit requests");
            let approval_message = match self.recv_from_wt().await {
                WtToPeerEnvelope::WithdrawalWtNonInitiatorNisoMessage1(msg) => msg,
                _ => panic!("PeerActor: expected WithdrawalWtNonInitiatorNisoMessage1"),
            };
            self.handle_non_initiator_approval_phase(approval_message)
                .await;

            let ack_message = match self.recv_from_wt().await {
                WtToPeerEnvelope::WithdrawalWtNonInitiatorNisoMessage2(msg) => msg,
                _ => panic!("PeerActor: expected WithdrawalWtNonInitiatorNisoMessage2"),
            };
            self.handle_non_initiator_ack_phase(ack_message).await;

            let commit_message = match self.recv_from_wt().await {
                WtToPeerEnvelope::WithdrawalWtNonInitiatorNisoMessage3(msg) => msg,
                _ => panic!("PeerActor: expected WithdrawalWtNonInitiatorNisoMessage3"),
            };
            self.handle_non_initiator_commit_phase(commit_message).await;
        }

        let common_commit_message = match self.recv_from_wt().await {
            WtToPeerEnvelope::WithdrawalWtNisoMessage2(msg) => msg,
            _ => panic!("PeerActor: expected WithdrawalWtNisoMessage2"),
        };
        self.handle_post_commit_phase(common_commit_message).await;
        self.log_withdrawal_step("shared withdrawal state received; entering digging game");
        self.run_ping_pong_loop().await;
        self.log_withdrawal_step("digging game complete; preparing final signature");
        self.finish_signing().await;

        if let Some(miner_task_handle) = miner_task_handle {
            miner_task_handle.abort();
        }

        info!("PeerActor {peer_number}: withdrawal complete.");
    }

    async fn start_initiator_withdrawal(&mut self) -> JoinHandle<()> {
        let bitcoin_node = self
            .initiator_runtime
            .as_ref()
            .expect("PeerActor: missing initiator runtime");
        let rpc_address = bitcoin_node.rpc_address;
        let cookie_path = bitcoin_node.cookie_path.clone();

        let miner = Client::new(
            &rpc_address.to_string(),
            Auth::CookieFile(cookie_path.clone()),
        )
        .unwrap();
        let mining_address = miner
            .get_new_address(Some("mining"), Some(AddressType::Bech32))
            .unwrap()
            .require_network(self.boomerang_config.network)
            .unwrap();
        miner
            .generate_to_address(
                self.withdrawal_config.initial_miner_num_blocks_to_mine,
                &mining_address,
            )
            .unwrap();

        let task_miner =
            Client::new(&rpc_address.to_string(), Auth::CookieFile(cookie_path)).unwrap();
        let task_mining_address = mining_address.clone();
        let miner_task_sleep_ms = self
            .withdrawal_config
            .miner_task_sleeping_time_in_milliseconds;
        let miner_task_handle = tokio::spawn(async move {
            loop {
                sleep(Duration::from_millis(miner_task_sleep_ms)).await;
                task_miner
                    .generate_to_address(1, &task_mining_address)
                    .unwrap();
            }
        });

        let secp = Secp256k1::new();
        let destination_keypair = Keypair::new(&secp, &mut thread_rng());
        let destination_pubkey = PublicKey::new(destination_keypair.public_key());
        let destination_address = Address::p2wpkh(
            &destination_pubkey.try_into().unwrap(),
            self.boomerang_config.network,
        );
        let boomerang_params = self
            .niso
            .call(|entity| entity.get_boomerang_params().unwrap())
            .await;
        let descriptor =
            Tr::<XOnlyPublicKey>::from_str(boomerang_params.get_boomerang_descriptor()).unwrap();
        let fund_address = descriptor.address(self.boomerang_config.network);
        let fund_txid = miner
            .send_to_address(
                &fund_address,
                Amount::from_int_btc(
                    self.withdrawal_config
                        .deposit_amount_to_boomerang_address_in_int_btc,
                ),
                None,
                None,
                Some(false),
                Some(true),
                None,
                None,
            )
            .unwrap();
        miner
            .generate_to_address(
                self.withdrawal_config
                    .miner_num_blocks_to_mine_for_deposit_transaction_to_be_mined,
                &mining_address,
            )
            .unwrap();
        let get_transaction_result = miner.get_transaction(&fund_txid, None).unwrap();
        let (vout, _) = get_transaction_result
            .transaction()
            .unwrap()
            .output
            .iter()
            .enumerate()
            .find(|(_, tx_out)| tx_out.script_pubkey == fund_address.script_pubkey())
            .map(|(vout, tx_out)| (vout, tx_out.clone()))
            .unwrap();

        self.log_withdrawal_step("funded the boomerang output and is waiting for locktime");

        loop {
            if miner.get_block_count().unwrap()
                >= self
                    .withdrawal_config
                    .absolute_locktime_for_withdrawal_transaction
            {
                break;
            }

            sleep(Duration::from_millis(
                self.withdrawal_config
                    .miner_task_sleeping_time_in_milliseconds,
            ))
            .await;
        }

        debug!(
            "PeerActor {}: withdrawal environment ready.",
            self.peer_number()
        );
        self.log_withdrawal_step("locktime reached; building initiator withdrawal proposal");

        let absolute_locktime = self
            .withdrawal_config
            .absolute_locktime_for_withdrawal_transaction as u32;
        let withdrawal_amount = self
            .withdrawal_config
            .withdrawal_transaction_amount_in_f64_btc;
        let withdrawal_niso_input_1 = self
            .peer
            .call(move |entity| {
                entity
                    .produce_withdrawal_niso_input_1(
                        destination_address,
                        fund_txid,
                        vout as u32,
                        absolute_locktime,
                        withdrawal_amount,
                    )
                    .unwrap()
            })
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_withdrawal_niso_input_1(withdrawal_niso_input_1)
                    .unwrap()
            })
            .await;
        let withdrawal_niso_boomlet_message_1 = self
            .niso
            .call(|entity| entity.produce_withdrawal_niso_boomlet_message_1().unwrap())
            .await;
        self.boomlet
            .call(|entity| {
                entity
                    .consume_withdrawal_niso_boomlet_message_1(withdrawal_niso_boomlet_message_1)
                    .unwrap()
            })
            .await;
        let withdrawal_boomlet_niso_message_1 = self
            .boomlet
            .call(|entity| entity.produce_withdrawal_boomlet_niso_message_1().unwrap())
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_withdrawal_boomlet_niso_message_1(withdrawal_boomlet_niso_message_1)
                    .unwrap()
            })
            .await;
        let withdrawal_niso_st_message_1 = self
            .niso
            .call(|entity| entity.produce_withdrawal_niso_st_message_1().unwrap())
            .await;
        self.st
            .call(|entity| {
                entity
                    .consume_withdrawal_niso_st_message_1(withdrawal_niso_st_message_1)
                    .unwrap()
            })
            .await;
        let withdrawal_st_output_1 = self
            .st
            .call(|entity| entity.produce_withdrawal_st_output_1().unwrap())
            .await;
        self.peer
            .call(|entity| {
                entity
                    .consume_withdrawal_st_output_1(withdrawal_st_output_1)
                    .unwrap()
            })
            .await;
        let withdrawal_st_input_1 = self
            .peer
            .call(|entity| entity.produce_withdrawal_st_input_1().unwrap())
            .await;
        self.st
            .call(|entity| {
                entity
                    .consume_withdrawal_st_input_1(withdrawal_st_input_1)
                    .unwrap()
            })
            .await;
        let withdrawal_st_niso_message_1 = self
            .st
            .call(|entity| entity.produce_withdrawal_st_niso_message_1().unwrap())
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_withdrawal_st_niso_message_1(withdrawal_st_niso_message_1)
                    .unwrap()
            })
            .await;
        let withdrawal_niso_boomlet_message_2 = self
            .niso
            .call(|entity| entity.produce_withdrawal_niso_boomlet_message_2().unwrap())
            .await;
        self.boomlet
            .call(|entity| {
                entity
                    .consume_withdrawal_niso_boomlet_message_2(withdrawal_niso_boomlet_message_2)
                    .unwrap()
            })
            .await;
        let withdrawal_boomlet_niso_message_2 = self
            .boomlet
            .call(|entity| entity.produce_withdrawal_boomlet_niso_message_2().unwrap())
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_withdrawal_boomlet_niso_message_2(withdrawal_boomlet_niso_message_2)
                    .unwrap()
            })
            .await;

        let withdrawal_niso_wt_message_1 = self
            .niso
            .call(|entity| entity.produce_withdrawal_niso_wt_message_1().unwrap())
            .await;
        self.send_to_wt(PeerToWtEnvelope::WithdrawalNisoWtMessage1 {
            wt_peer_id: self.own_wt_peer_id().await,
            msg: withdrawal_niso_wt_message_1,
        })
        .await;
        self.log_withdrawal_step("sent initiator withdrawal request to WT");

        miner_task_handle
    }

    async fn handle_non_initiator_approval_phase(
        &mut self,
        message: WithdrawalWtNonInitiatorNisoMessage1,
    ) {
        self.niso
            .call(|entity| {
                entity
                    .consume_withdrawal_wt_non_initiator_niso_message_1(message)
                    .unwrap()
            })
            .await;
        let withdrawal_non_initiator_niso_non_initiator_boomlet_message_1 = self
            .niso
            .call(|entity| {
                entity
                    .produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_1()
                    .unwrap()
            })
            .await;
        self.boomlet
            .call(|entity| {
                entity
                    .consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_1(
                        withdrawal_non_initiator_niso_non_initiator_boomlet_message_1,
                    )
                    .unwrap()
            })
            .await;
        let withdrawal_non_initiator_boomlet_non_initiator_niso_message_1 = self
            .boomlet
            .call(|entity| {
                entity
                    .produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_1()
                    .unwrap()
            })
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_1(
                        withdrawal_non_initiator_boomlet_non_initiator_niso_message_1,
                    )
                    .unwrap()
            })
            .await;
        let withdrawal_non_initiator_niso_output_1 = self
            .niso
            .call(|entity| {
                entity
                    .produce_withdrawal_non_initiator_niso_output_1()
                    .unwrap()
            })
            .await;
        self.peer
            .call(|entity| {
                entity
                    .consume_withdrawal_non_initiator_niso_output_1(
                        withdrawal_non_initiator_niso_output_1,
                    )
                    .unwrap()
            })
            .await;
        let withdrawal_non_initiator_niso_input_1 = self
            .peer
            .call(|entity| {
                entity
                    .produce_withdrawal_non_initiator_niso_input_1()
                    .unwrap()
            })
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_withdrawal_non_initiator_niso_input_1(
                        withdrawal_non_initiator_niso_input_1,
                    )
                    .unwrap()
            })
            .await;
        let withdrawal_non_initiator_niso_non_initiator_boomlet_message_2 = self
            .niso
            .call(|entity| {
                entity
                    .produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_2()
                    .unwrap()
            })
            .await;
        self.boomlet
            .call(|entity| {
                entity
                    .consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_2(
                        withdrawal_non_initiator_niso_non_initiator_boomlet_message_2,
                    )
                    .unwrap()
            })
            .await;
        let withdrawal_non_initiator_boomlet_non_initiator_niso_message_2 = self
            .boomlet
            .call(|entity| {
                entity
                    .produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_2()
                    .unwrap()
            })
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_2(
                        withdrawal_non_initiator_boomlet_non_initiator_niso_message_2,
                    )
                    .unwrap()
            })
            .await;
        let withdrawal_non_initiator_niso_non_initiator_st_message_1 = self
            .niso
            .call(|entity| {
                entity
                    .produce_withdrawal_non_initiator_niso_non_initiator_st_message_1()
                    .unwrap()
            })
            .await;
        self.st
            .call(|entity| {
                entity
                    .consume_withdrawal_non_initiator_niso_non_initiator_st_message_1(
                        withdrawal_non_initiator_niso_non_initiator_st_message_1,
                    )
                    .unwrap()
            })
            .await;
        let withdrawal_non_initiator_st_output_1 = self
            .st
            .call(|entity| {
                entity
                    .produce_withdrawal_non_initiator_st_output_1()
                    .unwrap()
            })
            .await;
        self.peer
            .call(|entity| {
                entity
                    .consume_withdrawal_non_initiator_st_output_1(
                        withdrawal_non_initiator_st_output_1,
                    )
                    .unwrap()
            })
            .await;
        let withdrawal_non_initiator_st_input_1 = self
            .peer
            .call(|entity| {
                entity
                    .produce_withdrawal_non_initiator_st_input_1()
                    .unwrap()
            })
            .await;
        self.st
            .call(|entity| {
                entity
                    .consume_withdrawal_non_initiator_st_input_1(
                        withdrawal_non_initiator_st_input_1,
                    )
                    .unwrap()
            })
            .await;
        let withdrawal_non_initiator_st_non_initiator_niso_message_1 = self
            .st
            .call(|entity| {
                entity
                    .produce_withdrawal_non_initiator_st_non_initiator_niso_message_1()
                    .unwrap()
            })
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_withdrawal_non_initiator_st_non_initiator_niso_message_1(
                        withdrawal_non_initiator_st_non_initiator_niso_message_1,
                    )
                    .unwrap()
            })
            .await;
        let withdrawal_non_initiator_niso_non_initiator_boomlet_message_3 = self
            .niso
            .call(|entity| {
                entity
                    .produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_3()
                    .unwrap()
            })
            .await;
        self.boomlet
            .call(|entity| {
                entity
                    .consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_3(
                        withdrawal_non_initiator_niso_non_initiator_boomlet_message_3,
                    )
                    .unwrap()
            })
            .await;
        let withdrawal_non_initiator_boomlet_non_initiator_niso_message_3 = self
            .boomlet
            .call(|entity| {
                entity
                    .produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_3()
                    .unwrap()
            })
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_3(
                        withdrawal_non_initiator_boomlet_non_initiator_niso_message_3,
                    )
                    .unwrap()
            })
            .await;

        let reply = self
            .niso
            .call(|entity| {
                entity
                    .produce_withdrawal_non_initiator_niso_wt_message_1()
                    .unwrap()
            })
            .await;
        self.send_to_wt(PeerToWtEnvelope::WithdrawalNonInitiatorNisoWtMessage1 {
            wt_peer_id: self.own_wt_peer_id().await,
            msg: reply,
        })
        .await;
        self.log_withdrawal_step("sent non-initiator approval response to WT");
    }

    async fn handle_initiator_tx_aggregation(&mut self, message: WithdrawalWtNisoMessage1) {
        self.niso
            .call(|entity| {
                entity
                    .consume_withdrawal_wt_niso_message_1(message)
                    .unwrap()
            })
            .await;
        let withdrawal_niso_boomlet_message_3 = self
            .niso
            .call(|entity| entity.produce_withdrawal_niso_boomlet_message_3().unwrap())
            .await;
        self.boomlet
            .call(|entity| {
                entity
                    .consume_withdrawal_niso_boomlet_message_3(withdrawal_niso_boomlet_message_3)
                    .unwrap()
            })
            .await;
        let withdrawal_boomlet_niso_message_3 = self
            .boomlet
            .call(|entity| entity.produce_withdrawal_boomlet_niso_message_3().unwrap())
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_withdrawal_boomlet_niso_message_3(withdrawal_boomlet_niso_message_3)
                    .unwrap()
            })
            .await;
        let withdrawal_niso_st_message_2 = self
            .niso
            .call(|entity| entity.produce_withdrawal_niso_st_message_2().unwrap())
            .await;
        self.st
            .call(|entity| {
                entity
                    .consume_withdrawal_niso_st_message_2(withdrawal_niso_st_message_2)
                    .unwrap()
            })
            .await;
        let withdrawal_st_output_2 = self
            .st
            .call(|entity| entity.produce_withdrawal_st_output_2().unwrap())
            .await;
        self.peer
            .call(|entity| {
                entity
                    .consume_withdrawal_st_output_2(withdrawal_st_output_2)
                    .unwrap()
            })
            .await;
        let withdrawal_st_input_2 = self
            .peer
            .call(|entity| entity.produce_withdrawal_st_input_2().unwrap())
            .await;
        self.st
            .call(|entity| {
                entity
                    .consume_withdrawal_st_input_2(withdrawal_st_input_2)
                    .unwrap()
            })
            .await;
        let withdrawal_st_niso_message_2 = self
            .st
            .call(|entity| entity.produce_withdrawal_st_niso_message_2().unwrap())
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_withdrawal_st_niso_message_2(withdrawal_st_niso_message_2)
                    .unwrap()
            })
            .await;
        let withdrawal_niso_boomlet_message_4 = self
            .niso
            .call(|entity| entity.produce_withdrawal_niso_boomlet_message_4().unwrap())
            .await;
        self.boomlet
            .call(|entity| {
                entity
                    .consume_withdrawal_niso_boomlet_message_4(withdrawal_niso_boomlet_message_4)
                    .unwrap()
            })
            .await;
        let withdrawal_boomlet_niso_message_4 = self
            .boomlet
            .call(|entity| entity.produce_withdrawal_boomlet_niso_message_4().unwrap())
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_withdrawal_boomlet_niso_message_4(withdrawal_boomlet_niso_message_4)
                    .unwrap()
            })
            .await;

        let reply = self
            .niso
            .call(|entity| entity.produce_withdrawal_niso_wt_message_2().unwrap())
            .await;
        self.send_to_wt(PeerToWtEnvelope::WithdrawalNisoWtMessage2 {
            wt_peer_id: self.own_wt_peer_id().await,
            msg: reply,
        })
        .await;
        self.log_withdrawal_step("sent initiator aggregation data to WT");
    }

    async fn handle_non_initiator_ack_phase(
        &mut self,
        message: WithdrawalWtNonInitiatorNisoMessage2,
    ) {
        self.niso
            .call(|entity| {
                entity
                    .consume_withdrawal_wt_non_initiator_niso_message_2(message)
                    .unwrap()
            })
            .await;
        let withdrawal_non_initiator_niso_non_initiator_boomlet_message_4 = self
            .niso
            .call(|entity| {
                entity
                    .produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_4()
                    .unwrap()
            })
            .await;
        self.boomlet
            .call(|entity| {
                entity
                    .consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_4(
                        withdrawal_non_initiator_niso_non_initiator_boomlet_message_4,
                    )
                    .unwrap()
            })
            .await;
        let withdrawal_non_initiator_boomlet_non_initiator_niso_message_4 = self
            .boomlet
            .call(|entity| {
                entity
                    .produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_4()
                    .unwrap()
            })
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_4(
                        withdrawal_non_initiator_boomlet_non_initiator_niso_message_4,
                    )
                    .unwrap()
            })
            .await;
        let withdrawal_non_initiator_niso_non_initiator_st_message_2 = self
            .niso
            .call(|entity| {
                entity
                    .produce_withdrawal_non_initiator_niso_non_initiator_st_message_2()
                    .unwrap()
            })
            .await;
        self.st
            .call(|entity| {
                entity
                    .consume_withdrawal_non_initiator_niso_non_initiator_st_message_2(
                        withdrawal_non_initiator_niso_non_initiator_st_message_2,
                    )
                    .unwrap()
            })
            .await;
        let withdrawal_non_initiator_st_output_2 = self
            .st
            .call(|entity| {
                entity
                    .produce_withdrawal_non_initiator_st_output_2()
                    .unwrap()
            })
            .await;
        self.peer
            .call(|entity| {
                entity
                    .consume_withdrawal_non_initiator_st_output_2(
                        withdrawal_non_initiator_st_output_2,
                    )
                    .unwrap()
            })
            .await;
        let withdrawal_non_initiator_st_input_2 = self
            .peer
            .call(|entity| {
                entity
                    .produce_withdrawal_non_initiator_st_input_2()
                    .unwrap()
            })
            .await;
        self.st
            .call(|entity| {
                entity
                    .consume_withdrawal_non_initiator_st_input_2(
                        withdrawal_non_initiator_st_input_2,
                    )
                    .unwrap()
            })
            .await;
        let withdrawal_non_initiator_st_non_initiator_niso_message_2 = self
            .st
            .call(|entity| {
                entity
                    .produce_withdrawal_non_initiator_st_non_initiator_niso_message_2()
                    .unwrap()
            })
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_withdrawal_non_initiator_st_non_initiator_niso_message_2(
                        withdrawal_non_initiator_st_non_initiator_niso_message_2,
                    )
                    .unwrap()
            })
            .await;
        let withdrawal_non_initiator_niso_non_initiator_boomlet_message_5 = self
            .niso
            .call(|entity| {
                entity
                    .produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_5()
                    .unwrap()
            })
            .await;
        self.boomlet
            .call(|entity| {
                entity
                    .consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_5(
                        withdrawal_non_initiator_niso_non_initiator_boomlet_message_5,
                    )
                    .unwrap()
            })
            .await;
        let withdrawal_non_initiator_boomlet_non_initiator_niso_message_5 = self
            .boomlet
            .call(|entity| {
                entity
                    .produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_5()
                    .unwrap()
            })
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_5(
                        withdrawal_non_initiator_boomlet_non_initiator_niso_message_5,
                    )
                    .unwrap()
            })
            .await;

        let reply = self
            .niso
            .call(|entity| {
                entity
                    .produce_withdrawal_non_initiator_niso_wt_message_2()
                    .unwrap()
            })
            .await;
        self.send_to_wt(PeerToWtEnvelope::WithdrawalNonInitiatorNisoWtMessage2 {
            wt_peer_id: self.own_wt_peer_id().await,
            msg: reply,
        })
        .await;
        self.log_withdrawal_step("sent non-initiator acknowledgement to WT");
    }

    async fn handle_non_initiator_commit_phase(
        &mut self,
        message: WithdrawalWtNonInitiatorNisoMessage3,
    ) {
        self.niso
            .call(|entity| {
                entity
                    .consume_withdrawal_wt_non_initiator_niso_message_3(message)
                    .unwrap()
            })
            .await;
        let withdrawal_non_initiator_niso_non_initiator_boomlet_message_6 = self
            .niso
            .call(|entity| {
                entity
                    .produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_6()
                    .unwrap()
            })
            .await;
        self.boomlet
            .call(|entity| {
                entity
                    .consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_6(
                        withdrawal_non_initiator_niso_non_initiator_boomlet_message_6,
                    )
                    .unwrap()
            })
            .await;
        let withdrawal_non_initiator_boomlet_non_initiator_niso_message_6 = self
            .boomlet
            .call(|entity| {
                entity
                    .produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_6()
                    .unwrap()
            })
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_6(
                        withdrawal_non_initiator_boomlet_non_initiator_niso_message_6,
                    )
                    .unwrap()
            })
            .await;

        let reply = self
            .niso
            .call(|entity| {
                entity
                    .produce_withdrawal_non_initiator_niso_wt_message_3()
                    .unwrap()
            })
            .await;
        self.send_to_wt(PeerToWtEnvelope::WithdrawalNonInitiatorNisoWtMessage3 {
            wt_peer_id: self.own_wt_peer_id().await,
            msg: reply,
        })
        .await;
        self.log_withdrawal_step("sent non-initiator commit confirmation to WT");
    }

    async fn handle_post_commit_phase(&mut self, message: WithdrawalWtNisoMessage2) {
        self.niso
            .call(|entity| {
                entity
                    .consume_withdrawal_wt_niso_message_2(message)
                    .unwrap()
            })
            .await;
        let withdrawal_niso_boomlet_message_5 = self
            .niso
            .call(|entity| entity.produce_withdrawal_niso_boomlet_message_5().unwrap())
            .await;
        self.boomlet
            .call(|entity| {
                entity
                    .consume_withdrawal_niso_boomlet_message_5(withdrawal_niso_boomlet_message_5)
                    .unwrap()
            })
            .await;
        let withdrawal_boomlet_niso_message_5 = self
            .boomlet
            .call(|entity| entity.produce_withdrawal_boomlet_niso_message_5().unwrap())
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_withdrawal_boomlet_niso_message_5(withdrawal_boomlet_niso_message_5)
                    .unwrap()
            })
            .await;

        let reply = self
            .niso
            .call(|entity| entity.produce_withdrawal_niso_wt_message_3().unwrap())
            .await;
        self.send_to_wt(PeerToWtEnvelope::WithdrawalNisoWtMessage3 {
            wt_peer_id: self.own_wt_peer_id().await,
            msg: reply,
        })
        .await;
        self.log_withdrawal_step("sent first digging ping to WT");
    }

    async fn run_ping_pong_loop(&mut self) {
        let mut ping_pong_round = 1usize;
        loop {
            match self.recv_from_wt().await {
                WtToPeerEnvelope::WithdrawalWtNisoMessage3(message) => {
                    debug!("PeerActor {}: received WT pong.", self.peer_number());
                    self.niso
                        .call(|entity| {
                            entity
                                .consume_withdrawal_wt_niso_message_3(message)
                                .unwrap()
                        })
                        .await;
                    let withdrawal_niso_boomlet_message_6 = self
                        .niso
                        .call(|entity| entity.produce_withdrawal_niso_boomlet_message_6().unwrap())
                        .await;
                    self.boomlet
                        .call(|entity| {
                            entity
                                .consume_withdrawal_niso_boomlet_message_6(
                                    withdrawal_niso_boomlet_message_6,
                                )
                                .unwrap()
                        })
                        .await;

                    if let BranchingMessage2::First(withdrawal_boomlet_niso_message_6) = self
                        .boomlet
                        .call(|entity| {
                            entity
                                .produce_withdrawal_boomlet_niso_message_6_or_produce_nothing()
                                .unwrap()
                        })
                        .await
                    {
                        self.niso
                            .call(|entity| {
                                entity
                                    .consume_withdrawal_boomlet_niso_message_6(
                                        withdrawal_boomlet_niso_message_6,
                                    )
                                    .unwrap()
                            })
                            .await;
                        let withdrawal_niso_st_message_3 = self
                            .niso
                            .call(|entity| entity.produce_withdrawal_niso_st_message_3().unwrap())
                            .await;
                        self.st
                            .call(|entity| {
                                entity
                                    .consume_withdrawal_niso_st_message_3(
                                        withdrawal_niso_st_message_3,
                                    )
                                    .unwrap()
                            })
                            .await;
                        let withdrawal_st_output_3 = self
                            .st
                            .call(|entity| entity.produce_withdrawal_st_output_3().unwrap())
                            .await;
                        self.peer
                            .call(|entity| {
                                entity
                                    .consume_withdrawal_st_output_3(withdrawal_st_output_3)
                                    .unwrap()
                            })
                            .await;
                        let withdrawal_st_input_3 = self
                            .peer
                            .call(|entity| entity.produce_withdrawal_st_input_3().unwrap())
                            .await;
                        self.st
                            .call(|entity| {
                                entity
                                    .consume_withdrawal_st_input_3(withdrawal_st_input_3)
                                    .unwrap()
                            })
                            .await;
                        let withdrawal_st_niso_message_3 = self
                            .st
                            .call(|entity| entity.produce_withdrawal_st_niso_message_3().unwrap())
                            .await;
                        self.niso
                            .call(|entity| {
                                entity
                                    .consume_withdrawal_st_niso_message_3(
                                        withdrawal_st_niso_message_3,
                                    )
                                    .unwrap()
                            })
                            .await;
                        let withdrawal_niso_boomlet_message_7 = self
                            .niso
                            .call(|entity| {
                                entity.produce_withdrawal_niso_boomlet_message_7().unwrap()
                            })
                            .await;
                        self.boomlet
                            .call(|entity| {
                                entity
                                    .consume_withdrawal_niso_boomlet_message_7(
                                        withdrawal_niso_boomlet_message_7,
                                    )
                                    .unwrap()
                            })
                            .await;
                    }

                    let withdrawal_boomlet_niso_message_7 = self
                        .boomlet
                        .call(|entity| entity.produce_withdrawal_boomlet_niso_message_7().unwrap())
                        .await;
                    self.niso
                        .call(|entity| {
                            entity
                                .consume_withdrawal_boomlet_niso_message_7(
                                    withdrawal_boomlet_niso_message_7,
                                )
                                .unwrap()
                        })
                        .await;
                    let reply = self
                        .niso
                        .call(|entity| entity.produce_withdrawal_niso_wt_message_4().unwrap())
                        .await;
                    self.send_to_wt(PeerToWtEnvelope::WithdrawalNisoWtMessage4 {
                        wt_peer_id: self.own_wt_peer_id().await,
                        msg: reply,
                    })
                    .await;
                    debug!("PeerActor {}: sent ping back to WT.", self.peer_number());
                    ping_pong_round += 1;
                }
                WtToPeerEnvelope::WithdrawalWtNisoMessage4(message) => {
                    debug!(
                        "PeerActor {}: received final reached-pings message.",
                        self.peer_number()
                    );
                    self.niso
                        .call(|entity| {
                            entity
                                .consume_withdrawal_wt_niso_message_4(message)
                                .unwrap()
                        })
                        .await;
                    let completed_rounds = ping_pong_round.saturating_sub(1);
                    self.log_withdrawal_step(&format!(
                        "WT released the final signing stage after {completed_rounds} digging rounds"
                    ));
                    break;
                }
                _ => panic!("PeerActor: unexpected WT envelope during ping-pong"),
            }
        }
    }

    async fn finish_signing(&mut self) {
        let withdrawal_niso_boomlet_message_8 = self
            .niso
            .call(|entity| entity.produce_withdrawal_niso_boomlet_message_8().unwrap())
            .await;
        self.boomlet
            .call(|entity| {
                entity
                    .consume_withdrawal_niso_boomlet_message_8(withdrawal_niso_boomlet_message_8)
                    .unwrap()
            })
            .await;
        let withdrawal_boomlet_niso_message_8 = self
            .boomlet
            .call(|entity| entity.produce_withdrawal_boomlet_niso_message_8().unwrap())
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_withdrawal_boomlet_niso_message_8(withdrawal_boomlet_niso_message_8)
                    .unwrap()
            })
            .await;
        let withdrawal_niso_output_1 = self
            .niso
            .call(|entity| entity.produce_withdrawal_niso_output_1().unwrap())
            .await;
        self.peer
            .call(|entity| {
                entity
                    .consume_withdrawal_niso_output_1(withdrawal_niso_output_1)
                    .unwrap()
            })
            .await;
        let withdrawal_iso_input_1 = self
            .peer
            .call(|entity| entity.produce_withdrawal_iso_input_1().unwrap())
            .await;
        self.iso
            .call(|entity| {
                entity
                    .consume_withdrawal_iso_input_1(withdrawal_iso_input_1)
                    .unwrap()
            })
            .await;
        let withdrawal_iso_boomlet_message_1 = self
            .iso
            .call(|entity| entity.produce_withdrawal_iso_boomlet_message_1().unwrap())
            .await;
        self.boomlet
            .call(|entity| {
                entity
                    .consume_withdrawal_iso_boomlet_message_1(withdrawal_iso_boomlet_message_1)
                    .unwrap()
            })
            .await;
        let withdrawal_boomlet_iso_message_1 = self
            .boomlet
            .call(|entity| entity.produce_withdrawal_boomlet_iso_message_1().unwrap())
            .await;
        self.iso
            .call(|entity| {
                entity
                    .consume_withdrawal_boomlet_iso_message_1(withdrawal_boomlet_iso_message_1)
                    .unwrap()
            })
            .await;
        let withdrawal_iso_boomlet_message_2 = self
            .iso
            .call(|entity| entity.produce_withdrawal_iso_boomlet_message_2().unwrap())
            .await;
        self.boomlet
            .call(|entity| {
                entity
                    .consume_withdrawal_iso_boomlet_message_2(withdrawal_iso_boomlet_message_2)
                    .unwrap()
            })
            .await;
        let withdrawal_boomlet_iso_message_2 = self
            .boomlet
            .call(|entity| entity.produce_withdrawal_boomlet_iso_message_2().unwrap())
            .await;
        self.iso
            .call(|entity| {
                entity
                    .consume_withdrawal_boomlet_iso_message_2(withdrawal_boomlet_iso_message_2)
                    .unwrap()
            })
            .await;
        let withdrawal_iso_output_1 = self
            .iso
            .call(|entity| entity.produce_withdrawal_iso_output_1().unwrap())
            .await;
        self.peer
            .call(|entity| {
                entity
                    .consume_withdrawal_iso_output_1(withdrawal_iso_output_1)
                    .unwrap()
            })
            .await;
        let withdrawal_niso_input_2 = self
            .peer
            .call(|entity| entity.produce_withdrawal_niso_input_2().unwrap())
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_withdrawal_niso_input_2(withdrawal_niso_input_2)
                    .unwrap()
            })
            .await;
        let withdrawal_niso_boomlet_message_9 = self
            .niso
            .call(|entity| entity.produce_withdrawal_niso_boomlet_message_9().unwrap())
            .await;
        self.boomlet
            .call(|entity| {
                entity
                    .consume_withdrawal_niso_boomlet_message_9(withdrawal_niso_boomlet_message_9)
                    .unwrap()
            })
            .await;
        let withdrawal_boomlet_niso_message_9 = self
            .boomlet
            .call(|entity| entity.produce_withdrawal_boomlet_niso_message_9().unwrap())
            .await;
        self.niso
            .call(|entity| {
                entity
                    .consume_withdrawal_boomlet_niso_message_9(withdrawal_boomlet_niso_message_9)
                    .unwrap()
            })
            .await;
        let signed_psbt_message = self
            .niso
            .call(|entity| entity.produce_withdrawal_niso_wt_message_5().unwrap())
            .await;
        self.send_to_wt(PeerToWtEnvelope::WithdrawalNisoWtMessage5 {
            wt_peer_id: self.own_wt_peer_id().await,
            msg: signed_psbt_message,
        })
        .await;
        self.log_withdrawal_step("sent signed PSBT back to WT");
        debug!("PeerActor {}: sent signed PSBT to WT.", self.peer_number());
    }
}
