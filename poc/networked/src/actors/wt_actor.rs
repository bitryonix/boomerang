/// WT actor: owns a single pre-initialized `Wt` protocol entity and drives it
/// through the full setup and withdrawal message sequences.
///
/// The WT is pre-initialized by `Network` before the actor is constructed.
///
/// Channel layout (all Vecs are indexed 0..NUM_PEERS / 0..NUM_SARS):
///   peer_rxs[i]        – receives messages from peer i's NISO
///   peer_txs[i]        – sends messages to peer i's NISO
///   sar_rxs[i]         – receives messages from SAR i
///   sar_txs[i]         – sends messages to SAR i
///   sar_id_to_channel  – maps SarId → sar channel index (pre-built by Network)
///
/// Peer 0 is always the withdrawal initiator.
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use cryptography::PublicKey;
use protocol::{
    constructs::{SarId, WtPeerId},
    messages::{BranchingMessage2, MetadataAttachedMessage, Parcel},
};
use tokio::sync::{Barrier, mpsc};
use tracing::{debug, info};
use wt::Wt;

use crate::envelopes::{PeerToWtEnvelope, SarToWtEnvelope, WtToPeerEnvelope, WtToSarEnvelope};

pub struct WtActor {
    wt: Wt,
    peer_rxs: Vec<mpsc::Receiver<PeerToWtEnvelope>>,
    peer_txs: Vec<mpsc::Sender<WtToPeerEnvelope>>,
    sar_rxs: Vec<mpsc::Receiver<SarToWtEnvelope>>,
    sar_txs: Vec<mpsc::Sender<WtToSarEnvelope>>,
    sar_id_to_channel: BTreeMap<SarId, usize>,
    setup_barrier: Arc<Barrier>,
}

impl WtActor {
    pub fn new(
        wt: Wt,
        peer_rxs: Vec<mpsc::Receiver<PeerToWtEnvelope>>,
        peer_txs: Vec<mpsc::Sender<WtToPeerEnvelope>>,
        sar_rxs: Vec<mpsc::Receiver<SarToWtEnvelope>>,
        sar_txs: Vec<mpsc::Sender<WtToSarEnvelope>>,
        sar_id_to_channel: BTreeMap<SarId, usize>,
        setup_barrier: Arc<Barrier>,
    ) -> Self {
        Self {
            wt,
            peer_rxs,
            peer_txs,
            sar_rxs,
            sar_txs,
            sar_id_to_channel,
            setup_barrier,
        }
    }

    pub async fn run(mut self) {
        let num_peers = self.peer_rxs.len();
        let num_sars = self.sar_rxs.len();

        info!("WtActor: starting setup with {num_peers} peers and {num_sars} SARs.");

        // ── Setup phase ──────────────────────────────────────────────────────

        // Collect SetupNisoWtMessage1 from all peers.
        // Build boomlet_pubkey → channel_idx for subsequent routing.
        let mut boomlet_pubkey_to_channel: HashMap<PublicKey, usize> = HashMap::new();
        let mut msg1_items: Vec<MetadataAttachedMessage<PublicKey, _>> = Vec::new();
        for idx in 0..num_peers {
            match self.peer_rxs[idx].recv().await.unwrap() {
                PeerToWtEnvelope::SetupNisoWtMessage1 {
                    boomlet_identity_pubkey,
                    msg,
                } => {
                    boomlet_pubkey_to_channel.insert(boomlet_identity_pubkey, idx);
                    msg1_items.push(MetadataAttachedMessage::new(boomlet_identity_pubkey, msg));
                }
                _ => panic!("WtActor: expected SetupNisoWtMessage1 from peer {idx}"),
            }
        }
        self.wt
            .consume_setup_niso_wt_message_1(Parcel::new(msg1_items))
            .unwrap();
        debug!("WtActor: consumed SetupNisoWtMessage1 from all peers.");
        info!("WtActor: collected peer identities and opening WT sessions.");

        // Produce SetupWtNisoMessage1 → route to each peer by WtPeerId.
        // Also build wt_peer_id → channel_idx for all subsequent WT→Peer routing.
        let wt_niso_msg1_parcel = self.wt.produce_setup_wt_niso_message_1().unwrap();
        let mut wt_peer_id_to_channel: HashMap<WtPeerId, usize> = HashMap::new();
        for item in wt_niso_msg1_parcel.open() {
            let (wt_peer_id, msg) = item.into_parts();
            let idx = *boomlet_pubkey_to_channel
                .get(wt_peer_id.get_boomlet_identity_pubkey())
                .unwrap();
            wt_peer_id_to_channel.insert(wt_peer_id, idx);
            self.peer_txs[idx]
                .send(WtToPeerEnvelope::SetupWtNisoMessage1(msg))
                .await
                .unwrap();
        }
        debug!("WtActor: sent SetupWtNisoMessage1 to all peers.");

        // Collect SetupNisoWtMessage2 from all peers.
        let mut msg2_items: Vec<MetadataAttachedMessage<WtPeerId, _>> = Vec::new();
        for idx in 0..num_peers {
            match self.peer_rxs[idx].recv().await.unwrap() {
                PeerToWtEnvelope::SetupNisoWtMessage2 { wt_peer_id, msg } => {
                    msg2_items.push(MetadataAttachedMessage::new(wt_peer_id, msg));
                }
                _ => panic!("WtActor: expected SetupNisoWtMessage2 from peer {idx}"),
            }
        }
        self.wt
            .consume_setup_niso_wt_message_2(Parcel::new(msg2_items))
            .unwrap();

        // Produce SetupWtNisoMessage2 → route to each peer.
        let wt_niso_msg2_parcel = self.wt.produce_setup_wt_niso_message_2().unwrap();
        for item in wt_niso_msg2_parcel.open() {
            let (wt_peer_id, msg) = item.into_parts();
            let idx = wt_peer_id_to_channel[&wt_peer_id];
            self.peer_txs[idx]
                .send(WtToPeerEnvelope::SetupWtNisoMessage2(msg))
                .await
                .unwrap();
        }
        debug!("WtActor: setup round 2 done.");

        // Collect SetupNisoWtMessage3 from all peers (contains SarIds).
        let mut msg3_items: Vec<MetadataAttachedMessage<WtPeerId, _>> = Vec::new();
        for idx in 0..num_peers {
            match self.peer_rxs[idx].recv().await.unwrap() {
                PeerToWtEnvelope::SetupNisoWtMessage3 { wt_peer_id, msg } => {
                    msg3_items.push(MetadataAttachedMessage::new(wt_peer_id, msg));
                }
                _ => panic!("WtActor: expected SetupNisoWtMessage3 from peer {idx}"),
            }
        }
        self.wt
            .consume_setup_niso_wt_message_3(Parcel::new(msg3_items))
            .unwrap();
        info!("WtActor: learned peer-to-SAR assignments and is finalizing SAR registration.");

        // Produce SetupWtSarMessage1 → route to each SAR by SarId.
        let wt_sar_msg1_parcel = self.wt.produce_setup_wt_sar_message_1().unwrap();
        for item in wt_sar_msg1_parcel.open() {
            let (sar_id, msg) = item.into_parts();
            let idx = self.sar_id_to_channel[&sar_id];
            self.sar_txs[idx]
                .send(WtToSarEnvelope::SetupWtSarMessage1(msg))
                .await
                .unwrap();
        }

        // Collect SetupSarWtMessage1 from all SARs.
        let mut sar_msg1_items: Vec<MetadataAttachedMessage<SarId, _>> = Vec::new();
        for idx in 0..num_sars {
            match self.sar_rxs[idx].recv().await.unwrap() {
                SarToWtEnvelope::SetupSarWtMessage1 { sar_id, msg } => {
                    sar_msg1_items.push(MetadataAttachedMessage::new(sar_id, *msg));
                }
                _ => panic!("WtActor: expected SetupSarWtMessage1 from SAR {idx}"),
            }
        }
        self.wt
            .consume_setup_sar_wt_message_1(Parcel::new(sar_msg1_items))
            .unwrap();
        info!("WtActor: SAR registration complete; releasing final setup state to peers.");

        // Produce SetupWtNisoMessage3 → route to each peer.
        let wt_niso_msg3_parcel = self.wt.produce_setup_wt_niso_message_3().unwrap();
        for item in wt_niso_msg3_parcel.open() {
            let (wt_peer_id, msg) = item.into_parts();
            let idx = wt_peer_id_to_channel[&wt_peer_id];
            self.peer_txs[idx]
                .send(WtToPeerEnvelope::SetupWtNisoMessage3(msg))
                .await
                .unwrap();
        }

        info!("WtActor: setup complete.");
        self.setup_barrier.wait().await;

        // ── Withdrawal phase ─────────────────────────────────────────────────
        // Peer 0 is the withdrawal initiator.

        // Receive WithdrawalNisoWtMessage1 from initiator (peer 0).
        let (initiator_wt_peer_id, wd_msg1) = match self.peer_rxs[0].recv().await.unwrap() {
            PeerToWtEnvelope::WithdrawalNisoWtMessage1 { wt_peer_id, msg } => (wt_peer_id, msg),
            _ => panic!("WtActor: expected WithdrawalNisoWtMessage1 from initiator"),
        };
        self.wt
            .consume_withdrawal_niso_wt_message_1(MetadataAttachedMessage::new(
                initiator_wt_peer_id.clone(),
                wd_msg1,
            ))
            .unwrap();
        info!(
            "WtActor: received initiator withdrawal request; collecting non-initiator approvals."
        );

        // Produce → non-initiator peers (channels 1..NUM_PEERS).
        let ni_msg1_parcel = self
            .wt
            .produce_withdrawal_wt_non_initiator_niso_message_1()
            .unwrap();
        for item in ni_msg1_parcel.open() {
            let (wt_peer_id, msg) = item.into_parts();
            let idx = wt_peer_id_to_channel[&wt_peer_id];
            self.peer_txs[idx]
                .send(WtToPeerEnvelope::WithdrawalWtNonInitiatorNisoMessage1(msg))
                .await
                .unwrap();
        }

        // Collect WithdrawalNonInitiatorNisoWtMessage1 from non-initiator peers.
        let mut ni_niso_msg1_items: Vec<MetadataAttachedMessage<WtPeerId, _>> = Vec::new();
        for idx in 1..num_peers {
            match self.peer_rxs[idx].recv().await.unwrap() {
                PeerToWtEnvelope::WithdrawalNonInitiatorNisoWtMessage1 { wt_peer_id, msg } => {
                    ni_niso_msg1_items.push(MetadataAttachedMessage::new(wt_peer_id, msg));
                }
                _ => {
                    panic!("WtActor: expected WithdrawalNonInitiatorNisoWtMessage1 from peer {idx}")
                }
            }
        }
        self.wt
            .consume_withdrawal_non_initiator_niso_wt_message_1(Parcel::new(ni_niso_msg1_items))
            .unwrap();

        // Produce → non-initiator peers.
        let ni_msg2_parcel = self
            .wt
            .produce_withdrawal_wt_non_initiator_niso_message_2()
            .unwrap();
        for item in ni_msg2_parcel.open() {
            let (wt_peer_id, msg) = item.into_parts();
            let idx = wt_peer_id_to_channel[&wt_peer_id];
            self.peer_txs[idx]
                .send(WtToPeerEnvelope::WithdrawalWtNonInitiatorNisoMessage2(msg))
                .await
                .unwrap();
        }

        // Collect WithdrawalNonInitiatorNisoWtMessage2 from non-initiator peers.
        let mut ni_niso_msg2_items: Vec<MetadataAttachedMessage<WtPeerId, _>> = Vec::new();
        for idx in 1..num_peers {
            match self.peer_rxs[idx].recv().await.unwrap() {
                PeerToWtEnvelope::WithdrawalNonInitiatorNisoWtMessage2 { wt_peer_id, msg } => {
                    ni_niso_msg2_items.push(MetadataAttachedMessage::new(wt_peer_id, msg));
                }
                _ => {
                    panic!("WtActor: expected WithdrawalNonInitiatorNisoWtMessage2 from peer {idx}")
                }
            }
        }
        self.wt
            .consume_withdrawal_non_initiator_niso_wt_message_2(Parcel::new(ni_niso_msg2_items))
            .unwrap();
        debug!("WtActor: non-initiator tx approval phase done.");
        info!(
            "WtActor: non-initiator approvals collected; asking initiator to aggregate the transaction."
        );

        // Produce WithdrawalWtNisoMessage1 (single) → initiator peer only.
        let wt_niso_wd_msg1 = self.wt.produce_withdrawal_wt_niso_message_1().unwrap();
        self.peer_txs[0]
            .send(WtToPeerEnvelope::WithdrawalWtNisoMessage1(wt_niso_wd_msg1))
            .await
            .unwrap();

        // Receive WithdrawalNisoWtMessage2 (single) from initiator.
        let wd_msg2 = match self.peer_rxs[0].recv().await.unwrap() {
            PeerToWtEnvelope::WithdrawalNisoWtMessage2 { wt_peer_id, msg } => {
                assert_eq!(
                    wt_peer_id, initiator_wt_peer_id,
                    "WtActor: initiator changed WT peer id during withdrawal"
                );
                msg
            }
            _ => panic!("WtActor: expected WithdrawalNisoWtMessage2 from initiator"),
        };
        self.wt
            .consume_withdrawal_niso_wt_message_2(wd_msg2)
            .unwrap();
        info!("WtActor: initiator aggregation received; starting initiator-side SAR duress check.");

        // Produce → all SARs (initiator duress check).
        let wt_sar_wd_msg1_parcel = self.wt.produce_withdrawal_wt_sar_message_1().unwrap();
        let mut initiator_sar_channels: Vec<usize> = Vec::new();
        for item in wt_sar_wd_msg1_parcel.open() {
            let (sar_id, msg) = item.into_parts();
            let idx = self.sar_id_to_channel[&sar_id];
            initiator_sar_channels.push(idx);
            self.sar_txs[idx]
                .send(WtToSarEnvelope::WithdrawalWtSarMessage1(msg))
                .await
                .unwrap();
        }

        // Collect WithdrawalSarWtMessage1 from the SARs that received it.
        let mut sar_wd_msg1_items: Vec<MetadataAttachedMessage<SarId, _>> = Vec::new();
        for idx in initiator_sar_channels {
            match self.sar_rxs[idx].recv().await.unwrap() {
                SarToWtEnvelope::WithdrawalSarWtMessage1 { sar_id, msg } => {
                    sar_wd_msg1_items.push(MetadataAttachedMessage::new(sar_id, msg));
                }
                _ => panic!("WtActor: expected WithdrawalSarWtMessage1 from SAR {idx}"),
            }
        }
        self.wt
            .consume_withdrawal_sar_wt_message_1(Parcel::new(sar_wd_msg1_items))
            .unwrap();
        debug!("WtActor: initiator SAR duress check done.");
        info!("WtActor: initiator-side SAR checks complete; requesting non-initiator commits.");

        // Produce → non-initiator peers (tx commit phase).
        let ni_msg3_parcel = self
            .wt
            .produce_withdrawal_wt_non_initiator_niso_message_3()
            .unwrap();
        for item in ni_msg3_parcel.open() {
            let (wt_peer_id, msg) = item.into_parts();
            let idx = wt_peer_id_to_channel[&wt_peer_id];
            self.peer_txs[idx]
                .send(WtToPeerEnvelope::WithdrawalWtNonInitiatorNisoMessage3(msg))
                .await
                .unwrap();
        }

        // Collect WithdrawalNonInitiatorNisoWtMessage3 from non-initiator peers.
        let mut ni_niso_msg3_items: Vec<MetadataAttachedMessage<WtPeerId, _>> = Vec::new();
        for idx in 1..num_peers {
            match self.peer_rxs[idx].recv().await.unwrap() {
                PeerToWtEnvelope::WithdrawalNonInitiatorNisoWtMessage3 { wt_peer_id, msg } => {
                    ni_niso_msg3_items.push(MetadataAttachedMessage::new(wt_peer_id, msg));
                }
                _ => {
                    panic!("WtActor: expected WithdrawalNonInitiatorNisoWtMessage3 from peer {idx}")
                }
            }
        }
        self.wt
            .consume_withdrawal_non_initiator_niso_wt_message_3(Parcel::new(ni_niso_msg3_items))
            .unwrap();
        info!("WtActor: non-initiator commits collected; starting non-initiator SAR duress check.");

        // Produce → non-initiator SARs (non-initiator duress check).
        // Track which SAR channels received the message so we can collect from exactly those.
        let ni_sar_msg1_parcel = self
            .wt
            .produce_withdrawal_wt_non_initiator_sar_message_1()
            .unwrap();
        let mut ni_sar_channels: Vec<usize> = Vec::new();
        for item in ni_sar_msg1_parcel.open() {
            let (sar_id, msg) = item.into_parts();
            let idx = self.sar_id_to_channel[&sar_id];
            ni_sar_channels.push(idx);
            self.sar_txs[idx]
                .send(WtToSarEnvelope::WithdrawalWtNonInitiatorSarMessage1(msg))
                .await
                .unwrap();
        }

        // Collect WithdrawalNonInitiatorSarWtMessage1 from non-initiator SARs.
        let mut ni_sar_msg1_items: Vec<MetadataAttachedMessage<SarId, _>> = Vec::new();
        for idx in ni_sar_channels {
            match self.sar_rxs[idx].recv().await.unwrap() {
                SarToWtEnvelope::WithdrawalNonInitiatorSarWtMessage1 { sar_id, msg } => {
                    ni_sar_msg1_items.push(MetadataAttachedMessage::new(sar_id, msg));
                }
                _ => panic!("WtActor: expected WithdrawalNonInitiatorSarWtMessage1 from SAR {idx}"),
            }
        }
        self.wt
            .consume_withdrawal_non_initiator_sar_wt_message_1(Parcel::new(ni_sar_msg1_items))
            .unwrap();
        debug!("WtActor: non-initiator SAR duress check done.");
        info!(
            "WtActor: all SAR checks complete; distributing the shared withdrawal state to peers."
        );

        // Produce → all peers (PSBT distribution).
        let wt_niso_wd_msg2_parcel = self.wt.produce_withdrawal_wt_niso_message_2().unwrap();
        for item in wt_niso_wd_msg2_parcel.open() {
            let (wt_peer_id, msg) = item.into_parts();
            let idx = wt_peer_id_to_channel[&wt_peer_id];
            self.peer_txs[idx]
                .send(WtToPeerEnvelope::WithdrawalWtNisoMessage2(msg))
                .await
                .unwrap();
        }

        // Collect WithdrawalNisoWtMessage3 (ping) from all peers.
        let mut niso_wd_msg3_items: Vec<MetadataAttachedMessage<WtPeerId, _>> = Vec::new();
        for idx in 0..num_peers {
            match self.peer_rxs[idx].recv().await.unwrap() {
                PeerToWtEnvelope::WithdrawalNisoWtMessage3 { wt_peer_id, msg } => {
                    niso_wd_msg3_items.push(MetadataAttachedMessage::new(wt_peer_id, msg));
                }
                _ => panic!("WtActor: expected WithdrawalNisoWtMessage3 from peer {idx}"),
            }
        }
        self.wt
            .consume_withdrawal_niso_wt_message_3(Parcel::new(niso_wd_msg3_items))
            .unwrap();
        info!("WtActor: received first digging ping from every peer; entering ping-pong loop.");

        // ── Ping-pong loop ────────────────────────────────────────────────────
        let mut ping_pong_round = 1usize;
        loop {
            match self
                .wt
                .produce_withdrawal_wt_sar_message_2_or_produce_withdrawal_wt_niso_message_4()
                .unwrap()
            {
                BranchingMessage2::First(sar_msg2_parcel) => {
                    if ping_pong_round <= 3 || ping_pong_round.is_multiple_of(10) {
                        info!("WtActor: digging round {ping_pong_round} in progress.");
                    }

                    // Send ping to all SARs.
                    for item in sar_msg2_parcel.open() {
                        let (sar_id, msg) = item.into_parts();
                        let idx = self.sar_id_to_channel[&sar_id];
                        self.sar_txs[idx]
                            .send(WtToSarEnvelope::WithdrawalWtSarMessage2(msg))
                            .await
                            .unwrap();
                    }

                    // Collect pong from all SARs.
                    let mut sar_msg2_items: Vec<MetadataAttachedMessage<SarId, _>> = Vec::new();
                    for idx in 0..num_sars {
                        match self.sar_rxs[idx].recv().await.unwrap() {
                            SarToWtEnvelope::WithdrawalSarWtMessage2 { sar_id, msg } => {
                                sar_msg2_items.push(MetadataAttachedMessage::new(sar_id, msg));
                            }
                            _ => panic!("WtActor: expected WithdrawalSarWtMessage2 from SAR {idx}"),
                        }
                    }
                    self.wt
                        .consume_withdrawal_sar_wt_message_2(Parcel::new(sar_msg2_items))
                        .unwrap();

                    // Produce pong → all peers.
                    let pong_parcel = self.wt.produce_withdrawal_wt_niso_message_3().unwrap();
                    for item in pong_parcel.open() {
                        let (wt_peer_id, msg) = item.into_parts();
                        let idx = wt_peer_id_to_channel[&wt_peer_id];
                        self.peer_txs[idx]
                            .send(WtToPeerEnvelope::WithdrawalWtNisoMessage3(msg))
                            .await
                            .unwrap();
                    }
                    debug!("WtActor: sent pong to all peers.");

                    // Collect ping from all peers.
                    let mut niso_msg4_items: Vec<MetadataAttachedMessage<WtPeerId, _>> = Vec::new();
                    for idx in 0..num_peers {
                        match self.peer_rxs[idx].recv().await.unwrap() {
                            PeerToWtEnvelope::WithdrawalNisoWtMessage4 { wt_peer_id, msg } => {
                                niso_msg4_items.push(MetadataAttachedMessage::new(wt_peer_id, msg));
                            }
                            _ => {
                                panic!("WtActor: expected WithdrawalNisoWtMessage4 from peer {idx}")
                            }
                        }
                    }
                    self.wt
                        .consume_withdrawal_niso_wt_message_4(Parcel::new(niso_msg4_items))
                        .unwrap();
                    debug!("WtActor: ping-pong iteration done.");
                    ping_pong_round += 1;
                }

                BranchingMessage2::Second(wt_niso_msg4_parcel) => {
                    let completed_rounds = ping_pong_round.saturating_sub(1);
                    info!(
                        "WtActor: digging threshold reached after {completed_rounds} rounds; requesting final signatures."
                    );
                    // Loop ends – send final message to all peers.
                    for item in wt_niso_msg4_parcel.open() {
                        let (wt_peer_id, msg) = item.into_parts();
                        let idx = wt_peer_id_to_channel[&wt_peer_id];
                        self.peer_txs[idx]
                            .send(WtToPeerEnvelope::WithdrawalWtNisoMessage4(msg))
                            .await
                            .unwrap();
                    }
                    debug!("WtActor: sent final reached-pings message to all peers.");
                    break;
                }
            }
        }

        // Collect WithdrawalNisoWtMessage5 (signed PSBTs) from all peers.
        let mut niso_msg5_items: Vec<MetadataAttachedMessage<WtPeerId, _>> = Vec::new();
        for idx in 0..num_peers {
            match self.peer_rxs[idx].recv().await.unwrap() {
                PeerToWtEnvelope::WithdrawalNisoWtMessage5 { wt_peer_id, msg } => {
                    niso_msg5_items.push(MetadataAttachedMessage::new(wt_peer_id, msg));
                }
                _ => panic!("WtActor: expected WithdrawalNisoWtMessage5 from peer {idx}"),
            }
        }
        self.wt
            .consume_withdrawal_niso_wt_message_5(Parcel::new(niso_msg5_items))
            .unwrap();

        info!("WtActor: withdrawal complete. Signed tx broadcasted.");
    }
}
