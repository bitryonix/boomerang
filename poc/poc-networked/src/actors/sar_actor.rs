/// SAR actor: owns a single `Sar` protocol entity and drives it through the
/// full setup and withdrawal message sequence via typed mpsc channels.
///
/// The `Sar` is pre-initialized by `Network` before the actor is constructed,
/// so `run()` does not call `initialize()`.
///
/// Channels:
///   peer_to_sar_rx  – receives Phone-originated setup messages from the peer actor
///   sar_to_peer_tx  – sends SAR setup responses back to the peer actor
///   wt_to_sar_rx    – receives WT messages (setup finalisation + withdrawal)
///   sar_to_wt_tx    – sends SAR responses to the WT actor
use std::sync::Arc;

use sar::Sar;
use tokio::sync::{Barrier, mpsc};
use tracing::{debug, info};

use crate::envelopes::{PeerToSarEnvelope, SarToPeerEnvelope, SarToWtEnvelope, WtToSarEnvelope};

pub struct SarActor {
    sar: Sar,
    peer_to_sar_rx: mpsc::Receiver<PeerToSarEnvelope>,
    sar_to_peer_tx: mpsc::Sender<SarToPeerEnvelope>,
    wt_to_sar_rx: mpsc::Receiver<WtToSarEnvelope>,
    sar_to_wt_tx: mpsc::Sender<SarToWtEnvelope>,
    setup_barrier: Arc<Barrier>,
}

impl SarActor {
    pub fn new(
        sar: Sar,
        peer_to_sar_rx: mpsc::Receiver<PeerToSarEnvelope>,
        sar_to_peer_tx: mpsc::Sender<SarToPeerEnvelope>,
        wt_to_sar_rx: mpsc::Receiver<WtToSarEnvelope>,
        sar_to_wt_tx: mpsc::Sender<SarToWtEnvelope>,
        setup_barrier: Arc<Barrier>,
    ) -> Self {
        Self {
            sar,
            peer_to_sar_rx,
            sar_to_peer_tx,
            wt_to_sar_rx,
            sar_to_wt_tx,
            setup_barrier,
        }
    }

    pub async fn run(mut self) {
        // SAR is pre-initialized by Network; just retrieve the identity.
        let sar_id = self.sar.get_sar_id().unwrap();
        debug!("SarActor: started (sar_id obtained).");
        info!("SarActor: starting setup and waiting for peer phone messages.");

        // ── Setup phase ──────────────────────────────────────────────────────

        // Step 3: receive SetupPhoneSarMessage1, reply with SetupSarPhoneMessage1
        match self.peer_to_sar_rx.recv().await.unwrap() {
            PeerToSarEnvelope::SetupPhoneSarMessage1(msg) => {
                self.sar.consume_setup_phone_sar_message_1(msg).unwrap();
                let reply = self.sar.produce_setup_sar_phone_message_1().unwrap();
                self.sar_to_peer_tx
                    .send(SarToPeerEnvelope::SetupSarPhoneMessage1(reply))
                    .await
                    .unwrap();
                debug!("SarActor: setup phone-sar round 1 done.");
            }
            _ => panic!("SarActor: unexpected message, expected SetupPhoneSarMessage1"),
        }

        // Step 7: receive SetupPhoneSarMessage2, reply with SetupSarPhoneMessage2
        match self.peer_to_sar_rx.recv().await.unwrap() {
            PeerToSarEnvelope::SetupPhoneSarMessage2(msg) => {
                self.sar.consume_setup_phone_sar_message_2(msg).unwrap();
                let reply = self.sar.produce_setup_sar_phone_message_2().unwrap();
                self.sar_to_peer_tx
                    .send(SarToPeerEnvelope::SetupSarPhoneMessage2(reply))
                    .await
                    .unwrap();
                debug!("SarActor: setup phone-sar round 2 done.");
            }
            _ => panic!("SarActor: unexpected message, expected SetupPhoneSarMessage2"),
        }

        // Step N: receive SetupWtSarMessage1 from WT, reply with SetupSarWtMessage1
        match self.wt_to_sar_rx.recv().await.unwrap() {
            WtToSarEnvelope::SetupWtSarMessage1(msg) => {
                self.sar.consume_setup_wt_sar_message_1(msg).unwrap();
                let reply = self.sar.produce_setup_sar_wt_message_1().unwrap();
                self.sar_to_wt_tx
                    .send(SarToWtEnvelope::SetupSarWtMessage1 {
                        sar_id: sar_id.clone(),
                        msg: Box::new(reply),
                    })
                    .await
                    .unwrap();
                debug!("SarActor: setup WT-SAR finalisation done.");
                info!("SarActor: registered with WT.");
            }
            _ => panic!("SarActor: unexpected message, expected SetupWtSarMessage1"),
        }

        info!("SarActor: setup complete.");
        self.setup_barrier.wait().await;

        // ── Withdrawal phase ─────────────────────────────────────────────────
        //
        // Two possible paths depending on which message arrives first:
        //   • Initiator SAR:     WithdrawalWtSarMessage1          → WithdrawalSarWtMessage1
        //                        (WithdrawalWtSarMessage2 ping)    → WithdrawalSarWtMessage2
        //   • Non-initiator SAR: WithdrawalWtNonInitiatorSarMessage1 → WithdrawalNonInitiatorSarWtMessage1
        //                        (may also receive a ping message)

        match self.wt_to_sar_rx.recv().await.unwrap() {
            WtToSarEnvelope::WithdrawalWtSarMessage1(msg) => {
                // Initiator SAR path
                info!("SarActor: acting on the initiator-side SAR withdrawal path.");
                self.sar.consume_withdrawal_wt_sar_message_1(msg).unwrap();
                let reply = self.sar.produce_withdrawal_sar_wt_message_1().unwrap();
                self.sar_to_wt_tx
                    .send(SarToWtEnvelope::WithdrawalSarWtMessage1 {
                        sar_id: sar_id.clone(),
                        msg: reply,
                    })
                    .await
                    .unwrap();
                debug!("SarActor: withdrawal initiator round 1 done.");

                // Keep responding until the WT closes its sender.
                while let Some(envelope) = self.wt_to_sar_rx.recv().await {
                    match envelope {
                        WtToSarEnvelope::WithdrawalWtSarMessage2(msg) => {
                            self.sar.consume_withdrawal_wt_sar_message_2(msg).unwrap();
                            let reply = self.sar.produce_withdrawal_sar_wt_message_2().unwrap();
                            self.sar_to_wt_tx
                                .send(SarToWtEnvelope::WithdrawalSarWtMessage2 {
                                    sar_id: sar_id.clone(),
                                    msg: reply,
                                })
                                .await
                                .unwrap();
                            debug!("SarActor: withdrawal initiator ping round done.");
                        }
                        _ => panic!("SarActor: expected WithdrawalWtSarMessage2"),
                    }
                }
            }

            WtToSarEnvelope::WithdrawalWtNonInitiatorSarMessage1(msg) => {
                // Non-initiator SAR path
                info!("SarActor: acting on the non-initiator SAR withdrawal path.");
                self.sar
                    .consume_withdrawal_wt_non_initiator_sar_message_1(msg)
                    .unwrap();
                let reply = self
                    .sar
                    .produce_withdrawal_non_initiator_sar_wt_message_1()
                    .unwrap();
                self.sar_to_wt_tx
                    .send(SarToWtEnvelope::WithdrawalNonInitiatorSarWtMessage1 {
                        sar_id: sar_id.clone(),
                        msg: reply,
                    })
                    .await
                    .unwrap();
                debug!("SarActor: withdrawal non-initiator round done.");

                // Keep responding until the WT closes its sender.
                while let Some(envelope) = self.wt_to_sar_rx.recv().await {
                    match envelope {
                        WtToSarEnvelope::WithdrawalWtSarMessage2(msg) => {
                            self.sar.consume_withdrawal_wt_sar_message_2(msg).unwrap();
                            let reply = self.sar.produce_withdrawal_sar_wt_message_2().unwrap();
                            self.sar_to_wt_tx
                                .send(SarToWtEnvelope::WithdrawalSarWtMessage2 {
                                    sar_id: sar_id.clone(),
                                    msg: reply,
                                })
                                .await
                                .unwrap();
                            debug!("SarActor: withdrawal non-initiator ping round done.");
                        }
                        _ => {
                            panic!("SarActor: expected WithdrawalWtSarMessage2 after non-initiator")
                        }
                    }
                }
            }

            _ => panic!("SarActor: unexpected withdrawal message"),
        }

        info!("SarActor: withdrawal complete.");
    }
}
