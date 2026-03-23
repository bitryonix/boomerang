use super::super::api::RoleRuntime;
use super::super::{prelude::*, shared::*};
use super::runtime::PeerRuntime;

impl PeerRuntime {
    pub(super) fn peer_number(&self) -> usize {
        self.peer_index + 1
    }

    pub(super) fn role_name(&self) -> &'static str {
        if self.is_withdrawal_initiator {
            "initiator"
        } else {
            "non-initiator"
        }
    }

    pub(super) fn log_setup_step(&self, step: &str) {
        info!(
            instance_id = %self.instance_id,
            peer_number = self.peer_number(),
            step,
            "peer setup progress",
        );
    }

    pub(super) fn log_withdrawal_step(&self, step: &str) {
        info!(
            instance_id = %self.instance_id,
            peer_number = self.peer_number(),
            step,
            "peer withdrawal progress",
        );
    }

    pub(super) fn other_peer_count(&self) -> usize {
        self.total_peers.saturating_sub(1)
    }

    pub(super) fn is_peer_link(&self, link_name: &str) -> bool {
        self.peer_links
            .values()
            .any(|candidate| candidate == link_name)
    }

    pub(super) fn refresh_niso_state(
        &mut self,
        context: &mut RuntimeContext,
    ) -> Result<(), RuntimeError> {
        context.send_message(self.niso_link.clone(), &QueryNisoState)?;
        let snapshot = context.recv_message::<NisoStateSnapshot>(&self.niso_link)?;
        let (peer_id, wt_peer_id, boomerang_params) = snapshot.into_parts();
        if let Some(peer_id) = peer_id {
            self.own_peer_id = Some(peer_id);
        }
        if let Some(wt_peer_id) = wt_peer_id {
            self.own_wt_peer_id = Some(wt_peer_id);
        }
        if let Some(boomerang_params) = boomerang_params {
            self.own_boomerang_params = Some(boomerang_params);
        }
        Ok(())
    }

    pub(super) fn own_peer_id(
        &mut self,
        context: &mut RuntimeContext,
    ) -> Result<PeerId, RuntimeError> {
        if self.own_peer_id.is_none() {
            self.refresh_niso_state(context)?;
        }
        self.own_peer_id
            .clone()
            .ok_or_else(|| RuntimeError::ProtocolStepFailed {
                role: self.role(),
                detail: "missing local peer id in NISO state".to_owned(),
            })
    }

    #[allow(dead_code)]
    pub(super) fn own_wt_peer_id(
        &mut self,
        context: &mut RuntimeContext,
    ) -> Result<WtPeerId, RuntimeError> {
        if self.own_wt_peer_id.is_none() {
            self.refresh_niso_state(context)?;
        }
        self.own_wt_peer_id
            .clone()
            .ok_or_else(|| RuntimeError::ProtocolStepFailed {
                role: self.role(),
                detail: "missing local WT peer id in NISO state".to_owned(),
            })
    }

    pub(super) fn own_boomerang_params(
        &mut self,
        context: &mut RuntimeContext,
    ) -> Result<BoomerangParams, RuntimeError> {
        if self.own_boomerang_params.is_none() {
            self.refresh_niso_state(context)?;
        }
        self.own_boomerang_params
            .clone()
            .ok_or_else(|| RuntimeError::ProtocolStepFailed {
                role: self.role(),
                detail: "missing boomerang params in NISO state".to_owned(),
            })
    }

    pub(super) fn send_peer_parcel<M: WireMessage>(
        &self,
        context: &RuntimeContext,
        parcel: Parcel<PeerId, M>,
    ) -> Result<(), RuntimeError> {
        for item in parcel.open() {
            let (peer_id, message) = item.into_parts();
            let link_name = self.peer_id_to_link.get(&peer_id).cloned().ok_or_else(|| {
                RuntimeError::ProtocolStepFailed {
                    role: self.role(),
                    detail: format!("missing peer route for peer id `{peer_id:?}`"),
                }
            })?;
            context.send_message(link_name, &message)?;
        }
        Ok(())
    }

    pub(super) fn recv_peer_parcel<M: WireMessage>(
        &mut self,
        context: &mut RuntimeContext,
    ) -> Result<Parcel<PeerId, M>, RuntimeError> {
        let mut received = Vec::with_capacity(self.other_peer_count());
        let mut seen_senders = BTreeSet::new();
        while received.len() < self.other_peer_count() {
            let inbound = context.recv_any()?;
            if !self.is_peer_link(&inbound.link_name) {
                return Err(RuntimeError::ProtocolStepFailed {
                    role: self.role(),
                    detail: format!(
                        "expected peer-to-peer traffic while collecting parcel, got link `{}`",
                        inbound.link_name
                    ),
                });
            }
            let sender_peer_id = self
                .link_to_peer_id
                .get(&inbound.link_name)
                .cloned()
                .ok_or_else(|| RuntimeError::ProtocolStepFailed {
                    role: self.role(),
                    detail: format!(
                        "missing sender peer mapping for peer link `{}`",
                        inbound.link_name
                    ),
                })?;
            if !seen_senders.insert(sender_peer_id.clone()) {
                return Err(RuntimeError::ProtocolStepFailed {
                    role: self.role(),
                    detail: format!("duplicate peer parcel sender `{sender_peer_id:?}`"),
                });
            }
            let message = decode_frame::<M>(&inbound.frame)?;
            received.push(MetadataAttachedMessage::new(sender_peer_id, message));
        }

        Ok(Parcel::new(received))
    }

    pub(super) fn recv_merged_out_of_band_message(
        &mut self,
        context: &mut RuntimeContext,
    ) -> Result<SetupUserPeersOutOfBandMessage1, RuntimeError> {
        let mut received = Vec::with_capacity(self.other_peer_count());
        let mut seen_senders = BTreeSet::new();
        while received.len() < self.other_peer_count() {
            let inbound = context.recv_any()?;
            if !self.is_peer_link(&inbound.link_name) {
                return Err(RuntimeError::ProtocolStepFailed {
                    role: self.role(),
                    detail: format!(
                        "expected out-of-band setup traffic on a peer link, got `{}`",
                        inbound.link_name
                    ),
                });
            }
            let message = decode_frame::<SetupUserPeersOutOfBandMessage1>(&inbound.frame)?;
            let sender_peer_id = infer_single_peer_id(&message)?;
            if !seen_senders.insert(sender_peer_id.clone()) {
                return Err(RuntimeError::ProtocolStepFailed {
                    role: self.role(),
                    detail: format!("duplicate out-of-band sender `{sender_peer_id:?}`"),
                });
            }
            self.link_to_peer_id
                .insert(inbound.link_name.clone(), sender_peer_id.clone());
            self.peer_id_to_link
                .insert(sender_peer_id, inbound.link_name.clone());
            received.push(message);
        }

        let mut iter = received.into_iter();
        let mut merged = iter
            .next()
            .ok_or_else(|| RuntimeError::ProtocolStepFailed {
                role: self.role(),
                detail: "expected at least one out-of-band message".to_owned(),
            })?;
        merged.merge(iter.collect());
        Ok(merged)
    }
}
