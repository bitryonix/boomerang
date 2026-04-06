use std::{collections::BTreeMap, sync::Arc};

use protocol::constructs::PeerId;
use tokio::sync::{RwLock, mpsc};

use crate::envelopes::PeerToPeerEnvelope;
use crate::error_ext::NetworkedResult;

pub type MailboxTx<T> = mpsc::Sender<T>;
pub type MailboxRx<T> = mpsc::Receiver<T>;

pub fn channel<T>(capacity: usize) -> (MailboxTx<T>, MailboxRx<T>) {
    mpsc::channel(capacity)
}

#[derive(Clone, Default)]
pub struct PeerDirectory {
    inboxes: Arc<RwLock<BTreeMap<PeerId, MailboxTx<PeerToPeerEnvelope>>>>,
}

impl PeerDirectory {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn register(&self, peer_id: PeerId, sender: MailboxTx<PeerToPeerEnvelope>) {
        self.inboxes.write().await.insert(peer_id, sender);
    }

    pub async fn snapshot(&self) -> BTreeMap<PeerId, MailboxTx<PeerToPeerEnvelope>> {
        self.inboxes.read().await.clone()
    }

    pub async fn send(
        &self,
        peer_id: &PeerId,
        envelope: PeerToPeerEnvelope,
    ) -> NetworkedResult<()> {
        let sender = self
            .inboxes
            .read()
            .await
            .get(peer_id)
            .cloned()
            .ok_or_else(|| std::io::Error::other("PeerDirectory: missing peer inbox"))?;

        sender
            .send(envelope)
            .await
            .map_err(|_| std::io::Error::other("PeerDirectory: peer inbox closed"))?;

        Ok(())
    }
}
