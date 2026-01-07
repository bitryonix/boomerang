use std::vec;

use getset::Getters;

use crate::messages::{Message, MetadataAttachedMessage};

#[derive(Debug, Clone, Getters)]
#[getset(get = "pub with_prefix")]
pub struct Parcel<CCID: PartialEq + Clone, MS: Message> {
    messages: Vec<MetadataAttachedMessage<CCID, MS>>,
}

impl<CCID: PartialEq + Clone, MS: Message> Parcel<CCID, MS> {
    pub fn new(messages: Vec<MetadataAttachedMessage<CCID, MS>>) -> Self {
        Parcel { messages }
    }

    pub fn carbon_copy_for_communication_channel_ids(
        message: MS,
        communication_channel_ids: impl IntoIterator<Item = CCID>,
    ) -> Self {
        let mut messages = Vec::<MetadataAttachedMessage<CCID, MS>>::new();
        communication_channel_ids.into_iter().for_each(|item| {
            messages.push(MetadataAttachedMessage::new(item, message.clone()));
        });

        Parcel { messages }
    }

    pub fn from_batch(batch: impl IntoIterator<Item = (CCID, MS)>) -> Self {
        let mut messages = Vec::<MetadataAttachedMessage<CCID, MS>>::new();
        batch
            .into_iter()
            .for_each(|(communication_channel_id, message)| {
                messages.push(MetadataAttachedMessage::new(
                    communication_channel_id,
                    message.clone(),
                ));
            });

        Parcel { messages }
    }

    pub fn look_for_message(&self, communication_channel_id: &CCID) -> Option<&MS> {
        self.messages
            .iter()
            .find(|metadata_attached_message| {
                metadata_attached_message.get_metadata() == communication_channel_id
            })
            .map(|metadata_attached_message| metadata_attached_message.get_message())
    }

    pub fn open(self) -> Vec<MetadataAttachedMessage<CCID, MS>> {
        self.messages
    }
}

impl<CCID: PartialEq + Clone, MS: Message> IntoIterator for Parcel<CCID, MS> {
    type Item = MetadataAttachedMessage<CCID, MS>;
    type IntoIter = vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.messages.into_iter()
    }
}
