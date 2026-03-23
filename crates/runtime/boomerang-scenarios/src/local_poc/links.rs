//! Bidirectional link-construction helpers for process drafts.

use std::{collections::BTreeMap, net::SocketAddr};

use boomerang_transport::LinkConfig;

use super::{
    draft::{ProcessDraft, ProcessRef},
    error::LocalPocError,
};

/// Adds one named bind/connect link pair between two draft processes.
pub(super) fn add_bidirectional_link(
    drafts: &mut BTreeMap<String, ProcessDraft>,
    left: ProcessRef<'_>,
    right: ProcessRef<'_>,
    link_name: &str,
    bind_addr: SocketAddr,
) -> Result<(), LocalPocError> {
    {
        let left_draft =
            drafts
                .get_mut(left.instance_id)
                .ok_or_else(|| LocalPocError::MissingProcessDraft {
                    instance_id: left.instance_id.to_owned(),
                })?;
        left_draft.links.push(LinkConfig {
            name: link_name.to_owned(),
            peer_role: right.role,
            peer_instance_id: right.instance_id.to_owned(),
            bind_addr: Some(bind_addr),
            connect_addr: None,
        });
    }

    {
        let right_draft = drafts.get_mut(right.instance_id).ok_or_else(|| {
            LocalPocError::MissingProcessDraft {
                instance_id: right.instance_id.to_owned(),
            }
        })?;
        right_draft.links.push(LinkConfig {
            name: link_name.to_owned(),
            peer_role: left.role,
            peer_instance_id: left.instance_id.to_owned(),
            bind_addr: None,
            connect_addr: Some(bind_addr),
        });
    }

    Ok(())
}
