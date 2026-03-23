use super::runtime::WtRuntime;
use crate::roles::{api::RoleRuntime, prelude::*, shared::*};

pub(super) fn run_setup(
    runtime: &mut WtRuntime,
    context: &mut RuntimeContext,
    peer_link_names: &[String],
    sar_link_names: &[String],
    peer_instance_by_link: &BTreeMap<String, String>,
) -> Result<(), RuntimeError> {
    let role = runtime.role();
    info!(
        instance_id = %runtime.instance_id,
        num_peers = peer_link_names.len(),
        num_sars = sar_link_names.len(),
        "WT runtime starting setup",
    );
    record_progress(context, role, &runtime.instance_id, "wt_setup_start")?;

    let mut boomlet_pubkey_to_link = HashMap::<cryptography::PublicKey, String>::new();
    let mut msg1_items = Vec::with_capacity(peer_link_names.len());
    for link_name in peer_link_names {
        let message =
            context.recv_message::<setup::from_niso::to_wt::SetupNisoWtMessage1>(link_name)?;
        let (boomlet_identity_pubkey, _, _, _) = message.clone().into_parts();
        boomlet_pubkey_to_link.insert(boomlet_identity_pubkey, link_name.clone());
        msg1_items.push(MetadataAttachedMessage::new(
            boomlet_identity_pubkey,
            message,
        ));
    }
    step(
        role,
        "WT consume_setup_niso_wt_message_1",
        runtime
            .entity
            .consume_setup_niso_wt_message_1(Parcel::new(msg1_items)),
    )?;
    info!(
        instance_id = %runtime.instance_id,
        "WT collected peer identities and is opening WT sessions",
    );
    record_progress(
        context,
        role,
        &runtime.instance_id,
        "wt_setup_peer_identities_collected",
    )?;

    let wt_niso_msg1_parcel = step(
        role,
        "WT produce_setup_wt_niso_message_1",
        runtime.entity.produce_setup_wt_niso_message_1(),
    )?;
    for item in wt_niso_msg1_parcel.open() {
        let (wt_peer_id, message) = item.into_parts();
        let link_name = boomlet_pubkey_to_link
            .get(wt_peer_id.get_boomlet_identity_pubkey())
            .cloned()
            .ok_or_else(|| RuntimeError::ProtocolStepFailed {
                role,
                detail: "missing peer link for WT setup message 1".to_owned(),
            })?;
        runtime
            .wt_peer_id_to_link
            .insert(wt_peer_id.clone(), link_name.clone());
        context.send_message(link_name, &message)?;
    }

    let mut msg2_items = Vec::with_capacity(peer_link_names.len());
    for link_name in peer_link_names {
        let message =
            context.recv_message::<setup::from_niso::to_wt::SetupNisoWtMessage2>(link_name)?;
        let wt_peer_id = runtime.wt_peer_id_for_link(link_name)?;
        msg2_items.push(MetadataAttachedMessage::new(wt_peer_id, message));
    }
    step(
        role,
        "WT consume_setup_niso_wt_message_2",
        runtime
            .entity
            .consume_setup_niso_wt_message_2(Parcel::new(msg2_items)),
    )?;

    let wt_niso_msg2_parcel = step(
        role,
        "WT produce_setup_wt_niso_message_2",
        runtime.entity.produce_setup_wt_niso_message_2(),
    )?;
    for item in wt_niso_msg2_parcel.open() {
        let (wt_peer_id, message) = item.into_parts();
        let link_name = runtime
            .wt_peer_id_to_link
            .get(&wt_peer_id)
            .cloned()
            .ok_or_else(|| RuntimeError::ProtocolStepFailed {
                role,
                detail: "missing WT peer route for setup message 2".to_owned(),
            })?;
        context.send_message(link_name, &message)?;
    }

    let mut msg3_items = Vec::with_capacity(peer_link_names.len());
    for link_name in peer_link_names {
        let message =
            context.recv_message::<setup::from_niso::to_wt::SetupNisoWtMessage3>(link_name)?;
        let wt_peer_id = runtime.wt_peer_id_for_link(link_name)?;
        let (_, sar_map) = message.clone().into_parts();
        let peer_instance_id = peer_instance_by_link.get(link_name).ok_or_else(|| {
            RuntimeError::ProtocolStepFailed {
                role,
                detail: format!("missing peer instance mapping for link `{link_name}`"),
            }
        })?;
        let sar_instance_id = paired_sar_instance_id(peer_instance_id)?;
        let sar_link = runtime
            .sar_links
            .get(&sar_instance_id)
            .cloned()
            .ok_or_else(|| RuntimeError::ProtocolStepFailed {
                role,
                detail: format!("missing paired SAR route `{sar_instance_id}`"),
            })?;
        for sar_id in sar_map.keys() {
            runtime
                .sar_id_to_link
                .entry(sar_id.clone())
                .or_insert_with(|| sar_link.clone());
        }
        msg3_items.push(MetadataAttachedMessage::new(wt_peer_id, message));
    }
    step(
        role,
        "WT consume_setup_niso_wt_message_3",
        runtime
            .entity
            .consume_setup_niso_wt_message_3(Parcel::new(msg3_items)),
    )?;
    info!(
        instance_id = %runtime.instance_id,
        "WT learned peer-to-SAR assignments and is registering SARs",
    );
    record_progress(
        context,
        role,
        &runtime.instance_id,
        "wt_setup_sar_assignment_collected",
    )?;

    let wt_sar_msg1_parcel = step(
        role,
        "WT produce_setup_wt_sar_message_1",
        runtime.entity.produce_setup_wt_sar_message_1(),
    )?;
    for item in wt_sar_msg1_parcel.open() {
        let (sar_id, message) = item.into_parts();
        let link_name = runtime
            .sar_id_to_link
            .get(&sar_id)
            .cloned()
            .ok_or_else(|| RuntimeError::ProtocolStepFailed {
                role,
                detail: format!("missing SAR route for `{sar_id:?}`"),
            })?;
        context.send_message(link_name, &message)?;
    }

    let mut sar_msg1_items = Vec::with_capacity(sar_link_names.len());
    for link_name in sar_link_names {
        let message =
            context.recv_message::<setup::from_sar::to_wt::SetupSarWtMessage1>(link_name)?;
        let sar_id = runtime.sar_id_for_link(link_name)?;
        sar_msg1_items.push(MetadataAttachedMessage::new(sar_id, message));
    }
    step(
        role,
        "WT consume_setup_sar_wt_message_1",
        runtime
            .entity
            .consume_setup_sar_wt_message_1(Parcel::new(sar_msg1_items)),
    )?;
    info!(
        instance_id = %runtime.instance_id,
        "WT finished SAR registration and is releasing final setup state",
    );
    record_progress(
        context,
        role,
        &runtime.instance_id,
        "wt_setup_sar_registration_complete",
    )?;

    let wt_niso_msg3_parcel = step(
        role,
        "WT produce_setup_wt_niso_message_3",
        runtime.entity.produce_setup_wt_niso_message_3(),
    )?;
    for item in wt_niso_msg3_parcel.open() {
        let (wt_peer_id, message) = item.into_parts();
        let link_name = runtime
            .wt_peer_id_to_link
            .get(&wt_peer_id)
            .cloned()
            .ok_or_else(|| RuntimeError::ProtocolStepFailed {
                role,
                detail: "missing WT peer route for setup message 3".to_owned(),
            })?;
        context.send_message(link_name, &message)?;
    }
    info!(instance_id = %runtime.instance_id, "WT setup complete");
    record_progress(context, role, &runtime.instance_id, "wt_setup_complete")?;

    Ok(())
}
