//! Instance-id and link-name helpers for the local POC topology.

use protocol_wire::control::TransportRole;

use super::error::LocalPocError;

pub(super) const WT_INSTANCE_ID: &str = "wt-1";

/// Returns the deterministic peer instance id for one peer number.
pub(super) fn peer_instance_id(peer_number: usize) -> String {
    format!("peer-{peer_number}")
}

/// Returns the deterministic SAR instance id for one SAR number.
pub(super) fn sar_instance_id(sar_number: usize) -> String {
    format!("sar-{sar_number}")
}

/// Returns the deterministic local-entity instance id for one peer-local suffix.
pub(super) fn local_instance_id(peer_number: usize, suffix: &str) -> String {
    format!("peer-{peer_number}-{suffix}")
}

/// Returns the link name between WT and one peer.
pub(super) fn wt_peer_link_name(peer_number: usize) -> String {
    format!("{WT_INSTANCE_ID}--{}", peer_instance_id(peer_number))
}

/// Returns the link name between WT and one SAR.
pub(super) fn wt_sar_link_name(sar_number: usize) -> String {
    format!("{WT_INSTANCE_ID}--{}", sar_instance_id(sar_number))
}

/// Returns the link name between one peer and its assigned SAR.
pub(super) fn peer_sar_link_name(peer_number: usize) -> String {
    format!(
        "{}--{}",
        peer_instance_id(peer_number),
        sar_instance_id(peer_number)
    )
}

/// Returns the link name between one peer and one of its local entities.
pub(super) fn peer_local_link_name(peer_number: usize, suffix: &str) -> String {
    format!(
        "{}--{}",
        peer_instance_id(peer_number),
        local_instance_id(peer_number, suffix)
    )
}

/// Returns the canonical symmetric link name between two peers.
pub(super) fn peer_peer_link_name(left: usize, right: usize) -> String {
    format!("{}--{}", peer_instance_id(left), peer_instance_id(right))
}

/// Maps a local suffix onto the corresponding transport role.
pub(super) fn local_role_for_suffix(suffix: &str) -> Result<TransportRole, LocalPocError> {
    match suffix {
        "phone" => Ok(TransportRole::Phone),
        "iso" => Ok(TransportRole::Iso),
        "niso" => Ok(TransportRole::Niso),
        "boomlet" | "boomletwo" => Ok(TransportRole::Boomlet),
        "st" => Ok(TransportRole::St),
        _ => Err(LocalPocError::UnexpectedLocalRoleSuffix {
            suffix: suffix.to_owned(),
        }),
    }
}

/// Extracts the peer number from a `peer-N-suffix` local instance id.
pub(super) fn peer_number_from_local_instance(instance_id: &str) -> Result<usize, LocalPocError> {
    let mut parts = instance_id.splitn(3, '-');
    let role = parts
        .next()
        .ok_or_else(|| LocalPocError::InvalidInstanceId {
            instance_id: instance_id.to_owned(),
            reason: "missing `peer` prefix".to_owned(),
        })?;
    let number = parts
        .next()
        .ok_or_else(|| LocalPocError::InvalidInstanceId {
            instance_id: instance_id.to_owned(),
            reason: "missing numeric peer index".to_owned(),
        })?;
    let _suffix = parts
        .next()
        .ok_or_else(|| LocalPocError::InvalidInstanceId {
            instance_id: instance_id.to_owned(),
            reason: "missing local role suffix".to_owned(),
        })?;
    if role != "peer" {
        return Err(LocalPocError::InvalidInstanceId {
            instance_id: instance_id.to_owned(),
            reason: "expected `peer` prefix".to_owned(),
        });
    }
    number
        .parse()
        .map_err(|_| LocalPocError::InvalidInstanceId {
            instance_id: instance_id.to_owned(),
            reason: "peer index must be numeric".to_owned(),
        })
}

/// Extracts the numeric suffix from an instance id with a known prefix.
pub(super) fn parse_instance_number(
    instance_id: &str,
    prefix: &str,
) -> Result<usize, LocalPocError> {
    instance_id
        .strip_prefix(prefix)
        .ok_or_else(|| LocalPocError::InvalidInstanceId {
            instance_id: instance_id.to_owned(),
            reason: format!("expected `{prefix}` prefix"),
        })?
        .parse()
        .map_err(|_| LocalPocError::InvalidInstanceId {
            instance_id: instance_id.to_owned(),
            reason: "numeric suffix must parse as usize".to_owned(),
        })
}
