use super::prelude::*;

pub(crate) fn dispatch_not_implemented(
    role: TransportRole,
    inbound: InboundFrame,
) -> Result<Vec<OutboundFrame>, RuntimeError> {
    let tag = inbound.frame.message_tag()?;
    Err(RuntimeError::DispatchNotImplemented {
        role,
        link_name: inbound.link_name,
        tag,
    })
}

pub(crate) fn step<T, E>(
    role: TransportRole,
    step_name: &str,
    result: Result<T, E>,
) -> Result<T, RuntimeError>
where
    E: Debug,
{
    result.map_err(|error| RuntimeError::ProtocolStepFailed {
        role,
        detail: format!("{step_name}: {error:?}"),
    })
}

pub(crate) fn single_outbound<M: WireMessage>(
    link_name: impl Into<String>,
    message: &M,
) -> Result<Vec<OutboundFrame>, RuntimeError> {
    Ok(vec![OutboundFrame::from_message(link_name, message)?])
}

pub(crate) fn record_progress(
    context: &RuntimeContext,
    role: TransportRole,
    instance_id: &str,
    stage: &str,
) -> Result<(), RuntimeError> {
    context.record_progress(&format!(
        "stage={stage} role={} instance_id={instance_id}",
        role.as_str()
    ))
}

pub(crate) fn parse_instance_number(
    instance_id: &str,
    prefix: &str,
) -> Result<usize, RuntimeError> {
    let suffix =
        instance_id
            .strip_prefix(prefix)
            .ok_or_else(|| RuntimeError::ProtocolStepFailed {
                role: TransportRole::Peer,
                detail: format!("invalid instance id `{instance_id}` for prefix `{prefix}`"),
            })?;
    suffix
        .parse::<usize>()
        .map_err(|error| RuntimeError::ProtocolStepFailed {
            role: TransportRole::Peer,
            detail: format!("failed to parse numeric suffix from `{instance_id}`: {error}"),
        })
}

pub(crate) fn paired_sar_instance_id(peer_instance_id: &str) -> Result<String, RuntimeError> {
    Ok(format!(
        "sar-{}",
        parse_instance_number(peer_instance_id, "peer-")?
    ))
}

pub(crate) fn infer_single_peer_id(
    message: &SetupUserPeersOutOfBandMessage1,
) -> Result<PeerId, RuntimeError> {
    let mut entries = message.clone().into_parts().into_iter();
    let (peer_id, _) = entries
        .next()
        .ok_or_else(|| RuntimeError::ProtocolStepFailed {
            role: TransportRole::Peer,
            detail: "setup out-of-band message did not contain a peer id".to_owned(),
        })?;
    if entries.next().is_some() {
        return Err(RuntimeError::ProtocolStepFailed {
            role: TransportRole::Peer,
            detail: "expected each peer out-of-band frame to carry exactly one sender".to_owned(),
        });
    }
    Ok(peer_id)
}
