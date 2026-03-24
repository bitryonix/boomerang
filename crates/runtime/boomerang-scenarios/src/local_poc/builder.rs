//! Public builder entrypoints and route construction for the local POC.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddrV4,
    path::{Path, PathBuf},
};

use boomerang_config::{
    BoomletSlot, ClusterManifest, NetworkedPocConfig, ProcessBootstrap, ProcessConfig,
    ProcessRoutes, RuntimeConfigError,
};
use protocol::constructs::{BitcoinCoreAuth, SarId, WtIdsCollection};
use protocol_wire::control::TransportRole;

use super::{
    draft::{ProcessDraft, process_ref},
    error::LocalPocError,
    identity::LocalPocPublishedIdentities,
    ids::{
        WT_INSTANCE_ID, local_instance_id, local_role_for_suffix, parse_instance_number,
        peer_instance_id, peer_local_link_name, peer_number_from_local_instance,
        peer_peer_link_name, peer_sar_link_name, sar_instance_id, wt_peer_link_name,
        wt_sar_link_name,
    },
    links::add_bidirectional_link,
    ports::{advance_port, next_socket_addr},
};

/// Builds the WT/SAR process configs used during WT/SAR prelaunch staging.
pub fn local_poc_identity_processes(
    config: &NetworkedPocConfig,
    state_root: &Path,
    base_port: u16,
    rpc_client_url: SocketAddrV4,
    rpc_client_auth: BitcoinCoreAuth,
) -> Result<Vec<ProcessConfig>, RuntimeConfigError> {
    config.validate()?;

    let mut wt_links = Vec::new();
    let mut sar_links = BTreeMap::<usize, Vec<boomerang_transport::LinkConfig>>::new();
    let mut next_port = base_port;

    for peer_number in 1..=config.topology.num_peers {
        wt_links.push(boomerang_transport::LinkConfig {
            name: wt_peer_link_name(peer_number),
            peer_role: TransportRole::Peer,
            peer_instance_id: peer_instance_id(peer_number),
            bind_addr: Some(next_socket_addr(next_port)),
            connect_addr: None,
        });
        advance_port(&mut next_port, "WT-peer links")?;

        let wt_sar_addr = next_socket_addr(next_port);
        wt_links.push(boomerang_transport::LinkConfig {
            name: wt_sar_link_name(peer_number),
            peer_role: TransportRole::Sar,
            peer_instance_id: sar_instance_id(peer_number),
            bind_addr: Some(wt_sar_addr),
            connect_addr: None,
        });
        sar_links
            .entry(peer_number)
            .or_default()
            .push(boomerang_transport::LinkConfig {
                name: wt_sar_link_name(peer_number),
                peer_role: TransportRole::Wt,
                peer_instance_id: WT_INSTANCE_ID.to_owned(),
                bind_addr: None,
                connect_addr: Some(wt_sar_addr),
            });
        advance_port(&mut next_port, "WT-SAR links")?;

        let peer_sar_addr = next_socket_addr(next_port);
        sar_links
            .entry(peer_number)
            .or_default()
            .push(boomerang_transport::LinkConfig {
                name: peer_sar_link_name(peer_number),
                peer_role: TransportRole::Peer,
                peer_instance_id: peer_instance_id(peer_number),
                bind_addr: Some(peer_sar_addr),
                connect_addr: None,
            });
        advance_port(&mut next_port, "peer-SAR links")?;

        // The final topology reserves six local peer-to-entity ports after each peer/SAR block.
        // We skip them here so identity-publication configs use the same deterministic addresses
        // as the later full cluster manifest.
        for _ in ["phone", "iso", "niso", "boomlet", "boomletwo", "st"] {
            advance_port(&mut next_port, "peer-local links")?;
        }
    }

    let mut processes = Vec::with_capacity(1 + config.topology.num_sars);
    processes.push(ProcessConfig {
        role: TransportRole::Wt,
        instance_id: WT_INSTANCE_ID.to_owned(),
        state_dir: state_root.join(WT_INSTANCE_ID),
        bootstrap: ProcessBootstrap::Wt {
            rpc_client_url,
            rpc_client_auth: rpc_client_auth.clone(),
        },
        routes: routes_for_process(
            WT_INSTANCE_ID,
            TransportRole::Wt,
            config.topology.num_peers,
            config.topology.num_sars,
        )
        .map_err(RuntimeConfigError::from)?,
        links: wt_links,
        boomerang: config.boomerang.clone(),
        withdrawal: config.withdrawal.clone(),
    });

    for peer_number in 1..=config.topology.num_peers {
        let instance_id = sar_instance_id(peer_number);
        processes.push(ProcessConfig {
            role: TransportRole::Sar,
            instance_id: instance_id.clone(),
            state_dir: state_root.join(&instance_id),
            bootstrap: ProcessBootstrap::Sar {},
            routes: routes_for_process(
                &instance_id,
                TransportRole::Sar,
                config.topology.num_peers,
                config.topology.num_sars,
            )
            .map_err(RuntimeConfigError::from)?,
            links: sar_links.remove(&peer_number).unwrap_or_default(),
            boomerang: config.boomerang.clone(),
            withdrawal: config.withdrawal.clone(),
        });
    }

    for process in &processes {
        process.validate()?;
    }

    Ok(processes)
}

/// Builds the full deterministic 41-process local POC cluster manifest.
pub fn local_poc_cluster_manifest(
    config: &NetworkedPocConfig,
    identities: &LocalPocPublishedIdentities,
    state_root: &Path,
    base_port: u16,
    rpc_client_url: SocketAddrV4,
    rpc_client_auth: BitcoinCoreAuth,
) -> Result<ClusterManifest, RuntimeConfigError> {
    config.validate()?;
    let wt_ids_collection = WtIdsCollection::new(identities.wt_id().clone(), BTreeSet::new());

    let mut drafts = BTreeMap::<String, ProcessDraft>::new();

    drafts.insert(
        WT_INSTANCE_ID.to_owned(),
        ProcessDraft {
            role: TransportRole::Wt,
            instance_id: WT_INSTANCE_ID.to_owned(),
            state_dir: state_root.join(WT_INSTANCE_ID),
            bootstrap: ProcessBootstrap::Wt {
                rpc_client_url,
                rpc_client_auth: rpc_client_auth.clone(),
            },
            links: Vec::new(),
            boomerang: config.boomerang.clone(),
            withdrawal: config.withdrawal.clone(),
        },
    );

    for peer_number in 1..=config.topology.num_peers {
        let sar_id = identities
            .sar_id_for_peer(peer_number)
            .map_err(RuntimeConfigError::from)?;
        let sar_instance = sar_instance_id(peer_number);
        drafts.insert(
            sar_instance.clone(),
            ProcessDraft {
                role: TransportRole::Sar,
                instance_id: sar_instance.clone(),
                state_dir: state_root.join(&sar_instance),
                bootstrap: ProcessBootstrap::Sar {},
                links: Vec::new(),
                boomerang: config.boomerang.clone(),
                withdrawal: config.withdrawal.clone(),
            },
        );

        let peer_instance = peer_instance_id(peer_number);
        drafts.insert(
            peer_instance.clone(),
            ProcessDraft {
                role: TransportRole::Peer,
                instance_id: peer_instance.clone(),
                state_dir: state_root.join(&peer_instance),
                bootstrap: ProcessBootstrap::Peer {
                    peer_index: peer_number - 1,
                    total_peers: config.topology.num_peers,
                    is_withdrawal_initiator: peer_number == 1,
                    rpc_client_url,
                    rpc_client_auth: rpc_client_auth.clone(),
                    wt_ids_collection: wt_ids_collection.clone(),
                    sar_ids_collection: BTreeSet::from([sar_id.clone()]),
                },
                links: Vec::new(),
                boomerang: config.boomerang.clone(),
                withdrawal: config.withdrawal.clone(),
            },
        );

        for (suffix, role, bootstrap) in local_entity_specs(sar_id) {
            let instance_id = local_instance_id(peer_number, suffix);
            drafts.insert(
                instance_id.clone(),
                ProcessDraft {
                    role,
                    instance_id: instance_id.clone(),
                    state_dir: state_root.join(&instance_id),
                    bootstrap: bootstrap.clone(),
                    links: Vec::new(),
                    boomerang: config.boomerang.clone(),
                    withdrawal: config.withdrawal.clone(),
                },
            );
        }
    }

    let mut next_port = base_port;

    for peer_number in 1..=config.topology.num_peers {
        add_bidirectional_link(
            &mut drafts,
            process_ref(TransportRole::Wt, WT_INSTANCE_ID),
            process_ref(TransportRole::Peer, &peer_instance_id(peer_number)),
            &wt_peer_link_name(peer_number),
            next_socket_addr(next_port),
        )?;
        advance_port(&mut next_port, "WT-peer links")?;

        add_bidirectional_link(
            &mut drafts,
            process_ref(TransportRole::Wt, WT_INSTANCE_ID),
            process_ref(TransportRole::Sar, &sar_instance_id(peer_number)),
            &wt_sar_link_name(peer_number),
            next_socket_addr(next_port),
        )?;
        advance_port(&mut next_port, "WT-SAR links")?;

        add_bidirectional_link(
            &mut drafts,
            process_ref(TransportRole::Sar, &sar_instance_id(peer_number)),
            process_ref(TransportRole::Peer, &peer_instance_id(peer_number)),
            &peer_sar_link_name(peer_number),
            next_socket_addr(next_port),
        )?;
        advance_port(&mut next_port, "peer-SAR links")?;

        for suffix in ["phone", "iso", "niso", "boomlet", "boomletwo", "st"] {
            add_bidirectional_link(
                &mut drafts,
                process_ref(TransportRole::Peer, &peer_instance_id(peer_number)),
                process_ref(
                    local_role_for_suffix(suffix)?,
                    &local_instance_id(peer_number, suffix),
                ),
                &peer_local_link_name(peer_number, suffix),
                next_socket_addr(next_port),
            )?;
            advance_port(&mut next_port, "peer-local links")?;
        }
    }

    for left in 1..=config.topology.num_peers {
        for right in (left + 1)..=config.topology.num_peers {
            add_bidirectional_link(
                &mut drafts,
                process_ref(TransportRole::Peer, &peer_instance_id(left)),
                process_ref(TransportRole::Peer, &peer_instance_id(right)),
                &peer_peer_link_name(left, right),
                next_socket_addr(next_port),
            )?;
            advance_port(&mut next_port, "peer-peer links")?;
        }
    }

    let mut processes = Vec::with_capacity(drafts.len());
    for (instance_id, draft) in drafts {
        let routes = routes_for_process(
            &instance_id,
            draft.role,
            config.topology.num_peers,
            config.topology.num_sars,
        )
        .map_err(RuntimeConfigError::from)?;
        processes.push(ProcessConfig {
            role: draft.role,
            instance_id: draft.instance_id,
            state_dir: draft.state_dir,
            bootstrap: draft.bootstrap,
            routes,
            links: draft.links,
            boomerang: draft.boomerang,
            withdrawal: draft.withdrawal,
        });
    }

    let manifest = ClusterManifest { processes };
    manifest.validate()?;
    Ok(manifest)
}

/// Returns the process-bootstrap specs for one peer's local entities.
fn local_entity_specs(sar_id: &SarId) -> Vec<(&'static str, TransportRole, ProcessBootstrap)> {
    vec![
        (
            "phone",
            TransportRole::Phone,
            ProcessBootstrap::Phone {
                sar_id: sar_id.clone(),
            },
        ),
        ("iso", TransportRole::Iso, ProcessBootstrap::Iso {}),
        ("niso", TransportRole::Niso, ProcessBootstrap::Niso {}),
        (
            "boomlet",
            TransportRole::Boomlet,
            ProcessBootstrap::Boomlet {
                slot: BoomletSlot::Primary,
            },
        ),
        (
            "boomletwo",
            TransportRole::Boomlet,
            ProcessBootstrap::Boomlet {
                slot: BoomletSlot::Backup,
            },
        ),
        ("st", TransportRole::St, ProcessBootstrap::St {}),
    ]
}

/// Builds the named runtime routes for one process in the local topology.
fn routes_for_process(
    instance_id: &str,
    role: TransportRole,
    num_peers: usize,
    num_sars: usize,
) -> Result<ProcessRoutes, LocalPocError> {
    match role {
        TransportRole::Wt => Ok(ProcessRoutes::Wt {
            peer_links: (1..=num_peers)
                .map(|peer_number| {
                    (
                        peer_instance_id(peer_number),
                        wt_peer_link_name(peer_number),
                    )
                })
                .collect(),
            sar_links: (1..=num_sars)
                .map(|sar_number| (sar_instance_id(sar_number), wt_sar_link_name(sar_number)))
                .collect(),
        }),
        TransportRole::Sar => {
            let peer_number = parse_instance_number(instance_id, "sar-")?;
            Ok(ProcessRoutes::Sar {
                peer_link: peer_sar_link_name(peer_number),
                wt_link: wt_sar_link_name(peer_number),
            })
        }
        TransportRole::Peer => {
            let peer_number = parse_instance_number(instance_id, "peer-")?;
            Ok(ProcessRoutes::Peer {
                wt_link: wt_peer_link_name(peer_number),
                sar_link: peer_sar_link_name(peer_number),
                phone_link: peer_local_link_name(peer_number, "phone"),
                iso_link: peer_local_link_name(peer_number, "iso"),
                niso_link: peer_local_link_name(peer_number, "niso"),
                st_link: peer_local_link_name(peer_number, "st"),
                boomlet_link: peer_local_link_name(peer_number, "boomlet"),
                boomletwo_link: peer_local_link_name(peer_number, "boomletwo"),
                peer_links: (1..=num_peers)
                    .filter(|other| *other != peer_number)
                    .map(|other| {
                        (
                            peer_instance_id(other),
                            peer_peer_link_name(peer_number.min(other), peer_number.max(other)),
                        )
                    })
                    .collect(),
            })
        }
        TransportRole::Niso => Ok(ProcessRoutes::Niso {
            peer_link: peer_local_link_name(peer_number_from_local_instance(instance_id)?, "niso"),
        }),
        TransportRole::Iso => Ok(ProcessRoutes::Iso {
            peer_link: peer_local_link_name(peer_number_from_local_instance(instance_id)?, "iso"),
        }),
        TransportRole::Boomlet => {
            let peer_number = peer_number_from_local_instance(instance_id)?;
            let prefix = format!("peer-{peer_number}-");
            let suffix = instance_id.strip_prefix(&prefix).ok_or_else(|| {
                LocalPocError::InvalidInstanceId {
                    instance_id: instance_id.to_owned(),
                    reason: "boomlet instance id did not preserve its peer-local suffix".to_owned(),
                }
            })?;
            Ok(ProcessRoutes::Boomlet {
                peer_link: peer_local_link_name(peer_number, suffix),
            })
        }
        TransportRole::Phone => Ok(ProcessRoutes::Phone {
            peer_link: peer_local_link_name(peer_number_from_local_instance(instance_id)?, "phone"),
        }),
        TransportRole::St => Ok(ProcessRoutes::St {
            peer_link: peer_local_link_name(peer_number_from_local_instance(instance_id)?, "st"),
        }),
    }
}

/// Returns the default supervisor state root used by local runs.
pub fn default_state_root() -> PathBuf {
    workspace_root().join("poc-runs")
}

/// Returns the preferred path to the `boomerang-node` binary for local runs.
pub fn default_node_bin() -> PathBuf {
    if let Some(path) = std::env::var_os("CARGO_BIN_EXE_boomerang-node") {
        return PathBuf::from(path);
    }

    workspace_root()
        .join("target")
        .join("debug")
        .join("boomerang-node")
}

fn workspace_root() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));

    // The scenarios crate may live under nested workspace folders, so we discover the real root
    // from the repository marker instead of assuming a fixed number of `..` segments.
    for candidate in manifest_dir.ancestors() {
        if candidate.join(".git").exists() {
            return candidate.to_path_buf();
        }
    }

    manifest_dir.to_path_buf()
}
