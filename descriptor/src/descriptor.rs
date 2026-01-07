use std::{collections::BTreeSet, str::FromStr};

use bitcoin::{Network, XOnlyPublicKey};
use cryptography::Cryptography;
use getset::Getters;
use miniscript::{
    Miniscript, Tap, ToPublicKey,
    descriptor::{TapTree, Tr},
    policy::Concrete,
};
use protocol::constructs::PeerId;
use tracing::{Level, event};
use tracing_utils::{traceable_unfold_or_panic, unreachable_panic};

#[derive(Debug, Getters)]
#[getset(get = "pub with_prefix")]
pub struct BoomerangDescriptor {
    // Main Fields
    network: Network,
    peer_ids_collection: BTreeSet<PeerId>,
    milestone_blocks_collection: Vec<u32>,
    // Internal Fields
    descriptor: Tr<XOnlyPublicKey>,
}

impl BoomerangDescriptor {
    pub fn new(
        network: Network,
        peer_ids_collection: BTreeSet<PeerId>,
        milestone_blocks_collection: Vec<u32>,
    ) -> Self {
        let n = peer_ids_collection.len();
        let mut normal_keys = peer_ids_collection
            .iter()
            .map(|peer_id| peer_id.get_boomlet_identity_pubkey().to_x_only_pubkey())
            .collect::<Vec<_>>();
        normal_keys.sort();
        let mut boom_keys = peer_ids_collection
            .iter()
            .map(|peer_id| peer_id.get_boom_pubkey().to_x_only_pubkey())
            .collect::<Vec<_>>();
        boom_keys.sort();
        let descriptor = traceable_unfold_or_panic!(
            Tr::<XOnlyPublicKey>::new(
                bitcoin::PublicKey::new(Self::generate_randomized_standard_unspendable_pubkey(
                    &peer_ids_collection
                ))
                .to_x_only_pubkey(),
                Some(milestone_blocks_collection.iter().enumerate().rev().fold(
                    TapTree::<XOnlyPublicKey>::Leaf(Miniscript::TRUE.into()),
                    |accumulator: TapTree<XOnlyPublicKey>, (index, milestone)| {
                        if index == n {
                            TapTree::<XOnlyPublicKey>::Leaf(
                                BoomerangDescriptor::multisig_timelocked_tap_script(
                                    &normal_keys,
                                    (n - index + 1) as u32,
                                    *milestone,
                                )
                                .into(),
                            )
                        } else if 0 < index && index < n {
                            TapTree::combine(
                                TapTree::<XOnlyPublicKey>::Leaf(
                                    BoomerangDescriptor::multisig_timelocked_tap_script(
                                        &normal_keys,
                                        (n - index + 1) as u32,
                                        *milestone,
                                    )
                                    .into(),
                                ),
                                accumulator,
                            )
                        } else {
                            TapTree::combine(
                                TapTree::<XOnlyPublicKey>::Leaf(
                                    BoomerangDescriptor::multisig_timelocked_tap_script(
                                        &boom_keys, n as u32, *milestone,
                                    )
                                    .into(),
                                ),
                                accumulator,
                            )
                        }
                    }
                ))
            ),
            "Assumed to be able to build a miniscript::Tr descriptor from a correct miniscript::TapTree."
        );

        BoomerangDescriptor {
            // Main Fields
            network,
            peer_ids_collection,
            milestone_blocks_collection,
            // Internal Fields
            descriptor,
        }
    }

    pub fn get_descriptor_str(&self) -> String {
        self.descriptor.to_string()
    }

    fn multisig_timelocked_tap_script(
        pks: &[XOnlyPublicKey],
        threshold: u32,
        milestone: u32,
    ) -> Miniscript<XOnlyPublicKey, Tap> {
        let policy = traceable_unfold_or_panic!(
            Concrete::<XOnlyPublicKey>::from_str(
                format!(
                    "and(after({}),thresh({},{}))",
                    milestone,
                    threshold,
                    pks
                        .iter()
                        .map(|pk| format!("pk({pk})"))
                        .reduce(|acc_str, pk_str| acc_str + "," + &pk_str)
                        .unwrap_or_else(|| {
                            unreachable_panic!("Assumed to be able to concatenate a series of stringified public keys for policy construction.");
                        }),
                ).as_ref()
            ),
            "Assumed Boomerang leaf policy to have a correct format.",
        );
        let miniscript = traceable_unfold_or_panic!(
            policy.compile::<Tap>(),
            "Assumed Boomerang leaf policy to be compilable to a miniscript.",
        );
        traceable_unfold_or_panic!(
            miniscript.sanity_check(),
            "Assumed Boomerang leaf tap script to be sane.",
        );
        miniscript
    }

    fn generate_randomized_standard_unspendable_pubkey(
        peer_ids_collection: &BTreeSet<PeerId>,
    ) -> bitcoin::secp256k1::PublicKey {
        let standard_unspendable_pubkey = traceable_unfold_or_panic!(
            bitcoin::secp256k1::PublicKey::from_str(
                "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
            ),
            "Assumed to be able to create the standard unspendable pubkey.",
        );

        let mut tries: usize = 0;
        loop {
            let mut randomization_factor = Vec::with_capacity(32 + tries);
            randomization_factor.extend_from_slice(&Cryptography::hash(&peer_ids_collection));
            for _counter in 0..tries {
                randomization_factor.extend_from_slice(&[0u8]);
            }

            let mut random_curve_point_bytes = Vec::with_capacity(33);
            random_curve_point_bytes.extend_from_slice(&[2u8]);
            random_curve_point_bytes.extend_from_slice(&Cryptography::hash(&randomization_factor));

            let random_curve_point_result =
                bitcoin::secp256k1::PublicKey::from_slice(&random_curve_point_bytes);
            if let Ok(random_curve_point) = random_curve_point_result
                && let Ok(randomized_unspendable_key) =
                    standard_unspendable_pubkey.combine(&random_curve_point)
            {
                break randomized_unspendable_key;
            }
            tries += 1;
        }
    }
}
