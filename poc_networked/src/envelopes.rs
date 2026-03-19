/// Typed envelope enums for every inter-actor channel direction.
///
/// Each enum covers all message types that can flow over that channel so the
/// transport layer is a single `mpsc` pair per direction.  The core protocol
/// crates are untouched; only this file references their public message types.
use cryptography::PublicKey;
use protocol::{
    constructs::{PeerId, SarId, WtPeerId},
    messages::{
        setup::{
            from_niso::{
                to_niso::{
                    SetupNisoPeerNisoMessage1, SetupNisoPeerNisoMessage2,
                    SetupNisoPeerNisoMessage3, SetupNisoPeerNisoMessage4,
                },
                to_wt::{SetupNisoWtMessage1, SetupNisoWtMessage2, SetupNisoWtMessage3},
            },
            from_phone::to_sar::{SetupPhoneSarMessage1, SetupPhoneSarMessage2},
            from_sar::{
                to_phone::{SetupSarPhoneMessage1, SetupSarPhoneMessage2},
                to_wt::SetupSarWtMessage1,
            },
            from_user::to_user::SetupUserPeersOutOfBandMessage1,
            from_wt::{
                to_niso::{SetupWtNisoMessage1, SetupWtNisoMessage2, SetupWtNisoMessage3},
                to_sar::SetupWtSarMessage1,
            },
        },
        withdrawal::{
            from_niso::to_wt::{
                WithdrawalNisoWtMessage1, WithdrawalNisoWtMessage2, WithdrawalNisoWtMessage3,
                WithdrawalNisoWtMessage4, WithdrawalNisoWtMessage5,
            },
            from_non_initiator_niso::to_wt::{
                WithdrawalNonInitiatorNisoWtMessage1, WithdrawalNonInitiatorNisoWtMessage2,
                WithdrawalNonInitiatorNisoWtMessage3,
            },
            from_non_initiator_sar::to_wt::WithdrawalNonInitiatorSarWtMessage1,
            from_sar::to_wt::{WithdrawalSarWtMessage1, WithdrawalSarWtMessage2},
            from_wt::{
                to_niso::{
                    WithdrawalWtNisoMessage1, WithdrawalWtNisoMessage2, WithdrawalWtNisoMessage3,
                    WithdrawalWtNisoMessage4,
                },
                to_non_initiator_niso::{
                    WithdrawalWtNonInitiatorNisoMessage1, WithdrawalWtNonInitiatorNisoMessage2,
                    WithdrawalWtNonInitiatorNisoMessage3,
                },
                to_non_initiator_sar::WithdrawalWtNonInitiatorSarMessage1,
                to_sar::{WithdrawalWtSarMessage1, WithdrawalWtSarMessage2},
            },
        },
    },
};

// ---------------------------------------------------------------------------
// Peer → WT
//
// Each peer has a dedicated channel to the WT.  The WT knows which peer a
// message came from based on which channel (index) it arrived on, so no
// sender identity needs to be embedded in the envelope.
// ---------------------------------------------------------------------------

/// All messages a peer's NISO can send to the WT.
pub enum PeerToWtEnvelope {
    // Setup – msg1 is keyed by boomlet_identity_pubkey before WtPeerId is known
    SetupNisoWtMessage1 {
        boomlet_identity_pubkey: PublicKey,
        msg: SetupNisoWtMessage1,
    },
    SetupNisoWtMessage2 {
        wt_peer_id: WtPeerId,
        msg: SetupNisoWtMessage2,
    },
    SetupNisoWtMessage3 {
        wt_peer_id: WtPeerId,
        msg: SetupNisoWtMessage3,
    },
    // Withdrawal – initiator NISO
    WithdrawalNisoWtMessage1 {
        wt_peer_id: WtPeerId,
        msg: WithdrawalNisoWtMessage1,
    },
    WithdrawalNisoWtMessage2 {
        wt_peer_id: WtPeerId,
        msg: WithdrawalNisoWtMessage2,
    },
    WithdrawalNisoWtMessage3 {
        wt_peer_id: WtPeerId,
        msg: WithdrawalNisoWtMessage3,
    },
    WithdrawalNisoWtMessage4 {
        wt_peer_id: WtPeerId,
        msg: WithdrawalNisoWtMessage4,
    },
    WithdrawalNisoWtMessage5 {
        wt_peer_id: WtPeerId,
        msg: WithdrawalNisoWtMessage5,
    },
    // Withdrawal – non-initiator NISO
    WithdrawalNonInitiatorNisoWtMessage1 {
        wt_peer_id: WtPeerId,
        msg: WithdrawalNonInitiatorNisoWtMessage1,
    },
    WithdrawalNonInitiatorNisoWtMessage2 {
        wt_peer_id: WtPeerId,
        msg: WithdrawalNonInitiatorNisoWtMessage2,
    },
    WithdrawalNonInitiatorNisoWtMessage3 {
        wt_peer_id: WtPeerId,
        msg: WithdrawalNonInitiatorNisoWtMessage3,
    },
}

// ---------------------------------------------------------------------------
// WT → Peer
// ---------------------------------------------------------------------------

/// All messages the WT can send to a peer's NISO (covers both initiator and
/// non-initiator withdrawal paths so one channel suffices per peer).
pub enum WtToPeerEnvelope {
    // Setup
    SetupWtNisoMessage1(SetupWtNisoMessage1),
    SetupWtNisoMessage2(SetupWtNisoMessage2),
    SetupWtNisoMessage3(SetupWtNisoMessage3),
    // Withdrawal – initiator NISO
    WithdrawalWtNisoMessage1(WithdrawalWtNisoMessage1),
    WithdrawalWtNisoMessage2(WithdrawalWtNisoMessage2),
    WithdrawalWtNisoMessage3(WithdrawalWtNisoMessage3),
    WithdrawalWtNisoMessage4(WithdrawalWtNisoMessage4),
    // Withdrawal – non-initiator NISO
    WithdrawalWtNonInitiatorNisoMessage1(WithdrawalWtNonInitiatorNisoMessage1),
    WithdrawalWtNonInitiatorNisoMessage2(WithdrawalWtNonInitiatorNisoMessage2),
    WithdrawalWtNonInitiatorNisoMessage3(WithdrawalWtNonInitiatorNisoMessage3),
}

// ---------------------------------------------------------------------------
// Peer → SAR  (Phone messages sent from the peer actor to its dedicated SAR)
// ---------------------------------------------------------------------------

pub enum PeerToSarEnvelope {
    // From Phone (setup)
    SetupPhoneSarMessage1(SetupPhoneSarMessage1),
    SetupPhoneSarMessage2(SetupPhoneSarMessage2),
}

// ---------------------------------------------------------------------------
// SAR → Peer  (carries Phone-bound responses during setup)
// ---------------------------------------------------------------------------

pub enum SarToPeerEnvelope {
    SetupSarPhoneMessage1(SetupSarPhoneMessage1),
    SetupSarPhoneMessage2(SetupSarPhoneMessage2),
}

// ---------------------------------------------------------------------------
// SAR → WT
// ---------------------------------------------------------------------------

pub enum SarToWtEnvelope {
    // Setup
    SetupSarWtMessage1 {
        sar_id: SarId,
        msg: Box<SetupSarWtMessage1>,
    },
    // Withdrawal – initiator SAR
    WithdrawalSarWtMessage1 {
        sar_id: SarId,
        msg: WithdrawalSarWtMessage1,
    },
    WithdrawalSarWtMessage2 {
        sar_id: SarId,
        msg: WithdrawalSarWtMessage2,
    },
    // Withdrawal – non-initiator SAR
    WithdrawalNonInitiatorSarWtMessage1 {
        sar_id: SarId,
        msg: WithdrawalNonInitiatorSarWtMessage1,
    },
}

// ---------------------------------------------------------------------------
// WT → SAR
// ---------------------------------------------------------------------------

pub enum WtToSarEnvelope {
    // Setup
    SetupWtSarMessage1(SetupWtSarMessage1),
    // Withdrawal – initiator SAR
    WithdrawalWtSarMessage1(WithdrawalWtSarMessage1),
    WithdrawalWtSarMessage2(WithdrawalWtSarMessage2),
    // Withdrawal – non-initiator SAR
    WithdrawalWtNonInitiatorSarMessage1(WithdrawalWtNonInitiatorSarMessage1),
}

// ---------------------------------------------------------------------------
// Peer ↔ Peer  (NISO-to-NISO out-of-band channel, setup only)
//
// Each peer has a dedicated channel pair to every other peer.
// The `sender_peer_id` field carries the sender's NISO PeerId so the
// receiver can reconstruct the `Parcel<PeerId, _>` the protocol entities expect.
// The WtPeerId is only used in WT-facing envelopes after WT assigns them.
// ---------------------------------------------------------------------------

pub enum PeerToPeerEnvelope {
    SetupNisoPeerNisoMessage1 {
        sender_peer_id: PeerId,
        msg: SetupNisoPeerNisoMessage1,
    },
    SetupNisoPeerNisoMessage2 {
        sender_peer_id: PeerId,
        msg: SetupNisoPeerNisoMessage2,
    },
    SetupNisoPeerNisoMessage3 {
        sender_peer_id: PeerId,
        msg: SetupNisoPeerNisoMessage3,
    },
    SetupNisoPeerNisoMessage4 {
        sender_peer_id: PeerId,
        msg: SetupNisoPeerNisoMessage4,
    },
    SetupUserPeersOutOfBandMessage1 {
        sender_peer_id: PeerId,
        msg: SetupUserPeersOutOfBandMessage1,
    },
}
