// Messages
pub static SETUP_BOOMLET_NISO_MESSAGE_10_MAGIC: &str =
    "setup_sar_acknowledgement_of_finalization_received";
pub static SETUP_BOOMLET_ISO_MESSAGE_4_MAGIC: &str = "setup_duress_finished";
pub static SETUP_BOOMLET_NISO_MESSAGE_4_MAGIC: &str = "setup_boomerang_params_fixed";
pub static SETUP_BOOMLET_NISO_MESSAGE_7_MAGIC: &str = "setup_wt_service_confirmed_by_peers";
pub static SETUP_BOOMLET_ISO_MESSAGE_6_MAGIC: &str = "setup_boomlet_backup_done";
pub static SETUP_BOOMLET_NISO_MESSAGE_12_MAGIC: &str = "setup_done";
pub static SETUP_ISO_BOOMLETWO_MESSAGE_1_MAGIC: &str = "setup_backup_started";
pub static SETUP_ISO_OUTPUT_2_MAGIC: &str =
    "setup_boomletwo_identity_pubkey_received_connect_boomlet_to_iso";
pub static SETUP_ISO_OUTPUT_3_MAGIC: &str =
    "setup_boomlet_backup_data_received_connect_boomletwo_to_iso";
pub static SETUP_ISO_OUTPUT_4_MAGIC: &str = "setup_boomlet_backup_done_connect_boomlet_to_iso";
pub static SETUP_ISO_OUTPUT_5_MAGIC: &str =
    "setup_boomlet_backup_completed_boomlet_closed_ready_to_finish_setup";
pub static SETUP_NISO_OUTPUT_2_MAGIC: &str = "setup_sar_finalization_confirmed";
pub static SETUP_NISO_BOOMLET_MESSAGE_1_MAGIC: &str = "setup_initialized";
pub static SETUP_NISO_BOOMLET_MESSAGE_5_MAGIC: &str =
    "setup_boomerang_params_fixed_boomlet_can_draw_mystery";
pub static SETUP_NISO_BOOMLET_MESSAGE_8_MAGIC: &str =
    "setup_wt_service_confirmed_by_peers_sars_can_be_finalized";
pub static SETUP_NISO_BOOMLET_MESSAGE_11_MAGIC: &str = "setup_boomlet_closed_finish_setup";
pub static SETUP_NISO_OUTPUT_3_MAGIC: &str = "setup_done";
pub static SETUP_ISO_INPUT_2_MAGIC: &str =
    "setup_user_is_informed_that_sar_is_set_and_can_install_boomlet_backup";
pub static SETUP_ST_INPUT_3_MAGIC: &str =
    "setup_user_verified_peer_ids_and_wt_ids_received_with_those_registered_before";
pub static SETUP_ISO_INPUT_4_MAGIC: &str =
    "setup_user_is_asked_to_connect_boomletwo_to_iso_boomletwo_connected_to_iso";
pub static SETUP_ISO_INPUT_5_MAGIC: &str =
    "setup_user_is_asked_to_connect_boomlet_to_iso_boomlet_connected_to_iso";
pub static SETUP_NISO_INPUT_4_MAGIC: &str = "setup_user_is_informed_that_boomlet_is_closed";
pub static SETUP_PHONE_OUTPUT_2_MAGIC: &str = "setup_sar_registered_and_connected_to_phone";
pub static SETUP_SAR_PHONE_MESSAGE_2_MAGIC: &str = "setup_sar_setup_done_and_in_sync_with_phone";

pub static WITHDRAWAL_BOOMLET_NISO_MESSAGE_12_MAGIC: &str = "withdrawal_ready_to_sign";
pub static WITHDRAWAL_ISO_BOOMLET_MESSAGE_1_MAGIC: &str = "withdrawal_initialized_start_signing";
pub static WITHDRAWAL_ISO_OUTPUT_1_MAGIC: &str =
    "withdrawal_psbt_signature_created_connect_boomlet_to_niso";
pub static WITHDRAWAL_NISO_OUTPUT_1_MAGIC: &str =
    "withdrawal_ready_to_sign_received_connect_boomlet_to_iso";
pub static WITHDRAWAL_NISO_BOOMLET_MESSAGE_9_MAGIC: &str =
    "withdrawal_signing_finished_export_signed_psbt";
pub static WITHDRAWAL_ST_INPUT_1_MAGIC: &str = "withdrawal_initiator_peer_approved_that_txid_received_is_the_same_as_the_one_derived_from_withdrawal_psbt";
pub static WITHDRAWAL_NON_INITIATOR_NISO_INPUT_1_MAGIC: &str =
    "withdrawal_non_initiator_peer_approved_the_withdrawal_psbt";
pub static WITHDRAWAL_NON_INITIATOR_ST_INPUT_1_MAGIC: &str = "withdrawal_non_initiator_peer_approved_that_txid_received_is_the_same_as_the_one_derived_from_withdrawal_psbt";
pub static WITHDRAWAL_NISO_INPUT_2_MAGIC: &str =
    "withdrawal_peer_is_informed_that_boomlet_should_be_connected_to_niso";
pub static WITHDRAWAL_NON_INITIATOR_NISO_NON_INITIATOR_BOOMLET_MESSAGE_2: &str =
    "withdrawal_peer_agreement_with_psbt_received";

// Others
pub static SHARED_STATE_BOOMERANG_PARAMS_MAGIC: &str = "setup_wt_service_initialized";
pub static SHARED_STATE_SAR_FINALIZATION_MAGIC: &str = "setup_wt_received_sar_data";
pub static SHARED_STATE_BACKUP_DONE_MAGIC: &str =
    "boomlet_backup_done_and_setup_finish_initialized";

pub static SUFFIX_ADDED_BY_WT_MAGIC: &str = "setup_sar_acknowledgement_of_finalization_received";
pub static SUFFIX_ADDED_BY_WT_MAGIC_SETUP_AFTER_SETUP_NISO_WT_MESSAGE_2_SETUP_SERVICE_INITIALIZED: &str = "setup_peers_registration_with_wt_completed";

pub static BOOMLET_BACKUP_REQUEST_MAGIC: &str = "boomlet_backup_request";
pub static BOOMLET_BACKUP_DONE_MAGIC: &str = "boomlet_backup_done";
pub static TX_APPROVAL_MAGIC: &str = "transaction_approved";
pub static TX_COMMIT_MAGIC: &str = "committed_to_transaction";
pub static PING_MAGIC: &str = "ping";
pub static PONG_MAGIC: &str = "pong";
