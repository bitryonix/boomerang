use std::str::FromStr;

use bitcoin::{
    Address, Amount, Network, PublicKey, XOnlyPublicKey,
    key::{Keypair, Secp256k1, rand::thread_rng},
};
use bitcoincore_rpc::{Auth, Client, RpcApi, json::AddressType};
use miniscript::descriptor::Tr;
use protocol::messages::{BranchingMessage2, MetadataAttachedMessage, Parcel};
use tokio::time::{Duration, sleep};

use crate::setup::BoomerangEntities;

pub async fn run(
    boomerang_entities: BoomerangEntities,
    initial_miner_num_blocks_to_mine: u64,
    miner_task_sleeping_time_in_milliseconds: u64,
    deposit_amount_to_boomerang_address_in_int_btc: u64,
    miner_num_blocks_to_mine_for_deposit_transaction_to_be_mined: u64,
    absolute_locktime_for_withdrawal_transaction: u32,
    withdrawal_transaction_amount_in_f64_btc: f64,
) -> Result<(), Box<dyn std::error::Error>> {
    // We now enter withdrawal.
    let BoomerangEntities {
        bitcoin_node,
        network,
        mut peer_1,
        mut peer_2,
        mut peer_3,
        mut peer_4,
        mut peer_5,
        mut peer_1_iso,
        mut peer_2_iso,
        mut peer_3_iso,
        mut peer_4_iso,
        mut peer_5_iso,
        mut peer_1_niso,
        mut peer_2_niso,
        mut peer_3_niso,
        mut peer_4_niso,
        mut peer_5_niso,
        mut peer_1_boomlet,
        mut peer_2_boomlet,
        mut peer_3_boomlet,
        mut peer_4_boomlet,
        mut peer_5_boomlet,
        peer_1_boomletwo: mut _peer_1_boomletwo,
        peer_2_boomletwo: mut _peer_2_boomletwo,
        peer_3_boomletwo: mut _peer_3_boomletwo,
        peer_4_boomletwo: mut _peer_4_boomletwo,
        peer_5_boomletwo: mut _peer_5_boomletwo,
        peer_1_phone: mut _peer_1_phone,
        peer_2_phone: mut _peer_2_phone,
        peer_3_phone: mut _peer_3_phone,
        peer_4_phone: mut _peer_4_phone,
        peer_5_phone: mut _peer_5_phone,
        mut peer_1_st,
        mut peer_2_st,
        mut peer_3_st,
        mut peer_4_st,
        mut peer_5_st,
        mut peer_1_sar_1,
        mut peer_1_sar_2,
        mut peer_2_sar_1,
        mut peer_2_sar_2,
        mut peer_3_sar_1,
        mut peer_3_sar_2,
        mut peer_4_sar_1,
        mut peer_4_sar_2,
        mut peer_5_sar_1,
        mut peer_5_sar_2,
        mut active_wt,
    } = boomerang_entities;
    let bitcoin_node_rpc_address = bitcoin_node.params.rpc_socket;
    let bitcoin_node_cookie_path = bitcoin_node.params.cookie_file.clone();

    let wt_peer_1_id = peer_1_niso.get_wt_peer_id().unwrap();
    let wt_peer_2_id = peer_2_niso.get_wt_peer_id().unwrap();
    let wt_peer_3_id = peer_3_niso.get_wt_peer_id().unwrap();
    let wt_peer_4_id = peer_4_niso.get_wt_peer_id().unwrap();
    let wt_peer_5_id = peer_5_niso.get_wt_peer_id().unwrap();

    let peer_1_sar_1_id = peer_1_sar_1.get_sar_id().unwrap();
    let peer_1_sar_2_id = peer_1_sar_2.get_sar_id().unwrap();
    let peer_2_sar_1_id = peer_2_sar_1.get_sar_id().unwrap();
    let peer_2_sar_2_id = peer_2_sar_2.get_sar_id().unwrap();
    let peer_3_sar_1_id = peer_3_sar_1.get_sar_id().unwrap();
    let peer_3_sar_2_id = peer_3_sar_2.get_sar_id().unwrap();
    let peer_4_sar_1_id = peer_4_sar_1.get_sar_id().unwrap();
    let peer_4_sar_2_id = peer_4_sar_2.get_sar_id().unwrap();
    let peer_5_sar_1_id = peer_5_sar_1.get_sar_id().unwrap();
    let peer_5_sar_2_id = peer_5_sar_2.get_sar_id().unwrap();

    println!("Withdrawal started.");
    // Depositing to boomerang address.
    let miner = Client::new(
        &bitcoin_node_rpc_address.to_string(),
        Auth::CookieFile(bitcoin_node_cookie_path.clone()),
    )
    .unwrap();
    let mining_address = miner
        .get_new_address(Some("mining"), Some(AddressType::Bech32))
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap();
    miner
        .generate_to_address(initial_miner_num_blocks_to_mine, &mining_address)
        .unwrap();
    let task_miner = Client::new(
        &bitcoin_node_rpc_address.to_string(),
        Auth::CookieFile(bitcoin_node_cookie_path.clone()),
    )
    .unwrap();
    let task_mining_address = mining_address.clone();
    let miner_task_handle = tokio::spawn(async move {
        loop {
            sleep(Duration::from_millis(
                miner_task_sleeping_time_in_milliseconds,
            ))
            .await;
            task_miner
                .generate_to_address(1, &task_mining_address)
                .unwrap();
        }
    });
    let secp = Secp256k1::new();
    let destination_keypair = Keypair::new(&secp, &mut thread_rng());
    let destination_pubkey = PublicKey::new(destination_keypair.public_key());
    let destination_address = Address::p2wpkh(&destination_pubkey.try_into().unwrap(), network);
    let boomerang_params = peer_1_niso.get_boomerang_params().unwrap();
    let descriptor =
        Tr::<XOnlyPublicKey>::from_str(boomerang_params.get_boomerang_descriptor()).unwrap();
    let fund_address = descriptor.address(network);
    let fund_txid = miner
        .send_to_address(
            &fund_address,
            Amount::from_int_btc(deposit_amount_to_boomerang_address_in_int_btc),
            None,
            None,
            Some(false),
            Some(true),
            None,
            None,
        )
        .unwrap();
    miner
        .generate_to_address(
            miner_num_blocks_to_mine_for_deposit_transaction_to_be_mined,
            &mining_address,
        )
        .unwrap();
    let get_transaction_result = miner.get_transaction(&fund_txid, None).unwrap();
    let (vout, _tx_out) = get_transaction_result
        .transaction()
        .unwrap()
        .output
        .iter()
        .enumerate()
        .find(|(_vout, tx_out)| tx_out.script_pubkey == fund_address.script_pubkey())
        .map(|(vout, tx_out)| (vout, tx_out.clone()))
        .unwrap();
    println!(
        "Confirmations: {}",
        get_transaction_result.info.confirmations
    );

    ////////////////////////////////////////////
    // Step 1 of Initiator Withdrawal Diagram //
    ////////////////////////////////////////////
    println!("Step 1 (Initiator Diagram):");
    let peer_1_withdrawal_niso_input_1 = peer_1
        .produce_withdrawal_niso_input_1(
            destination_address,
            fund_txid,
            vout as u32,
            absolute_locktime_for_withdrawal_transaction,
            withdrawal_transaction_amount_in_f64_btc,
        )
        .unwrap();
    println!(
        "Initiator peer produced WithdrawalNisoInput1 to share the withdrawal PSBT with their NISO."
    );

    ////////////////////////////////////////////
    // Step 2 of Initiator Withdrawal Diagram //
    ////////////////////////////////////////////
    println!("Step 2 (Initiator Diagram):");
    peer_1_niso
        .consume_withdrawal_niso_input_1(peer_1_withdrawal_niso_input_1)
        .unwrap();
    println!("Initiator NISO received the withdrawal PSBT.");
    let peer_1_withdrawal_niso_boomlet_message_1 = peer_1_niso
        .produce_withdrawal_niso_boomlet_message_1()
        .unwrap();
    println!("Initiator Niso produced WithdrawalNisoBoomletMessage1 to give PSBT to Boomlet.");

    ////////////////////////////////////////////
    // Step 3 of Initiator Withdrawal Diagram //
    ////////////////////////////////////////////
    println!("Step 3 (Initiator Diagram):");
    peer_1_boomlet
        .consume_withdrawal_niso_boomlet_message_1(peer_1_withdrawal_niso_boomlet_message_1)
        .unwrap();
    println!("Initiator Boomlet received the withdrawal PSBT.");
    let peer_1_withdrawal_boomlet_niso_message_1 = peer_1_boomlet
        .produce_withdrawal_boomlet_niso_message_1()
        .unwrap();
    println!(
        "Initiator Boomlet produced WithdrawalBoomletNisoMessage1 to give the peer verification request to NISO."
    );

    ////////////////////////////////////////////
    // Step 4 of Initiator Withdrawal Diagram //
    ////////////////////////////////////////////
    println!("Step 4 (Initiator Diagram):");
    peer_1_niso
        .consume_withdrawal_boomlet_niso_message_1(peer_1_withdrawal_boomlet_niso_message_1)
        .unwrap();
    println!("Initiator NISO received the peer verification request.");
    let peer_1_withdrawal_niso_st_message_1 =
        peer_1_niso.produce_withdrawal_niso_st_message_1().unwrap();
    println!(
        "Initiator NISO produced WithdrawalNisoStMessage1 to give the peer verification request to ST."
    );

    ////////////////////////////////////////////
    // Step 5 of Initiator Withdrawal Diagram //
    ////////////////////////////////////////////
    println!("Step 5 (Initiator Diagram):");
    peer_1_st
        .consume_withdrawal_niso_st_message_1(peer_1_withdrawal_niso_st_message_1)
        .unwrap();
    println!("Initiator ST received the peer verification request.");
    let peer_1_withdrawal_st_output_1 = peer_1_st.produce_withdrawal_st_output_1().unwrap();
    println!(
        "Initiator ST produced WithdrawalStOutput1 to give the peer verification request to peer."
    );

    ////////////////////////////////////////////
    // Step 6 of Initiator Withdrawal Diagram //
    ////////////////////////////////////////////
    println!("Step 6 (Initiator Diagram):");
    peer_1
        .consume_withdrawal_st_output_1(peer_1_withdrawal_st_output_1)
        .unwrap();
    println!("Initiator peer received the peer verification request.");
    let peer_1_withdrawal_st_input_1 = peer_1.produce_withdrawal_st_input_1().unwrap();
    println!(
        "Initiator peer produced WithdrawalStInput1 to give peer's consent to transaction to ST."
    );

    ////////////////////////////////////////////
    // Step 7 of Initiator Withdrawal Diagram //
    ////////////////////////////////////////////
    println!("Step 7 (Initiator Diagram):");
    peer_1_st
        .consume_withdrawal_st_input_1(peer_1_withdrawal_st_input_1)
        .unwrap();
    println!("Initiator ST received peer's consent to transaction.");
    let peer_1_withdrawal_st_niso_message_1 =
        peer_1_st.produce_withdrawal_st_niso_message_1().unwrap();
    println!(
        "Initiator ST produced WithdrawalStNisoMessage1 to give peer's consent to transaction to NISO."
    );

    ////////////////////////////////////////////
    // Step 8 of Initiator Withdrawal Diagram //
    ////////////////////////////////////////////
    println!("Step 8 (Initiator Diagram):");
    peer_1_niso
        .consume_withdrawal_st_niso_message_1(peer_1_withdrawal_st_niso_message_1)
        .unwrap();
    println!("Initiator NISO received peer's consent to transaction.");
    let peer_1_withdrawal_niso_boomlet_message_2 = peer_1_niso
        .produce_withdrawal_niso_boomlet_message_2()
        .unwrap();
    println!(
        "Initiator NISO produced WithdrawalNisoBoomletMessage2 to give peer's consent to transaction to Boomlet."
    );

    ////////////////////////////////////////////
    // Step 9 of Initiator Withdrawal Diagram //
    ////////////////////////////////////////////
    println!("Step 9 (Initiator Diagram):");
    peer_1_boomlet
        .consume_withdrawal_niso_boomlet_message_2(peer_1_withdrawal_niso_boomlet_message_2)
        .unwrap();
    println!("Initiator Boomlet received peer's consent to transaction.");
    let peer_1_withdrawal_boomlet_niso_message_2 = peer_1_boomlet
        .produce_withdrawal_boomlet_niso_message_2()
        .unwrap();
    println!(
        "Initiator Boomlet produced WithdrawalBoomletNisoMessage2 to give the tx approval to NISO."
    );

    /////////////////////////////////////////////
    // Step 10 of Initiator Withdrawal Diagram //
    /////////////////////////////////////////////
    println!("Step 10 (Initiator Diagram):");
    peer_1_niso
        .consume_withdrawal_boomlet_niso_message_2(peer_1_withdrawal_boomlet_niso_message_2)
        .unwrap();
    println!("Initiator NISO received the tx approval.");
    let peer_1_withdrawal_niso_wt_message_1 =
        peer_1_niso.produce_withdrawal_niso_wt_message_1().unwrap();
    println!(
        "Initiator NISO produced WithdrawalNisoWtMessage1 to give the tx approval to watchtower."
    );

    ////////////////////////////////////////////////
    // Step 11 of Non-Initiator Withdrawal Diagram //
    ////////////////////////////////////////////////
    println!("Step 11 (Non-Initiator Diagram):");
    active_wt
        .consume_withdrawal_niso_wt_message_1(MetadataAttachedMessage::new(
            wt_peer_1_id.clone(),
            peer_1_withdrawal_niso_wt_message_1,
        ))
        .unwrap();
    println!("Watchtower received the tx approval.");
    let active_wt_parcel_to_be_sent_withdrawal_wt_non_initiator_niso_message_1 = active_wt
        .produce_withdrawal_wt_non_initiator_niso_message_1()
        .unwrap();
    println!(
        "Watchtower produced WithdrawalWtNonInitiatorNisoMessage1 to give the encrypted withdrawal PSBT to non-initiator NISOs."
    );

    ////////////////////////////////////////////////
    // Step 12 of Non-Initiator Withdrawal Diagram //
    ////////////////////////////////////////////////
    println!("Step 12 (Non-Initiator Diagram):");
    let peer_2_withdrawal_wt_non_initiator_niso_message_1 =
        active_wt_parcel_to_be_sent_withdrawal_wt_non_initiator_niso_message_1
            .look_for_message(&wt_peer_2_id)
            .unwrap()
            .clone();
    let peer_3_withdrawal_wt_non_initiator_niso_message_1 =
        active_wt_parcel_to_be_sent_withdrawal_wt_non_initiator_niso_message_1
            .look_for_message(&wt_peer_3_id)
            .unwrap()
            .clone();
    let peer_4_withdrawal_wt_non_initiator_niso_message_1 =
        active_wt_parcel_to_be_sent_withdrawal_wt_non_initiator_niso_message_1
            .look_for_message(&wt_peer_4_id)
            .unwrap()
            .clone();
    let peer_5_withdrawal_wt_non_initiator_niso_message_1 =
        active_wt_parcel_to_be_sent_withdrawal_wt_non_initiator_niso_message_1
            .look_for_message(&wt_peer_5_id)
            .unwrap()
            .clone();
    peer_2_niso
        .consume_withdrawal_wt_non_initiator_niso_message_1(
            peer_2_withdrawal_wt_non_initiator_niso_message_1,
        )
        .unwrap();
    peer_3_niso
        .consume_withdrawal_wt_non_initiator_niso_message_1(
            peer_3_withdrawal_wt_non_initiator_niso_message_1,
        )
        .unwrap();
    peer_4_niso
        .consume_withdrawal_wt_non_initiator_niso_message_1(
            peer_4_withdrawal_wt_non_initiator_niso_message_1,
        )
        .unwrap();
    peer_5_niso
        .consume_withdrawal_wt_non_initiator_niso_message_1(
            peer_5_withdrawal_wt_non_initiator_niso_message_1,
        )
        .unwrap();
    println!("Non-Initiator NISOs received the encrypted withdrawal PSBT.");
    let peer_2_withdrawal_non_initiator_niso_non_initiator_boomlet_message_1 = peer_2_niso
        .produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_1()
        .unwrap();
    let peer_3_withdrawal_non_initiator_niso_non_initiator_boomlet_message_1 = peer_3_niso
        .produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_1()
        .unwrap();
    let peer_4_withdrawal_non_initiator_niso_non_initiator_boomlet_message_1 = peer_4_niso
        .produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_1()
        .unwrap();
    let peer_5_withdrawal_non_initiator_niso_non_initiator_boomlet_message_1 = peer_5_niso
        .produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_1()
        .unwrap();
    println!(
        "Non-Initiator NISOs produced WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage1 to give the encrypted withdrawal PSBT to Boomlets."
    );

    ////////////////////////////////////////////////
    // Step 13 of Non-Initiator Withdrawal Diagram //
    ////////////////////////////////////////////////
    println!("Step 13 (Non-Initiator Diagram):");
    peer_2_boomlet
        .consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_1(
            peer_2_withdrawal_non_initiator_niso_non_initiator_boomlet_message_1,
        )
        .unwrap();
    peer_3_boomlet
        .consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_1(
            peer_3_withdrawal_non_initiator_niso_non_initiator_boomlet_message_1,
        )
        .unwrap();
    peer_4_boomlet
        .consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_1(
            peer_4_withdrawal_non_initiator_niso_non_initiator_boomlet_message_1,
        )
        .unwrap();
    peer_5_boomlet
        .consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_1(
            peer_5_withdrawal_non_initiator_niso_non_initiator_boomlet_message_1,
        )
        .unwrap();
    println!("Non-Initiator Boomlets received the encrypted withdrawal PSBT.");
    let peer_2_withdrawal_non_initiator_boomlet_non_initiator_niso_message_1 = peer_2_boomlet
        .produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_1()
        .unwrap();
    let peer_3_withdrawal_non_initiator_boomlet_non_initiator_niso_message_1 = peer_3_boomlet
        .produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_1()
        .unwrap();
    let peer_4_withdrawal_non_initiator_boomlet_non_initiator_niso_message_1 = peer_4_boomlet
        .produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_1()
        .unwrap();
    let peer_5_withdrawal_non_initiator_boomlet_non_initiator_niso_message_1 = peer_5_boomlet
        .produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_1()
        .unwrap();
    println!(
        "Non-Initiator Boomlets produced WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage1 to give the decrypted withdrawal PSBT to NISOs."
    );

    ////////////////////////////////////////////////
    // Step 14 of Non-Initiator Withdrawal Diagram //
    ////////////////////////////////////////////////
    println!("Step 14 (Non-Initiator Diagram):");
    peer_2_niso
        .consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_1(
            peer_2_withdrawal_non_initiator_boomlet_non_initiator_niso_message_1,
        )
        .unwrap();
    peer_3_niso
        .consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_1(
            peer_3_withdrawal_non_initiator_boomlet_non_initiator_niso_message_1,
        )
        .unwrap();
    peer_4_niso
        .consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_1(
            peer_4_withdrawal_non_initiator_boomlet_non_initiator_niso_message_1,
        )
        .unwrap();
    peer_5_niso
        .consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_1(
            peer_5_withdrawal_non_initiator_boomlet_non_initiator_niso_message_1,
        )
        .unwrap();
    println!("Non-Initiator NISOs received the decrypted withdrawal PSBT.");
    let peer_2_withdrawal_non_initiator_niso_output_1 = peer_2_niso
        .produce_withdrawal_non_initiator_niso_output_1()
        .unwrap();
    let peer_3_withdrawal_non_initiator_niso_output_1 = peer_3_niso
        .produce_withdrawal_non_initiator_niso_output_1()
        .unwrap();
    let peer_4_withdrawal_non_initiator_niso_output_1 = peer_4_niso
        .produce_withdrawal_non_initiator_niso_output_1()
        .unwrap();
    let peer_5_withdrawal_non_initiator_niso_output_1 = peer_5_niso
        .produce_withdrawal_non_initiator_niso_output_1()
        .unwrap();
    println!(
        "Non-Initiator NISOs produced WithdrawalNonInitiatorNisoOutput1 to give the withdrawal PSBT to peers."
    );

    ////////////////////////////////////////////////
    // Step 15 of Non-Initiator Withdrawal Diagram //
    ////////////////////////////////////////////////
    println!("Step 15 (Non-Initiator Diagram):");
    peer_2
        .consume_withdrawal_non_initiator_niso_output_1(
            peer_2_withdrawal_non_initiator_niso_output_1,
        )
        .unwrap();
    peer_3
        .consume_withdrawal_non_initiator_niso_output_1(
            peer_3_withdrawal_non_initiator_niso_output_1,
        )
        .unwrap();
    peer_4
        .consume_withdrawal_non_initiator_niso_output_1(
            peer_4_withdrawal_non_initiator_niso_output_1,
        )
        .unwrap();
    peer_5
        .consume_withdrawal_non_initiator_niso_output_1(
            peer_5_withdrawal_non_initiator_niso_output_1,
        )
        .unwrap();

    println!("Peers received the withdrawal PSBT.");
    let peer_2_withdrawal_non_initiator_niso_input_1 = peer_2
        .produce_withdrawal_non_initiator_niso_input_1()
        .unwrap();
    let peer_3_withdrawal_non_initiator_niso_input_1 = peer_3
        .produce_withdrawal_non_initiator_niso_input_1()
        .unwrap();
    let peer_4_withdrawal_non_initiator_niso_input_1 = peer_4
        .produce_withdrawal_non_initiator_niso_input_1()
        .unwrap();
    let peer_5_withdrawal_non_initiator_niso_input_1 = peer_5
        .produce_withdrawal_non_initiator_niso_input_1()
        .unwrap();

    println!(
        "Peers produced WithdrawalNonInitiatorNisoInput1 to give their agreement with the withdrawal PSBT to non-initiator NISOs."
    );

    ////////////////////////////////////////////////
    // Step 16 of Non-Initiator Withdrawal Diagram //
    ////////////////////////////////////////////////
    println!("Step 16 (Non-Initiator Diagram):");
    peer_2_niso
        .consume_withdrawal_non_initiator_niso_input_1(peer_2_withdrawal_non_initiator_niso_input_1)
        .unwrap();
    peer_3_niso
        .consume_withdrawal_non_initiator_niso_input_1(peer_3_withdrawal_non_initiator_niso_input_1)
        .unwrap();
    peer_4_niso
        .consume_withdrawal_non_initiator_niso_input_1(peer_4_withdrawal_non_initiator_niso_input_1)
        .unwrap();
    peer_5_niso
        .consume_withdrawal_non_initiator_niso_input_1(peer_5_withdrawal_non_initiator_niso_input_1)
        .unwrap();
    println!("Non-Initiator NISOs received peers' agreement with the withdrawal PSBT.");
    let peer_2_withdrawal_non_initiator_niso_non_initiator_boomlet_message_2 = peer_2_niso
        .produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_2()
        .unwrap();
    let peer_3_withdrawal_non_initiator_niso_non_initiator_boomlet_message_2 = peer_3_niso
        .produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_2()
        .unwrap();
    let peer_4_withdrawal_non_initiator_niso_non_initiator_boomlet_message_2 = peer_4_niso
        .produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_2()
        .unwrap();
    let peer_5_withdrawal_non_initiator_niso_non_initiator_boomlet_message_2 = peer_5_niso
        .produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_2()
        .unwrap();
    println!(
        "Non-Initiator NISOs produced WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage2 to give the event block height Boomlets."
    );

    ////////////////////////////////////////////////
    // Step 17 of Non-Initiator Withdrawal Diagram //
    ////////////////////////////////////////////////
    println!("Step 17 (Non-Initiator Diagram):");
    peer_2_boomlet
        .consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_2(
            peer_2_withdrawal_non_initiator_niso_non_initiator_boomlet_message_2,
        )
        .unwrap();
    peer_3_boomlet
        .consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_2(
            peer_3_withdrawal_non_initiator_niso_non_initiator_boomlet_message_2,
        )
        .unwrap();
    peer_4_boomlet
        .consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_2(
            peer_4_withdrawal_non_initiator_niso_non_initiator_boomlet_message_2,
        )
        .unwrap();
    peer_5_boomlet
        .consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_2(
            peer_5_withdrawal_non_initiator_niso_non_initiator_boomlet_message_2,
        )
        .unwrap();
    println!("Non-Initiator Boomlets received the event block height.");
    let peer_2_withdrawal_non_initiator_boomlet_non_initiator_niso_message_2 = peer_2_boomlet
        .produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_2()
        .unwrap();
    let peer_3_withdrawal_non_initiator_boomlet_non_initiator_niso_message_2 = peer_3_boomlet
        .produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_2()
        .unwrap();
    let peer_4_withdrawal_non_initiator_boomlet_non_initiator_niso_message_2 = peer_4_boomlet
        .produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_2()
        .unwrap();
    let peer_5_withdrawal_non_initiator_boomlet_non_initiator_niso_message_2 = peer_5_boomlet
        .produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_2()
        .unwrap();
    println!(
        "Non-Initiator Boomlets produced WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage1 to give the peer verification request to NISOs."
    );

    ////////////////////////////////////////////////
    // Step 18 of Non-Initiator Withdrawal Diagram //
    ////////////////////////////////////////////////
    println!("Step 18 (Non-Initiator Diagram):");
    peer_2_niso
        .consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_2(
            peer_2_withdrawal_non_initiator_boomlet_non_initiator_niso_message_2,
        )
        .unwrap();
    peer_3_niso
        .consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_2(
            peer_3_withdrawal_non_initiator_boomlet_non_initiator_niso_message_2,
        )
        .unwrap();
    peer_4_niso
        .consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_2(
            peer_4_withdrawal_non_initiator_boomlet_non_initiator_niso_message_2,
        )
        .unwrap();
    peer_5_niso
        .consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_2(
            peer_5_withdrawal_non_initiator_boomlet_non_initiator_niso_message_2,
        )
        .unwrap();
    println!("Non-Initiator NISOs received the peer verification request.");
    let peer_2_withdrawal_non_initiator_niso_non_initiator_st_message_1 = peer_2_niso
        .produce_withdrawal_non_initiator_niso_non_initiator_st_message_1()
        .unwrap();
    let peer_3_withdrawal_non_initiator_niso_non_initiator_st_message_1 = peer_3_niso
        .produce_withdrawal_non_initiator_niso_non_initiator_st_message_1()
        .unwrap();
    let peer_4_withdrawal_non_initiator_niso_non_initiator_st_message_1 = peer_4_niso
        .produce_withdrawal_non_initiator_niso_non_initiator_st_message_1()
        .unwrap();
    let peer_5_withdrawal_non_initiator_niso_non_initiator_st_message_1 = peer_5_niso
        .produce_withdrawal_non_initiator_niso_non_initiator_st_message_1()
        .unwrap();
    println!(
        "Non-Initiator NISOs produced WithdrawalNonInitiatorNisoNonInitiatorStMessage1 to give the peer verification request to STs."
    );

    ////////////////////////////////////////////////
    // Step 19 of Non-Initiator Withdrawal Diagram //
    ////////////////////////////////////////////////
    println!("Step 19 (Non-Initiator Diagram):");
    peer_2_st
        .consume_withdrawal_non_initiator_niso_non_initiator_st_message_1(
            peer_2_withdrawal_non_initiator_niso_non_initiator_st_message_1,
        )
        .unwrap();
    peer_3_st
        .consume_withdrawal_non_initiator_niso_non_initiator_st_message_1(
            peer_3_withdrawal_non_initiator_niso_non_initiator_st_message_1,
        )
        .unwrap();
    peer_4_st
        .consume_withdrawal_non_initiator_niso_non_initiator_st_message_1(
            peer_4_withdrawal_non_initiator_niso_non_initiator_st_message_1,
        )
        .unwrap();
    peer_5_st
        .consume_withdrawal_non_initiator_niso_non_initiator_st_message_1(
            peer_5_withdrawal_non_initiator_niso_non_initiator_st_message_1,
        )
        .unwrap();
    println!("Non-Initiator STs received the peer verification request.");
    let peer_2_withdrawal_non_initiator_st_output_1 = peer_2_st
        .produce_withdrawal_non_initiator_st_output_1()
        .unwrap();
    let peer_3_withdrawal_non_initiator_st_output_1 = peer_3_st
        .produce_withdrawal_non_initiator_st_output_1()
        .unwrap();
    let peer_4_withdrawal_non_initiator_st_output_1 = peer_4_st
        .produce_withdrawal_non_initiator_st_output_1()
        .unwrap();
    let peer_5_withdrawal_non_initiator_st_output_1 = peer_5_st
        .produce_withdrawal_non_initiator_st_output_1()
        .unwrap();
    println!(
        "Non-Initiator STs produced WithdrawalNonInitiatorStOutput1 to give the peer verification request to peer."
    );

    /////////////////////////////////////////////////
    // Step 20 of Non-Initiator Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 20 (Non-Initiator Diagram):");
    peer_2
        .consume_withdrawal_non_initiator_st_output_1(peer_2_withdrawal_non_initiator_st_output_1)
        .unwrap();
    peer_3
        .consume_withdrawal_non_initiator_st_output_1(peer_3_withdrawal_non_initiator_st_output_1)
        .unwrap();
    peer_4
        .consume_withdrawal_non_initiator_st_output_1(peer_4_withdrawal_non_initiator_st_output_1)
        .unwrap();
    peer_5
        .consume_withdrawal_non_initiator_st_output_1(peer_5_withdrawal_non_initiator_st_output_1)
        .unwrap();

    println!("Non-Initiator peers received the peer verification request.");
    let peer_2_withdrawal_non_initiator_st_input_1 = peer_2
        .produce_withdrawal_non_initiator_st_input_1()
        .unwrap();
    let peer_3_withdrawal_non_initiator_st_input_1 = peer_3
        .produce_withdrawal_non_initiator_st_input_1()
        .unwrap();
    let peer_4_withdrawal_non_initiator_st_input_1 = peer_4
        .produce_withdrawal_non_initiator_st_input_1()
        .unwrap();
    let peer_5_withdrawal_non_initiator_st_input_1 = peer_5
        .produce_withdrawal_non_initiator_st_input_1()
        .unwrap();
    println!(
        "Non-Initiator peers produced WithdrawalNonInitiatorStInput1 to give peers' consent to transaction to STs."
    );

    /////////////////////////////////////////////////
    // Step 21 of Non-Initiator Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 21 (Non-Initiator Diagram):");
    peer_2_st
        .consume_withdrawal_non_initiator_st_input_1(peer_2_withdrawal_non_initiator_st_input_1)
        .unwrap();
    peer_3_st
        .consume_withdrawal_non_initiator_st_input_1(peer_3_withdrawal_non_initiator_st_input_1)
        .unwrap();
    peer_4_st
        .consume_withdrawal_non_initiator_st_input_1(peer_4_withdrawal_non_initiator_st_input_1)
        .unwrap();
    peer_5_st
        .consume_withdrawal_non_initiator_st_input_1(peer_5_withdrawal_non_initiator_st_input_1)
        .unwrap();
    println!("Non-Initiator STs received peers' consent to transaction.");
    let peer_2_withdrawal_non_initiator_st_non_initiator_niso_message_1 = peer_2_st
        .produce_withdrawal_non_initiator_st_non_initiator_niso_message_1()
        .unwrap();
    let peer_3_withdrawal_non_initiator_st_non_initiator_niso_message_1 = peer_3_st
        .produce_withdrawal_non_initiator_st_non_initiator_niso_message_1()
        .unwrap();
    let peer_4_withdrawal_non_initiator_st_non_initiator_niso_message_1 = peer_4_st
        .produce_withdrawal_non_initiator_st_non_initiator_niso_message_1()
        .unwrap();
    let peer_5_withdrawal_non_initiator_st_non_initiator_niso_message_1 = peer_5_st
        .produce_withdrawal_non_initiator_st_non_initiator_niso_message_1()
        .unwrap();
    println!(
        "Non-Initiator STs produced WithdrawalNonInitiatorStNonInitiatorNisoMessage1 to give peers' consent to transaction to NISOs."
    );

    /////////////////////////////////////////////////
    // Step 22 of Non-Initiator Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 22 (Non-Initiator Diagram):");
    peer_2_niso
        .consume_withdrawal_non_initiator_st_non_initiator_niso_message_1(
            peer_2_withdrawal_non_initiator_st_non_initiator_niso_message_1,
        )
        .unwrap();
    peer_3_niso
        .consume_withdrawal_non_initiator_st_non_initiator_niso_message_1(
            peer_3_withdrawal_non_initiator_st_non_initiator_niso_message_1,
        )
        .unwrap();
    peer_4_niso
        .consume_withdrawal_non_initiator_st_non_initiator_niso_message_1(
            peer_4_withdrawal_non_initiator_st_non_initiator_niso_message_1,
        )
        .unwrap();
    peer_5_niso
        .consume_withdrawal_non_initiator_st_non_initiator_niso_message_1(
            peer_5_withdrawal_non_initiator_st_non_initiator_niso_message_1,
        )
        .unwrap();
    println!("Non-Initiator NISOs received peers' consent to transaction.");
    let peer_2_withdrawal_non_initiator_niso_non_initiator_boomlet_message_3 = peer_2_niso
        .produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_3()
        .unwrap();
    let peer_3_withdrawal_non_initiator_niso_non_initiator_boomlet_message_3 = peer_3_niso
        .produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_3()
        .unwrap();
    let peer_4_withdrawal_non_initiator_niso_non_initiator_boomlet_message_3 = peer_4_niso
        .produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_3()
        .unwrap();
    let peer_5_withdrawal_non_initiator_niso_non_initiator_boomlet_message_3 = peer_5_niso
        .produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_3()
        .unwrap();
    println!(
        "Non-Initiator NISOs produced WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage3 to give peers' consent to transaction Boomlets."
    );

    /////////////////////////////////////////////////
    // Step 23 of Non-Initiator Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 23 (Non-Initiator Diagram):");
    peer_2_boomlet
        .consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_3(
            peer_2_withdrawal_non_initiator_niso_non_initiator_boomlet_message_3,
        )
        .unwrap();
    peer_3_boomlet
        .consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_3(
            peer_3_withdrawal_non_initiator_niso_non_initiator_boomlet_message_3,
        )
        .unwrap();
    peer_4_boomlet
        .consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_3(
            peer_4_withdrawal_non_initiator_niso_non_initiator_boomlet_message_3,
        )
        .unwrap();
    peer_5_boomlet
        .consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_3(
            peer_5_withdrawal_non_initiator_niso_non_initiator_boomlet_message_3,
        )
        .unwrap();
    println!("Non-Initiator Boomlets received peers' consent to transaction.");
    let peer_2_withdrawal_non_initiator_boomlet_non_initiator_niso_message_3 = peer_2_boomlet
        .produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_3()
        .unwrap();
    let peer_3_withdrawal_non_initiator_boomlet_non_initiator_niso_message_3 = peer_3_boomlet
        .produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_3()
        .unwrap();
    let peer_4_withdrawal_non_initiator_boomlet_non_initiator_niso_message_3 = peer_4_boomlet
        .produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_3()
        .unwrap();
    let peer_5_withdrawal_non_initiator_boomlet_non_initiator_niso_message_3 = peer_5_boomlet
        .produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_3()
        .unwrap();
    println!(
        "Non-Initiator Boomlets produced WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage3 to give the tx approval to NISOs."
    );

    /////////////////////////////////////////////////
    // Step 24 of Non-Initiator Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 24 (Non-Initiator Diagram):");
    peer_2_niso
        .consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_3(
            peer_2_withdrawal_non_initiator_boomlet_non_initiator_niso_message_3,
        )
        .unwrap();
    peer_3_niso
        .consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_3(
            peer_3_withdrawal_non_initiator_boomlet_non_initiator_niso_message_3,
        )
        .unwrap();
    peer_4_niso
        .consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_3(
            peer_4_withdrawal_non_initiator_boomlet_non_initiator_niso_message_3,
        )
        .unwrap();
    peer_5_niso
        .consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_3(
            peer_5_withdrawal_non_initiator_boomlet_non_initiator_niso_message_3,
        )
        .unwrap();
    println!("Non-Initiator NISOs received the tx approval.");
    let peer_2_withdrawal_non_initiator_niso_wt_message_1 = peer_2_niso
        .produce_withdrawal_non_initiator_niso_wt_message_1()
        .unwrap();
    let peer_3_withdrawal_non_initiator_niso_wt_message_1 = peer_3_niso
        .produce_withdrawal_non_initiator_niso_wt_message_1()
        .unwrap();
    let peer_4_withdrawal_non_initiator_niso_wt_message_1 = peer_4_niso
        .produce_withdrawal_non_initiator_niso_wt_message_1()
        .unwrap();
    let peer_5_withdrawal_non_initiator_niso_wt_message_1 = peer_5_niso
        .produce_withdrawal_non_initiator_niso_wt_message_1()
        .unwrap();
    println!(
        "Non-Initiator NISOs produced WithdrawalNonInitiatorNisoWtMessage1 to give the tx approval to watchtower."
    );

    /////////////////////////////////////////////////
    // Step 25 of Initiator     Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 25 (Initiator Diagram):");

    let active_wt_parcel_to_be_received_withdrawal_non_initiator_niso_wt_message_1 =
        Parcel::new(vec![
            MetadataAttachedMessage::new(
                wt_peer_2_id.clone(),
                peer_2_withdrawal_non_initiator_niso_wt_message_1,
            ),
            MetadataAttachedMessage::new(
                wt_peer_3_id.clone(),
                peer_3_withdrawal_non_initiator_niso_wt_message_1,
            ),
            MetadataAttachedMessage::new(
                wt_peer_4_id.clone(),
                peer_4_withdrawal_non_initiator_niso_wt_message_1,
            ),
            MetadataAttachedMessage::new(
                wt_peer_5_id.clone(),
                peer_5_withdrawal_non_initiator_niso_wt_message_1,
            ),
        ]);
    active_wt
        .consume_withdrawal_non_initiator_niso_wt_message_1(
            active_wt_parcel_to_be_received_withdrawal_non_initiator_niso_wt_message_1,
        )
        .unwrap();
    println!("Watchtower received the non-initiator tx approvals.");
    let active_wt_withdrawal_wt_niso_message_1 =
        active_wt.produce_withdrawal_wt_niso_message_1().unwrap();
    println!(
        "Watchtower produced WithdrawalWtNisoMessage1 to give the tx approval of all peers to the initiator NISO."
    );

    /////////////////////////////////////////////////
    // Step 26 of Non-Initiator Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 26 (Non-Initiator Diagram):");
    let active_wt_parcel_to_be_sent_withdrawal_wt_non_initiator_niso_message_2 = active_wt
        .produce_withdrawal_wt_non_initiator_niso_message_2()
        .unwrap();
    println!(
        "Watchtower produced parcel of WithdrawalWtNonInitiatorNisoMessage2 to give the tx approval of all peers to the non-initiator NISOs."
    );

    /////////////////////////////////////////////////
    // Step 27 of Initiator     Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 27 (Initiator Diagram):");
    peer_1_niso
        .consume_withdrawal_wt_niso_message_1(active_wt_withdrawal_wt_niso_message_1)
        .unwrap();
    println!("Initiator NISO received the tx approval of all peers.");
    let peer_1_withdrawal_niso_boomlet_message_3 = peer_1_niso
        .produce_withdrawal_niso_boomlet_message_3()
        .unwrap();
    println!(
        "Initiator NISO produced WithdrawalNisoBoomletMessage3 to give the tx approval of all peers to Boomlet."
    );
    /////////////////////////////////////////////////
    // Step 27n of Non-Initiator Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 27n (Non-Initiator Diagram):");
    peer_2_niso
        .consume_withdrawal_wt_non_initiator_niso_message_2(
            active_wt_parcel_to_be_sent_withdrawal_wt_non_initiator_niso_message_2
                .look_for_message(&wt_peer_2_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_3_niso
        .consume_withdrawal_wt_non_initiator_niso_message_2(
            active_wt_parcel_to_be_sent_withdrawal_wt_non_initiator_niso_message_2
                .look_for_message(&wt_peer_3_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_4_niso
        .consume_withdrawal_wt_non_initiator_niso_message_2(
            active_wt_parcel_to_be_sent_withdrawal_wt_non_initiator_niso_message_2
                .look_for_message(&wt_peer_4_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_5_niso
        .consume_withdrawal_wt_non_initiator_niso_message_2(
            active_wt_parcel_to_be_sent_withdrawal_wt_non_initiator_niso_message_2
                .look_for_message(&wt_peer_5_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    println!("Non-Initiator NISOs received the tx approval of all peers.");
    let peer_2_withdrawal_non_initiator_niso_non_initiator_boomlet_message_4 = peer_2_niso
        .produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_4()
        .unwrap();
    let peer_3_withdrawal_non_initiator_niso_non_initiator_boomlet_message_4 = peer_3_niso
        .produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_4()
        .unwrap();
    let peer_4_withdrawal_non_initiator_niso_non_initiator_boomlet_message_4 = peer_4_niso
        .produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_4()
        .unwrap();
    let peer_5_withdrawal_non_initiator_niso_non_initiator_boomlet_message_4 = peer_5_niso
        .produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_4()
        .unwrap();
    println!(
        "Non-Initiator NISOs produced WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage4 to give all tx approvals Boomlets."
    );

    /////////////////////////////////////////////////
    // Step 28 of Initiator     Withdrawal Diagram //
    /////////////////////////////////////////////////

    println!("Step 28 (Initiator Diagram):");
    peer_1_boomlet
        .consume_withdrawal_niso_boomlet_message_3(peer_1_withdrawal_niso_boomlet_message_3)
        .unwrap();
    println!("Initiator Boomlet received the tx approval of all peers.");
    let peer_1_withdrawal_boomlet_niso_message_3 = peer_1_boomlet
        .produce_withdrawal_boomlet_niso_message_3()
        .unwrap();
    println!(
        "Initiator Boomlet produced WithdrawalBoomletNisoMessage3 to give the duress check space with nonce to NISO."
    );

    /////////////////////////////////////////////////
    // Step 28n of Non-Initiator Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 28n (Non-Initiator Diagram):");

    peer_2_boomlet
        .consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_4(
            peer_2_withdrawal_non_initiator_niso_non_initiator_boomlet_message_4,
        )
        .unwrap();
    peer_3_boomlet
        .consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_4(
            peer_3_withdrawal_non_initiator_niso_non_initiator_boomlet_message_4,
        )
        .unwrap();
    peer_4_boomlet
        .consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_4(
            peer_4_withdrawal_non_initiator_niso_non_initiator_boomlet_message_4,
        )
        .unwrap();
    peer_5_boomlet
        .consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_4(
            peer_5_withdrawal_non_initiator_niso_non_initiator_boomlet_message_4,
        )
        .unwrap();
    println!("Non-Initiator Boomlets received all tx approvals.");
    let peer_2_withdrawal_non_initiator_boomlet_non_initiator_niso_message_4 = peer_2_boomlet
        .produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_4()
        .unwrap();
    let peer_3_withdrawal_non_initiator_boomlet_non_initiator_niso_message_4 = peer_3_boomlet
        .produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_4()
        .unwrap();
    let peer_4_withdrawal_non_initiator_boomlet_non_initiator_niso_message_4 = peer_4_boomlet
        .produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_4()
        .unwrap();
    let peer_5_withdrawal_non_initiator_boomlet_non_initiator_niso_message_4 = peer_5_boomlet
        .produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_4()
        .unwrap();
    println!(
        "Non-Initiator Boomlets produced WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage4 to give the duress check space with nonce to NISOs."
    );

    /////////////////////////////////////////////////
    // Step 29 of Initiator     Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 29 (Initiator Diagram):");
    peer_1_niso
        .consume_withdrawal_boomlet_niso_message_3(peer_1_withdrawal_boomlet_niso_message_3)
        .unwrap();
    println!("Initiator NISO received the duress check space with nonce.");
    let peer_1_withdrawal_niso_st_message_2 =
        peer_1_niso.produce_withdrawal_niso_st_message_2().unwrap();
    println!(
        "Initiator NISO produced WithdrawalNisoStMessage2 to give the duress check space with nonce to ST."
    );

    /////////////////////////////////////////////////
    // Step 29n of Non-Initiator Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 29n (Non-Initiator Diagram):");
    peer_2_niso
        .consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_4(
            peer_2_withdrawal_non_initiator_boomlet_non_initiator_niso_message_4,
        )
        .unwrap();
    peer_3_niso
        .consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_4(
            peer_3_withdrawal_non_initiator_boomlet_non_initiator_niso_message_4,
        )
        .unwrap();
    peer_4_niso
        .consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_4(
            peer_4_withdrawal_non_initiator_boomlet_non_initiator_niso_message_4,
        )
        .unwrap();
    peer_5_niso
        .consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_4(
            peer_5_withdrawal_non_initiator_boomlet_non_initiator_niso_message_4,
        )
        .unwrap();
    println!("Non-Initiator NISOs received the duress check space with nonce.");
    let peer_2_withdrawal_non_initiator_niso_non_initiator_st_message_2 = peer_2_niso
        .produce_withdrawal_non_initiator_niso_non_initiator_st_message_2()
        .unwrap();
    let peer_3_withdrawal_non_initiator_niso_non_initiator_st_message_2 = peer_3_niso
        .produce_withdrawal_non_initiator_niso_non_initiator_st_message_2()
        .unwrap();
    let peer_4_withdrawal_non_initiator_niso_non_initiator_st_message_2 = peer_4_niso
        .produce_withdrawal_non_initiator_niso_non_initiator_st_message_2()
        .unwrap();
    let peer_5_withdrawal_non_initiator_niso_non_initiator_st_message_2 = peer_5_niso
        .produce_withdrawal_non_initiator_niso_non_initiator_st_message_2()
        .unwrap();
    println!(
        "Non-Initiator NISOs produced WithdrawalNonInitiatorNisoNonInitiatorStMessage2 to give the duress check space with nonce to STs."
    );

    /////////////////////////////////////////////////
    // Step 30 of Initiator     Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 30 (Initiator Diagram):");
    peer_1_st
        .consume_withdrawal_niso_st_message_2(peer_1_withdrawal_niso_st_message_2)
        .unwrap();
    println!("Initiator ST received the duress check space with nonce.");
    let peer_1_withdrawal_st_output_2 = peer_1_st.produce_withdrawal_st_output_2().unwrap();
    println!(
        "Initiator ST produced WithdrawalStOutput2 to give the duress check space with nonce to peer."
    );
    /////////////////////////////////////////////////
    // Step 30n of Non-Initiator Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 30n (Non-Initiator Diagram):");
    peer_2_st
        .consume_withdrawal_non_initiator_niso_non_initiator_st_message_2(
            peer_2_withdrawal_non_initiator_niso_non_initiator_st_message_2,
        )
        .unwrap();
    peer_3_st
        .consume_withdrawal_non_initiator_niso_non_initiator_st_message_2(
            peer_3_withdrawal_non_initiator_niso_non_initiator_st_message_2,
        )
        .unwrap();
    peer_4_st
        .consume_withdrawal_non_initiator_niso_non_initiator_st_message_2(
            peer_4_withdrawal_non_initiator_niso_non_initiator_st_message_2,
        )
        .unwrap();
    peer_5_st
        .consume_withdrawal_non_initiator_niso_non_initiator_st_message_2(
            peer_5_withdrawal_non_initiator_niso_non_initiator_st_message_2,
        )
        .unwrap();
    println!("Non-Initiator STs received the duress check space with nonce.");
    let peer_2_withdrawal_non_initiator_st_output_2 = peer_2_st
        .produce_withdrawal_non_initiator_st_output_2()
        .unwrap();
    let peer_3_withdrawal_non_initiator_st_output_2 = peer_3_st
        .produce_withdrawal_non_initiator_st_output_2()
        .unwrap();
    let peer_4_withdrawal_non_initiator_st_output_2 = peer_4_st
        .produce_withdrawal_non_initiator_st_output_2()
        .unwrap();
    let peer_5_withdrawal_non_initiator_st_output_2 = peer_5_st
        .produce_withdrawal_non_initiator_st_output_2()
        .unwrap();
    println!(
        "Non-Initiator STs produced WithdrawalNonInitiatorStOutput2 to give the duress check space with nonce to peer."
    );

    /////////////////////////////////////////////////
    // Step 31 of Initiator     Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 31 (Initiator Diagram):");
    peer_1
        .consume_withdrawal_st_output_2(peer_1_withdrawal_st_output_2)
        .unwrap();
    println!("Initiator peer received the duress check space.");
    let peer_1_withdrawal_st_input_2 = peer_1.produce_withdrawal_st_input_2().unwrap();

    println!("Initiator peer produced WithdrawalStInput2 to give the duress signal index to ST.");

    /////////////////////////////////////////////////
    // Step 31n of Non-Initiator Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 31n (Non-Initiator Diagram):");
    peer_2
        .consume_withdrawal_non_initiator_st_output_2(peer_2_withdrawal_non_initiator_st_output_2)
        .unwrap();
    peer_3
        .consume_withdrawal_non_initiator_st_output_2(peer_3_withdrawal_non_initiator_st_output_2)
        .unwrap();
    peer_4
        .consume_withdrawal_non_initiator_st_output_2(peer_4_withdrawal_non_initiator_st_output_2)
        .unwrap();
    peer_5
        .consume_withdrawal_non_initiator_st_output_2(peer_5_withdrawal_non_initiator_st_output_2)
        .unwrap();
    println!("Non-Initiator peers received the duress check space.");
    let peer_2_withdrawal_non_initiator_st_input_2 = peer_2
        .produce_withdrawal_non_initiator_st_input_2()
        .unwrap();
    let peer_3_withdrawal_non_initiator_st_input_2 = peer_3
        .produce_withdrawal_non_initiator_st_input_2()
        .unwrap();
    let peer_4_withdrawal_non_initiator_st_input_2 = peer_4
        .produce_withdrawal_non_initiator_st_input_2()
        .unwrap();
    let peer_5_withdrawal_non_initiator_st_input_2 = peer_5
        .produce_withdrawal_non_initiator_st_input_2()
        .unwrap();

    println!(
        "Non-Initiator peers produced WithdrawalNonInitiatorStInput2 to give the duress signal index to STs."
    );

    /////////////////////////////////////////////////
    // Step 32 of Initiator     Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 32 (Initiator Diagram):");
    peer_1_st
        .consume_withdrawal_st_input_2(peer_1_withdrawal_st_input_2)
        .unwrap();
    println!("Initiator ST received the duress signal index with nonce.");
    let peer_1_withdrawal_st_niso_message_2 =
        peer_1_st.produce_withdrawal_st_niso_message_2().unwrap();
    println!(
        "Initiator ST produced WithdrawalStNisoMessage2 to give the duress signal index with nonce to NISO."
    );
    /////////////////////////////////////////////////
    // Step 32n of Non-Initiator Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 32n (Non-Initiator Diagram):");
    peer_2_st
        .consume_withdrawal_non_initiator_st_input_2(peer_2_withdrawal_non_initiator_st_input_2)
        .unwrap();
    peer_3_st
        .consume_withdrawal_non_initiator_st_input_2(peer_3_withdrawal_non_initiator_st_input_2)
        .unwrap();
    peer_4_st
        .consume_withdrawal_non_initiator_st_input_2(peer_4_withdrawal_non_initiator_st_input_2)
        .unwrap();
    peer_5_st
        .consume_withdrawal_non_initiator_st_input_2(peer_5_withdrawal_non_initiator_st_input_2)
        .unwrap();
    println!("Non-Initiator STs received the duress signal index with nonce.");
    let peer_2_withdrawal_non_initiator_st_non_initiator_niso_message_2 = peer_2_st
        .produce_withdrawal_non_initiator_st_non_initiator_niso_message_2()
        .unwrap();
    let peer_3_withdrawal_non_initiator_st_non_initiator_niso_message_2 = peer_3_st
        .produce_withdrawal_non_initiator_st_non_initiator_niso_message_2()
        .unwrap();
    let peer_4_withdrawal_non_initiator_st_non_initiator_niso_message_2 = peer_4_st
        .produce_withdrawal_non_initiator_st_non_initiator_niso_message_2()
        .unwrap();
    let peer_5_withdrawal_non_initiator_st_non_initiator_niso_message_2 = peer_5_st
        .produce_withdrawal_non_initiator_st_non_initiator_niso_message_2()
        .unwrap();
    println!(
        "Non-Initiator STs produced WithdrawalNonInitiatorStNonInitiatorNisoMessage2 to give the tx response to NISOs."
    );

    /////////////////////////////////////////////////
    // Step 33 of Initiator     Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 33 (Initiator Diagram):");
    peer_1_niso
        .consume_withdrawal_st_niso_message_2(peer_1_withdrawal_st_niso_message_2)
        .unwrap();
    println!("Initiator NISO received the duress signal index with nonce.");
    let peer_1_withdrawal_niso_boomlet_message_4 = peer_1_niso
        .produce_withdrawal_niso_boomlet_message_4()
        .unwrap();
    println!(
        "Initiator NISO produced WithdrawalNisoBoomletMessage4 to give the duress signal index with nonce to Boomlet."
    );

    /////////////////////////////////////////////////
    // Step 33n of Non-Initiator Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 33n (Non-Initiator Diagram):");
    peer_2_niso
        .consume_withdrawal_non_initiator_st_non_initiator_niso_message_2(
            peer_2_withdrawal_non_initiator_st_non_initiator_niso_message_2,
        )
        .unwrap();
    peer_3_niso
        .consume_withdrawal_non_initiator_st_non_initiator_niso_message_2(
            peer_3_withdrawal_non_initiator_st_non_initiator_niso_message_2,
        )
        .unwrap();
    peer_4_niso
        .consume_withdrawal_non_initiator_st_non_initiator_niso_message_2(
            peer_4_withdrawal_non_initiator_st_non_initiator_niso_message_2,
        )
        .unwrap();
    peer_5_niso
        .consume_withdrawal_non_initiator_st_non_initiator_niso_message_2(
            peer_5_withdrawal_non_initiator_st_non_initiator_niso_message_2,
        )
        .unwrap();
    println!("Non-Initiator NISOs received the duress signal index with nonce.");
    let peer_2_withdrawal_non_initiator_niso_non_initiator_boomlet_message_5 = peer_2_niso
        .produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_5()
        .unwrap();
    let peer_3_withdrawal_non_initiator_niso_non_initiator_boomlet_message_5 = peer_3_niso
        .produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_5()
        .unwrap();
    let peer_4_withdrawal_non_initiator_niso_non_initiator_boomlet_message_5 = peer_4_niso
        .produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_5()
        .unwrap();
    let peer_5_withdrawal_non_initiator_niso_non_initiator_boomlet_message_5 = peer_5_niso
        .produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_5()
        .unwrap();
    println!(
        "Non-Initiator NISOs produced WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage5 to give the duress signal index with nonce to Boomlets."
    );

    /////////////////////////////////////////////////
    // Step 34 of Initiator     Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 34 (Initiator Diagram):");
    peer_1_boomlet
        .consume_withdrawal_niso_boomlet_message_4(peer_1_withdrawal_niso_boomlet_message_4)
        .unwrap();
    println!("Initiator Boomlet received the duress signal index with nonce.");
    let peer_1_withdrawal_boomlet_niso_message_4 = peer_1_boomlet
        .produce_withdrawal_boomlet_niso_message_4()
        .unwrap();
    println!(
        "Initiator Boomlet produced WithdrawalBoomletNisoMessage4 to give the tx commit to NISO."
    );

    /////////////////////////////////////////////////
    // Step 34n of Non-Initiator Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 34n (Non-Initiator Diagram):");
    peer_2_boomlet
        .consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_5(
            peer_2_withdrawal_non_initiator_niso_non_initiator_boomlet_message_5,
        )
        .unwrap();
    peer_3_boomlet
        .consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_5(
            peer_3_withdrawal_non_initiator_niso_non_initiator_boomlet_message_5,
        )
        .unwrap();
    peer_4_boomlet
        .consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_5(
            peer_4_withdrawal_non_initiator_niso_non_initiator_boomlet_message_5,
        )
        .unwrap();
    peer_5_boomlet
        .consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_5(
            peer_5_withdrawal_non_initiator_niso_non_initiator_boomlet_message_5,
        )
        .unwrap();
    println!("Non-Initiator Boomlets received the duress signal index with nonce.");
    let peer_2_withdrawal_non_initiator_boomlet_non_initiator_niso_message_5 = peer_2_boomlet
        .produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_5()
        .unwrap();
    let peer_3_withdrawal_non_initiator_boomlet_non_initiator_niso_message_5 = peer_3_boomlet
        .produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_5()
        .unwrap();
    let peer_4_withdrawal_non_initiator_boomlet_non_initiator_niso_message_5 = peer_4_boomlet
        .produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_5()
        .unwrap();
    let peer_5_withdrawal_non_initiator_boomlet_non_initiator_niso_message_5 = peer_5_boomlet
        .produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_5()
        .unwrap();
    println!(
        "Non-Initiator Boomlets produced WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage5 to give Boomlets' acknowledgement of all tx approvals to NISOs."
    );

    /////////////////////////////////////////////////
    // Step 35 of Initiator     Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 35 (Initiator Diagram):");
    peer_1_niso
        .consume_withdrawal_boomlet_niso_message_4(peer_1_withdrawal_boomlet_niso_message_4)
        .unwrap();
    println!("Initiator NISO received the tx commit.");
    let peer_1_withdrawal_niso_wt_message_2 =
        peer_1_niso.produce_withdrawal_niso_wt_message_2().unwrap();
    println!(
        "Initiator NISO produced WithdrawalNisoWtMessage2 to give the tx commit to watchtower."
    );

    //////////////////////////////////////////////////
    // Step 35n of Non-Initiator Withdrawal Diagram //
    //////////////////////////////////////////////////
    println!("Step 35n (Non-Initiator Diagram):");
    peer_2_niso
        .consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_5(
            peer_2_withdrawal_non_initiator_boomlet_non_initiator_niso_message_5,
        )
        .unwrap();
    peer_3_niso
        .consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_5(
            peer_3_withdrawal_non_initiator_boomlet_non_initiator_niso_message_5,
        )
        .unwrap();
    peer_4_niso
        .consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_5(
            peer_4_withdrawal_non_initiator_boomlet_non_initiator_niso_message_5,
        )
        .unwrap();
    peer_5_niso
        .consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_5(
            peer_5_withdrawal_non_initiator_boomlet_non_initiator_niso_message_5,
        )
        .unwrap();
    println!("Non-Initiator NISOs received Boomlets' acknowledgement of all tx approvals.");
    let peer_2_withdrawal_non_initiator_niso_wt_message_2 = peer_2_niso
        .produce_withdrawal_non_initiator_niso_wt_message_2()
        .unwrap();
    let peer_3_withdrawal_non_initiator_niso_wt_message_2 = peer_3_niso
        .produce_withdrawal_non_initiator_niso_wt_message_2()
        .unwrap();
    let peer_4_withdrawal_non_initiator_niso_wt_message_2 = peer_4_niso
        .produce_withdrawal_non_initiator_niso_wt_message_2()
        .unwrap();
    let peer_5_withdrawal_non_initiator_niso_wt_message_2 = peer_5_niso
        .produce_withdrawal_non_initiator_niso_wt_message_2()
        .unwrap();
    println!(
        "Non-Initiator NISOs produced WithdrawalNonInitiatorNisoWtMessage2 to give Boomlets' acknowledgement of all tx approvals to watchtower."
    );

    /////////////////////////////////////////////////
    // Step 36 of Initiator     Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 36 (Initiator Diagram):");
    let active_wt_parcel_to_be_received_withdrawal_non_initiator_niso_wt_message_2 =
        Parcel::new(vec![
            MetadataAttachedMessage::new(
                wt_peer_2_id.clone(),
                peer_2_withdrawal_non_initiator_niso_wt_message_2,
            ),
            MetadataAttachedMessage::new(
                wt_peer_3_id.clone(),
                peer_3_withdrawal_non_initiator_niso_wt_message_2,
            ),
            MetadataAttachedMessage::new(
                wt_peer_4_id.clone(),
                peer_4_withdrawal_non_initiator_niso_wt_message_2,
            ),
            MetadataAttachedMessage::new(
                wt_peer_5_id.clone(),
                peer_5_withdrawal_non_initiator_niso_wt_message_2,
            ),
        ]);
    active_wt
        .consume_withdrawal_non_initiator_niso_wt_message_2(
            active_wt_parcel_to_be_received_withdrawal_non_initiator_niso_wt_message_2,
        )
        .unwrap();
    println!("Watchtower received Boomlets' acknowledgement of all tx approvals.");
    active_wt
        .consume_withdrawal_niso_wt_message_2(peer_1_withdrawal_niso_wt_message_2)
        .unwrap();
    println!("Watchtower received initiator's tx commit.");

    let active_wt_parcel_to_be_sent_withdrawal_wt_sar_message_1 =
        active_wt.produce_withdrawal_wt_sar_message_1().unwrap();
    println!(
        "Watchtower produced WithdrawalWtSarMessage1 to give initiator's duress placeholder to SARs."
    );

    /////////////////////////////////////////////////
    // Step 37 of Initiator     Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 37 (Initiator Diagram):");
    peer_1_sar_1
        .consume_withdrawal_wt_sar_message_1(
            active_wt_parcel_to_be_sent_withdrawal_wt_sar_message_1
                .look_for_message(&peer_1_sar_1_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_1_sar_2
        .consume_withdrawal_wt_sar_message_1(
            active_wt_parcel_to_be_sent_withdrawal_wt_sar_message_1
                .look_for_message(&peer_1_sar_2_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    println!("Initiator SARs received initiator's duress placeholder.");
    let peer_1_sar_1_withdrawal_sar_wt_message_1 =
        peer_1_sar_1.produce_withdrawal_sar_wt_message_1().unwrap();
    let peer_1_sar_2_withdrawal_sar_wt_message_1 =
        peer_1_sar_2.produce_withdrawal_sar_wt_message_1().unwrap();
    println!(
        "Initiator SARs produced WithdrawalSarWtMessage1 to give their signature on initiator's duress placeholder to watchtower."
    );

    /////////////////////////////////////////////////
    // Step 38 of Non-Initiator Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 38 (Non-Initiator Diagram):");
    let active_wt_parcel_to_be_received_withdrawal_sar_wt_message_1 = Parcel::new(vec![
        MetadataAttachedMessage::new(
            peer_1_sar_1_id.clone(),
            peer_1_sar_1_withdrawal_sar_wt_message_1,
        ),
        MetadataAttachedMessage::new(
            peer_1_sar_2_id.clone(),
            peer_1_sar_2_withdrawal_sar_wt_message_1,
        ),
    ]);
    active_wt
        .consume_withdrawal_sar_wt_message_1(
            active_wt_parcel_to_be_received_withdrawal_sar_wt_message_1,
        )
        .unwrap();
    println!("Watchtower received initiator SARs' signature on initiator's duress placeholder.");

    let active_wt_parcel_to_be_sent_withdrawal_wt_non_initiator_niso_message_3 = active_wt
        .produce_withdrawal_wt_non_initiator_niso_message_3()
        .unwrap();
    println!(
        "Watchtower produced WithdrawalWtNonInitiatorNisoMessage2 to give the initiator tx commit non-initiator NISOs."
    );

    /////////////////////////////////////////////////
    // Step 39 of Non-Initiator Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 39 (Non-Initiator Diagram):");
    let peer_2_withdrawal_wt_non_initiator_niso_message_3 =
        active_wt_parcel_to_be_sent_withdrawal_wt_non_initiator_niso_message_3
            .look_for_message(&wt_peer_2_id)
            .unwrap()
            .clone();
    let peer_3_withdrawal_wt_non_initiator_niso_message_3 =
        active_wt_parcel_to_be_sent_withdrawal_wt_non_initiator_niso_message_3
            .look_for_message(&wt_peer_3_id)
            .unwrap()
            .clone();
    let peer_4_withdrawal_wt_non_initiator_niso_message_3 =
        active_wt_parcel_to_be_sent_withdrawal_wt_non_initiator_niso_message_3
            .look_for_message(&wt_peer_4_id)
            .unwrap()
            .clone();
    let peer_5_withdrawal_wt_non_initiator_niso_message_3 =
        active_wt_parcel_to_be_sent_withdrawal_wt_non_initiator_niso_message_3
            .look_for_message(&wt_peer_5_id)
            .unwrap()
            .clone();
    peer_2_niso
        .consume_withdrawal_wt_non_initiator_niso_message_3(
            peer_2_withdrawal_wt_non_initiator_niso_message_3,
        )
        .unwrap();
    peer_3_niso
        .consume_withdrawal_wt_non_initiator_niso_message_3(
            peer_3_withdrawal_wt_non_initiator_niso_message_3,
        )
        .unwrap();
    peer_4_niso
        .consume_withdrawal_wt_non_initiator_niso_message_3(
            peer_4_withdrawal_wt_non_initiator_niso_message_3,
        )
        .unwrap();
    peer_5_niso
        .consume_withdrawal_wt_non_initiator_niso_message_3(
            peer_5_withdrawal_wt_non_initiator_niso_message_3,
        )
        .unwrap();
    println!("Non-Initiator NISOs received the initiator tx commit.");
    let peer_2_withdrawal_non_initiator_niso_non_initiator_boomlet_message_6 = peer_2_niso
        .produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_6()
        .unwrap();
    let peer_3_withdrawal_non_initiator_niso_non_initiator_boomlet_message_6 = peer_3_niso
        .produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_6()
        .unwrap();
    let peer_4_withdrawal_non_initiator_niso_non_initiator_boomlet_message_6 = peer_4_niso
        .produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_6()
        .unwrap();
    let peer_5_withdrawal_non_initiator_niso_non_initiator_boomlet_message_6 = peer_5_niso
        .produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_6()
        .unwrap();
    println!(
        "Non-Initiator NISOs produced WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage6 to give the initiator tx commit to Boomlets."
    );

    /////////////////////////////////////////////////
    // Step 40 of Non-Initiator Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 40 (Non-Initiator Diagram):");
    peer_2_boomlet
        .consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_6(
            peer_2_withdrawal_non_initiator_niso_non_initiator_boomlet_message_6,
        )
        .unwrap();
    peer_3_boomlet
        .consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_6(
            peer_3_withdrawal_non_initiator_niso_non_initiator_boomlet_message_6,
        )
        .unwrap();
    peer_4_boomlet
        .consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_6(
            peer_4_withdrawal_non_initiator_niso_non_initiator_boomlet_message_6,
        )
        .unwrap();
    peer_5_boomlet
        .consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_6(
            peer_5_withdrawal_non_initiator_niso_non_initiator_boomlet_message_6,
        )
        .unwrap();
    println!("Non-Initiator Boomlets received the initiator tx commit.");
    let peer_2_withdrawal_non_initiator_boomlet_non_initiator_niso_message_6 = peer_2_boomlet
        .produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_6()
        .unwrap();
    let peer_3_withdrawal_non_initiator_boomlet_non_initiator_niso_message_6 = peer_3_boomlet
        .produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_6()
        .unwrap();
    let peer_4_withdrawal_non_initiator_boomlet_non_initiator_niso_message_6 = peer_4_boomlet
        .produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_6()
        .unwrap();
    let peer_5_withdrawal_non_initiator_boomlet_non_initiator_niso_message_6 = peer_5_boomlet
        .produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_6()
        .unwrap();
    println!(
        "Non-Initiator Boomlets produced WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage6 to give the tx commit to NISOs."
    );
    /////////////////////////////////////////////////
    // Step 41 of Non-Initiator Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 41 (Non-Initiator Diagram):");
    peer_2_niso
        .consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_6(
            peer_2_withdrawal_non_initiator_boomlet_non_initiator_niso_message_6,
        )
        .unwrap();
    peer_3_niso
        .consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_6(
            peer_3_withdrawal_non_initiator_boomlet_non_initiator_niso_message_6,
        )
        .unwrap();
    peer_4_niso
        .consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_6(
            peer_4_withdrawal_non_initiator_boomlet_non_initiator_niso_message_6,
        )
        .unwrap();
    peer_5_niso
        .consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_6(
            peer_5_withdrawal_non_initiator_boomlet_non_initiator_niso_message_6,
        )
        .unwrap();
    println!("Non-Initiator NISOs received the tx commit.");
    let peer_2_withdrawal_non_initiator_niso_wt_message_3 = peer_2_niso
        .produce_withdrawal_non_initiator_niso_wt_message_3()
        .unwrap();
    let peer_3_withdrawal_non_initiator_niso_wt_message_3 = peer_3_niso
        .produce_withdrawal_non_initiator_niso_wt_message_3()
        .unwrap();
    let peer_4_withdrawal_non_initiator_niso_wt_message_3 = peer_4_niso
        .produce_withdrawal_non_initiator_niso_wt_message_3()
        .unwrap();
    let peer_5_withdrawal_non_initiator_niso_wt_message_3 = peer_5_niso
        .produce_withdrawal_non_initiator_niso_wt_message_3()
        .unwrap();
    println!(
        "Non-Initiator NISOs produced WithdrawalNonInitiatorNisoWtMessage3 to give the tx commit to watchtower."
    );

    /////////////////////////////////////////////////
    // Step 42 of Non-Initiator Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 42 (Non-Initiator Diagram):");
    let active_wt_parcel_to_be_received_withdrawal_non_initiator_niso_wt_message_3 =
        Parcel::new(vec![
            MetadataAttachedMessage::new(
                wt_peer_2_id.clone(),
                peer_2_withdrawal_non_initiator_niso_wt_message_3,
            ),
            MetadataAttachedMessage::new(
                wt_peer_3_id.clone(),
                peer_3_withdrawal_non_initiator_niso_wt_message_3,
            ),
            MetadataAttachedMessage::new(
                wt_peer_4_id.clone(),
                peer_4_withdrawal_non_initiator_niso_wt_message_3,
            ),
            MetadataAttachedMessage::new(
                wt_peer_5_id.clone(),
                peer_5_withdrawal_non_initiator_niso_wt_message_3,
            ),
        ]);
    active_wt
        .consume_withdrawal_non_initiator_niso_wt_message_3(
            active_wt_parcel_to_be_received_withdrawal_non_initiator_niso_wt_message_3,
        )
        .unwrap();
    println!("Watchtower received the non-initiator tx commits.");
    let active_wt_parcel_to_be_sent_withdrawal_wt_non_initiator_sar_message_1 = active_wt
        .produce_withdrawal_wt_non_initiator_sar_message_1()
        .unwrap();
    println!(
        "Watchtower produced WithdrawalWtNonInitiatorSarMessage1 to give non-initiators' duress placeholder to SARs."
    );
    /////////////////////////////////////////////////
    // Step 43 of Non-Initiator Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 43 (Non-Initiator Diagram):");
    peer_2_sar_1
        .consume_withdrawal_wt_non_initiator_sar_message_1(
            active_wt_parcel_to_be_sent_withdrawal_wt_non_initiator_sar_message_1
                .look_for_message(&peer_2_sar_1_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_2_sar_2
        .consume_withdrawal_wt_non_initiator_sar_message_1(
            active_wt_parcel_to_be_sent_withdrawal_wt_non_initiator_sar_message_1
                .look_for_message(&peer_2_sar_2_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_3_sar_1
        .consume_withdrawal_wt_non_initiator_sar_message_1(
            active_wt_parcel_to_be_sent_withdrawal_wt_non_initiator_sar_message_1
                .look_for_message(&peer_3_sar_1_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_3_sar_2
        .consume_withdrawal_wt_non_initiator_sar_message_1(
            active_wt_parcel_to_be_sent_withdrawal_wt_non_initiator_sar_message_1
                .look_for_message(&peer_3_sar_2_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_4_sar_1
        .consume_withdrawal_wt_non_initiator_sar_message_1(
            active_wt_parcel_to_be_sent_withdrawal_wt_non_initiator_sar_message_1
                .look_for_message(&peer_4_sar_1_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_4_sar_2
        .consume_withdrawal_wt_non_initiator_sar_message_1(
            active_wt_parcel_to_be_sent_withdrawal_wt_non_initiator_sar_message_1
                .look_for_message(&peer_4_sar_2_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_5_sar_1
        .consume_withdrawal_wt_non_initiator_sar_message_1(
            active_wt_parcel_to_be_sent_withdrawal_wt_non_initiator_sar_message_1
                .look_for_message(&peer_5_sar_1_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_5_sar_2
        .consume_withdrawal_wt_non_initiator_sar_message_1(
            active_wt_parcel_to_be_sent_withdrawal_wt_non_initiator_sar_message_1
                .look_for_message(&peer_5_sar_2_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    println!("Non-Initiator SARs received non-initiators' duress placeholder.");
    let peer_2_sar_1_withdrawal_non_initiator_sar_wt_message_1 = peer_2_sar_1
        .produce_withdrawal_non_initiator_sar_wt_message_1()
        .unwrap();
    let peer_2_sar_2_withdrawal_non_initiator_sar_wt_message_1 = peer_2_sar_2
        .produce_withdrawal_non_initiator_sar_wt_message_1()
        .unwrap();
    let peer_3_sar_1_withdrawal_non_initiator_sar_wt_message_1 = peer_3_sar_1
        .produce_withdrawal_non_initiator_sar_wt_message_1()
        .unwrap();
    let peer_3_sar_2_withdrawal_non_initiator_sar_wt_message_1 = peer_3_sar_2
        .produce_withdrawal_non_initiator_sar_wt_message_1()
        .unwrap();
    let peer_4_sar_1_withdrawal_non_initiator_sar_wt_message_1 = peer_4_sar_1
        .produce_withdrawal_non_initiator_sar_wt_message_1()
        .unwrap();
    let peer_4_sar_2_withdrawal_non_initiator_sar_wt_message_1 = peer_4_sar_2
        .produce_withdrawal_non_initiator_sar_wt_message_1()
        .unwrap();
    let peer_5_sar_1_withdrawal_non_initiator_sar_wt_message_1 = peer_5_sar_1
        .produce_withdrawal_non_initiator_sar_wt_message_1()
        .unwrap();
    let peer_5_sar_2_withdrawal_non_initiator_sar_wt_message_1 = peer_5_sar_2
        .produce_withdrawal_non_initiator_sar_wt_message_1()
        .unwrap();
    println!(
        "Non-Initiator SARs produced WithdrawalNonInitiatorSarWtMessage1 to give their signature on non-initiators' duress placeholder to watchtower."
    );
    /////////////////////////////////////////////
    // Step 44 of Initiator Withdrawal Diagram //
    /////////////////////////////////////////////
    println!("Step 44 (Non-Initiator Diagram):");
    let active_wt_parcel_to_be_received_withdrawal_non_initiator_sar_wt_message_1 =
        Parcel::new(vec![
            MetadataAttachedMessage::new(
                peer_2_sar_1_id.clone(),
                peer_2_sar_1_withdrawal_non_initiator_sar_wt_message_1,
            ),
            MetadataAttachedMessage::new(
                peer_2_sar_2_id.clone(),
                peer_2_sar_2_withdrawal_non_initiator_sar_wt_message_1,
            ),
            MetadataAttachedMessage::new(
                peer_3_sar_1_id.clone(),
                peer_3_sar_1_withdrawal_non_initiator_sar_wt_message_1,
            ),
            MetadataAttachedMessage::new(
                peer_3_sar_2_id.clone(),
                peer_3_sar_2_withdrawal_non_initiator_sar_wt_message_1,
            ),
            MetadataAttachedMessage::new(
                peer_4_sar_1_id.clone(),
                peer_4_sar_1_withdrawal_non_initiator_sar_wt_message_1,
            ),
            MetadataAttachedMessage::new(
                peer_4_sar_2_id.clone(),
                peer_4_sar_2_withdrawal_non_initiator_sar_wt_message_1,
            ),
            MetadataAttachedMessage::new(
                peer_5_sar_1_id.clone(),
                peer_5_sar_1_withdrawal_non_initiator_sar_wt_message_1,
            ),
            MetadataAttachedMessage::new(
                peer_5_sar_2_id.clone(),
                peer_5_sar_2_withdrawal_non_initiator_sar_wt_message_1,
            ),
        ]);
    active_wt
        .consume_withdrawal_non_initiator_sar_wt_message_1(
            active_wt_parcel_to_be_received_withdrawal_non_initiator_sar_wt_message_1,
        )
        .unwrap();
    println!("Watchtower received SARs' signature on non-initiators' duress placeholder.");
    let active_wt_parcel_to_be_sent_withdrawal_wt_niso_message_2 =
        active_wt.produce_withdrawal_wt_niso_message_2().unwrap();
    println!(
        "Watchtower produced WithdrawalWtNisoMessage2 to give the tx commit of all peers and their own signed duress placeholders to NISOs."
    );

    /////////////////////////////////////////////
    // Step 45 of Initiator Withdrawal Diagram //
    /////////////////////////////////////////////
    println!("Step 45 (Initiator Diagram):");
    peer_1_niso
        .consume_withdrawal_wt_niso_message_2(
            active_wt_parcel_to_be_sent_withdrawal_wt_niso_message_2
                .look_for_message(&wt_peer_1_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_2_niso
        .consume_withdrawal_wt_niso_message_2(
            active_wt_parcel_to_be_sent_withdrawal_wt_niso_message_2
                .look_for_message(&wt_peer_2_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_3_niso
        .consume_withdrawal_wt_niso_message_2(
            active_wt_parcel_to_be_sent_withdrawal_wt_niso_message_2
                .look_for_message(&wt_peer_3_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_4_niso
        .consume_withdrawal_wt_niso_message_2(
            active_wt_parcel_to_be_sent_withdrawal_wt_niso_message_2
                .look_for_message(&wt_peer_4_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_5_niso
        .consume_withdrawal_wt_niso_message_2(
            active_wt_parcel_to_be_sent_withdrawal_wt_niso_message_2
                .look_for_message(&wt_peer_5_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    println!("NISOs received the tx commit of all peers and their own signed duress placeholders.");
    let peer_1_withdrawal_niso_boomlet_message_5 = peer_1_niso
        .produce_withdrawal_niso_boomlet_message_5()
        .unwrap();
    let peer_2_withdrawal_niso_boomlet_message_5 = peer_2_niso
        .produce_withdrawal_niso_boomlet_message_5()
        .unwrap();
    let peer_3_withdrawal_niso_boomlet_message_5 = peer_3_niso
        .produce_withdrawal_niso_boomlet_message_5()
        .unwrap();
    let peer_4_withdrawal_niso_boomlet_message_5 = peer_4_niso
        .produce_withdrawal_niso_boomlet_message_5()
        .unwrap();
    let peer_5_withdrawal_niso_boomlet_message_5 = peer_5_niso
        .produce_withdrawal_niso_boomlet_message_5()
        .unwrap();
    println!(
        "NISOs produced WithdrawalNisoBoomletMessage5 to give the tx commit of all peers and their own signed duress placeholders to Boomlets."
    );

    /////////////////////////////////////////////////
    // Step 46 of Initiator     Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 46 (Initiator Diagram):");
    peer_1_boomlet
        .consume_withdrawal_niso_boomlet_message_5(peer_1_withdrawal_niso_boomlet_message_5)
        .unwrap();
    peer_2_boomlet
        .consume_withdrawal_niso_boomlet_message_5(peer_2_withdrawal_niso_boomlet_message_5)
        .unwrap();
    peer_3_boomlet
        .consume_withdrawal_niso_boomlet_message_5(peer_3_withdrawal_niso_boomlet_message_5)
        .unwrap();
    peer_4_boomlet
        .consume_withdrawal_niso_boomlet_message_5(peer_4_withdrawal_niso_boomlet_message_5)
        .unwrap();
    peer_5_boomlet
        .consume_withdrawal_niso_boomlet_message_5(peer_5_withdrawal_niso_boomlet_message_5)
        .unwrap();
    println!(
        "Boomlets received the tx commit of all peers and their own signed duress placeholders."
    );
    let peer_1_withdrawal_boomlet_niso_message_5 = peer_1_boomlet
        .produce_withdrawal_boomlet_niso_message_5()
        .unwrap();
    let peer_2_withdrawal_boomlet_niso_message_5 = peer_2_boomlet
        .produce_withdrawal_boomlet_niso_message_5()
        .unwrap();
    let peer_3_withdrawal_boomlet_niso_message_5 = peer_3_boomlet
        .produce_withdrawal_boomlet_niso_message_5()
        .unwrap();
    let peer_4_withdrawal_boomlet_niso_message_5 = peer_4_boomlet
        .produce_withdrawal_boomlet_niso_message_5()
        .unwrap();
    let peer_5_withdrawal_boomlet_niso_message_5 = peer_5_boomlet
        .produce_withdrawal_boomlet_niso_message_5()
        .unwrap();
    println!("Boomlets produced WithdrawalBoomletNisoMessage5 to give the ping to NISOs.");

    /////////////////////////////////////////////////
    // Step 47 of Initiator     Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 47 (Initiator Diagram):");
    peer_1_niso
        .consume_withdrawal_boomlet_niso_message_5(peer_1_withdrawal_boomlet_niso_message_5)
        .unwrap();
    peer_2_niso
        .consume_withdrawal_boomlet_niso_message_5(peer_2_withdrawal_boomlet_niso_message_5)
        .unwrap();
    peer_3_niso
        .consume_withdrawal_boomlet_niso_message_5(peer_3_withdrawal_boomlet_niso_message_5)
        .unwrap();
    peer_4_niso
        .consume_withdrawal_boomlet_niso_message_5(peer_4_withdrawal_boomlet_niso_message_5)
        .unwrap();
    peer_5_niso
        .consume_withdrawal_boomlet_niso_message_5(peer_5_withdrawal_boomlet_niso_message_5)
        .unwrap();
    println!("NISOs received the ping.");
    let peer_1_withdrawal_niso_wt_message_3 =
        peer_1_niso.produce_withdrawal_niso_wt_message_3().unwrap();
    let peer_2_withdrawal_niso_wt_message_3 =
        peer_2_niso.produce_withdrawal_niso_wt_message_3().unwrap();
    let peer_3_withdrawal_niso_wt_message_3 =
        peer_3_niso.produce_withdrawal_niso_wt_message_3().unwrap();
    let peer_4_withdrawal_niso_wt_message_3 =
        peer_4_niso.produce_withdrawal_niso_wt_message_3().unwrap();
    let peer_5_withdrawal_niso_wt_message_3 =
        peer_5_niso.produce_withdrawal_niso_wt_message_3().unwrap();
    println!("NISOs produced WithdrawalNisoWtMessage3 to give the ping to watchtower.");

    /////////////////////////////////////////////////
    // Step 48 of Initiator     Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 48 (Initiator Diagram):");
    let active_wt_parcel_to_be_received_withdrawal_non_initiator_sar_wt_message_3 =
        Parcel::new(vec![
            MetadataAttachedMessage::new(wt_peer_1_id.clone(), peer_1_withdrawal_niso_wt_message_3),
            MetadataAttachedMessage::new(wt_peer_2_id.clone(), peer_2_withdrawal_niso_wt_message_3),
            MetadataAttachedMessage::new(wt_peer_3_id.clone(), peer_3_withdrawal_niso_wt_message_3),
            MetadataAttachedMessage::new(wt_peer_4_id.clone(), peer_4_withdrawal_niso_wt_message_3),
            MetadataAttachedMessage::new(wt_peer_5_id.clone(), peer_5_withdrawal_niso_wt_message_3),
        ]);
    active_wt
        .consume_withdrawal_niso_wt_message_3(
            active_wt_parcel_to_be_received_withdrawal_non_initiator_sar_wt_message_3,
        )
        .unwrap();
    println!("Watchtower received the pings.");
    let mut active_wt_withdrawal_wt_sar_message_2_or_withdrawal_wt_niso_message_4 = active_wt
        .produce_withdrawal_wt_sar_message_2_or_produce_withdrawal_wt_niso_message_4()
        .unwrap();

    let mut loop_counter = 1;
    while let BranchingMessage2::First(active_wt_parcel_to_be_sent_withdrawal_wt_sar_message_2) =
        active_wt_withdrawal_wt_sar_message_2_or_withdrawal_wt_niso_message_4
    {
        println!(
            "Watchtower produced WithdrawalWtSarMessage2 to give the pingpong duress placeholders to SARs."
        );

        /////////////////////////////////////////////////
        // Step 49 of Initiator     Withdrawal Diagram //
        /////////////////////////////////////////////////
        println!("Step 49 (Initiator Diagram) - Iteration {loop_counter}:");
        peer_1_sar_1
            .consume_withdrawal_wt_sar_message_2(
                active_wt_parcel_to_be_sent_withdrawal_wt_sar_message_2
                    .look_for_message(&peer_1_sar_1_id)
                    .unwrap()
                    .clone(),
            )
            .unwrap();
        peer_1_sar_2
            .consume_withdrawal_wt_sar_message_2(
                active_wt_parcel_to_be_sent_withdrawal_wt_sar_message_2
                    .look_for_message(&peer_1_sar_2_id)
                    .unwrap()
                    .clone(),
            )
            .unwrap();
        peer_2_sar_1
            .consume_withdrawal_wt_sar_message_2(
                active_wt_parcel_to_be_sent_withdrawal_wt_sar_message_2
                    .look_for_message(&peer_2_sar_1_id)
                    .unwrap()
                    .clone(),
            )
            .unwrap();
        peer_2_sar_2
            .consume_withdrawal_wt_sar_message_2(
                active_wt_parcel_to_be_sent_withdrawal_wt_sar_message_2
                    .look_for_message(&peer_2_sar_2_id)
                    .unwrap()
                    .clone(),
            )
            .unwrap();
        peer_3_sar_1
            .consume_withdrawal_wt_sar_message_2(
                active_wt_parcel_to_be_sent_withdrawal_wt_sar_message_2
                    .look_for_message(&peer_3_sar_1_id)
                    .unwrap()
                    .clone(),
            )
            .unwrap();
        peer_3_sar_2
            .consume_withdrawal_wt_sar_message_2(
                active_wt_parcel_to_be_sent_withdrawal_wt_sar_message_2
                    .look_for_message(&peer_3_sar_2_id)
                    .unwrap()
                    .clone(),
            )
            .unwrap();
        peer_4_sar_1
            .consume_withdrawal_wt_sar_message_2(
                active_wt_parcel_to_be_sent_withdrawal_wt_sar_message_2
                    .look_for_message(&peer_4_sar_1_id)
                    .unwrap()
                    .clone(),
            )
            .unwrap();
        peer_4_sar_2
            .consume_withdrawal_wt_sar_message_2(
                active_wt_parcel_to_be_sent_withdrawal_wt_sar_message_2
                    .look_for_message(&peer_4_sar_2_id)
                    .unwrap()
                    .clone(),
            )
            .unwrap();
        peer_5_sar_1
            .consume_withdrawal_wt_sar_message_2(
                active_wt_parcel_to_be_sent_withdrawal_wt_sar_message_2
                    .look_for_message(&peer_5_sar_1_id)
                    .unwrap()
                    .clone(),
            )
            .unwrap();
        peer_5_sar_2
            .consume_withdrawal_wt_sar_message_2(
                active_wt_parcel_to_be_sent_withdrawal_wt_sar_message_2
                    .look_for_message(&peer_5_sar_2_id)
                    .unwrap()
                    .clone(),
            )
            .unwrap();
        println!("SARs received the pingpong duress placeholders.");
        let peer_1_sar_1_withdrawal_sar_wt_message_2 =
            peer_1_sar_1.produce_withdrawal_sar_wt_message_2().unwrap();
        let peer_1_sar_2_withdrawal_sar_wt_message_2 =
            peer_1_sar_2.produce_withdrawal_sar_wt_message_2().unwrap();
        let peer_2_sar_1_withdrawal_sar_wt_message_2 =
            peer_2_sar_1.produce_withdrawal_sar_wt_message_2().unwrap();
        let peer_2_sar_2_withdrawal_sar_wt_message_2 =
            peer_2_sar_2.produce_withdrawal_sar_wt_message_2().unwrap();
        let peer_3_sar_1_withdrawal_sar_wt_message_2 =
            peer_3_sar_1.produce_withdrawal_sar_wt_message_2().unwrap();
        let peer_3_sar_2_withdrawal_sar_wt_message_2 =
            peer_3_sar_2.produce_withdrawal_sar_wt_message_2().unwrap();
        let peer_4_sar_1_withdrawal_sar_wt_message_2 =
            peer_4_sar_1.produce_withdrawal_sar_wt_message_2().unwrap();
        let peer_4_sar_2_withdrawal_sar_wt_message_2 =
            peer_4_sar_2.produce_withdrawal_sar_wt_message_2().unwrap();
        let peer_5_sar_1_withdrawal_sar_wt_message_2 =
            peer_5_sar_1.produce_withdrawal_sar_wt_message_2().unwrap();
        let peer_5_sar_2_withdrawal_sar_wt_message_2 =
            peer_5_sar_2.produce_withdrawal_sar_wt_message_2().unwrap();
        println!(
            "SARs produced WithdrawalSarWtMessage2 to give their signature on the pingpong duress placeholders to watchtower."
        );

        /////////////////////////////////////////////////
        // Step 50 of Initiator     Withdrawal Diagram //
        /////////////////////////////////////////////////
        println!("Step 50 (Initiator Diagram) - Iteration {loop_counter}:");
        let active_wt_parcel_to_be_received_withdrawal_sar_wt_message_2 = Parcel::new(vec![
            MetadataAttachedMessage::new(
                peer_1_sar_1_id.clone(),
                peer_1_sar_1_withdrawal_sar_wt_message_2,
            ),
            MetadataAttachedMessage::new(
                peer_1_sar_2_id.clone(),
                peer_1_sar_2_withdrawal_sar_wt_message_2,
            ),
            MetadataAttachedMessage::new(
                peer_2_sar_1_id.clone(),
                peer_2_sar_1_withdrawal_sar_wt_message_2,
            ),
            MetadataAttachedMessage::new(
                peer_2_sar_2_id.clone(),
                peer_2_sar_2_withdrawal_sar_wt_message_2,
            ),
            MetadataAttachedMessage::new(
                peer_3_sar_1_id.clone(),
                peer_3_sar_1_withdrawal_sar_wt_message_2,
            ),
            MetadataAttachedMessage::new(
                peer_3_sar_2_id.clone(),
                peer_3_sar_2_withdrawal_sar_wt_message_2,
            ),
            MetadataAttachedMessage::new(
                peer_4_sar_1_id.clone(),
                peer_4_sar_1_withdrawal_sar_wt_message_2,
            ),
            MetadataAttachedMessage::new(
                peer_4_sar_2_id.clone(),
                peer_4_sar_2_withdrawal_sar_wt_message_2,
            ),
            MetadataAttachedMessage::new(
                peer_5_sar_1_id.clone(),
                peer_5_sar_1_withdrawal_sar_wt_message_2,
            ),
            MetadataAttachedMessage::new(
                peer_5_sar_2_id.clone(),
                peer_5_sar_2_withdrawal_sar_wt_message_2,
            ),
        ]);
        active_wt
            .consume_withdrawal_sar_wt_message_2(
                active_wt_parcel_to_be_received_withdrawal_sar_wt_message_2,
            )
            .unwrap();
        println!("Watchtower received SARs' signature on the pingpong duress placeholders.");
        let active_wt_parcel_to_be_sent_withdrawal_wt_niso_message_3 =
            active_wt.produce_withdrawal_wt_niso_message_3().unwrap();
        println!("Watchtower produced WithdrawalWtNisoMessage3 to give the pong to NISOs.");

        /////////////////////////////////////////////////
        // Step 51 of Initiator     Withdrawal Diagram //
        /////////////////////////////////////////////////
        println!("Step 51 (Initiator Diagram) - Iteration {loop_counter}:");
        peer_1_niso
            .consume_withdrawal_wt_niso_message_3(
                active_wt_parcel_to_be_sent_withdrawal_wt_niso_message_3
                    .look_for_message(&wt_peer_1_id)
                    .unwrap()
                    .clone(),
            )
            .unwrap();
        peer_2_niso
            .consume_withdrawal_wt_niso_message_3(
                active_wt_parcel_to_be_sent_withdrawal_wt_niso_message_3
                    .look_for_message(&wt_peer_2_id)
                    .unwrap()
                    .clone(),
            )
            .unwrap();
        peer_3_niso
            .consume_withdrawal_wt_niso_message_3(
                active_wt_parcel_to_be_sent_withdrawal_wt_niso_message_3
                    .look_for_message(&wt_peer_3_id)
                    .unwrap()
                    .clone(),
            )
            .unwrap();
        peer_4_niso
            .consume_withdrawal_wt_niso_message_3(
                active_wt_parcel_to_be_sent_withdrawal_wt_niso_message_3
                    .look_for_message(&wt_peer_4_id)
                    .unwrap()
                    .clone(),
            )
            .unwrap();
        peer_5_niso
            .consume_withdrawal_wt_niso_message_3(
                active_wt_parcel_to_be_sent_withdrawal_wt_niso_message_3
                    .look_for_message(&wt_peer_5_id)
                    .unwrap()
                    .clone(),
            )
            .unwrap();
        println!("NISOs received the pong.");
        let peer_1_withdrawal_niso_boomlet_message_6 = peer_1_niso
            .produce_withdrawal_niso_boomlet_message_6()
            .unwrap();
        let peer_2_withdrawal_niso_boomlet_message_6 = peer_2_niso
            .produce_withdrawal_niso_boomlet_message_6()
            .unwrap();
        let peer_3_withdrawal_niso_boomlet_message_6 = peer_3_niso
            .produce_withdrawal_niso_boomlet_message_6()
            .unwrap();
        let peer_4_withdrawal_niso_boomlet_message_6 = peer_4_niso
            .produce_withdrawal_niso_boomlet_message_6()
            .unwrap();
        let peer_5_withdrawal_niso_boomlet_message_6 = peer_5_niso
            .produce_withdrawal_niso_boomlet_message_6()
            .unwrap();
        println!("NISOs produced WithdrawalNisoBoomletMessage6 to give the pong to Boomlets.");

        let entities = [
            (
                1,
                wt_peer_1_id.clone(),
                &mut peer_1,
                &mut peer_1_boomlet,
                &mut peer_1_niso,
                &mut peer_1_st,
                peer_1_withdrawal_niso_boomlet_message_6,
            ),
            (
                2,
                wt_peer_2_id.clone(),
                &mut peer_2,
                &mut peer_2_boomlet,
                &mut peer_2_niso,
                &mut peer_2_st,
                peer_2_withdrawal_niso_boomlet_message_6,
            ),
            (
                3,
                wt_peer_3_id.clone(),
                &mut peer_3,
                &mut peer_3_boomlet,
                &mut peer_3_niso,
                &mut peer_3_st,
                peer_3_withdrawal_niso_boomlet_message_6,
            ),
            (
                4,
                wt_peer_4_id.clone(),
                &mut peer_4,
                &mut peer_4_boomlet,
                &mut peer_4_niso,
                &mut peer_4_st,
                peer_4_withdrawal_niso_boomlet_message_6,
            ),
            (
                5,
                wt_peer_5_id.clone(),
                &mut peer_5,
                &mut peer_5_boomlet,
                &mut peer_5_niso,
                &mut peer_5_st,
                peer_5_withdrawal_niso_boomlet_message_6,
            ),
        ];
        let pings_collection = entities
            .into_iter()
            .map(|(i, wt_peer_i_id, peer_i, peer_i_boomlet, peer_i_niso, peer_i_st, peer_i_withdrawal_niso_boomlet_message_6)| {
                /////////////////////////////////////////////////
                // Step 52 of Initiator     Withdrawal Diagram //
                /////////////////////////////////////////////////
                println!("Step 52 (Initiator Diagram) - Iteration {loop_counter} - Peer {i}:");
                peer_i_boomlet.consume_withdrawal_niso_boomlet_message_6(peer_i_withdrawal_niso_boomlet_message_6).unwrap();
                println!("Boomlet {i} received the pong.");
                let peer_i_boomlet_withdrawal_boomlet_niso_message_6_or_nothing = peer_i_boomlet.produce_withdrawal_boomlet_niso_message_6_or_produce_nothing().unwrap();

                if let BranchingMessage2::First(peer_i_withdrawal_boomlet_niso_message_6) = peer_i_boomlet_withdrawal_boomlet_niso_message_6_or_nothing {
                    println!("Boomlet {i} produced WithdrawalBoomletNisoMessage6 to give the duress check space with nonce to NISO {i}.");




                    /////////////////////////////////////////////////
                    // Step 53 of Initiator     Withdrawal Diagram //
                    /////////////////////////////////////////////////
                    println!("Step 32 (Initiator Diagram) - Iteration {loop_counter} - Peer {i}:");
                    println!("Step 53 (Non-Initiator Diagram) - Iteration {loop_counter} - Peer {i}:");
                    peer_i_niso.consume_withdrawal_boomlet_niso_message_6(peer_i_withdrawal_boomlet_niso_message_6).unwrap();
                    println!("NISO {i} received the duress check space with nonce.");
                    let peer_i_withdrawal_niso_st_message_3 = peer_i_niso.produce_withdrawal_niso_st_message_3().unwrap();
                    println!("NISO {i} produced WithdrawalNisoStMessage3 to the duress check space with nonce to ST {i}.");




                    /////////////////////////////////////////////////
                    // Step 54 of Initiator     Withdrawal Diagram //
                    /////////////////////////////////////////////////
                    println!("Step 54 (Initiator Diagram) - Iteration {loop_counter} - Peer {i}:");
                    peer_i_st.consume_withdrawal_niso_st_message_3(peer_i_withdrawal_niso_st_message_3).unwrap();
                    println!("ST {i} received the duress check space with nonce.");
                    let peer_i_withdrawal_st_output_3 = peer_i_st.produce_withdrawal_st_output_3().unwrap();
                    println!("ST {i} produced WithdrawalStOutput3 to give the duress check space with nonce to peer {i}.");




                    /////////////////////////////////////////////////
                    // Step 55 of Initiator     Withdrawal Diagram //
                    /////////////////////////////////////////////////
                    println!("Step 55 (Initiator Diagram) - Iteration {loop_counter} - Peer {i}:");
                    peer_i.consume_withdrawal_st_output_3(peer_i_withdrawal_st_output_3).unwrap();

                    println!("Peer {i} received the duress check space.");
                    let peer_i_withdrawal_st_input_3 = peer_i.produce_withdrawal_st_input_3().unwrap();
                    println!("Peer {i} produced WithdrawalStInput3 to give the duress signal index to ST {i}.");




                    /////////////////////////////////////////////////
                    // Step 56 of Initiator     Withdrawal Diagram //
                    /////////////////////////////////////////////////
                    println!("Step 56 (Initiator Diagram) - Iteration {loop_counter} - Peer {i}:");
                    peer_i_st.consume_withdrawal_st_input_3(peer_i_withdrawal_st_input_3).unwrap();
                    println!("ST {i} received the duress signal index with nonce.");
                    let peer_i_withdrawal_st_niso_message_3 = peer_i_st.produce_withdrawal_st_niso_message_3().unwrap();
                    println!("ST {i} produced WithdrawalStNisoMessage3 to give the duress signal index with nonce to NISO {i}.");




                    /////////////////////////////////////////////////
                    // Step 57 of Initiator     Withdrawal Diagram //
                    /////////////////////////////////////////////////
                    println!("Step 57 (Initiator Diagram) - Iteration {loop_counter} - Peer {i}:");
                    peer_i_niso.consume_withdrawal_st_niso_message_3(peer_i_withdrawal_st_niso_message_3).unwrap();
                    println!("NISO {i} received the the duress signal index with nonce.");
                    let peer_i_withdrawal_niso_boomlet_message_7 = peer_i_niso.produce_withdrawal_niso_boomlet_message_7().unwrap();
                    println!("NISO {i} produced WithdrawalNisoBoomletMessage7 to give the duress signal index with nonce to Boomlet {i}.");




                    /////////////////////////////////////////////////
                    // Step 58 of Initiator     Withdrawal Diagram //
                    /////////////////////////////////////////////////
                    println!("Step 58 (Initiator Diagram) - Iteration {loop_counter} - Peer {i}:");
                    peer_i_boomlet.consume_withdrawal_niso_boomlet_message_7(peer_i_withdrawal_niso_boomlet_message_7).unwrap();
                    println!("Boomlet {i} received the duress signal index with nonce.");
                }

                let peer_i_withdrawal_boomlet_niso_message_7 = peer_i_boomlet.produce_withdrawal_boomlet_niso_message_7().unwrap();
                println!("Boomlet {i} produced WithdrawalBoomletNisoMessage7 to give the ping to NISO {i}.");




                /////////////////////////////////////////////////
                // Step 59 of Initiator     Withdrawal Diagram //
                /////////////////////////////////////////////////
                println!("Step 59 (Initiator Diagram) - Iteration {loop_counter} - Peer {i}:");
                peer_i_niso.consume_withdrawal_boomlet_niso_message_7(peer_i_withdrawal_boomlet_niso_message_7).unwrap();
                println!("NISO {i} received the ping.");
                let peer_i_withdrawal_niso_wt_message_4 = peer_i_niso.produce_withdrawal_niso_wt_message_4().unwrap();
                println!("NISO {i} produced WithdrawalNisoWtMessage4 to give the ping to watchtower.");

                (wt_peer_i_id, peer_i_withdrawal_niso_wt_message_4)
            })
            .collect::<Vec<_>>();

        /////////////////////////////////////////////////
        // Step 60 of Initiator     Withdrawal Diagram //
        /////////////////////////////////////////////////
        println!("Step 60 (Initiator Diagram) - Iteration {loop_counter}:");
        active_wt
            .consume_withdrawal_niso_wt_message_4(Parcel::from_batch(pings_collection))
            .unwrap();
        println!("Watchtower received the pings.");

        active_wt_withdrawal_wt_sar_message_2_or_withdrawal_wt_niso_message_4 = active_wt
            .produce_withdrawal_wt_sar_message_2_or_produce_withdrawal_wt_niso_message_4()
            .unwrap();
        loop_counter += 1;
    }

    let active_wt_parcel_to_be_sent_withdrawal_wt_niso_message_4 =
        match active_wt_withdrawal_wt_sar_message_2_or_withdrawal_wt_niso_message_4 {
            BranchingMessage2::Second(message) => message,
            _ => unreachable!(
                "Pingpong has ended, therefore WT must have produced the ending message."
            ),
        };
    println!("Watchtower produced WithdrawalWtNisoMessage4 to give the reached pings to NISOs.");

    /////////////////////////////////////////////////
    // Step 61 of Initiator     Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 61 (Initiator Diagram):");
    peer_1_niso
        .consume_withdrawal_wt_niso_message_4(
            active_wt_parcel_to_be_sent_withdrawal_wt_niso_message_4
                .look_for_message(&wt_peer_1_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_2_niso
        .consume_withdrawal_wt_niso_message_4(
            active_wt_parcel_to_be_sent_withdrawal_wt_niso_message_4
                .look_for_message(&wt_peer_2_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_3_niso
        .consume_withdrawal_wt_niso_message_4(
            active_wt_parcel_to_be_sent_withdrawal_wt_niso_message_4
                .look_for_message(&wt_peer_3_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_4_niso
        .consume_withdrawal_wt_niso_message_4(
            active_wt_parcel_to_be_sent_withdrawal_wt_niso_message_4
                .look_for_message(&wt_peer_4_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_5_niso
        .consume_withdrawal_wt_niso_message_4(
            active_wt_parcel_to_be_sent_withdrawal_wt_niso_message_4
                .look_for_message(&wt_peer_5_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    println!("NISOs received the reached acks.");
    let peer_1_withdrawal_niso_boomlet_message_8 = peer_1_niso
        .produce_withdrawal_niso_boomlet_message_8()
        .unwrap();
    let peer_2_withdrawal_niso_boomlet_message_8 = peer_2_niso
        .produce_withdrawal_niso_boomlet_message_8()
        .unwrap();
    let peer_3_withdrawal_niso_boomlet_message_8 = peer_3_niso
        .produce_withdrawal_niso_boomlet_message_8()
        .unwrap();
    let peer_4_withdrawal_niso_boomlet_message_8 = peer_4_niso
        .produce_withdrawal_niso_boomlet_message_8()
        .unwrap();
    let peer_5_withdrawal_niso_boomlet_message_8 = peer_5_niso
        .produce_withdrawal_niso_boomlet_message_8()
        .unwrap();
    println!("NISOs produced WithdrawalNisoBoomletMessage8 to give the reached pings to Boomlets.");

    /////////////////////////////////////////////////
    // Step 62 of Initiator     Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 62 (Initiator Diagram):");
    peer_1_boomlet
        .consume_withdrawal_niso_boomlet_message_8(peer_1_withdrawal_niso_boomlet_message_8)
        .unwrap();
    peer_2_boomlet
        .consume_withdrawal_niso_boomlet_message_8(peer_2_withdrawal_niso_boomlet_message_8)
        .unwrap();
    peer_3_boomlet
        .consume_withdrawal_niso_boomlet_message_8(peer_3_withdrawal_niso_boomlet_message_8)
        .unwrap();
    peer_4_boomlet
        .consume_withdrawal_niso_boomlet_message_8(peer_4_withdrawal_niso_boomlet_message_8)
        .unwrap();
    peer_5_boomlet
        .consume_withdrawal_niso_boomlet_message_8(peer_5_withdrawal_niso_boomlet_message_8)
        .unwrap();
    println!("Boomlets received the reached pings.");
    let peer_1_withdrawal_boomlet_niso_message_8 = peer_1_boomlet
        .produce_withdrawal_boomlet_niso_message_8()
        .unwrap();
    let peer_2_withdrawal_boomlet_niso_message_8 = peer_2_boomlet
        .produce_withdrawal_boomlet_niso_message_8()
        .unwrap();
    let peer_3_withdrawal_boomlet_niso_message_8 = peer_3_boomlet
        .produce_withdrawal_boomlet_niso_message_8()
        .unwrap();
    let peer_4_withdrawal_boomlet_niso_message_8 = peer_4_boomlet
        .produce_withdrawal_boomlet_niso_message_8()
        .unwrap();
    let peer_5_withdrawal_boomlet_niso_message_8 = peer_5_boomlet
        .produce_withdrawal_boomlet_niso_message_8()
        .unwrap();
    println!(
        "Boomlets produced WithdrawalBoomletNisoMessage8 to inform NISOs that they are ready to sign."
    );

    /////////////////////////////////////////////////
    // Step 63 of Initiator     Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 63 (Initiator Diagram):");
    peer_1_niso
        .consume_withdrawal_boomlet_niso_message_8(peer_1_withdrawal_boomlet_niso_message_8)
        .unwrap();
    peer_2_niso
        .consume_withdrawal_boomlet_niso_message_8(peer_2_withdrawal_boomlet_niso_message_8)
        .unwrap();
    peer_3_niso
        .consume_withdrawal_boomlet_niso_message_8(peer_3_withdrawal_boomlet_niso_message_8)
        .unwrap();
    peer_4_niso
        .consume_withdrawal_boomlet_niso_message_8(peer_4_withdrawal_boomlet_niso_message_8)
        .unwrap();
    peer_5_niso
        .consume_withdrawal_boomlet_niso_message_8(peer_5_withdrawal_boomlet_niso_message_8)
        .unwrap();
    println!("NISOs know that Boomlets are ready to sign.");
    let peer_1_withdrawal_niso_output_1 = peer_1_niso.produce_withdrawal_niso_output_1().unwrap();
    let peer_2_withdrawal_niso_output_1 = peer_2_niso.produce_withdrawal_niso_output_1().unwrap();
    let peer_3_withdrawal_niso_output_1 = peer_3_niso.produce_withdrawal_niso_output_1().unwrap();
    let peer_4_withdrawal_niso_output_1 = peer_4_niso.produce_withdrawal_niso_output_1().unwrap();
    let peer_5_withdrawal_niso_output_1 = peer_5_niso.produce_withdrawal_niso_output_1().unwrap();
    println!(
        "NISOs produced WithdrawalNisoOutput1 to inform peers that Boomlets are ready to sign."
    );

    /////////////////////////////////////////////////
    // Step 64 of Initiator     Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 64 (Initiator Diagram):");
    peer_1
        .consume_withdrawal_niso_output_1(peer_1_withdrawal_niso_output_1)
        .unwrap();
    peer_2
        .consume_withdrawal_niso_output_1(peer_2_withdrawal_niso_output_1)
        .unwrap();
    peer_3
        .consume_withdrawal_niso_output_1(peer_3_withdrawal_niso_output_1)
        .unwrap();
    peer_4
        .consume_withdrawal_niso_output_1(peer_4_withdrawal_niso_output_1)
        .unwrap();
    peer_5
        .consume_withdrawal_niso_output_1(peer_5_withdrawal_niso_output_1)
        .unwrap();

    println!("Peers know that Boomlets are ready to sign.");

    let peer_1_withdrawal_iso_input_1 = peer_1.produce_withdrawal_iso_input_1().unwrap();
    let peer_2_withdrawal_iso_input_1 = peer_2.produce_withdrawal_iso_input_1().unwrap();
    let peer_3_withdrawal_iso_input_1 = peer_3.produce_withdrawal_iso_input_1().unwrap();
    let peer_4_withdrawal_iso_input_1 = peer_4.produce_withdrawal_iso_input_1().unwrap();
    let peer_5_withdrawal_iso_input_1 = peer_5.produce_withdrawal_iso_input_1().unwrap();

    println!("Peers produced WithdrawalIsoInput1 to give signing data to ISOs.");

    /////////////////////////////////////////////////
    // Step 65 of Initiator     Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 65 (Initiator Diagram):");
    peer_1_iso
        .consume_withdrawal_iso_input_1(peer_1_withdrawal_iso_input_1)
        .unwrap();
    peer_2_iso
        .consume_withdrawal_iso_input_1(peer_2_withdrawal_iso_input_1)
        .unwrap();
    peer_3_iso
        .consume_withdrawal_iso_input_1(peer_3_withdrawal_iso_input_1)
        .unwrap();
    peer_4_iso
        .consume_withdrawal_iso_input_1(peer_4_withdrawal_iso_input_1)
        .unwrap();
    peer_5_iso
        .consume_withdrawal_iso_input_1(peer_5_withdrawal_iso_input_1)
        .unwrap();
    println!("ISOs received signing data.");
    let peer_1_withdrawal_iso_boomlet_message_1 = peer_1_iso
        .produce_withdrawal_iso_boomlet_message_1()
        .unwrap();
    let peer_2_withdrawal_iso_boomlet_message_1 = peer_2_iso
        .produce_withdrawal_iso_boomlet_message_1()
        .unwrap();
    let peer_3_withdrawal_iso_boomlet_message_1 = peer_3_iso
        .produce_withdrawal_iso_boomlet_message_1()
        .unwrap();
    let peer_4_withdrawal_iso_boomlet_message_1 = peer_4_iso
        .produce_withdrawal_iso_boomlet_message_1()
        .unwrap();
    let peer_5_withdrawal_iso_boomlet_message_1 = peer_5_iso
        .produce_withdrawal_iso_boomlet_message_1()
        .unwrap();
    println!(
        "ISOs produced WithdrawalIsoBoomletMessage1 to signal the start of musig2 signing procedure to Boomlets."
    );

    /////////////////////////////////////////////////
    // Step 66 of Initiator     Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 66 (Initiator Diagram):");
    peer_1_boomlet
        .consume_withdrawal_iso_boomlet_message_1(peer_1_withdrawal_iso_boomlet_message_1)
        .unwrap();
    peer_2_boomlet
        .consume_withdrawal_iso_boomlet_message_1(peer_2_withdrawal_iso_boomlet_message_1)
        .unwrap();
    peer_3_boomlet
        .consume_withdrawal_iso_boomlet_message_1(peer_3_withdrawal_iso_boomlet_message_1)
        .unwrap();
    peer_4_boomlet
        .consume_withdrawal_iso_boomlet_message_1(peer_4_withdrawal_iso_boomlet_message_1)
        .unwrap();
    peer_5_boomlet
        .consume_withdrawal_iso_boomlet_message_1(peer_5_withdrawal_iso_boomlet_message_1)
        .unwrap();
    println!("Boomlets know about the start of musig2 signing procedure.");
    let peer_1_withdrawal_boomlet_iso_message_1 = peer_1_boomlet
        .produce_withdrawal_boomlet_iso_message_1()
        .unwrap();
    let peer_2_withdrawal_boomlet_iso_message_1 = peer_2_boomlet
        .produce_withdrawal_boomlet_iso_message_1()
        .unwrap();
    let peer_3_withdrawal_boomlet_iso_message_1 = peer_3_boomlet
        .produce_withdrawal_boomlet_iso_message_1()
        .unwrap();
    let peer_4_withdrawal_boomlet_iso_message_1 = peer_4_boomlet
        .produce_withdrawal_boomlet_iso_message_1()
        .unwrap();
    let peer_5_withdrawal_boomlet_iso_message_1 = peer_5_boomlet
        .produce_withdrawal_boomlet_iso_message_1()
        .unwrap();
    println!("Boomlets produced WithdrawalBoomletIsoMessage1 to required signing data to ISOs.");

    /////////////////////////////////////////////////
    // Step 67 of Initiator     Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 67 (Initiator Diagram):");
    peer_1_iso
        .consume_withdrawal_boomlet_iso_message_1(peer_1_withdrawal_boomlet_iso_message_1)
        .unwrap();
    peer_2_iso
        .consume_withdrawal_boomlet_iso_message_1(peer_2_withdrawal_boomlet_iso_message_1)
        .unwrap();
    peer_3_iso
        .consume_withdrawal_boomlet_iso_message_1(peer_3_withdrawal_boomlet_iso_message_1)
        .unwrap();
    peer_4_iso
        .consume_withdrawal_boomlet_iso_message_1(peer_4_withdrawal_boomlet_iso_message_1)
        .unwrap();
    peer_5_iso
        .consume_withdrawal_boomlet_iso_message_1(peer_5_withdrawal_boomlet_iso_message_1)
        .unwrap();
    println!("ISOs received required signing data.");
    let peer_1_withdrawal_iso_boomlet_message_2 = peer_1_iso
        .produce_withdrawal_iso_boomlet_message_2()
        .unwrap();
    let peer_2_withdrawal_iso_boomlet_message_2 = peer_2_iso
        .produce_withdrawal_iso_boomlet_message_2()
        .unwrap();
    let peer_3_withdrawal_iso_boomlet_message_2 = peer_3_iso
        .produce_withdrawal_iso_boomlet_message_2()
        .unwrap();
    let peer_4_withdrawal_iso_boomlet_message_2 = peer_4_iso
        .produce_withdrawal_iso_boomlet_message_2()
        .unwrap();
    let peer_5_withdrawal_iso_boomlet_message_2 = peer_5_iso
        .produce_withdrawal_iso_boomlet_message_2()
        .unwrap();
    println!(
        "ISOs produced WithdrawalIsoBoomletMessage2 to give their partial signatures on PSBT to Boomlets."
    );

    /////////////////////////////////////////////////
    // Step 68 of Initiator     Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 68 (Initiator Diagram):");
    peer_1_boomlet
        .consume_withdrawal_iso_boomlet_message_2(peer_1_withdrawal_iso_boomlet_message_2)
        .unwrap();
    peer_2_boomlet
        .consume_withdrawal_iso_boomlet_message_2(peer_2_withdrawal_iso_boomlet_message_2)
        .unwrap();
    peer_3_boomlet
        .consume_withdrawal_iso_boomlet_message_2(peer_3_withdrawal_iso_boomlet_message_2)
        .unwrap();
    peer_4_boomlet
        .consume_withdrawal_iso_boomlet_message_2(peer_4_withdrawal_iso_boomlet_message_2)
        .unwrap();
    peer_5_boomlet
        .consume_withdrawal_iso_boomlet_message_2(peer_5_withdrawal_iso_boomlet_message_2)
        .unwrap();
    println!("Boomlets received partial signatures of ISOs.");
    let peer_1_withdrawal_boomlet_iso_message_2 = peer_1_boomlet
        .produce_withdrawal_boomlet_iso_message_2()
        .unwrap();
    let peer_2_withdrawal_boomlet_iso_message_2 = peer_2_boomlet
        .produce_withdrawal_boomlet_iso_message_2()
        .unwrap();
    let peer_3_withdrawal_boomlet_iso_message_2 = peer_3_boomlet
        .produce_withdrawal_boomlet_iso_message_2()
        .unwrap();
    let peer_4_withdrawal_boomlet_iso_message_2 = peer_4_boomlet
        .produce_withdrawal_boomlet_iso_message_2()
        .unwrap();
    let peer_5_withdrawal_boomlet_iso_message_2 = peer_5_boomlet
        .produce_withdrawal_boomlet_iso_message_2()
        .unwrap();
    println!(
        "Boomlets produced WithdrawalBoomletIsoMessage2 to give their partial signatures on PSBT to ISOs."
    );

    /////////////////////////////////////////////////
    // Step 69 of Initiator     Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 69 (Initiator Diagram):");
    peer_1_iso
        .consume_withdrawal_boomlet_iso_message_2(peer_1_withdrawal_boomlet_iso_message_2)
        .unwrap();
    peer_2_iso
        .consume_withdrawal_boomlet_iso_message_2(peer_2_withdrawal_boomlet_iso_message_2)
        .unwrap();
    peer_3_iso
        .consume_withdrawal_boomlet_iso_message_2(peer_3_withdrawal_boomlet_iso_message_2)
        .unwrap();
    peer_4_iso
        .consume_withdrawal_boomlet_iso_message_2(peer_4_withdrawal_boomlet_iso_message_2)
        .unwrap();
    peer_5_iso
        .consume_withdrawal_boomlet_iso_message_2(peer_5_withdrawal_boomlet_iso_message_2)
        .unwrap();
    println!("ISOs received partial signatures of Boomlets.");
    let peer_1_withdrawal_iso_output_1 = peer_1_iso.produce_withdrawal_iso_output_1().unwrap();
    let peer_2_withdrawal_iso_output_1 = peer_2_iso.produce_withdrawal_iso_output_1().unwrap();
    let peer_3_withdrawal_iso_output_1 = peer_3_iso.produce_withdrawal_iso_output_1().unwrap();
    let peer_4_withdrawal_iso_output_1 = peer_4_iso.produce_withdrawal_iso_output_1().unwrap();
    let peer_5_withdrawal_iso_output_1 = peer_5_iso.produce_withdrawal_iso_output_1().unwrap();
    println!("ISOs produced WithdrawalIsoOutput1 to inform peers that psbt signature is created.");

    /////////////////////////////////////////////////
    // Step 70 of Initiator     Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 70 (Initiator Diagram):");
    peer_1
        .consume_withdrawal_iso_output_1(peer_1_withdrawal_iso_output_1)
        .unwrap();
    peer_2
        .consume_withdrawal_iso_output_1(peer_2_withdrawal_iso_output_1)
        .unwrap();
    peer_3
        .consume_withdrawal_iso_output_1(peer_3_withdrawal_iso_output_1)
        .unwrap();
    peer_4
        .consume_withdrawal_iso_output_1(peer_4_withdrawal_iso_output_1)
        .unwrap();
    peer_5
        .consume_withdrawal_iso_output_1(peer_5_withdrawal_iso_output_1)
        .unwrap();

    println!("Peers know that psbt signature is created.");
    let peer_1_withdrawal_niso_input_2 = peer_1.produce_withdrawal_niso_input_2().unwrap();
    let peer_2_withdrawal_niso_input_2 = peer_2.produce_withdrawal_niso_input_2().unwrap();
    let peer_3_withdrawal_niso_input_2 = peer_3.produce_withdrawal_niso_input_2().unwrap();
    let peer_4_withdrawal_niso_input_2 = peer_4.produce_withdrawal_niso_input_2().unwrap();
    let peer_5_withdrawal_niso_input_2 = peer_5.produce_withdrawal_niso_input_2().unwrap();
    println!("Peers produced WithdrawalNisoInput2 to tell NISOs that psbt signature is created.");

    /////////////////////////////////////////////////
    // Step 71 of Initiator     Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 71 (Initiator Diagram):");
    peer_1_niso
        .consume_withdrawal_niso_input_2(peer_1_withdrawal_niso_input_2)
        .unwrap();
    peer_2_niso
        .consume_withdrawal_niso_input_2(peer_2_withdrawal_niso_input_2)
        .unwrap();
    peer_3_niso
        .consume_withdrawal_niso_input_2(peer_3_withdrawal_niso_input_2)
        .unwrap();
    peer_4_niso
        .consume_withdrawal_niso_input_2(peer_4_withdrawal_niso_input_2)
        .unwrap();
    peer_5_niso
        .consume_withdrawal_niso_input_2(peer_5_withdrawal_niso_input_2)
        .unwrap();
    println!("NISOs know that psbt signature is created.");
    let peer_1_withdrawal_niso_boomlet_message_9 = peer_1_niso
        .produce_withdrawal_niso_boomlet_message_9()
        .unwrap();
    let peer_2_withdrawal_niso_boomlet_message_9 = peer_2_niso
        .produce_withdrawal_niso_boomlet_message_9()
        .unwrap();
    let peer_3_withdrawal_niso_boomlet_message_9 = peer_3_niso
        .produce_withdrawal_niso_boomlet_message_9()
        .unwrap();
    let peer_4_withdrawal_niso_boomlet_message_9 = peer_4_niso
        .produce_withdrawal_niso_boomlet_message_9()
        .unwrap();
    let peer_5_withdrawal_niso_boomlet_message_9 = peer_5_niso
        .produce_withdrawal_niso_boomlet_message_9()
        .unwrap();
    println!("ISOs produced WithdrawalIsoBoomletMessage9 to ask Boomlets for the signed PSBT.");

    /////////////////////////////////////////////////
    // Step 72 of Initiator     Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 72 (Initiator Diagram):");
    peer_1_boomlet
        .consume_withdrawal_niso_boomlet_message_9(peer_1_withdrawal_niso_boomlet_message_9)
        .unwrap();
    peer_2_boomlet
        .consume_withdrawal_niso_boomlet_message_9(peer_2_withdrawal_niso_boomlet_message_9)
        .unwrap();
    peer_3_boomlet
        .consume_withdrawal_niso_boomlet_message_9(peer_3_withdrawal_niso_boomlet_message_9)
        .unwrap();
    peer_4_boomlet
        .consume_withdrawal_niso_boomlet_message_9(peer_4_withdrawal_niso_boomlet_message_9)
        .unwrap();
    peer_5_boomlet
        .consume_withdrawal_niso_boomlet_message_9(peer_5_withdrawal_niso_boomlet_message_9)
        .unwrap();
    println!("Boomlets received NISOs request for the signed PSBT.");
    let peer_1_withdrawal_boomlet_niso_message_9 = peer_1_boomlet
        .produce_withdrawal_boomlet_niso_message_9()
        .unwrap();
    let peer_2_withdrawal_boomlet_niso_message_9 = peer_2_boomlet
        .produce_withdrawal_boomlet_niso_message_9()
        .unwrap();
    let peer_3_withdrawal_boomlet_niso_message_9 = peer_3_boomlet
        .produce_withdrawal_boomlet_niso_message_9()
        .unwrap();
    let peer_4_withdrawal_boomlet_niso_message_9 = peer_4_boomlet
        .produce_withdrawal_boomlet_niso_message_9()
        .unwrap();
    let peer_5_withdrawal_boomlet_niso_message_9 = peer_5_boomlet
        .produce_withdrawal_boomlet_niso_message_9()
        .unwrap();
    println!("Boomlets produced WithdrawalBoomletNisoMessage9 to give the signed PSBT to NISOs.");

    /////////////////////////////////////////////////
    // Step 73 of Initiator     Withdrawal Diagram //
    /////////////////////////////////////////////////
    println!("Step 73 (Initiator Diagram):");
    peer_1_niso
        .consume_withdrawal_boomlet_niso_message_9(peer_1_withdrawal_boomlet_niso_message_9)
        .unwrap();
    peer_2_niso
        .consume_withdrawal_boomlet_niso_message_9(peer_2_withdrawal_boomlet_niso_message_9)
        .unwrap();
    peer_3_niso
        .consume_withdrawal_boomlet_niso_message_9(peer_3_withdrawal_boomlet_niso_message_9)
        .unwrap();
    peer_4_niso
        .consume_withdrawal_boomlet_niso_message_9(peer_4_withdrawal_boomlet_niso_message_9)
        .unwrap();
    peer_5_niso
        .consume_withdrawal_boomlet_niso_message_9(peer_5_withdrawal_boomlet_niso_message_9)
        .unwrap();
    println!("NISOs received the signed PSBT.");
    let peer_1_withdrawal_niso_wt_message_5 =
        peer_1_niso.produce_withdrawal_niso_wt_message_5().unwrap();
    let peer_2_withdrawal_niso_wt_message_5 =
        peer_2_niso.produce_withdrawal_niso_wt_message_5().unwrap();
    let peer_3_withdrawal_niso_wt_message_5 =
        peer_3_niso.produce_withdrawal_niso_wt_message_5().unwrap();
    let peer_4_withdrawal_niso_wt_message_5 =
        peer_4_niso.produce_withdrawal_niso_wt_message_5().unwrap();
    let peer_5_withdrawal_niso_wt_message_5 =
        peer_5_niso.produce_withdrawal_niso_wt_message_5().unwrap();
    println!("NISOs produced WithdrawalNisoWtMessage5 to give the signed PSBTs to watchtower.");
    let active_wt_parcel_to_be_received_withdrawal_niso_wt_message_5 = Parcel::new(vec![
        MetadataAttachedMessage::new(wt_peer_1_id.clone(), peer_1_withdrawal_niso_wt_message_5),
        MetadataAttachedMessage::new(wt_peer_2_id.clone(), peer_2_withdrawal_niso_wt_message_5),
        MetadataAttachedMessage::new(wt_peer_3_id.clone(), peer_3_withdrawal_niso_wt_message_5),
        MetadataAttachedMessage::new(wt_peer_4_id.clone(), peer_4_withdrawal_niso_wt_message_5),
        MetadataAttachedMessage::new(wt_peer_5_id.clone(), peer_5_withdrawal_niso_wt_message_5),
    ]);
    active_wt
        .consume_withdrawal_niso_wt_message_5(
            active_wt_parcel_to_be_received_withdrawal_niso_wt_message_5,
        )
        .unwrap();
    println!(
        "Watchtower received the signed PSBTs, combined them, and broadcasted the final signed transaction."
    );
    println!("Finished!");

    miner_task_handle.abort();
    Ok(())
}
