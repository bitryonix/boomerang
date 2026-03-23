use bitcoin::{
    Psbt, Transaction, TxOut, absolute,
    psbt::{self, raw::ProprietaryKey},
};
use bitcoincore_rpc::RpcApi;
use derive_more::{Display, Error};
use miniscript::{MiniscriptKey, ToPublicKey, descriptor::Tr};
use tracing::{Level, event};
use tracing_utils::traceable_unfold_or_panic;

pub struct BitcoinUtils;

impl BitcoinUtils {
    pub fn psbt_inputs_from_descriptor<'a, T: MiniscriptKey + ToPublicKey>(
        psbt: &'a Psbt,
        descriptor: &Tr<T>,
    ) -> Vec<(usize, &'a psbt::Input)> {
        let mut relevant_inputs = vec![];
        let descriptor_script_pubkey = descriptor.script_pubkey();
        psbt.inputs.iter().enumerate().for_each(|(index, input)| {
            if let Some(prev_tx_out) = &input.witness_utxo
                && prev_tx_out.script_pubkey == descriptor_script_pubkey
            {
                relevant_inputs.push((index, input));
            };
        });

        relevant_inputs
    }

    pub fn psbt_inputs_from_descriptor_mut<'a, T: MiniscriptKey + ToPublicKey>(
        psbt: &'a mut Psbt,
        descriptor: &Tr<T>,
    ) -> Vec<(usize, &'a mut psbt::Input)> {
        let mut relevant_inputs = vec![];
        let descriptor_script_pubkey = descriptor.script_pubkey();
        psbt.inputs
            .iter_mut()
            .enumerate()
            .for_each(|(index, input)| {
                if let Some(prev_tx_out) = &input.witness_utxo
                    && prev_tx_out.script_pubkey == descriptor_script_pubkey
                {
                    relevant_inputs.push((index, input));
                };
            });

        relevant_inputs
    }

    pub fn psbt_inputs_from_proprietary_key_mut(
        psbt: &mut Psbt,
        proprietary_key: ProprietaryKey<u8>,
    ) -> Vec<(usize, &mut psbt::Input)> {
        let mut relevant_inputs = vec![];
        psbt.inputs
            .iter_mut()
            .enumerate()
            .for_each(|(index, input)| {
                if input.proprietary.contains_key(&proprietary_key) {
                    relevant_inputs.push((index, input));
                }
            });

        relevant_inputs
    }

    pub fn hydrate_psbt_with_tx_out(
        bitcoincore_rpc_client: &bitcoincore_rpc::Client,
        psbt: &mut Psbt,
    ) -> Result<(), HydratePsbtWithTxOutError> {
        psbt.inputs
            .iter_mut()
            .enumerate()
            .try_for_each(|(index, input)| {
                let tx_out = BitcoinUtils::get_tx_out_of_input_of_unsigned_tx(
                    bitcoincore_rpc_client,
                    &psbt.unsigned_tx,
                    index,
                )
                .map_err(|err| match err {
                    GetTxOutOfUnsignedTxError::BitcoinCoreRpcClient(inner_err) => {
                        HydratePsbtWithTxOutError::BitcoinCoreRpcClient(inner_err)
                    }
                    GetTxOutOfUnsignedTxError::NonExistentOutPoints => {
                        HydratePsbtWithTxOutError::NonExistentOutPoints
                    }
                })?;
                // We do not need to fetch non-Boomerang (therefore non-witness) UTXOs of inputs.
                if tx_out.script_pubkey.is_witness_program() {
                    input.witness_utxo = Some(tx_out);
                }

                Ok(())
            })?;

        Ok(())
    }

    fn get_tx_out_of_input_of_unsigned_tx(
        bitcoincore_rpc_client: &bitcoincore_rpc::Client,
        unsigned_tx: &Transaction,
        index: usize,
    ) -> Result<TxOut, GetTxOutOfUnsignedTxError> {
        let tx_in = traceable_unfold_or_panic!(
            unsigned_tx.tx_in(index),
            "Assumed input index to be in range of transaction's tx ins."
        );
        let get_tx_out_result = bitcoincore_rpc_client
            .get_tx_out(
                &tx_in.previous_output.txid,
                tx_in.previous_output.vout,
                Some(false),
            )
            .map_err(GetTxOutOfUnsignedTxError::BitcoinCoreRpcClient)?
            .ok_or(GetTxOutOfUnsignedTxError::NonExistentOutPoints)?;
        let tx_out_script_pubkey = traceable_unfold_or_panic!(
            get_tx_out_result.script_pub_key.script(),
            "Assumed script pubkey to be derivable from tx out."
        );
        Ok(TxOut {
            value: get_tx_out_result.value,
            script_pubkey: tx_out_script_pubkey,
        })
    }

    pub fn absolute_height_saturating_sub(
        height: absolute::Height,
        amount: u32,
    ) -> absolute::Height {
        let height_u32 = height.to_consensus_u32();
        absolute::Height::from_consensus(height_u32.saturating_sub(amount))
            .expect("Assumed the result to be a valid block height.")
    }

    pub fn absolute_height_saturating_add(
        height: absolute::Height,
        amount: u32,
    ) -> absolute::Height {
        let height_u32 = height.to_consensus_u32();
        absolute::Height::from_consensus(height_u32.saturating_add(amount))
            .expect("Assumed the result to be a valid block height.")
    }
}

#[derive(Debug, Display, Error)]
pub enum HydratePsbtWithTxOutError {
    BitcoinCoreRpcClient(bitcoincore_rpc::Error),
    NonExistentOutPoints,
}

#[derive(Debug, Display, Error)]
pub enum VerifyInputsTxOutsAndScriptPubkeysError {
    BitcoinCoreRpcClient(bitcoincore_rpc::Error),
    NonExistentOutPoints,
    NonWitnessTxOut,
    ContradictoryTxOut,
    NonExistentTxOut,
    UnexpectedScriptPubkey,
}

#[derive(Debug, Display, Error)]
pub enum GetTxOutOfUnsignedTxError {
    BitcoinCoreRpcClient(bitcoincore_rpc::Error),
    NonExistentOutPoints,
}
