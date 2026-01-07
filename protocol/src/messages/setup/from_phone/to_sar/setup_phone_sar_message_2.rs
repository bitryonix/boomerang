use cryptography::SymmetricCiphertext;
use serde::{Deserialize, Serialize};

use crate::{constructs::SarServiceFeePaymentReceipt, messages::Message};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupPhoneSarMessage2 {
    sar_service_fee_payment_receipt: SarServiceFeePaymentReceipt,
    static_doxing_data_encrypted_by_doxing_key: SymmetricCiphertext,
    doxing_data_identifier: [u8; 32],
    dynamic_doxing_data_encrypted_by_doxing_key: SymmetricCiphertext,
}

impl SetupPhoneSarMessage2 {
    pub fn new(
        sar_service_fee_payment_receipt: SarServiceFeePaymentReceipt,
        static_doxing_data_encrypted_by_doxing_key: SymmetricCiphertext,
        doxing_data_identifier: [u8; 32],
        dynamic_doxing_data_encrypted_by_doxing_key: SymmetricCiphertext,
    ) -> Self {
        SetupPhoneSarMessage2 {
            sar_service_fee_payment_receipt,
            static_doxing_data_encrypted_by_doxing_key,
            doxing_data_identifier,
            dynamic_doxing_data_encrypted_by_doxing_key,
        }
    }

    pub fn into_parts(
        self,
    ) -> (
        SarServiceFeePaymentReceipt,
        SymmetricCiphertext,
        [u8; 32],
        SymmetricCiphertext,
    ) {
        (
            self.sar_service_fee_payment_receipt,
            self.static_doxing_data_encrypted_by_doxing_key,
            self.doxing_data_identifier,
            self.dynamic_doxing_data_encrypted_by_doxing_key,
        )
    }
}

impl Message for SetupPhoneSarMessage2 {}
