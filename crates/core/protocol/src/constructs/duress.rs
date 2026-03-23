use std::collections::BTreeMap;

use cryptography::{
    Cryptography, CryptographySymmetricDecryptionError, CryptographySymmetricEncryptionError,
    SymmetricCiphertext, SymmetricKey,
};
use derive_more::{Display, Error};
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::constructs::SarId;

pub const DURESS_CHOICE_SIZE: usize = 5;
pub const DURESS_SET_SIZE: usize = 195;
pub const DURESS_SET: [&str; DURESS_SET_SIZE] = [
    "Afghanistan",
    "Albania",
    "Algeria",
    "Andorra",
    "Angola",
    "Antigua and Barbuda",
    "Argentina",
    "Armenia",
    "Australia",
    "Austria",
    "Azerbaijan",
    "Bahamas",
    "Bahrain",
    "Bangladesh",
    "Barbados",
    "Belarus",
    "Belgium",
    "Belize",
    "Benin",
    "Bhutan",
    "Bolivia",
    "Bosnia and Herzegovina",
    "Botswana",
    "Brazil",
    "Brunei",
    "Bulgaria",
    "Burkina Faso",
    "Burundi",
    "Cabo Verde",
    "Cambodia",
    "Cameroon",
    "Canada",
    "Central African Republic",
    "Chad",
    "Chile",
    "China",
    "Colombia",
    "Comoros",
    "Republic of the Congo",
    "Democratic Republic of the Congo",
    "Costa Rica",
    "Côte d'Ivoire",
    "Croatia",
    "Cuba",
    "Cyprus",
    "Czech Republic",
    "Denmark",
    "Djibouti",
    "Dominica",
    "Dominican Republic",
    "Ecuador",
    "Egypt",
    "El Salvador",
    "Equatorial Guinea",
    "Eritrea",
    "Estonia",
    "Eswatini",
    "Ethiopia",
    "Fiji",
    "Finland",
    "France",
    "Gabon",
    "Gambia",
    "Georgia",
    "Germany",
    "Ghana",
    "Greece",
    "Grenada",
    "Guatemala",
    "Guinea",
    "Guinea-Bissau",
    "Guyana",
    "Haiti",
    "Honduras",
    "Hungary",
    "Iceland",
    "India",
    "Indonesia",
    "Iran",
    "Iraq",
    "Ireland",
    "Israel",
    "Italy",
    "Jamaica",
    "Japan",
    "Jordan",
    "Kazakhstan",
    "Kenya",
    "Kiribati",
    "North Korea",
    "South Korea",
    "Kuwait",
    "Kyrgyzstan",
    "Laos",
    "Latvia",
    "Lebanon",
    "Lesotho",
    "Liberia",
    "Libya",
    "Liechtenstein",
    "Lithuania",
    "Luxembourg",
    "Madagascar",
    "Malawi",
    "Malaysia",
    "Maldives",
    "Mali",
    "Malta",
    "Marshall Islands",
    "Mauritania",
    "Mauritius",
    "Mexico",
    "Micronesia",
    "Moldova",
    "Monaco",
    "Mongolia",
    "Montenegro",
    "Morocco",
    "Mozambique",
    "Myanmar",
    "Namibia",
    "Nauru",
    "Nepal",
    "Netherlands",
    "New Zealand",
    "Nicaragua",
    "Niger",
    "Nigeria",
    "North Macedonia",
    "Norway",
    "Oman",
    "Pakistan",
    "Palau",
    "Panama",
    "Papua New Guinea",
    "Paraguay",
    "Peru",
    "Philippines",
    "Poland",
    "Portugal",
    "Qatar",
    "Romania",
    "Russia",
    "Rwanda",
    "Saint Kitts and Nevis",
    "Saint Lucia",
    "Saint Vincent and the Grenadines",
    "Samoa",
    "San Marino",
    "Sao Tome and Principe",
    "Saudi Arabia",
    "Senegal",
    "Serbia",
    "Seychelles",
    "Sierra Leone",
    "Singapore",
    "Slovakia",
    "Slovenia",
    "Solomon Islands",
    "Somalia",
    "South Africa",
    "South Sudan",
    "Spain",
    "Sri Lanka",
    "State of Palestine",
    "Sudan",
    "Suriname",
    "Sweden",
    "Switzerland",
    "Syria",
    "Tajikistan",
    "Tanzania",
    "Thailand",
    "Timor-Leste",
    "Togo",
    "Tonga",
    "Trinidad and Tobago",
    "Tunisia",
    "Türkiye",
    "Turkmenistan",
    "Tuvalu",
    "Uganda",
    "Ukraine",
    "United Arab Emirates",
    "United Kingdom",
    "United States",
    "Uruguay",
    "Uzbekistan",
    "Vanuatu",
    "Vatican City",
    "Venezuela",
    "Vietnam",
    "Yemen",
    "Zambia",
    "Zimbabwe",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuressCheckSpace {
    duress_sets_collection: [Vec<usize>; DURESS_CHOICE_SIZE],
}

impl DuressCheckSpace {
    pub fn random_generate<R: Rng + ?Sized>(rng: &mut R) -> Self {
        let mut consent_set_space_array: [Vec<usize>; DURESS_CHOICE_SIZE] =
            std::array::from_fn(|_| Vec::new());
        for consent_set_space in &mut consent_set_space_array {
            for index in 0..DURESS_SET_SIZE {
                consent_set_space.push(index);
            }
            DuressCheckSpace::randomize_array(rng, consent_set_space);
        }
        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce);

        DuressCheckSpace {
            duress_sets_collection: consent_set_space_array,
        }
    }

    fn randomize_array<R: Rng + ?Sized, T>(rng: &mut R, array: &mut [T]) {
        for counter in 0..array.len() {
            let destination = rng.random_range(0..=counter);
            array.swap(counter, destination);
        }
    }

    pub fn derive_consent_set(&self, duress_signal_index: &DuressSignalIndex) -> DuressConsentSet {
        let duress_consent_set = std::array::from_fn(|i| {
            let set = &self.duress_sets_collection[i];
            let choice = duress_signal_index.index[i];
            set[choice]
        });

        DuressConsentSet { duress_consent_set }
    }

    pub fn find_indices(
        &self,
        country_codes: [usize; DURESS_CHOICE_SIZE],
    ) -> [usize; DURESS_CHOICE_SIZE] {
        std::array::from_fn(|i| {
            self.duress_sets_collection[i]
                .iter()
                .enumerate()
                .find_map(|(index, duress_set_country_code)| {
                    if country_codes[i] == *duress_set_country_code {
                        Some(index)
                    } else {
                        None
                    }
                })
                .unwrap()
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuressCheckSpaceWithNonce {
    duress_check_space: DuressCheckSpace,
    nonce: [u8; 32],
}

impl DuressCheckSpaceWithNonce {
    pub fn new(duress_check_space: DuressCheckSpace, nonce: [u8; 32]) -> Self {
        DuressCheckSpaceWithNonce {
            duress_check_space,
            nonce,
        }
    }

    pub fn random_generate<R: Rng + ?Sized>(rng: &mut R) -> Self {
        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce);

        DuressCheckSpaceWithNonce {
            duress_check_space: DuressCheckSpace::random_generate(rng),
            nonce,
        }
    }

    pub fn get_nonce(&self) -> [u8; 32] {
        self.nonce
    }

    pub fn derive_consent_set(
        &self,
        duress_signal_index_with_nonce: &DuressSignalIndexWithNonce,
    ) -> Result<DuressConsentSet, DuressCheckSpaceWithNonceDeriveDuressConsentSetError> {
        if self.nonce != duress_signal_index_with_nonce.nonce {
            return Err(DuressCheckSpaceWithNonceDeriveDuressConsentSetError::NonceMismatch);
        }

        Ok(self
            .duress_check_space
            .derive_consent_set(&duress_signal_index_with_nonce.duress_signal_index))
    }

    pub fn into_parts(self) -> (DuressCheckSpace, [u8; 32]) {
        (self.duress_check_space, self.nonce)
    }

    pub fn find_indices(
        &self,
        country_codes: [usize; DURESS_CHOICE_SIZE],
    ) -> [usize; DURESS_CHOICE_SIZE] {
        self.duress_check_space.find_indices(country_codes)
    }
}

#[derive(Debug, Display, Error)]
pub enum DuressCheckSpaceWithNonceDeriveDuressConsentSetError {
    NonceMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuressSignalIndex {
    index: [usize; DURESS_CHOICE_SIZE],
}

impl DuressSignalIndex {
    pub fn new(index: [usize; DURESS_CHOICE_SIZE]) -> Self {
        DuressSignalIndex { index }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuressSignalIndexWithNonce {
    duress_signal_index: DuressSignalIndex,
    nonce: [u8; 32],
}

impl DuressSignalIndexWithNonce {
    pub fn new(duress_signal_index: DuressSignalIndex, nonce: [u8; 32]) -> Self {
        DuressSignalIndexWithNonce {
            duress_signal_index,
            nonce,
        }
    }

    pub fn get_nonce(&self) -> [u8; 32] {
        self.nonce
    }

    pub fn into_parts(self) -> (DuressSignalIndex, [u8; 32]) {
        (self.duress_signal_index, self.nonce)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuressConsentSet {
    duress_consent_set: [usize; DURESS_CHOICE_SIZE],
}

impl DuressConsentSet {
    pub fn new(duress_consent_set: [usize; DURESS_CHOICE_SIZE]) -> Self {
        DuressConsentSet { duress_consent_set }
    }

    pub fn get_country_codes(&self) -> [usize; DURESS_CHOICE_SIZE] {
        self.duress_consent_set
    }
}

impl PartialEq for DuressConsentSet {
    fn eq(&self, other: &Self) -> bool {
        let mut self_copied = self.duress_consent_set;
        let mut other_copied = other.duress_consent_set;
        self_copied.sort();
        other_copied.sort();
        self_copied == other_copied
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuressPlaceholderContent {
    inner: [u8; 32],
}

impl DuressPlaceholderContent {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        DuressPlaceholderContent { inner: bytes }
    }

    pub fn is_all_zeros(&self) -> bool {
        self.inner == [0u8; 32]
    }

    pub fn to_doxing_key(self) -> SymmetricKey {
        SymmetricKey::from_bytes(&self.inner)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.inner
    }

    pub fn encrypt(
        &self,
        symmetric_key: &SymmetricKey,
    ) -> Result<DuressPlaceholder, DuressPlaceholderContentEncryptionError> {
        Ok(DuressPlaceholder::new(
            Cryptography::symmetric_encrypt(&self.inner, symmetric_key)
                .map_err(DuressPlaceholderContentEncryptionError::SymmetricEncryption)?,
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DuressPlaceholder {
    inner: SymmetricCiphertext,
}

impl DuressPlaceholder {
    pub(self) fn new(inner: SymmetricCiphertext) -> Self {
        DuressPlaceholder { inner }
    }

    pub fn decrypt(
        &self,
        symmetric_key: &SymmetricKey,
    ) -> Result<DuressPlaceholderContent, DuressPlaceholderDecryptionError> {
        let duress_placeholder_content_bytes =
            Cryptography::symmetric_decrypt::<[u8; 32]>(&self.inner, symmetric_key)
                .map_err(DuressPlaceholderDecryptionError::SymmetricDecryption)?;

        Ok(DuressPlaceholderContent::from_bytes(
            duress_placeholder_content_bytes,
        ))
    }

    pub fn get_iv(&self) -> &[u8; 16] {
        self.inner.get_iv()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DuressPadded<T: Serialize> {
    data: T,
    duress_padding: BTreeMap<SarId, DuressPlaceholder>,
}

impl<T: Serialize> DuressPadded<T> {
    pub fn new(data: T, duress_padding: BTreeMap<SarId, DuressPlaceholder>) -> Self {
        DuressPadded {
            data,
            duress_padding,
        }
    }

    pub fn into_parts(self) -> (T, BTreeMap<SarId, DuressPlaceholder>) {
        (self.data, self.duress_padding)
    }
}

#[derive(Debug, Display, Error)]
pub enum DuressPlaceholderContentEncryptionError {
    SymmetricEncryption(CryptographySymmetricEncryptionError),
}

#[derive(Debug, Display, Error)]
pub enum DuressPlaceholderDecryptionError {
    SymmetricDecryption(CryptographySymmetricDecryptionError),
}
