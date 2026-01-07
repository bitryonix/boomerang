use std::ops::Deref;

use rand::distr::{Alphanumeric, SampleString};
use secrecy::{ExposeSecret, SecretString, SerializableSecret};
use serde::{Deserialize, Serialize, Serializer};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Passphrase {
    #[serde(serialize_with = "secret_serializer")]
    inner: SecretString,
}

impl Passphrase {
    pub fn new(passphrase_string: String) -> Self {
        Passphrase {
            inner: SecretString::new(passphrase_string.into_boxed_str()),
        }
    }

    pub fn new_random() -> Self {
        let passphrase_string = Alphanumeric.sample_string(&mut rand::rng(), 32);
        Passphrase {
            inner: SecretString::new(passphrase_string.into_boxed_str()),
        }
    }
}

impl SerializableSecret for Passphrase {}

impl Deref for Passphrase {
    type Target = SecretString;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

fn secret_serializer<S: Serializer>(
    secret: &SecretString,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(secret.expose_secret())
}
