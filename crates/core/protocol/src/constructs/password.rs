use std::ops::Deref;

use rand::distr::{Alphanumeric, SampleString};
use secrecy::{ExposeSecret, SecretString, SerializableSecret};
use serde::{Deserialize, Serialize, Serializer};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Password {
    #[serde(serialize_with = "secret_serializer")]
    inner: SecretString,
}

impl Password {
    pub fn new(password_string: String) -> Self {
        Password {
            inner: SecretString::new(password_string.into_boxed_str()),
        }
    }

    pub fn new_random() -> Self {
        let password_string = Alphanumeric.sample_string(&mut rand::rng(), 32);
        Password {
            inner: SecretString::new(password_string.into_boxed_str()),
        }
    }
}

impl SerializableSecret for Password {}

impl Deref for Password {
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
