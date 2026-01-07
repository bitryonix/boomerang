use std::path::PathBuf;

use bitcoincore_rpc::Auth;
use serde::{Deserialize, Serialize};

/// Wrapper around bitcoincore_rpc::Auth to implement (derive) Serialize and Deserialize traits for.
#[derive(Clone, Debug, Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub enum BitcoinCoreAuth {
    None,
    UserPass(String, String),
    CookieFile(PathBuf),
}

impl From<BitcoinCoreAuth> for Auth {
    fn from(value: BitcoinCoreAuth) -> Auth {
        match value {
            BitcoinCoreAuth::None => Auth::None,
            BitcoinCoreAuth::UserPass(user, pass) => Auth::UserPass(user, pass),
            BitcoinCoreAuth::CookieFile(path_buf) => Auth::CookieFile(path_buf),
        }
    }
}
