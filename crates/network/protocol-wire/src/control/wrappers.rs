//! Wire wrappers for parcel-shaped control payloads.

use protocol::{
    constructs::PeerId,
    messages::{
        Parcel,
        setup::from_niso::to_niso::{
            SetupNisoPeerNisoMessage1, SetupNisoPeerNisoMessage2, SetupNisoPeerNisoMessage3,
            SetupNisoPeerNisoMessage4,
        },
    },
};
use serde::{Deserialize, Serialize};

/// Wraps one typed parcel carrying `SetupNisoPeerNisoMessage1` values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupNisoPeerNisoParcel1 {
    parcel: Parcel<PeerId, SetupNisoPeerNisoMessage1>,
}

impl SetupNisoPeerNisoParcel1 {
    /// Creates the parcel wrapper consumed by wire codecs and runtimes.
    pub fn new(parcel: Parcel<PeerId, SetupNisoPeerNisoMessage1>) -> Self {
        Self { parcel }
    }

    /// Extracts the wrapped parcel.
    pub fn into_inner(self) -> Parcel<PeerId, SetupNisoPeerNisoMessage1> {
        self.parcel
    }
}

/// Wraps one typed parcel carrying `SetupNisoPeerNisoMessage2` values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupNisoPeerNisoParcel2 {
    parcel: Parcel<PeerId, SetupNisoPeerNisoMessage2>,
}

impl SetupNisoPeerNisoParcel2 {
    /// Creates the parcel wrapper consumed by wire codecs and runtimes.
    pub fn new(parcel: Parcel<PeerId, SetupNisoPeerNisoMessage2>) -> Self {
        Self { parcel }
    }

    /// Extracts the wrapped parcel.
    pub fn into_inner(self) -> Parcel<PeerId, SetupNisoPeerNisoMessage2> {
        self.parcel
    }
}

/// Wraps one typed parcel carrying `SetupNisoPeerNisoMessage3` values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupNisoPeerNisoParcel3 {
    parcel: Parcel<PeerId, SetupNisoPeerNisoMessage3>,
}

impl SetupNisoPeerNisoParcel3 {
    /// Creates the parcel wrapper consumed by wire codecs and runtimes.
    pub fn new(parcel: Parcel<PeerId, SetupNisoPeerNisoMessage3>) -> Self {
        Self { parcel }
    }

    /// Extracts the wrapped parcel.
    pub fn into_inner(self) -> Parcel<PeerId, SetupNisoPeerNisoMessage3> {
        self.parcel
    }
}

/// Wraps one typed parcel carrying `SetupNisoPeerNisoMessage4` values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupNisoPeerNisoParcel4 {
    parcel: Parcel<PeerId, SetupNisoPeerNisoMessage4>,
}

impl SetupNisoPeerNisoParcel4 {
    /// Creates the parcel wrapper consumed by wire codecs and runtimes.
    pub fn new(parcel: Parcel<PeerId, SetupNisoPeerNisoMessage4>) -> Self {
        Self { parcel }
    }

    /// Extracts the wrapped parcel.
    pub fn into_inner(self) -> Parcel<PeerId, SetupNisoPeerNisoMessage4> {
        self.parcel
    }
}
