//! Wire-only control payloads shared by transport and runtime layers.

mod hello;
mod roles;
mod state;
mod wrappers;

pub use hello::{TransportHello, TransportReady, TransportResetState};
pub use roles::TransportRole;
pub use state::{NisoStateSnapshot, QueryNisoState};
pub use wrappers::{
    SetupNisoPeerNisoParcel1, SetupNisoPeerNisoParcel2, SetupNisoPeerNisoParcel3,
    SetupNisoPeerNisoParcel4,
};
