//! Error helpers for the legacy networked PoC runtime.
//!
//! The actor-based PoC predates the repository-wide error-handling policy. These helpers let the
//! legacy actors convert `Option` and `Result` values into a shared boxed error shape so failures
//! can bubble up through the task tree instead of aborting the process.

use std::{error::Error, fmt::Debug, io};

/// Shared boxed error type used by the legacy networked PoC runtime.
pub(crate) type NetworkedResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

/// Converts legacy `Option` and `Result` values into [`NetworkedResult`].
pub(crate) trait OrErr<T> {
    /// Lifts the wrapped value into [`NetworkedResult`].
    fn or_err(self) -> NetworkedResult<T>;
}

impl<T> OrErr<T> for Option<T> {
    fn or_err(self) -> NetworkedResult<T> {
        self.ok_or_else(|| {
            io::Error::other("legacy networked PoC encountered missing state").into()
        })
    }
}

impl<T, E> OrErr<T> for Result<T, E>
where
    E: Debug + Send + Sync + 'static,
{
    fn or_err(self) -> NetworkedResult<T> {
        self.map_err(|err| io::Error::other(format!("{err:?}")).into())
    }
}

/// Creates a boxed I/O error for an unexpected runtime condition.
pub(crate) fn unexpected<T>(message: impl Into<String>) -> NetworkedResult<T> {
    Err(io::Error::other(message.into()).into())
}
