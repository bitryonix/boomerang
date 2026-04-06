//! Result helpers for the legacy PoC scripts.
//!
//! These scripts are long, linear scenario drivers. This helper converts legacy `Option` and
//! `Result` values into the crate's boxed error shape so the flows can propagate failures instead
//! of aborting with `unwrap()`.

use std::{error::Error, fmt::Debug, io};

/// Shared boxed error type used by the legacy PoC step runners.
pub(crate) type PocStepsResult<T> = Result<T, Box<dyn Error>>;

/// Converts legacy `Option` and `Result` values into [`PocStepsResult`].
pub(crate) trait OrErr<T> {
    /// Lifts the wrapped value into [`PocStepsResult`], producing a generic invariant error when
    /// the value is absent or failed.
    fn or_err(self) -> PocStepsResult<T>;
}

impl<T> OrErr<T> for Option<T> {
    fn or_err(self) -> PocStepsResult<T> {
        self.ok_or_else(|| io::Error::other("legacy PoC flow encountered missing state").into())
    }
}

impl<T, E> OrErr<T> for Result<T, E>
where
    E: Debug + Send + Sync + 'static,
{
    fn or_err(self) -> PocStepsResult<T> {
        self.map_err(|err| io::Error::other(format!("{err:?}")).into())
    }
}
