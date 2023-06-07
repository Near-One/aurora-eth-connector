#![deny(clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

#[cfg(test)]
mod connector;
#[cfg(all(test, feature = "migration-tests"))]
mod migration;
#[cfg(test)]
pub mod utils;

#[cfg(test)]
pub mod fee_management;
