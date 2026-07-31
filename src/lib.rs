//! Wire types for the Greentic admin → designer deploy and environment seam.
//!
//! This crate is types and serde only: no HTTP client, no database, no async.
//! The designer's `admin/client` already owns retry, auth and its own error
//! taxonomy, and a contract that also shipped a client would be claiming those
//! policies for both consumers.
#![forbid(unsafe_code)]

mod enums;
mod timestamp;

pub use enums::{DeployTarget, EnvStatus, JobStatus};
pub use timestamp::parse_lenient;
