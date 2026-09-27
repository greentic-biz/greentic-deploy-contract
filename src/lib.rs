//! Wire types for the Greentic admin ↔ designer deploy, environment and release seam.
//!
//! This crate is types and serde only: no HTTP client, no database, no async.
//! The designer's `admin/client` already owns retry, auth and its own error
//! taxonomy, and a contract that also shipped a client would be claiming those
//! policies for both consumers.
//!
//! One exception, behind the opt-in cargo feature `signing`: the DSSE
//! Ed25519 sign/verify functions for execution authorisations
//! (`dsse::sign`, `dsse::verify`, `dsse::parse_trusted_keys`). They
//! live here so the admin (signer) and the designer (verifier) cannot
//! disagree about the bytes a signature covers. Without the feature, the
//! envelope type and [`dsse::pae`] are still available.
#![forbid(unsafe_code)]

mod enums;
mod timestamp;
mod types;

pub use enums::{DeployTarget, EnvStatus, JobStatus};
pub use timestamp::parse_lenient;
pub use types::{DeploymentJob, EnvListItem, EnvOrigin, RunnerStatus};

pub mod dsse;
pub mod execution;
pub mod governance;
pub mod health;
pub mod inventory;
pub mod release;
