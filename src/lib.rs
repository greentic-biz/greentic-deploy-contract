//! Wire types for the Greentic admin ↔ designer deploy, environment and release seam.
//!
//! This crate is types and serde only: no HTTP client, no database, no async.
//! The designer's `admin/client` already owns retry, auth and its own error
//! taxonomy, and a contract that also shipped a client would be claiming those
//! policies for both consumers.
//!
//! One exception, behind the opt-in cargo feature `signing`: the DSSE
//! Ed25519 sign/verify functions (generic k-of-n `dsse::sign_bytes` /
//! `dsse::verify_bytes`, and the execution-authorisation wrappers
//! `dsse::sign`, `dsse::verify`, plus `dsse::parse_trusted_keys`). They
//! live here so the admin (signer) and the designer (verifier) cannot
//! disagree about the bytes a signature covers. Without the feature, the
//! envelope type and [`dsse::pae`] are still available.
//!
//! The same feature adds the typed `sign_*` / `verify_*` pairs of the other
//! signed schemas (offline release envelope, trust rotation, revocation list,
//! status report), all built on the generic core through the `signed` module. Their
//! types and `validate()` need no feature.
#![forbid(unsafe_code)]

mod enums;
mod timestamp;
mod types;

pub use enums::{DeployTarget, EnvStatus, JobStatus};
pub use timestamp::parse_lenient;
pub use types::{DeploymentJob, EnvListItem, EnvOrigin, RunnerStatus};

/// The largest `sequence` any signed stream in this crate accepts (trust
/// rotations, revocation lists, status reports): 2^53 - 1, the largest
/// integer every JSON consumer reads exactly. A stream that reached
/// `u64::MAX` could never advance again (`sequence > last` is then
/// unsatisfiable), so one buggy or compromised statement would freeze it
/// for good; capping well below that keeps every stream advanceable.
pub const MAX_SEQUENCE: u64 = (1 << 53) - 1;

pub mod capabilities;
pub mod dsse;
pub mod execution;
pub mod execution_v2;
pub mod execution_v3;
pub mod governance;
pub mod health;
pub mod inventory;
pub mod migration;
pub mod offline;
pub mod release;
pub mod release_runtime;
pub mod revocation;
#[cfg(feature = "signing")]
pub mod signed;
pub mod status;
pub mod trust;
