//! Execution authorisation v3 (unified update lifecycle, L2): change the
//! RUNTIME IMAGE a deployment unit runs, and nothing else.
//!
//! A NEW schema, never a v1/v2 variant (P5-R4): a designer built before v3
//! refuses its payload type, where a v1 `update` carrying a changed
//! `target.runtime_image_digest` would be executed as an application update
//! of the same bundle and reported healthy without the runtime moving.
//!
//! Every unit keeps its bundle and its configuration: `target.bundle_digest`
//! and `target.overrides_digest` must equal the expected baseline's. Both
//! runtime digests are required and must differ. Shares v1/v2's monotonic
//! `sequence` stream per `(installation_id, environment_id)`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::execution::{CommonFields, TrafficPolicy, UnitTarget, ValidationError, validate_common};
use crate::execution_v2::VerifiedAuthorisation;

pub const EXECUTION_AUTHORISATION_V3_SCHEMA: &str = "greentic.execution-authorisation.v3";
pub const EXECUTION_AUTHORISATION_V3_PAYLOAD_TYPE: &str =
    "application/vnd.greentic.execution-authorisation.v3+json";

/// No `#[serde(other)]`: an unknown operation fails to parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecOperationV3 {
    /// Move the unit from `expected_baseline.runtime_image_digest` to
    /// `target.runtime_image_digest`.
    RuntimeUpdate,
    /// Return the unit to the runtime it ran before a runtime update:
    /// `target` is that update's `expected_baseline` runtime; the bundle is
    /// whatever the unit runs now (`expected_baseline`).
    RuntimeRollback,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionAuthorisationV3 {
    pub schema: String,
    pub authorisation_id: String,
    pub installation_id: String,
    pub tenant_id: String,
    pub environment_id: String,
    pub rollout_id: String,
    pub release_id: String,
    /// The PLATFORM release's catalogue digest.
    pub release_digest: String,
    pub operation: ExecOperationV3,
    pub units: Vec<UnitTarget>,
    pub policy_generation: u64,
    pub sequence: u64,
    pub fence: i64,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub traffic: TrafficPolicy,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValidationErrorV3 {
    /// A field every schema version shares failed the common checks.
    Common(ValidationError),
    /// The named unit's target bundle differs from its expected baseline.
    BundleChanged(String),
    /// The named unit's target configuration differs from its baseline.
    OverridesChanged(String),
    /// The named unit runs no bundle, so has no runtime to change.
    NothingDeployed(String),
    /// The named unit lacks an expected or a target runtime digest.
    RuntimeMissing(String),
    /// The named unit names the same runtime on both sides.
    RuntimeUnchanged(String),
}

impl std::fmt::Display for ValidationErrorV3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Common(e) => write!(f, "v3 authorisation: {e}"),
            Self::BundleChanged(u) => write!(
                f,
                "v3 unit `{u}` changes its bundle; a runtime change keeps it"
            ),
            Self::OverridesChanged(u) => write!(
                f,
                "v3 unit `{u}` changes its configuration; a runtime change keeps it"
            ),
            Self::NothingDeployed(u) => write!(
                f,
                "v3 unit `{u}` runs no bundle; there is no runtime to change"
            ),
            Self::RuntimeMissing(u) => write!(
                f,
                "v3 unit `{u}` lacks an expected or target runtime digest"
            ),
            Self::RuntimeUnchanged(u) => {
                write!(f, "v3 unit `{u}` names the same runtime on both sides")
            }
        }
    }
}

impl std::error::Error for ValidationErrorV3 {}

impl From<ValidationError> for ValidationErrorV3 {
    fn from(e: ValidationError) -> Self {
        Self::Common(e)
    }
}

impl ExecutionAuthorisationV3 {
    pub fn validate(&self) -> Result<(), ValidationErrorV3> {
        validate_common(&CommonFields {
            expected_schema: EXECUTION_AUTHORISATION_V3_SCHEMA,
            schema: &self.schema,
            ids: [
                (&self.authorisation_id, "authorisation_id"),
                (&self.installation_id, "installation_id"),
                (&self.tenant_id, "tenant_id"),
                (&self.environment_id, "environment_id"),
                (&self.rollout_id, "rollout_id"),
                (&self.release_id, "release_id"),
            ],
            release_digest: &self.release_digest,
            units: &self.units,
            // The bundle rule below is stricter than "target present".
            require_target_digest: false,
            not_before: self.not_before,
            expires_at: self.expires_at,
            traffic: &self.traffic,
        })?;
        for unit in &self.units {
            let (e, t, id) = (&unit.expected_baseline, &unit.target, &unit.unit_id);
            if e.bundle_digest.is_none() {
                return Err(ValidationErrorV3::NothingDeployed(id.clone()));
            }
            if t.bundle_digest != e.bundle_digest {
                return Err(ValidationErrorV3::BundleChanged(id.clone()));
            }
            if t.overrides_digest != e.overrides_digest {
                return Err(ValidationErrorV3::OverridesChanged(id.clone()));
            }
            match (&e.runtime_image_digest, &t.runtime_image_digest) {
                (Some(a), Some(b)) if a == b => {
                    return Err(ValidationErrorV3::RuntimeUnchanged(id.clone()));
                }
                (Some(_), Some(_)) => {}
                _ => return Err(ValidationErrorV3::RuntimeMissing(id.clone())),
            }
        }
        Ok(())
    }
}

/// A verified authorisation of ANY schema version. A receiver matching on it
/// must REFUSE its wildcard arm, never execute it.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum VerifiedAny {
    Change(VerifiedAuthorisation),
    Runtime(ExecutionAuthorisationV3),
}

macro_rules! delegate_ref {
    ($($name:ident),* $(,)?) => {$(
        pub fn $name(&self) -> &str {
            match self {
                Self::Change(a) => a.$name(),
                Self::Runtime(a) => &a.$name,
            }
        }
    )*};
}

impl VerifiedAny {
    delegate_ref!(authorisation_id, installation_id, tenant_id, environment_id);

    /// v1, v2 and v3 share ONE sequence stream per
    /// `(installation_id, environment_id)`; replay checks key on this.
    pub fn sequence(&self) -> u64 {
        match self {
            Self::Change(a) => a.sequence(),
            Self::Runtime(a) => a.sequence,
        }
    }

    pub fn fence(&self) -> i64 {
        match self {
            Self::Change(a) => a.fence(),
            Self::Runtime(a) => a.fence,
        }
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        match self {
            Self::Change(a) => a.expires_at(),
            Self::Runtime(a) => a.expires_at,
        }
    }
}

#[cfg(feature = "signing")]
#[path = "execution_v3_sign.rs"]
mod sign;
#[cfg(feature = "signing")]
pub use sign::{SignV3Error, sign_v3, verify_any_v3, verify_v3};

#[cfg(test)]
#[path = "execution_v3_tests.rs"]
pub(crate) mod tests;
