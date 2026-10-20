//! Execution authorisation v4: v2 plus the RELEASE CHANNEL the authorisation
//! was issued under.
//!
//! A NEW schema with a NEW DSSE payload type, never a field added to v2: a
//! signed schema is never changed, and a designer built before v4 refuses the
//! payload type outright (`WrongPayloadType` from `verify_any` and
//! `verify_any_v3`), so a channel-scoped instruction can never be executed by
//! a verifier that cannot check the channel.
//!
//! Operations, ids, units, traffic policy and validation are v2's, applied by
//! the same code ([`ExecutionAuthorisationV2::validate`]). The one addition is
//! [`ReleaseChannel`], covered by the signature like every other field.
//! Shares v1/v2/v3's monotonic `sequence` stream per
//! `(installation_id, environment_id)`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::execution::{TrafficPolicy, UnitTarget};
use crate::execution_v2::{ExecOperationV2, ExecutionAuthorisationV2, ValidationErrorV2};

pub const EXECUTION_AUTHORISATION_V4_SCHEMA: &str = "greentic.execution-authorisation.v4";
pub const EXECUTION_AUTHORISATION_V4_PAYLOAD_TYPE: &str =
    "application/vnd.greentic.execution-authorisation.v4+json";

/// The release channel an authorisation was issued under. A closed set: no
/// `#[serde(other)]`, so an unknown channel fails to parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseChannel {
    Stable,
    Dev,
}

impl ReleaseChannel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Dev => "dev",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionAuthorisationV4 {
    pub schema: String,
    pub authorisation_id: String,
    pub installation_id: String,
    pub tenant_id: String,
    pub environment_id: String,
    pub rollout_id: String,
    pub release_id: String,
    /// `sha256:<64 lowercase hex>`.
    pub release_digest: String,
    /// The channel the release was issued under; a receiver checks it
    /// against the channel its installation follows.
    pub channel: ReleaseChannel,
    pub operation: ExecOperationV2,
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
pub enum ValidationErrorV4 {
    /// The `schema` field is not [`EXECUTION_AUTHORISATION_V4_SCHEMA`].
    WrongSchema,
    /// A rule v2 applies (and v4 shares) failed.
    Shared(ValidationErrorV2),
}

impl std::fmt::Display for ValidationErrorV4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongSchema => write!(
                f,
                "v4 authorisation: schema must be `{EXECUTION_AUTHORISATION_V4_SCHEMA}`"
            ),
            Self::Shared(e) => write!(f, "v4 authorisation: {e}"),
        }
    }
}

impl std::error::Error for ValidationErrorV4 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Shared(e) => Some(e),
            Self::WrongSchema => None,
        }
    }
}

impl From<ValidationErrorV2> for ValidationErrorV4 {
    fn from(e: ValidationErrorV2) -> Self {
        Self::Shared(e)
    }
}

impl ExecutionAuthorisationV4 {
    /// Everything v4 shares with v2, as a v2 value, so one function judges
    /// both and the rules cannot drift.
    fn as_v2(&self) -> ExecutionAuthorisationV2 {
        ExecutionAuthorisationV2 {
            schema: crate::execution_v2::EXECUTION_AUTHORISATION_V2_SCHEMA.to_string(),
            authorisation_id: self.authorisation_id.clone(),
            installation_id: self.installation_id.clone(),
            tenant_id: self.tenant_id.clone(),
            environment_id: self.environment_id.clone(),
            rollout_id: self.rollout_id.clone(),
            release_id: self.release_id.clone(),
            release_digest: self.release_digest.clone(),
            operation: self.operation,
            units: self.units.clone(),
            policy_generation: self.policy_generation,
            sequence: self.sequence,
            fence: self.fence,
            not_before: self.not_before,
            expires_at: self.expires_at,
            traffic: self.traffic.clone(),
        }
    }

    /// Refuse an authorisation malformed on its own terms. Time admission
    /// and the channel comparison are the receiver's checks.
    pub fn validate(&self) -> Result<(), ValidationErrorV4> {
        if self.schema != EXECUTION_AUTHORISATION_V4_SCHEMA {
            return Err(ValidationErrorV4::WrongSchema);
        }
        self.as_v2().validate()?;
        Ok(())
    }
}

#[cfg(feature = "signing")]
#[path = "execution_v4_sign.rs"]
mod sign;
#[cfg(feature = "signing")]
pub use sign::{SignV4Error, sign_v4, verify_any_v4, verify_v4};

#[cfg(test)]
#[path = "execution_v4_tests.rs"]
pub(crate) mod tests;
