//! Execution authorisation v2 (unified update lifecycle, phase 5, P5-R4).
//!
//! v2 is v1 plus ONE capability: [`ExecOperationV2::Remove`], an explicit,
//! authorised removal of deployment units. It is a NEW schema with a NEW
//! DSSE payload type rather than a new variant on v1's [`ExecOperation`]:
//! a signed schema is never changed, and adding `remove` to v1 would make
//! every existing v1 verifier's refusal of it (an unknown operation fails to
//! parse) silently turn into acceptance on a rebuilt one.
//!
//! Every field besides `schema` and `operation` has v1's name, type and
//! meaning, and is validated by the same function
//! ([`crate::execution::validate_common`]), so the two versions cannot drift
//! apart on the rules they share.
//!
//! Omission is never deletion (P5-R1): a unit missing from an `update` is
//! left untouched. Only a `remove` authorisation removes, and removal is a
//! sequence — clear the split, drain for `drain_seconds`, archive, remove —
//! whose data is always preserved under retention (P5-R2, [`DataDisposition`]).
//!
//! A receiver that accepts both versions uses [`VerifiedAuthorisation`] (and,
//! with the `signing` feature, `verify_any`), which dispatches on the DSSE
//! payload type only AFTER the signature over that type has verified.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::execution::{
    CommonFields, ExecOperation, ExecutionAuthorisation, TrafficPolicy, UnitBaseline, UnitTarget,
    ValidationError, validate_common,
};

/// The `schema` value every v2 authorisation carries.
pub const EXECUTION_AUTHORISATION_V2_SCHEMA: &str = "greentic.execution-authorisation.v2";

/// The DSSE `payloadType` a v2 authorisation is signed under.
pub const EXECUTION_AUTHORISATION_V2_PAYLOAD_TYPE: &str =
    "application/vnd.greentic.execution-authorisation.v2+json";

/// The longest drain a `remove` may ask for, in seconds (one hour). A drain
/// longer than this outlives most authorisation windows' useful life and
/// keeps a retiring revision serving for no stated reason.
pub const MAX_DRAIN_SECONDS: u32 = 3600;

/// What a v2 authorisation asks the designer to do.
///
/// Serialises as `"update"`, `"rollback"`, or
/// `{"remove": {"data": "retain", "drain_seconds": ..}}`. No
/// `#[serde(other)]`: an operation this build does not know fails to parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecOperationV2 {
    Update,
    Rollback,
    /// Retire the listed units: clear their traffic split, drain for
    /// `drain_seconds`, archive, then remove.
    Remove {
        /// What happens to the units' data. Always [`DataDisposition::Retain`]
        /// in v2.
        data: DataDisposition,
        /// How long to wait for in-flight work after traffic is cleared,
        /// `0..=`[`MAX_DRAIN_SECONDS`]. `0` means "clear the split and retire
        /// with no wait" — the drain step of the sequence is then a no-op.
        drain_seconds: u32,
    },
}

/// What a removal does with the removed units' data.
///
/// Only [`Self::Retain`] exists, on purpose: a boolean here would let an
/// executor read `false` as "delete". Destroying data is a SEPARATE, future,
/// separately authorised workflow (P5-R2) with its own schema; it will never
/// be expressed by adding a variant a v2 signer could already mint. No
/// `#[serde(other)]`: an unknown disposition fails to parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataDisposition {
    /// Keep the data under the environment's retention policy.
    Retain,
}

impl From<ExecOperation> for ExecOperationV2 {
    fn from(op: ExecOperation) -> Self {
        match op {
            ExecOperation::Update => Self::Update,
            ExecOperation::Rollback => Self::Rollback,
        }
    }
}

/// The admin's signed v2 instruction. Field-for-field v1 except `schema`
/// (always [`EXECUTION_AUTHORISATION_V2_SCHEMA`]) and `operation`.
///
/// For a `remove`, each unit's `expected_baseline` is what is running now
/// (a `bundle_digest` is required: a unit that was never deployed cannot be
/// removed), `target` is empty (every digest `None`), and `traffic.steps`
/// is exactly `[100]` — a removal splits nothing, and a percentage "removal"
/// would imply a split no executor runs.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionAuthorisationV2 {
    pub schema: String,
    pub authorisation_id: String,
    pub installation_id: String,
    pub tenant_id: String,
    pub environment_id: String,
    pub rollout_id: String,
    pub release_id: String,
    /// `sha256:<64 lowercase hex>`.
    pub release_digest: String,
    pub operation: ExecOperationV2,
    pub units: Vec<UnitTarget>,
    pub policy_generation: u64,
    /// Shares v1's monotonic stream per `(installation_id, environment_id)`.
    pub sequence: u64,
    pub fence: i64,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub traffic: TrafficPolicy,
}

/// Why an [`ExecutionAuthorisationV2`] refuses to validate.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValidationErrorV2 {
    /// A rule v1 and v2 share.
    Common(ValidationError),
    /// A `remove` unit carries a target digest; carries the unit id.
    RemoveTargetNotEmpty(String),
    /// A `remove` unit has no `expected_baseline.bundle_digest`; carries the
    /// unit id.
    RemoveNothingDeployed(String),
    /// `drain_seconds` exceeds [`MAX_DRAIN_SECONDS`].
    DrainTooLong,
    /// A `remove` whose `traffic.steps` is not exactly `[100]`.
    RemoveTrafficSplit,
}

impl std::fmt::Display for ValidationErrorV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Common(e) => write!(f, "v2 authorisation: {e}"),
            Self::RemoveTargetNotEmpty(u) => {
                write!(f, "v2 remove unit `{u}` names a target; a removal has none")
            }
            Self::RemoveNothingDeployed(u) => write!(
                f,
                "v2 remove unit `{u}` has no expected bundle_digest; nothing deployed can be removed"
            ),
            Self::DrainTooLong => {
                write!(f, "v2 remove: drain_seconds exceeds {MAX_DRAIN_SECONDS}")
            }
            Self::RemoveTrafficSplit => {
                f.write_str("v2 remove: traffic steps must be exactly [100]")
            }
        }
    }
}

impl std::error::Error for ValidationErrorV2 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Common(e) => Some(e),
            _ => None,
        }
    }
}

impl From<ValidationError> for ValidationErrorV2 {
    fn from(e: ValidationError) -> Self {
        Self::Common(e)
    }
}

impl ExecutionAuthorisationV2 {
    /// Refuse an authorisation that is malformed on its own terms. As in v1,
    /// time ADMISSION is the receiver's check.
    pub fn validate(&self) -> Result<(), ValidationErrorV2> {
        validate_common(&CommonFields {
            expected_schema: EXECUTION_AUTHORISATION_V2_SCHEMA,
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
            require_target_digest: self.operation == ExecOperationV2::Update,
            not_before: self.not_before,
            expires_at: self.expires_at,
            traffic: &self.traffic,
        })?;
        if let ExecOperationV2::Remove { drain_seconds, .. } = self.operation {
            if drain_seconds > MAX_DRAIN_SECONDS {
                return Err(ValidationErrorV2::DrainTooLong);
            }
            if self.traffic.steps != [100] {
                return Err(ValidationErrorV2::RemoveTrafficSplit);
            }
            for unit in &self.units {
                if unit.expected_baseline.bundle_digest.is_none() {
                    return Err(ValidationErrorV2::RemoveNothingDeployed(
                        unit.unit_id.clone(),
                    ));
                }
                if unit.target != UnitBaseline::default() {
                    return Err(ValidationErrorV2::RemoveTargetNotEmpty(
                        unit.unit_id.clone(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// A verified authorisation of either schema version. The accessors read the
/// fields both versions share; [`Self::operation`] maps v1's operation into
/// the v2 vocabulary, so a receiver matches on one enum.
///
/// `#[non_exhaustive]`: a v3 adds a variant without breaking consumers,
/// whose wildcard arm must REFUSE, never execute.
///
/// v1 and v2 share ONE sequence stream per `(installation_id,
/// environment_id)`: a receiver's replay check must key on
/// [`Self::sequence`] regardless of version.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum VerifiedAuthorisation {
    V1(ExecutionAuthorisation),
    V2(ExecutionAuthorisationV2),
}

macro_rules! shared_ref {
    ($($name:ident: $ty:ty),* $(,)?) => {$(
        pub fn $name(&self) -> &$ty {
            match self {
                Self::V1(a) => &a.$name,
                Self::V2(a) => &a.$name,
            }
        }
    )*};
}

macro_rules! shared_copy {
    ($($name:ident: $ty:ty),* $(,)?) => {$(
        pub fn $name(&self) -> $ty {
            match self {
                Self::V1(a) => a.$name,
                Self::V2(a) => a.$name,
            }
        }
    )*};
}

impl VerifiedAuthorisation {
    shared_ref!(
        schema: str,
        authorisation_id: str,
        installation_id: str,
        tenant_id: str,
        environment_id: str,
        rollout_id: str,
        release_id: str,
        release_digest: str,
        units: [UnitTarget],
        traffic: TrafficPolicy,
    );
    shared_copy!(
        policy_generation: u64,
        sequence: u64,
        fence: i64,
        not_before: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    );

    /// The operation, in the v2 vocabulary. A v1 authorisation is never a
    /// `Remove`.
    pub fn operation(&self) -> ExecOperationV2 {
        match self {
            Self::V1(a) => a.operation.into(),
            Self::V2(a) => a.operation,
        }
    }

    /// `1` or `2`.
    pub fn schema_version(&self) -> u8 {
        match self {
            Self::V1(_) => 1,
            Self::V2(_) => 2,
        }
    }
}

#[cfg(feature = "signing")]
#[path = "execution_v2_sign.rs"]
mod sign;
#[cfg(feature = "signing")]
pub use sign::{SignV2Error, sign_v2, verify_any, verify_v2};

#[cfg(test)]
#[path = "execution_v2_tests.rs"]
pub(crate) mod tests;
