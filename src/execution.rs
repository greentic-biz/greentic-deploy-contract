//! Execution authorisation v1 (unified update lifecycle, phase 2b).
//!
//! The admin issues an [`ExecutionAuthorisation`] — a signed instruction to
//! change specific deployment units from one recorded baseline to another —
//! and the designer verifies it (see [`crate::dsse`]) immediately before it
//! mutates anything. The designer reports progress back as
//! [`ExecutionCheckpoint`]s.
//!
//! **This is a NEW record type, not a revision of an existing one.** Signed
//! schemas are never mutated: a receiver refuses an unknown `schema` string,
//! and — because [`ExecOperation`] deliberately has no `#[serde(other)]`
//! catch-all — an unknown operation fails to parse rather than degrading to
//! something the sender did not ask for.
//!
//! The authorisation types are `deny_unknown_fields`. The signer and the
//! verifier must agree on every field the signature covers: a field this build
//! does not know is a field it cannot enforce, so a payload carrying one is
//! refused. A new field is a new schema, never an additive change to v1.

use std::collections::BTreeSet;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::health::UnitHealthReport;

/// The `schema` value every v1 authorisation carries.
pub const EXECUTION_AUTHORISATION_SCHEMA: &str = "greentic.execution-authorisation.v1";

/// The DSSE `payloadType` a v1 authorisation is signed under.
pub const EXECUTION_AUTHORISATION_PAYLOAD_TYPE: &str =
    "application/vnd.greentic.execution-authorisation.v1+json";

/// The longest window an authorisation may be valid for.
pub const MAX_VALIDITY: Duration = Duration::hours(24);

/// The longest [`ExecutionCheckpoint::detail`], in characters.
pub const MAX_CHECKPOINT_DETAIL_CHARS: usize = 2000;

/// The longest [`ExecutionCheckpoint::reason`] code, in bytes.
pub const MAX_CHECKPOINT_REASON_BYTES: usize = 128;

/// What the authorisation asks the designer to do.
///
/// No `#[serde(other)]` on purpose: an operation this build does not know
/// must fail to parse, never fall back to a default.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecOperation {
    Update,
    Rollback,
}

/// The digests that identify what a unit runs. Every present value is
/// `sha256:<64 lowercase hex>`.
///
/// In an `expected_baseline`, `None` means "this unit was not previously
/// deployed" — a unit that HAS a recorded digest does not match it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitBaseline {
    #[serde(default)]
    pub bundle_digest: Option<String>,
    #[serde(default)]
    pub runtime_image_digest: Option<String>,
    #[serde(default)]
    pub overrides_digest: Option<String>,
}

/// One unit the authorisation covers.
///
/// For an `update`, `target.bundle_digest` is the release artifact digest.
/// For a `rollback`, `target` is the recorded pre-change baseline, and
/// `expected_baseline` is the post-change state — so a newer release that
/// landed since makes the baseline check fail rather than being overwritten.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitTarget {
    pub unit_id: String,
    pub expected_baseline: UnitBaseline,
    pub target: UnitBaseline,
}

/// How traffic moves onto the new revision, in whole percents.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrafficPolicy {
    /// Strictly ascending, each in `1..=100`, ending at `100`.
    pub steps: Vec<u8>,
    /// How long a step waits for sufficient health evidence, `30..=3600`.
    pub step_wait_secs: u32,
    /// Largest `server_error_rate` a step may observe and still advance.
    pub max_error_rate: f64,
    /// On a breach, send traffic back automatically (else the unit ends in
    /// `recovery_required`).
    pub auto_rollback: bool,
}

/// The admin's signed instruction to change deployment units. See the module
/// doc for why it refuses unknown fields.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionAuthorisation {
    /// Always [`EXECUTION_AUTHORISATION_SCHEMA`].
    pub schema: String,
    /// The idempotency key the designer journals execution under.
    pub authorisation_id: String,
    pub installation_id: String,
    pub tenant_id: String,
    pub environment_id: String,
    pub rollout_id: String,
    pub release_id: String,
    /// `sha256:<64 lowercase hex>`.
    pub release_digest: String,
    pub operation: ExecOperation,
    /// Non-empty; `unit_id`s are unique.
    pub units: Vec<UnitTarget>,
    pub policy_generation: u64,
    /// Monotonic per `(installation_id, environment_id)`. A rollback gets a
    /// NEW, higher sequence, so a replayed authorisation is refused.
    pub sequence: u64,
    /// The rollout lease fence at issuance.
    pub fence: i64,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub traffic: TrafficPolicy,
}

/// Why an [`ExecutionAuthorisation`] refuses to validate. Nothing here
/// panics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidationError {
    /// `schema` is not [`EXECUTION_AUTHORISATION_SCHEMA`].
    UnknownSchema(String),
    /// A required identifier is empty; carries the field name.
    EmptyField(&'static str),
    /// An identifier has leading or trailing whitespace; carries the field
    /// name. Refused rather than trimmed, so `"a"` and `"a "` can never be
    /// two distinct units that a receiver later reads as one.
    BadIdentifier(&'static str),
    /// An `update` unit has no `target.bundle_digest`; carries the unit id.
    MissingTargetDigest(String),
    /// A digest is not `sha256:<64 lowercase hex>`; carries the field name.
    BadDigest(&'static str),
    NoUnits,
    DuplicateUnit(String),
    /// `expires_at` is not after `not_before`.
    WindowInverted,
    /// `expires_at - not_before` exceeds [`MAX_VALIDITY`].
    WindowTooLong,
    BadTrafficSteps,
    BadStepWait,
    BadMaxErrorRate,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownSchema(s) => write!(f, "unknown schema `{s}`"),
            Self::EmptyField(n) => write!(f, "`{n}` is empty"),
            Self::BadIdentifier(n) => write!(f, "`{n}` has leading or trailing whitespace"),
            Self::MissingTargetDigest(u) => {
                write!(f, "update unit `{u}` has no target bundle_digest")
            }
            Self::BadDigest(n) => write!(f, "`{n}` is not sha256:<64 lowercase hex>"),
            Self::NoUnits => f.write_str("the authorisation covers no units"),
            Self::DuplicateUnit(u) => write!(f, "unit `{u}` appears more than once"),
            Self::WindowInverted => f.write_str("expires_at is not after not_before"),
            Self::WindowTooLong => f.write_str("validity window exceeds 24 hours"),
            Self::BadTrafficSteps => f.write_str(
                "traffic steps must be non-empty, strictly ascending, each 1..=100, ending at 100",
            ),
            Self::BadStepWait => f.write_str("step_wait_secs must be in 30..=3600"),
            Self::BadMaxErrorRate => f.write_str("max_error_rate must be in 0.0..=1.0"),
        }
    }
}

impl std::error::Error for ValidationError {}

/// `sha256:` followed by exactly 64 LOWERCASE hex digits. Stricter than
/// [`crate::release::sha256_prefixed`], which normalises: a signed value is
/// compared byte for byte, so it must already be canonical.
pub fn is_sha256_digest(s: &str) -> bool {
    s.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn check_digest(value: &str, field: &'static str) -> Result<(), ValidationError> {
    if is_sha256_digest(value) {
        Ok(())
    } else {
        Err(ValidationError::BadDigest(field))
    }
}

/// Non-empty and free of leading/trailing whitespace — the identifier rule
/// every signed schema in this crate applies.
pub(crate) fn is_clean_identifier(s: &str) -> bool {
    !s.trim().is_empty() && s.trim() == s
}

/// A stable snake_case code: non-empty, `[a-z0-9_]`, at most
/// [`MAX_CHECKPOINT_REASON_BYTES`].
pub(crate) fn is_reason_code(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_CHECKPOINT_REASON_BYTES
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn check_non_empty(value: &str, field: &'static str) -> Result<(), ValidationError> {
    if value.trim().is_empty() {
        Err(ValidationError::EmptyField(field))
    } else if value.trim() != value {
        Err(ValidationError::BadIdentifier(field))
    } else {
        Ok(())
    }
}

impl UnitBaseline {
    fn validate(&self) -> Result<(), ValidationError> {
        let fields = [
            (&self.bundle_digest, "bundle_digest"),
            (&self.runtime_image_digest, "runtime_image_digest"),
            (&self.overrides_digest, "overrides_digest"),
        ];
        for (value, name) in fields {
            if let Some(v) = value {
                check_digest(v, name)?;
            }
        }
        Ok(())
    }
}

impl TrafficPolicy {
    /// Refuse a policy the executor could not follow. Never panics.
    pub fn validate(&self) -> Result<(), ValidationError> {
        let in_range = self.steps.iter().all(|s| (1..=100).contains(s));
        let ascending = self.steps.windows(2).all(|w| w[0] < w[1]);
        if !in_range || !ascending || self.steps.last() != Some(&100) {
            return Err(ValidationError::BadTrafficSteps);
        }
        if !(30..=3600).contains(&self.step_wait_secs) {
            return Err(ValidationError::BadStepWait);
        }
        // `contains` is false for NaN, so NaN is refused too.
        if !(0.0..=1.0).contains(&self.max_error_rate) {
            return Err(ValidationError::BadMaxErrorRate);
        }
        Ok(())
    }
}

impl ExecutionAuthorisation {
    /// Refuse an authorisation that is malformed on its own terms. Time
    /// ADMISSION (`not_before <= now < expires_at`) is the receiver's check,
    /// since this crate reads no clock; this only checks the window's shape.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.schema != EXECUTION_AUTHORISATION_SCHEMA {
            return Err(ValidationError::UnknownSchema(self.schema.clone()));
        }
        check_non_empty(&self.authorisation_id, "authorisation_id")?;
        check_non_empty(&self.installation_id, "installation_id")?;
        check_non_empty(&self.tenant_id, "tenant_id")?;
        check_non_empty(&self.environment_id, "environment_id")?;
        check_non_empty(&self.rollout_id, "rollout_id")?;
        check_non_empty(&self.release_id, "release_id")?;
        check_digest(&self.release_digest, "release_digest")?;
        if self.units.is_empty() {
            return Err(ValidationError::NoUnits);
        }
        let mut seen = BTreeSet::new();
        for unit in &self.units {
            check_non_empty(&unit.unit_id, "unit_id")?;
            if !seen.insert(unit.unit_id.as_str()) {
                return Err(ValidationError::DuplicateUnit(unit.unit_id.clone()));
            }
            unit.expected_baseline.validate()?;
            unit.target.validate()?;
            // An update's target IS the release artifact; a rollback's target
            // may legitimately be "not previously deployed" (`None`).
            if self.operation == ExecOperation::Update && unit.target.bundle_digest.is_none() {
                return Err(ValidationError::MissingTargetDigest(unit.unit_id.clone()));
            }
        }
        if self.expires_at <= self.not_before {
            return Err(ValidationError::WindowInverted);
        }
        if self.expires_at - self.not_before > MAX_VALIDITY {
            return Err(ValidationError::WindowTooLong);
        }
        self.traffic.validate()
    }
}

/// Where one unit's execution stands. Journalled by the designer; the admin
/// derives completion only from these plus health evidence.
///
/// `DesiredStateApplied` is NOT healthy: it means the change was applied,
/// not that the new revision was shown to work.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecState {
    Staged,
    Applying,
    DesiredStateApplied,
    Reconciling,
    Verifying,
    Healthy,
    RollbackPending,
    RollingBack,
    RolledBack,
    RecoveryRequired,
    /// Refused at admission; nothing was mutated.
    Rejected,
}

impl ExecState {
    /// A state no further checkpoint moves the unit out of.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Healthy | Self::RolledBack | Self::RecoveryRequired | Self::Rejected
        )
    }
}

/// One progress report for one unit of one authorisation, designer → admin.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExecutionCheckpoint {
    pub authorisation_id: String,
    pub unit_id: String,
    pub state: ExecState,
    /// The fence of the authorisation being executed; the admin refuses a
    /// checkpoint whose fence is older than the lease's current one.
    pub fence: i64,
    /// The candidate revision's share of traffic, `0..=100`.
    #[serde(default)]
    pub traffic_percent: Option<u8>,
    /// A stable snake_case code (`baseline_changed`, `insufficient_evidence`, …),
    /// at most [`MAX_CHECKPOINT_REASON_BYTES`].
    #[serde(default)]
    pub reason: Option<String>,
    /// A sentence for the operator, at most [`MAX_CHECKPOINT_DETAIL_CHARS`].
    /// Never carries secret material.
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub observed_revision: Option<String>,
    #[serde(default)]
    pub health: Option<UnitHealthReport>,
    /// Monotonic per `(authorisation_id, unit_id)`.
    pub seq: u32,
    pub recorded_at: DateTime<Utc>,
}

/// Why an [`ExecutionCheckpoint`] refuses to validate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckpointError {
    EmptyField(&'static str),
    TrafficPercentOutOfRange,
    /// `reason` is not a non-empty `[a-z0-9_]` code of at most
    /// [`MAX_CHECKPOINT_REASON_BYTES`].
    BadReason,
    DetailTooLong,
    /// `health.unit_id` names a different unit than the checkpoint.
    HealthUnitMismatch,
    Health(crate::health::UnitHealthReportError),
}

impl std::fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyField(n) => write!(f, "`{n}` is empty"),
            Self::TrafficPercentOutOfRange => f.write_str("traffic_percent exceeds 100"),
            Self::BadReason => {
                f.write_str("reason must be a non-empty snake_case code of at most 128 bytes")
            }
            Self::DetailTooLong => {
                write!(f, "detail exceeds {MAX_CHECKPOINT_DETAIL_CHARS} characters")
            }
            Self::HealthUnitMismatch => f.write_str("health report is for a different unit"),
            Self::Health(e) => write!(f, "health report: {e}"),
        }
    }
}

impl std::error::Error for CheckpointError {}

impl ExecutionCheckpoint {
    /// Refuse a checkpoint that contradicts itself. Never panics.
    pub fn validate(&self) -> Result<(), CheckpointError> {
        if self.authorisation_id.trim().is_empty() {
            return Err(CheckpointError::EmptyField("authorisation_id"));
        }
        if self.unit_id.trim().is_empty() {
            return Err(CheckpointError::EmptyField("unit_id"));
        }
        if self.traffic_percent.is_some_and(|p| p > 100) {
            return Err(CheckpointError::TrafficPercentOutOfRange);
        }
        if let Some(reason) = &self.reason
            && !is_reason_code(reason)
        {
            return Err(CheckpointError::BadReason);
        }
        if self
            .detail
            .as_ref()
            .is_some_and(|d| d.chars().count() > MAX_CHECKPOINT_DETAIL_CHARS)
        {
            return Err(CheckpointError::DetailTooLong);
        }
        if let Some(health) = &self.health {
            if health.unit_id != self.unit_id {
                return Err(CheckpointError::HealthUnitMismatch);
            }
            health.validate().map_err(CheckpointError::Health)?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "execution_tests.rs"]
pub(crate) mod tests;
