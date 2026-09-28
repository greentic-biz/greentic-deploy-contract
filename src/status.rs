//! Status report v1 (unified release lifecycle, phase 4; design doc §6
//! "Status return").
//!
//! A disconnected installation's local audit and deployment status stay
//! authoritative. The local admin may export a [`StatusReport`] — built from
//! the execution checkpoints it received and signed with the installation's
//! STATUS key (never the execution or release key) — for the cloud to import.
//! The cloud verifies it against that installation's status trust, refuses a
//! `sequence` not greater than the last it stored (replay), and labels the
//! result as imported status with its `observed_at`. Those importer checks
//! are [`StatusReport::admit`]; persisting the new sequence is the caller's.
//! The absence of a report stays unknown: it is never read as failed or as
//! successful.
//!
//! **Minimal by construction.** An entry carries identifiers, a digest, an
//! [`ExecState`] and a snake_case reason code — no free-form detail, no
//! health data, no secret material. There is no field that could carry one.
//!
//! **Signed schemas never change**: `deny_unknown_fields`, and [`ExecState`]
//! has no catch-all. A new field is a new schema.

use std::collections::BTreeSet;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::execution::{ExecState, is_reason_code, is_sha256_digest};

/// The `schema` value every v1 status report carries.
pub const STATUS_REPORT_SCHEMA: &str = "greentic.status-report.v1";

/// The DSSE `payloadType` a v1 status report is signed under.
pub const STATUS_REPORT_PAYLOAD_TYPE: &str = "application/vnd.greentic.status-report.v1+json";

/// The most entries one report may carry.
pub const MAX_STATUS_ENTRIES: usize = 5000;

/// The longest identifier (installation, report, rollout, authorisation,
/// environment, unit), in bytes. Identifiers are printable ASCII without
/// spaces, so nothing in a report can inject into a log line or a portal.
pub const MAX_STATUS_ID_BYTES: usize = 256;

/// One unit's latest known state in one rollout.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusEntry {
    pub rollout_id: String,
    #[serde(default)]
    pub authorisation_id: Option<String>,
    /// `sha256:<64 lowercase hex>`.
    pub release_digest: String,
    pub environment_id: String,
    pub unit_id: String,
    pub state: ExecState,
    /// A stable snake_case code, at most 128 bytes (the checkpoint rule).
    #[serde(default)]
    pub reason: Option<String>,
    /// When the local admin recorded this state; not after the report's
    /// `observed_at`.
    pub recorded_at: DateTime<Utc>,
}

/// A signed, minimal export of an installation's deployment status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusReport {
    /// Always [`STATUS_REPORT_SCHEMA`].
    pub schema: String,
    pub installation_id: String,
    pub report_id: String,
    /// Monotonic per installation, `>= 1`.
    pub sequence: u64,
    /// When the report was assembled.
    pub observed_at: DateTime<Utc>,
    /// At most [`MAX_STATUS_ENTRIES`]; may be empty (nothing new).
    #[serde(default)]
    pub entries: Vec<StatusEntry>,
}

/// Why a [`StatusReport`] refuses to validate.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StatusError {
    UnknownSchema(String),
    /// An identifier is empty, longer than [`MAX_STATUS_ID_BYTES`], or not
    /// printable non-space ASCII; carries the field.
    BadIdentifier(&'static str),
    /// `0`, or above [`crate::MAX_SEQUENCE`].
    BadSequence,
    /// Two entries for one `(rollout_id, environment_id, unit_id)`; "the
    /// latest state" would be ambiguous.
    DuplicateEntry,
    TooManyEntries,
    BadDigest,
    BadReason,
    /// An entry's `recorded_at` is after the report's `observed_at`.
    RecordedAfterObservation,
}

impl std::fmt::Display for StatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownSchema(s) => write!(f, "unknown schema `{s}`"),
            Self::BadIdentifier(n) => write!(
                f,
                "`{n}` must be 1..={MAX_STATUS_ID_BYTES} bytes of printable non-space ASCII"
            ),
            Self::BadSequence => f.write_str("sequence must be in 1..=MAX_SEQUENCE"),
            Self::DuplicateEntry => {
                f.write_str("two entries for the same rollout, environment and unit")
            }
            Self::TooManyEntries => write!(f, "more than {MAX_STATUS_ENTRIES} entries"),
            Self::BadDigest => f.write_str("release_digest is not sha256:<64 lowercase hex>"),
            Self::BadReason => {
                f.write_str("reason must be a non-empty snake_case code of at most 128 bytes")
            }
            Self::RecordedAfterObservation => {
                f.write_str("an entry was recorded after the report was observed")
            }
        }
    }
}

impl std::error::Error for StatusError {}

fn ident(value: &str, field: &'static str) -> Result<(), StatusError> {
    if !value.is_empty()
        && value.len() <= MAX_STATUS_ID_BYTES
        && value.bytes().all(|b| b.is_ascii_graphic())
    {
        Ok(())
    } else {
        Err(StatusError::BadIdentifier(field))
    }
}

impl StatusEntry {
    fn validate(&self, observed_at: DateTime<Utc>) -> Result<(), StatusError> {
        ident(&self.rollout_id, "rollout_id")?;
        if let Some(id) = &self.authorisation_id {
            ident(id, "authorisation_id")?;
        }
        if !is_sha256_digest(&self.release_digest) {
            return Err(StatusError::BadDigest);
        }
        ident(&self.environment_id, "environment_id")?;
        ident(&self.unit_id, "unit_id")?;
        if self.reason.as_deref().is_some_and(|r| !is_reason_code(r)) {
            return Err(StatusError::BadReason);
        }
        if self.recorded_at > observed_at {
            return Err(StatusError::RecordedAfterObservation);
        }
        Ok(())
    }
}

impl StatusReport {
    /// Refuse a report that is malformed on its own terms. Replay
    /// (`sequence` greater than the last stored) and the signer being THIS
    /// installation's status key are the importer's checks.
    pub fn validate(&self) -> Result<(), StatusError> {
        if self.schema != STATUS_REPORT_SCHEMA {
            return Err(StatusError::UnknownSchema(self.schema.clone()));
        }
        ident(&self.installation_id, "installation_id")?;
        ident(&self.report_id, "report_id")?;
        if self.sequence == 0 || self.sequence > crate::MAX_SEQUENCE {
            return Err(StatusError::BadSequence);
        }
        if self.entries.len() > MAX_STATUS_ENTRIES {
            return Err(StatusError::TooManyEntries);
        }
        let mut seen = BTreeSet::new();
        for entry in &self.entries {
            entry.validate(self.observed_at)?;
            let key = (
                entry.rollout_id.as_str(),
                entry.environment_id.as_str(),
                entry.unit_id.as_str(),
            );
            if !seen.insert(key) {
                return Err(StatusError::DuplicateEntry);
            }
        }
        Ok(())
    }

    /// The importer's checks, once the signature is verified against THIS
    /// installation's status key: the report names that installation, its
    /// sequence is greater than `last_seq` (the caller persists the new one
    /// only after storing the report), and `observed_at` is not more than
    /// `skew` in the future. A negative `skew` is read as zero.
    pub fn admit(
        &self,
        installation_id: &str,
        last_seq: u64,
        now: DateTime<Utc>,
        skew: Duration,
    ) -> Result<(), StatusAdmitError> {
        if self.installation_id != installation_id {
            return Err(StatusAdmitError::WrongInstallation);
        }
        if self.sequence <= last_seq {
            return Err(StatusAdmitError::Replayed {
                sequence: self.sequence,
                last: last_seq,
            });
        }
        if self.observed_at - now > skew.max(Duration::zero()) {
            return Err(StatusAdmitError::ObservedInFuture);
        }
        Ok(())
    }
}

/// Why [`StatusReport::admit`] refused a verified report.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StatusAdmitError {
    /// Names another installation than the one whose key verified it.
    WrongInstallation,
    Replayed {
        sequence: u64,
        last: u64,
    },
    ObservedInFuture,
}

impl std::fmt::Display for StatusAdmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongInstallation => f.write_str("report names another installation"),
            Self::Replayed { sequence, last } => write!(
                f,
                "report sequence {sequence} is not greater than the last stored {last}"
            ),
            Self::ObservedInFuture => f.write_str("report is observed in the future"),
        }
    }
}

impl std::error::Error for StatusAdmitError {}

#[cfg(feature = "signing")]
pub use signing::*;

#[cfg(feature = "signing")]
mod signing {
    use ed25519_dalek::SigningKey;

    use super::{STATUS_REPORT_PAYLOAD_TYPE, StatusError, StatusReport};
    use crate::dsse::DsseEnvelope;
    use crate::revocation::RevocationList;
    use crate::signed::{OpenError, OpenSpec, Opened, SignError, open_typed, sign_typed};
    use crate::trust::{TrustDomain, TrustSet};

    /// Validate, then sign `report` with the installation's status key(s).
    pub fn sign_status(
        report: &StatusReport,
        keys: &[&SigningKey],
    ) -> Result<DsseEnvelope, SignError<StatusError>> {
        sign_typed(
            STATUS_REPORT_PAYLOAD_TYPE,
            report,
            StatusReport::validate,
            keys,
        )
    }

    /// Verify `env` against the installation's STATUS trust set (`threshold`
    /// distinct signers, none revoked by `revocation`), then parse and
    /// validate. Then call [`StatusReport::admit`].
    pub fn verify_status(
        env: &DsseEnvelope,
        trusted: &TrustSet,
        threshold: usize,
        revocation: Option<&RevocationList>,
    ) -> Result<Opened<StatusReport>, OpenError<StatusError>> {
        open_typed(
            env,
            OpenSpec {
                payload_type: STATUS_REPORT_PAYLOAD_TYPE,
                domain: TrustDomain::StatusReport,
                trusted,
                threshold,
                revocation,
            },
            StatusReport::validate,
        )
    }
}

#[cfg(test)]
#[path = "status_tests.rs"]
mod tests;
