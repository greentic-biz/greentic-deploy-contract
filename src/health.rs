//! Per-unit health evidence, reported by the designer to the admin (unified
//! update lifecycle, phase 2a, Task C2a-2).
//!
//! The designer computes this from its own runtime read (a Cloud Run
//! readiness check plus a Cloud Monitoring window); the admin's rollout view
//! renders it beside target selection. The designer's reporting route is
//! already reviewed and sends its existing `orchestrate::env_deploy::
//! unit_health::UnitHealth` JSON unchanged, and the admin stores whatever it
//! receives — so this type mirrors that JSON **field for field, including
//! its casing**, rather than picking a shape of its own that a translation
//! layer would then have to bridge.
//!
//! Only two things here are NOT part of `UnitHealth` itself:
//!
//! - `unit_id` and `reported_at` are report-level additions — the envelope
//!   the designer wraps a `UnitHealth` reading in before sending it. They
//!   stay in this crate's own snake_case convention (matching
//!   [`crate::inventory::DeploymentUnitRecord`]'s `unit_id` / `reported_at`),
//!   since there is no existing designer JSON for them to match.
//! - `window_end` is `Option<DateTime<Utc>>` here, though the designer's own
//!   `UnitHealth.window_end` is a required string. A report is only ever
//!   built from an already-established window today, so the two agree in
//!   practice; keeping it optional at the contract level means a future
//!   caller that reports before a window exists is a valid message, not an
//!   `Err`, and it makes both ends of the window symmetric.
//!
//! Everything else — `revision`, the `state`-tagged `readiness` and
//! `evidence`, the `windowStart` / `latencyMs` / `serverErrorRate` casing,
//! the four `RequestCounts` buckets, and `evidence.remediation` — is copied
//! from the designer's struct definitions verbatim, so a JSON body the
//! designer already produces deserializes here unchanged (see the
//! `designer_unit_health_json_deserializes_unchanged` test, built from the
//! designer's own `unit_health.rs` field definitions since no single test
//! there pins the whole body).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Whether Cloud Run reports the revision ready. Field-for-field identical to
/// the designer's `unit_health::Readiness`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Readiness {
    Ready,
    NotReady {
        reason: String,
    },
    /// Not read, or the runtime reported no `Ready` condition.
    Unknown,
}

/// Why there is not enough evidence to call a unit healthy. A closed set — a
/// rollout gate matches on the reason, so a free string would be
/// unmatchable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InsufficientReason {
    /// The designer recorded no revision for this unit's last deploy.
    NoRecordedRevision,
    /// The revision served no requests inside the window.
    Idle,
    /// The read was refused, or cannot be made on this lane at all.
    CannotEvaluate,
    /// The runtime could not be reached, or answered with a failure.
    Unavailable,
    /// The revision is not ready (or no longer exists).
    NotReady,
}

/// Whether a report is enough to judge the unit. `Sufficient` is a claim
/// [`UnitHealthReport::validate`] checks, not just a label — see its rules.
/// Field-for-field identical to the designer's `unit_health::Evidence`,
/// `remediation` included.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Evidence {
    Sufficient,
    Insufficient {
        reason: InsufficientReason,
        /// A sentence for the operator.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
        /// The ready-to-run fix, when the refusal carries one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        remediation: Option<String>,
    },
}

/// Requests over the window, by response class.
///
/// **On [`UnitHealthReport::requests`], `None` means the count was never
/// MEASURED — never a real zero.** A revision that ran and served nothing
/// reports `Some` with every field at zero (and `idle: true`); only a read
/// that could not happen at all — no recorded revision, a refused API call,
/// an unreachable runtime — reports `None`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestCounts {
    pub ok_2xx: u64,
    /// Counted separately from `ok_2xx`: a redirect is traffic the revision
    /// served, but not evidence that it answers correctly.
    pub redirect_3xx: u64,
    pub client_4xx: u64,
    pub server_5xx: u64,
}

impl RequestCounts {
    /// Every request this struct counts.
    pub fn counted(&self) -> u64 {
        self.ok_2xx + self.redirect_3xx + self.client_4xx + self.server_5xx
    }
}

/// Response-time percentiles, in milliseconds, over the same window as
/// `requests`. Either field may be absent on its own — a latency read can
/// fail while the request counts still stand.
///
/// **A consumer gate must treat a missing `p99` as
/// [`InsufficientReason::CannotEvaluate`], never as "within budget".** There
/// is no such thing as a fast p99 that was never measured.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Latency {
    pub p50: Option<f64>,
    pub p99: Option<f64>,
}

/// One unit's health evidence for one report window.
///
/// `requests: None` means the count was never measured — never a real zero;
/// see [`RequestCounts`]. `evidence` is [`Evidence::Sufficient`] only when
/// the unit was ready, served traffic inside the window, and the read
/// actually answered — [`UnitHealthReport::validate`] enforces that a report
/// cannot claim `Sufficient` any other way.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UnitHealthReport {
    /// Report-level addition; not part of the designer's `UnitHealth`.
    pub unit_id: String,
    /// The revision this report is about. `None` when the designer has no
    /// recorded revision for the unit at all.
    #[serde(default)]
    pub revision: Option<String>,
    pub readiness: Readiness,
    #[serde(rename = "windowStart", default)]
    pub window_start: Option<DateTime<Utc>>,
    /// See the module doc: optional here even though the designer's own
    /// `window_end` is a required string.
    #[serde(rename = "windowEnd", default)]
    pub window_end: Option<DateTime<Utc>>,
    #[serde(default)]
    pub requests: Option<RequestCounts>,
    #[serde(rename = "latencyMs", default)]
    pub latency_ms: Latency,
    /// `server_5xx / all requests`, `None` when there were none to divide by.
    #[serde(rename = "serverErrorRate", default)]
    pub server_error_rate: Option<f64>,
    /// True only when traffic was MEASURED as zero — never a stand-in for
    /// "not measured"; see `requests`.
    pub idle: bool,
    pub evidence: Evidence,
    /// Report-level addition; not part of the designer's `UnitHealth`. When
    /// the designer produced this report — not the window it describes.
    pub reported_at: DateTime<Utc>,
}

/// Why a [`UnitHealthReport`] refuses to validate. Every rule below returns
/// one of these; nothing here panics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnitHealthReportError {
    /// `window_end` is before `window_start`, when both are known.
    WindowInverted,
    /// `evidence` claims `Sufficient` over a `readiness` that is not `Ready`.
    SufficientWithoutReadyRevision,
    /// `evidence` claims `Sufficient` while `idle` is `true` — an idle
    /// revision has no errors because it did nothing, which is not evidence
    /// that it is healthy.
    SufficientWhileIdle,
    /// `evidence` claims `Sufficient` with `requests: None` — nothing was
    /// actually measured to support the claim.
    SufficientWithoutRequests,
}

impl std::fmt::Display for UnitHealthReportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::WindowInverted => "window_end is before window_start",
            Self::SufficientWithoutReadyRevision => {
                "evidence is `sufficient` but readiness is not `ready`"
            }
            Self::SufficientWhileIdle => "evidence is `sufficient` but idle is true",
            Self::SufficientWithoutRequests => {
                "evidence is `sufficient` but requests were never measured"
            }
        };
        f.write_str(msg)
    }
}

impl std::error::Error for UnitHealthReportError {}

impl UnitHealthReport {
    /// Refuse a report that contradicts itself. See [`UnitHealthReportError`]
    /// for the rules; never panics.
    pub fn validate(&self) -> Result<(), UnitHealthReportError> {
        if let (Some(start), Some(end)) = (self.window_start, self.window_end)
            && end < start
        {
            return Err(UnitHealthReportError::WindowInverted);
        }
        if matches!(self.evidence, Evidence::Sufficient) {
            if self.readiness != Readiness::Ready {
                return Err(UnitHealthReportError::SufficientWithoutReadyRevision);
            }
            if self.idle {
                return Err(UnitHealthReportError::SufficientWhileIdle);
            }
            if self.requests.is_none() {
                return Err(UnitHealthReportError::SufficientWithoutRequests);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "health_tests.rs"]
mod tests;
