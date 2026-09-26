//! Per-unit health evidence, reported by the designer to the admin (unified
//! update lifecycle, phase 2a, Task C2a-2).
//!
//! The designer computes this from its own runtime read (a Cloud Run
//! readiness check plus a Cloud Monitoring window); the admin's rollout view
//! renders it beside target selection. Both sides must agree on the shape,
//! which is why it lives here rather than being re-derived independently on
//! either side.
//!
//! This mirrors the designer's internal `orchestrate::env_deploy::unit_health`
//! model, with four deliberate departures, recorded so a future reader does
//! not "fix" this type back into disagreement with what the designer already
//! ships:
//!
//! - [`Readiness`] and [`Evidence`] tag on `status` and `kind` respectively,
//!   not the designer's internal `state` for both — this contract already
//!   tags its other enums by what they discriminate (see
//!   [`crate::governance::GateStatus`]'s `status`, `CompatVerdict`'s
//!   `verdict` in [`crate::release`]), and reusing one tag name for two
//!   different nested enums invites a reader to assume they share a
//!   vocabulary when they do not.
//! - [`Evidence::Insufficient`] carries no `remediation` field. The
//!   designer's internal type adds one so its own UI can offer a ready-to-run
//!   `gcloud` fix; the admin's rollout view has no use for it here.
//! - `window_start` / `window_end` are required [`DateTime<Utc>`], not the
//!   designer's optional RFC 3339 strings — a report is only ever sent for a
//!   window that was actually established.
//! - `latency_ms` is `Option<`[`Latency`]`>`; the designer keeps an
//!   always-present struct whose two fields default to `None` instead.
//!
//! Everything else — field names, the closed [`InsufficientReason`] set, the
//! four request-count buckets — matches the designer's model exactly.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Whether Cloud Run reports the revision ready.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Evidence {
    Sufficient,
    Insufficient {
        reason: InsufficientReason,
        /// A sentence for the operator.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
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
    pub unit_id: String,
    /// The revision this report is about. `None` when the designer has no
    /// recorded revision for the unit at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_revision: Option<String>,
    pub readiness: Readiness,
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests: Option<RequestCounts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<Latency>,
    /// `server_5xx / all requests`, `None` when there were none to divide by.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_error_rate: Option<f64>,
    /// True only when traffic was MEASURED as zero — never a stand-in for
    /// "not measured"; see `requests`.
    pub idle: bool,
    pub evidence: Evidence,
    /// When the designer produced this report — not the window it describes.
    pub reported_at: DateTime<Utc>,
}

/// Why a [`UnitHealthReport`] refuses to validate. Every rule below returns
/// one of these; nothing here panics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnitHealthReportError {
    /// `window_end` is before `window_start`.
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
        if self.window_end < self.window_start {
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
