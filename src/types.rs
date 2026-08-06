//! The three shapes that cross the admin → designer seam.
//!
//! Field names and casing are exactly what the admin serializes today. Two
//! fields the admin's database row carries are deliberately absent:
//!
//! - `tenant_id` — the designer calls these endpoints as a tenant-scoped
//!   identity, so it is redundant on the wire.
//! - `config` — admin-side advanced configuration. Passing an untyped blob
//!   through a crate whose purpose is typing this seam would defeat the point.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::enums::{DeployTarget, EnvStatus, JobStatus};

/// One environment as it appears in the designer's environment list.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnvListItem {
    pub id: String,
    /// Owning team slug. `None` = tenant-wide (visible to every team).
    pub team_slug: Option<String>,
    pub name: String,
    pub target: DeployTarget,
    pub status: EnvStatus,
    pub status_detail: Option<String>,
    pub region: Option<String>,
    /// GCP project id for a Cloud Run target, taken from the environment's
    /// operator-managed config. `None` for targets that need no project, and
    /// for any admin older than this field.
    ///
    /// No `#[serde(default)]` is needed: serde's derive already yields `None`
    /// for a missing plain `Option<T>` field. The sibling timestamp fields
    /// carry the attribute because they use `with = "…"`, which does not get
    /// that treatment — do not copy their pattern here on the assumption that
    /// `Option` requires it.
    pub project: Option<String>,
    #[serde(default, with = "crate::timestamp::opt_rfc3339")]
    pub last_deployed_at: Option<DateTime<Utc>>,
    #[serde(default, with = "crate::timestamp::opt_rfc3339")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(default, with = "crate::timestamp::opt_rfc3339")]
    pub updated_at: Option<DateTime<Utc>>,
    /// True when BYOC credentials are stored. The credentials reference itself
    /// is server-only and is not part of this contract.
    pub has_credentials: bool,
}

/// An async deploy job for an environment, or for one unit within it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeploymentJob {
    pub id: String,
    pub environment_id: String,
    /// The deployed pack reference, `name@version`.
    pub pack_ref: String,
    pub status: JobStatus,
    pub detail: Option<String>,
    /// Present once a deploy succeeds.
    pub endpoint: Option<String>,
    #[serde(default, with = "crate::timestamp::opt_rfc3339")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(default, with = "crate::timestamp::opt_rfc3339")]
    pub updated_at: Option<DateTime<Utc>>,
}

/// Best-effort health of the runner serving an environment.
///
/// This is environment-scoped, not per-unit: one runner serves every unit
/// deployed to the environment. It never fails — no deploy, no endpoint, or an
/// unreachable runner all collapse to `reachable: false, healthy: false`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunnerStatus {
    pub reachable: bool,
    pub healthy: bool,
    pub missing_secrets: Vec<String>,
}

#[cfg(test)]
// The brief's test text asserts booleans via `assert_eq!(x, true)`; keep that
// text verbatim rather than rewriting it to satisfy this style lint.
#[allow(clippy::bool_assert_comparison)]
mod tests {
    use super::*;

    #[test]
    fn env_list_item_field_names_match_the_admin_payload() {
        let json = serde_json::json!({
            "id": "env_1",
            "team_slug": "core",
            "name": "Production",
            "target": "greentic_cloud",
            "status": "live",
            "status_detail": null,
            "region": "ap-southeast-1",
            "project": null,
            "last_deployed_at": "2026-07-30T10:00:00+00:00",
            "created_at": "2026-07-01T09:00:00+00:00",
            "updated_at": "2026-07-30T10:00:00+00:00",
            "has_credentials": true
        });

        let item: EnvListItem = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(item.id, "env_1");
        assert_eq!(item.target, DeployTarget::GreenticCloud);
        assert_eq!(item.status, EnvStatus::Live);
        assert_eq!(item.has_credentials, true);
        assert!(item.updated_at.is_some());

        // Round-trips to exactly the payload it came from.
        assert_eq!(serde_json::to_value(&item).unwrap(), json);
    }

    #[test]
    fn deployment_job_field_names_match_the_admin_payload() {
        let json = serde_json::json!({
            "id": "job_1",
            "environment_id": "env_1",
            "pack_ref": "acme.bundle@1.2.0",
            "status": "succeeded",
            "detail": null,
            "endpoint": "https://runner.example",
            "created_at": "2026-07-30T09:00:00+00:00",
            "updated_at": "2026-07-30T09:05:00+00:00"
        });

        let job: DeploymentJob = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(job.status, JobStatus::Succeeded);
        assert_eq!(job.pack_ref, "acme.bundle@1.2.0");
        assert_eq!(serde_json::to_value(&job).unwrap(), json);
    }

    #[test]
    fn runner_status_field_names_match_the_admin_payload() {
        let json = serde_json::json!({
            "reachable": true,
            "healthy": false,
            "missing_secrets": ["slack_token"]
        });

        let st: RunnerStatus = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(st.reachable, true);
        assert_eq!(st.missing_secrets, vec!["slack_token".to_string()]);
        assert_eq!(serde_json::to_value(&st).unwrap(), json);
    }

    /// A payload from a newer admin, read by an older designer: an unknown
    /// status and a malformed timestamp together must still yield a usable row.
    #[test]
    fn a_newer_admin_payload_still_deserializes() {
        let item: EnvListItem = serde_json::from_value(serde_json::json!({
            "id": "env_1",
            "team_slug": null,
            "name": "Production",
            "target": "fly",
            "status": "suspended",
            "status_detail": null,
            "region": null,
            "last_deployed_at": null,
            "created_at": "who knows",
            "updated_at": null,
            "has_credentials": false
        }))
        .unwrap();

        assert_eq!(item.target, DeployTarget::Unknown("fly".to_string()));
        assert_eq!(item.status, EnvStatus::Unknown("suspended".to_string()));
        assert_eq!(item.created_at, None);
        assert_eq!(item.name, "Production");
    }

    /// An admin build that predates one of these timestamp fields omits the
    /// key entirely rather than sending it as `null`. `#[serde(with = ...)]`
    /// disables serde's usual "a missing `Option<T>` field is `None`", so
    /// without `#[serde(default, ...)]` this is a hard deserialize failure,
    /// not a degraded value — the designer's own
    /// `web/src/features/deploy-run/types.ts` already documents an admin in
    /// the wild that omits `created_at`/`updated_at` on the job shape. Every
    /// timestamp key omitted, not just one, so this is proof the whole
    /// struct tolerates it, not just the field a narrower test would exercise.
    #[test]
    fn env_list_item_with_every_timestamp_key_omitted_still_deserializes() {
        let item: EnvListItem = serde_json::from_value(serde_json::json!({
            "id": "env_1",
            "team_slug": null,
            "name": "Production",
            "target": "greentic_cloud",
            "status": "live",
            "status_detail": null,
            "region": null,
            "has_credentials": true
        }))
        .expect("missing timestamp keys must not fail the whole payload");

        assert_eq!(item.last_deployed_at, None);
        assert_eq!(item.created_at, None);
        assert_eq!(item.updated_at, None);
        assert_eq!(item.name, "Production");
    }

    /// See `env_list_item_with_every_timestamp_key_omitted_still_deserializes`
    /// — same exposure, `DeploymentJob`'s two timestamp fields.
    #[test]
    fn deployment_job_with_every_timestamp_key_omitted_still_deserializes() {
        let job: DeploymentJob = serde_json::from_value(serde_json::json!({
            "id": "job_1",
            "environment_id": "env_1",
            "pack_ref": "acme.bundle@1.2.0",
            "status": "running",
            "detail": null,
            "endpoint": null
        }))
        .expect("missing timestamp keys must not fail the whole payload");

        assert_eq!(job.created_at, None);
        assert_eq!(job.updated_at, None);
        assert_eq!(job.status, JobStatus::Running);
    }

    #[test]
    fn env_list_item_without_project_reads_as_none() {
        // An admin older than this field sends no `project` key. Deserialising
        // must yield `None`, not fail — the crate exists so the two sides can
        // ship independently, and the field's `Option<T>` type is what makes
        // that true.
        let json = serde_json::json!({
            "id": "env_1",
            "team_slug": "core",
            "name": "Production",
            "target": "gcp",
            "status": "live",
            "status_detail": null,
            "region": "asia-southeast2",
            "last_deployed_at": null,
            "created_at": "2026-07-01T09:00:00+00:00",
            "updated_at": "2026-07-30T10:00:00+00:00",
            "has_credentials": true
        });

        let item: EnvListItem = serde_json::from_value(json).expect("older payload deserialises");
        assert_eq!(item.project, None);
    }

    #[test]
    fn env_list_item_carries_the_project_when_present() {
        let json = serde_json::json!({
            "id": "env_1",
            "team_slug": "core",
            "name": "Production",
            "target": "gcp",
            "status": "live",
            "status_detail": null,
            "region": "asia-southeast2",
            "last_deployed_at": null,
            "created_at": "2026-07-01T09:00:00+00:00",
            "updated_at": "2026-07-30T10:00:00+00:00",
            "has_credentials": true,
            "project": "acme-prod-1234"
        });

        let item: EnvListItem = serde_json::from_value(json).expect("new payload deserialises");
        assert_eq!(item.project.as_deref(), Some("acme-prod-1234"));
    }
}
