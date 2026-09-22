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
    /// Artifact Registry repository that a Cloud Run deploy publishes bundles
    /// into, taken from the environment's operator-managed config. `None` for
    /// targets that need no registry, and for any admin older than this field.
    ///
    /// No `#[serde(default)]` is needed: serde's derive already yields `None`
    /// for a missing plain `Option<T>` field. The sibling timestamp fields
    /// carry the attribute because they use `with = "…"`, which does not get
    /// that treatment — do not copy their pattern here on the assumption that
    /// `Option` requires it.
    pub repository: Option<String>,
    /// How a Kubernetes environment's router Service is exposed —
    /// `ClusterIP`, `NodePort` or `LoadBalancer` — taken from the
    /// environment's operator-managed config. `None` for every non-K8s target,
    /// for a K8s environment whose operator never chose one, and for any admin
    /// older than this field.
    ///
    /// Carried as the operator's own string rather than an enum: it is
    /// forwarded verbatim as `greentic-deployer`'s `service_type` wizard
    /// answer, which matches case-insensitively and refuses an unknown value
    /// itself. A second enum here would be a second copy of that vocabulary to
    /// keep in step with a crate this one does not depend on.
    ///
    /// `None` must be read as the deployer's default (`ClusterIP`, in-cluster
    /// only), never as a guess at an exposed type — exposing a Service is the
    /// operator's decision, and it can put a load balancer on their bill.
    ///
    /// No `#[serde(default)]` is needed, for the same reason as `project`.
    pub service_type: Option<String>,
    /// Registry host (`host[:port]`) a Kubernetes environment's bundles are
    /// pushed to and whose images its pods pull, from the environment's
    /// operator-managed config. `None` for every non-k8s target, and for any
    /// admin older than this field — in which case the designer falls back to
    /// its own per-workspace store, which is where this value lived before.
    ///
    /// No `#[serde(default)]`: see `project` above.
    pub k8s_registry: Option<String>,
    /// Repository prefix under [`Self::k8s_registry`].
    pub k8s_registry_repository: Option<String>,
    /// Whether that registry is plain HTTP, as the operator's spelling of it
    /// (`"true"`/`"false"`). A `String`, not a `bool`: a missing `bool` would
    /// need `#[serde(default)]`, and the deployer parses the spelling itself,
    /// so a second parser here would be a second opinion about what "true"
    /// means.
    pub k8s_registry_insecure: Option<String>,
    /// Full image reference for the worker/router container, forwarded as
    /// greentic-deployer's `runtime_image` answer. `None` keeps the
    /// deployer's own default.
    pub k8s_worker_image: Option<String>,
    /// Full image reference for the init containers, forwarded as
    /// greentic-deployer's `init_image` answer. `None` keeps the deployer's
    /// own default.
    pub k8s_init_image: Option<String>,
    #[serde(default, with = "crate::timestamp::opt_rfc3339")]
    pub last_deployed_at: Option<DateTime<Utc>>,
    #[serde(default, with = "crate::timestamp::opt_rfc3339")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(default, with = "crate::timestamp::opt_rfc3339")]
    pub updated_at: Option<DateTime<Utc>>,
    /// True when BYOC credentials are stored. The credentials reference itself
    /// is server-only and is not part of this contract.
    pub has_credentials: bool,
    /// Set when this environment is a partnership's environment projected into
    /// the tenant: the partner configured it and the tenant may deploy to it
    /// but not edit it. `None` means the tenant owns it — which is also what
    /// every admin older than this field means.
    ///
    /// Skipped when `None` so every existing payload still round-trips
    /// byte-for-byte.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<EnvOrigin>,
}

/// Where a projected environment comes from. See [`EnvListItem::origin`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvOrigin {
    pub partnership_id: String,
    pub partnership_name: String,
    /// True when the tenant can no longer deploy to it: it left the
    /// partnership, or the partnership was disabled. A revoked environment is
    /// still listed so a bound canvas can say why, and can be unbound.
    pub revoked: bool,
    /// The partnership marked this environment as the one its member tenants
    /// use by default: pre-selected in pickers and bound to a new canvas. Never
    /// true on a revoked origin. Absent (older admins) reads as false.
    #[serde(default, skip_serializing_if = "is_false")]
    pub default: bool,
}

fn is_false(v: &bool) -> bool {
    !v
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
            "repository": null,
            "service_type": null,
            "k8s_registry": null,
            "k8s_registry_repository": null,
            "k8s_registry_insecure": null,
            "k8s_worker_image": null,
            "k8s_init_image": null,
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
        let obj = serde_json::to_value(&item).unwrap();
        assert_eq!(obj, json);
        assert_eq!(obj["repository"], serde_json::Value::Null);
        assert_eq!(obj["service_type"], serde_json::Value::Null);
        assert_eq!(obj["k8s_registry"], serde_json::Value::Null);
        assert_eq!(obj["k8s_registry_repository"], serde_json::Value::Null);
        assert_eq!(obj["k8s_registry_insecure"], serde_json::Value::Null);
        assert_eq!(obj["k8s_worker_image"], serde_json::Value::Null);
        assert_eq!(obj["k8s_init_image"], serde_json::Value::Null);
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

    #[test]
    fn env_list_item_without_repository_reads_as_none() {
        // An admin that has not deployed this field yet simply omits the key.
        // This is the ONLY thing pinning that tolerance — see the field's doc
        // comment for why no `#[serde(default)]` is involved.
        let json = serde_json::json!({
            "id": "env_1",
            "team_slug": null,
            "name": "Prod",
            "target": "gcp",
            "status": "live",
            "status_detail": null,
            "region": "asia-southeast1",
            "project": "acme-prod-1234",
            "last_deployed_at": null,
            "created_at": null,
            "updated_at": null,
            "has_credentials": true
        });

        let item: EnvListItem = serde_json::from_value(json).unwrap();
        assert_eq!(item.repository, None);
    }

    #[test]
    fn env_list_item_carries_the_repository_when_present() {
        let json = serde_json::json!({
            "id": "env_1",
            "team_slug": null,
            "name": "Prod",
            "target": "gcp",
            "status": "live",
            "status_detail": null,
            "region": "asia-southeast1",
            "project": "acme-prod-1234",
            "repository": "greentic",
            "last_deployed_at": null,
            "created_at": null,
            "updated_at": null,
            "has_credentials": true
        });

        let item: EnvListItem = serde_json::from_value(json).unwrap();
        assert_eq!(item.repository.as_deref(), Some("greentic"));
    }
    #[test]
    fn env_list_item_without_service_type_reads_as_none() {
        // An admin that has not deployed this field yet simply omits the key,
        // and `None` is what makes the deployer keep its in-cluster default.
        let json = serde_json::json!({
            "id": "env_1",
            "team_slug": null,
            "name": "Cluster",
            "target": "k8s",
            "status": "live",
            "status_detail": null,
            "region": null,
            "project": null,
            "repository": null,
            "last_deployed_at": null,
            "created_at": null,
            "updated_at": null,
            "has_credentials": true
        });

        let item: EnvListItem = serde_json::from_value(json).unwrap();
        assert_eq!(item.service_type, None);
    }

    #[test]
    fn env_list_item_carries_the_service_type_verbatim() {
        let json = serde_json::json!({
            "id": "env_1",
            "team_slug": null,
            "name": "Cluster",
            "target": "k8s",
            "status": "live",
            "status_detail": null,
            "region": null,
            "project": null,
            "repository": null,
            "service_type": "LoadBalancer",
            "last_deployed_at": null,
            "created_at": null,
            "updated_at": null,
            "has_credentials": true
        });

        let item: EnvListItem = serde_json::from_value(json).unwrap();
        assert_eq!(item.service_type.as_deref(), Some("LoadBalancer"));
    }

    #[test]
    fn env_list_item_without_the_k8s_registry_fields_reads_as_none() {
        // An admin that predates these fields simply omits the keys, and
        // `None` is what keeps the deployer on its own defaults.
        let json = serde_json::json!({
            "id": "env-1",
            "team_slug": null,
            "name": "prod",
            "target": "k8s",
            "status": "ready",
            "status_detail": null,
            "region": null,
            "project": null,
            "repository": null,
            "service_type": null,
            "last_deployed_at": null,
            "created_at": null,
            "updated_at": null,
            "has_credentials": false
        });
        let item: EnvListItem = serde_json::from_value(json).unwrap();
        assert_eq!(item.k8s_registry, None);
        assert_eq!(item.k8s_registry_repository, None);
        assert_eq!(item.k8s_registry_insecure, None);
        assert_eq!(item.k8s_worker_image, None);
        assert_eq!(item.k8s_init_image, None);
    }

    #[test]
    fn env_list_item_round_trips_the_k8s_registry_fields() {
        let json = serde_json::json!({
            "id": "env-1",
            "team_slug": null,
            "name": "prod",
            "target": "k8s",
            "status": "ready",
            "status_detail": null,
            "region": null,
            "project": null,
            "repository": null,
            "service_type": "ClusterIP",
            "k8s_registry": "registry.client.local",
            "k8s_registry_repository": "greentic",
            "k8s_registry_insecure": "true",
            "k8s_worker_image": "registry.client.local/greentic/greentic-start-distroless:1.2.3",
            "k8s_init_image": "registry.client.local/greentic/busybox:1.36.1",
            "last_deployed_at": null,
            "created_at": null,
            "updated_at": null,
            "has_credentials": false
        });
        let item: EnvListItem = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(item.k8s_registry.as_deref(), Some("registry.client.local"));
        assert_eq!(item.k8s_registry_insecure.as_deref(), Some("true"));
        assert_eq!(
            item.k8s_worker_image.as_deref(),
            Some("registry.client.local/greentic/greentic-start-distroless:1.2.3")
        );
        let back = serde_json::to_value(&item).unwrap();
        assert_eq!(back["k8s_init_image"], json["k8s_init_image"]);
    }

    #[test]
    fn env_list_item_without_origin_reads_as_none_and_omits_it_on_the_wire() {
        // A tenant-owned environment, and every admin older than this field,
        // sends no `origin` key. It must read as `None` — and must not be
        // written back as `"origin": null`, or the round-trip test above
        // stops being byte-for-byte for every existing payload.
        let json = serde_json::json!({
            "id": "env_1",
            "team_slug": null,
            "name": "Production",
            "target": "gcp",
            "status": "idle",
            "status_detail": null,
            "region": "asia-southeast1",
            "last_deployed_at": null,
            "created_at": null,
            "updated_at": null,
            "has_credentials": false
        });
        let item: EnvListItem = serde_json::from_value(json).expect("deserialises");
        assert_eq!(item.origin, None);
        let obj = serde_json::to_value(&item).unwrap();
        assert!(
            obj.get("origin").is_none(),
            "None must be omitted, got {obj}"
        );
    }

    #[test]
    fn env_list_item_carries_a_partnership_origin() {
        let json = serde_json::json!({
            "id": "env_p",
            "team_slug": null,
            "name": "Acme Partner Cloud",
            "target": "gcp",
            "status": "idle",
            "status_detail": null,
            "region": "asia-southeast1",
            "last_deployed_at": null,
            "created_at": null,
            "updated_at": null,
            "has_credentials": true,
            "origin": {
                "partnership_id": "pship_1",
                "partnership_name": "Acme",
                "revoked": false
            }
        });
        let item: EnvListItem = serde_json::from_value(json.clone()).expect("deserialises");
        assert_eq!(
            item.origin,
            Some(EnvOrigin {
                partnership_id: "pship_1".into(),
                partnership_name: "Acme".into(),
                revoked: false,
                default: false,
            })
        );
        let obj = serde_json::to_value(&item).unwrap();
        assert_eq!(obj["origin"], json["origin"]);
    }

    #[test]
    fn origin_without_default_reads_as_false() {
        let o: EnvOrigin = serde_json::from_value(serde_json::json!({
            "partnership_id": "p1", "partnership_name": "Acme", "revoked": false
        }))
        .unwrap();
        assert!(!o.default);
    }

    #[test]
    fn origin_default_round_trips() {
        let json = serde_json::json!({
            "partnership_id": "p1", "partnership_name": "Acme", "revoked": false, "default": true
        });
        let o: EnvOrigin = serde_json::from_value(json.clone()).unwrap();
        assert!(o.default);
        assert_eq!(serde_json::to_value(&o).unwrap(), json);
    }
}
