//! Installation identity and deployment inventory (design doc §2, §9).

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Connectivity {
    Online,
    AirGapped,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallationIdentity {
    pub installation_id: String,
    /// `platform` (Greentic operating DWaaS) or `enterprise`.
    pub owner_kind: String,
    pub owner_ref: String,
    pub connectivity: Connectivity,
    #[serde(default)]
    pub architectures: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

/// `Default` exists so a consumer builds one with `..Default::default()` and
/// a later additive field is not a compile break at every literal.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationOwnership {
    pub application_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_id: Option<String>,
    pub release_digest: String,
    /// Stable resource ids this application owns inside the unit.
    #[serde(default)]
    pub owned_resources: Vec<String>,
    /// Digest over the tenant's retained overrides; never the values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overrides_digest: Option<String>,
    /// The version (or digest) of each owned resource, keyed by the id in
    /// `owned_resources` — what an application-scoped rollback restores.
    /// Every key must also appear in `owned_resources`; the restoring side
    /// (PDS3) refuses a version for a resource the application does not own,
    /// so a rollback can never restore someone else's resource.
    /// Skipped when empty, so a report that carries none is byte-identical
    /// to one written before the field existed.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub owned_resource_versions: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitReport {
    pub adapter: String,
    #[serde(default)]
    pub shared: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_release_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_image_digest: Option<String>,
    #[serde(default)]
    pub applications: Vec<ApplicationOwnership>,
    /// `0` creates; otherwise must equal the stored generation.
    pub expected_generation: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentUnitRecord {
    pub tenant_id: String,
    pub environment_id: String,
    pub unit_id: String,
    pub generation: u64,
    pub reported_at: DateTime<Utc>,
    #[serde(flatten)]
    pub report: UnitReport,
}

#[cfg(test)]
#[path = "inventory_tests.rs"]
mod tests;
