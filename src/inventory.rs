//! Installation identity and deployment inventory (design doc §2, §9).

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
