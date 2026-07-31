//! The three enums that were previously `String` fields with their legal values
//! written only in a doc comment.

use serde::{Deserialize, Serialize};

/// Where an environment is deployed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeployTarget {
    GreenticCloud,
    Aws,
    Azure,
    Gcp,
    /// A value this build does not know. Carries the original string so the UI
    /// can show what the server actually said, and so re-serializing does not
    /// corrupt it.
    #[serde(untagged)]
    Unknown(String),
}

/// Lifecycle state of an environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvStatus {
    Idle,
    Provisioning,
    Live,
    Error,
    /// See [`DeployTarget::Unknown`].
    #[serde(untagged)]
    Unknown(String),
}

/// Lifecycle state of a deploy job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Queued,
    Running,
    Succeeded,
    Failed,
    /// See [`DeployTarget::Unknown`].
    #[serde(untagged)]
    Unknown(String),
}

impl DeployTarget {
    /// Convert from the admin's stored text column. Total: an unrecognised
    /// value becomes [`Self::Unknown`].
    pub fn from_wire(raw: &str) -> Self {
        match raw {
            "greentic_cloud" => Self::GreenticCloud,
            "aws" => Self::Aws,
            "azure" => Self::Azure,
            "gcp" => Self::Gcp,
            other => Self::Unknown(other.to_string()),
        }
    }
}

impl EnvStatus {
    /// See [`DeployTarget::from_wire`].
    pub fn from_wire(raw: &str) -> Self {
        match raw {
            "idle" => Self::Idle,
            "provisioning" => Self::Provisioning,
            "live" => Self::Live,
            "error" => Self::Error,
            other => Self::Unknown(other.to_string()),
        }
    }
}

impl JobStatus {
    /// See [`DeployTarget::from_wire`].
    pub fn from_wire(raw: &str) -> Self {
        match raw {
            "queued" => Self::Queued,
            "running" => Self::Running,
            "succeeded" => Self::Succeeded,
            "failed" => Self::Failed,
            other => Self::Unknown(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deploy_target_round_trips_known_values() {
        for (variant, wire) in [
            (DeployTarget::GreenticCloud, "\"greentic_cloud\""),
            (DeployTarget::Aws, "\"aws\""),
            (DeployTarget::Azure, "\"azure\""),
            (DeployTarget::Gcp, "\"gcp\""),
        ] {
            assert_eq!(serde_json::to_string(&variant).unwrap(), wire);
            assert_eq!(serde_json::from_str::<DeployTarget>(wire).unwrap(), variant);
        }
    }

    #[test]
    fn env_status_round_trips_known_values() {
        for (variant, wire) in [
            (EnvStatus::Idle, "\"idle\""),
            (EnvStatus::Provisioning, "\"provisioning\""),
            (EnvStatus::Live, "\"live\""),
            (EnvStatus::Error, "\"error\""),
        ] {
            assert_eq!(serde_json::to_string(&variant).unwrap(), wire);
            assert_eq!(serde_json::from_str::<EnvStatus>(wire).unwrap(), variant);
        }
    }

    #[test]
    fn job_status_round_trips_known_values() {
        for (variant, wire) in [
            (JobStatus::Queued, "\"queued\""),
            (JobStatus::Running, "\"running\""),
            (JobStatus::Succeeded, "\"succeeded\""),
            (JobStatus::Failed, "\"failed\""),
        ] {
            assert_eq!(serde_json::to_string(&variant).unwrap(), wire);
            assert_eq!(serde_json::from_str::<JobStatus>(wire).unwrap(), variant);
        }
    }

    /// The load-bearing one. The admin and the designer are pinned to this
    /// crate by independent git revs, so they will routinely disagree by a
    /// revision or two. An unrecognised value must degrade to `Unknown` — a
    /// strict enum would fail the whole response and blank the environment
    /// list over one new status.
    #[test]
    fn unknown_values_degrade_and_keep_the_original_string() {
        let s: EnvStatus = serde_json::from_str("\"suspended\"").unwrap();
        assert_eq!(s, EnvStatus::Unknown("suspended".to_string()));
        // Round-trips back out unchanged, so a proxy never corrupts a value it
        // did not understand.
        assert_eq!(serde_json::to_string(&s).unwrap(), "\"suspended\"");

        let j: JobStatus = serde_json::from_str("\"cancelled\"").unwrap();
        assert_eq!(j, JobStatus::Unknown("cancelled".to_string()));

        let t: DeployTarget = serde_json::from_str("\"fly\"").unwrap();
        assert_eq!(t, DeployTarget::Unknown("fly".to_string()));
    }

    /// The admin stores these as plain text columns, so it converts from `&str`
    /// rather than from JSON. That conversion is total — there is no failure
    /// case — which is what keeps the admin's projection free of a `panic!` or
    /// a fake fallback arm.
    #[test]
    fn from_wire_is_total() {
        assert_eq!(DeployTarget::from_wire("aws"), DeployTarget::Aws);
        assert_eq!(EnvStatus::from_wire("live"), EnvStatus::Live);
        assert_eq!(JobStatus::from_wire("queued"), JobStatus::Queued);

        assert_eq!(
            EnvStatus::from_wire("suspended"),
            EnvStatus::Unknown("suspended".to_string())
        );
        assert_eq!(EnvStatus::from_wire(""), EnvStatus::Unknown(String::new()));
    }
}
