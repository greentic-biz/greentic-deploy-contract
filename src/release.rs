//! The release catalogue's wire contract (design doc §1, §7, §9).
//!
//! The canonical digest and the compatibility verdict live HERE, not in
//! either consumer: admin and designer both compute them, and two
//! implementations of "what is this release" is how a registered release and
//! a deployed one end up disagreeing with nothing red anywhere.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseKind {
    Platform,
    Application,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseArtifact {
    pub name: String,
    pub version: String,
    /// `sha256:<64 lowercase hex>`.
    pub digest: String,
    /// Rust target triple for a platform binary; `None` for a portable pack.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    /// Where the bytes can be fetched (URL or OCI ref). Not part of the digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyKind {
    Pack,
    Extension,
    Component,
    Provider,
    Runtime,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyPin {
    pub kind: DependencyKind,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_req: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Compatibility {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_runtime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abi: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_capabilities: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_repo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_revision: Option<String>,
    /// Who built it: `designer`, `github-actions`, `admin-scanner`.
    pub builder: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub built_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackDeclaration {
    pub supported: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterReleaseRequest {
    pub kind: ReleaseKind,
    pub publisher: String,
    pub name: String,
    pub version: String,
    pub artifacts: Vec<ReleaseArtifact>,
    #[serde(default)]
    pub dependencies: Vec<DependencyPin>,
    #[serde(default)]
    pub compatibility: Compatibility,
    pub provenance: Provenance,
    pub rollback: RollbackDeclaration,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseRecord {
    pub release_id: String,
    pub release_digest: String,
    pub registered_at: DateTime<Utc>,
    pub registered_by: String,
    #[serde(flatten)]
    pub request: RegisterReleaseRequest,
}

/// The content that names a release. Provenance and artifact `source` are
/// deliberately excluded: a rebuild of identical bytes, or the same bytes
/// served from a mirror, is the same release.
#[derive(Serialize)]
struct Canonical<'a> {
    kind: ReleaseKind,
    publisher: &'a str,
    name: &'a str,
    version: &'a str,
    artifacts: Vec<(&'a str, &'a str, Option<&'a str>, &'a str)>,
    dependencies: Vec<(DependencyKind, &'a str, Option<&'a str>, Option<&'a str>)>,
    min_runtime: Option<&'a str>,
    abi: Option<&'a str>,
    required_capabilities: Vec<&'a str>,
    rollback_supported: bool,
}

pub fn release_digest(req: &RegisterReleaseRequest) -> Result<String, serde_json::Error> {
    let mut artifacts: Vec<_> = req
        .artifacts
        .iter()
        .map(|a| {
            (
                a.name.as_str(),
                a.version.as_str(),
                a.target.as_deref(),
                a.digest.as_str(),
            )
        })
        .collect();
    artifacts.sort();
    let mut dependencies: Vec<_> = req
        .dependencies
        .iter()
        .map(|d| {
            (
                d.kind,
                d.name.as_str(),
                d.version_req.as_deref(),
                d.digest.as_deref(),
            )
        })
        .collect();
    dependencies.sort();
    let mut required_capabilities: Vec<&str> = req
        .compatibility
        .required_capabilities
        .iter()
        .map(String::as_str)
        .collect();
    required_capabilities.sort_unstable();
    required_capabilities.dedup();
    let canonical = Canonical {
        kind: req.kind,
        publisher: &req.publisher,
        name: &req.name,
        version: &req.version,
        artifacts,
        dependencies,
        min_runtime: req.compatibility.min_runtime.as_deref(),
        abi: req.compatibility.abi.as_deref(),
        required_capabilities,
        rollback_supported: req.rollback.supported,
    };
    let bytes = serde_json::to_vec(&canonical)?;
    Ok(format!("sha256:{}", hex_lower(&Sha256::digest(&bytes))))
}

/// Normalise a bare or prefixed sha256 to `sha256:<lower hex>`; `None` when
/// the input is not exactly 64 hex digits.
pub fn sha256_prefixed(input: &str) -> Option<String> {
    let hex = input.strip_prefix("sha256:").unwrap_or(input);
    (hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()))
        .then(|| format!("sha256:{}", hex.to_ascii_lowercase()))
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// What a deployment target can prove about itself.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostFacts {
    /// `None` when the target cannot report it (e.g. a floating image tag).
    #[serde(default)]
    pub runtime_version: Option<String>,
    #[serde(default)]
    pub abi: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum CompatVerdict {
    Compatible,
    /// Nothing is known to be wrong, but something could not be checked.
    Unverified {
        reasons: Vec<String>,
    },
    Incompatible {
        reasons: Vec<String>,
    },
}

pub fn check_compatibility(c: &Compatibility, host: &HostFacts) -> CompatVerdict {
    let mut incompatible = Vec::new();
    let mut unverified = Vec::new();
    for cap in &c.required_capabilities {
        if !host.capabilities.iter().any(|h| h == cap) {
            incompatible.push(format!("capability `{cap}` is not provided by the target"));
        }
    }
    if let Some(abi) = &c.abi
        && !host.abi.iter().any(|h| h == abi)
    {
        incompatible.push(format!("ABI `{abi}` is not provided by the target"));
    }
    if let Some(min) = &c.min_runtime {
        match (
            semver::Version::parse(min),
            host.runtime_version.as_deref().map(semver::Version::parse),
        ) {
            (Err(_), _) => {
                unverified.push(format!("minimum runtime `{min}` is not a semver version"))
            }
            (Ok(_), None) => unverified.push(format!(
                "target runtime version is unknown; requires >= {min}"
            )),
            (Ok(_), Some(Err(_))) => {
                unverified.push("target runtime version is not semver".to_string())
            }
            (Ok(min_v), Some(Ok(have))) if have < min_v => {
                incompatible.push(format!(
                    "target runtime {have} is older than the required {min_v}"
                ));
            }
            _ => {}
        }
    }
    if !incompatible.is_empty() {
        CompatVerdict::Incompatible {
            reasons: incompatible,
        }
    } else if !unverified.is_empty() {
        CompatVerdict::Unverified {
            reasons: unverified,
        }
    } else {
        CompatVerdict::Compatible
    }
}

#[cfg(test)]
#[path = "release_tests.rs"]
mod tests;
