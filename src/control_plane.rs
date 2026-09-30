//! The Greentic control plane (admin + designer images + their chart) as a
//! platform release: one composite, tested set.
//!
//! A control-plane release is an ordinary [`RegisterReleaseRequest`] of kind
//! `platform` named [`CONTROL_PLANE_RELEASE_NAME`] whose artifacts are this
//! manifest (JSON, media type [`CONTROL_PLANE_MANIFEST_MEDIA_TYPE`]) and the
//! chart `.tgz`, and whose `Runtime` dependency pins name each image by its
//! OCI index digest (`image:<internal name>`). Because `release_digest` covers
//! every artifact digest and every pin digest, the images are bound into the
//! signed release without any change to an existing signed schema.
//!
//! Images are never packaged in an offline envelope: an index digest is not
//! the byte digest of any file, so a `packaged` closure entry cannot express
//! one. They resolve to `internal_registry` entries and are proven present
//! by the installation.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::release::{DependencyKind, RegisterReleaseRequest, ReleaseKind};

pub const CONTROL_PLANE_SCHEMA: &str = "greentic.control-plane-release.v1";
pub const CONTROL_PLANE_RELEASE_NAME: &str = "greentic-control-plane";
pub const CONTROL_PLANE_MANIFEST_MEDIA_TYPE: &str =
    "application/vnd.greentic.control-plane.v1+json";
/// Contains `helm`, so the admin's envelope builder files it under `charts/`.
pub const HELM_CHART_MEDIA_TYPE: &str = "application/vnd.cncf.helm.chart.content.v1.tar+gzip";
pub const IMAGE_PIN_PREFIX: &str = "image:";

/// One replaceable process of the control plane.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Component {
    Admin,
    Designer,
}

impl Component {
    pub const ALL: [Component; 2] = [Component::Admin, Component::Designer];

    /// The repository name inside an installation's registry — what
    /// `deploy/helm/scripts/save-images.sh` names the image.
    pub fn internal_name(self) -> &'static str {
        match self {
            Component::Admin => "greentic-admin",
            Component::Designer => "greentic-designer",
        }
    }

    /// Short lowercase name, equal to the wire spelling (`admin`, `designer`).
    pub fn short_name(self) -> &'static str {
        match self {
            Component::Admin => "admin",
            Component::Designer => "designer",
        }
    }

    /// Inverse of [`Component::short_name`].
    pub fn from_short(s: &str) -> Option<Component> {
        Component::ALL.into_iter().find(|c| c.short_name() == s)
    }

    /// The chart value that pins this component's image by digest.
    pub fn digest_value_key(self) -> &'static str {
        match self {
            Component::Admin => "admin.image.digest",
            Component::Designer => "designer.image.digest",
        }
    }

    /// The chart value naming this component's repository.
    pub fn repository_value_key(self) -> &'static str {
        match self {
            Component::Admin => "admin.image.repository",
            Component::Designer => "designer.image.repository",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentImage {
    pub component: Component,
    /// Where the vendor publishes it, e.g. `ghcr.io/greentic-biz/greentic-designer`.
    pub source_repository: String,
    /// The multi-platform OCI index digest.
    pub index_digest: String,
    /// `os/arch[/variant]` → that platform's manifest digest. A registry
    /// loaded with a single-platform bundle holds one of these, not the index.
    pub platform_digests: BTreeMap<String, String>,
    /// The component's own Cargo version (semver).
    pub app_version: String,
    /// The highest migration version embedded in this image's binary.
    pub schema_head: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChartRef {
    pub name: String,
    pub version: String,
    pub digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlPlaneManifest {
    pub schema: String,
    /// Equal to the release's `version`.
    pub version: String,
    pub components: Vec<ComponentImage>,
    pub chart: ChartRef,
    /// Semver requirement the RUNNING admin must satisfy for this upgrade.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upgrade_from: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlPlaneError {
    WrongSchema,
    NoComponents,
    DuplicateComponent(Component),
    BadDigest(&'static str),
    BadPlatform(String),
    NoPlatforms(Component),
    BadVersion(&'static str),
    BadSchemaHead(Component),
    BadUpgradeFrom,
    BlankRepository(Component),
}

impl std::fmt::Display for ControlPlaneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ControlPlaneError {}

fn digest_ok(d: &str) -> bool {
    crate::sha256_prefixed(d).as_deref() == Some(d)
}

fn platform_ok(p: &str) -> bool {
    let parts: Vec<&str> = p.split('/').collect();
    (2..=3).contains(&parts.len())
        && parts.iter().all(|s| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
}

const INDEX_FIELDS: [&str; 2] = ["components[0].index_digest", "components[1].index_digest"];
const VERSION_FIELDS: [&str; 2] = ["components[0].app_version", "components[1].app_version"];

impl ControlPlaneManifest {
    pub fn validate(&self) -> Result<(), ControlPlaneError> {
        if self.schema != CONTROL_PLANE_SCHEMA {
            return Err(ControlPlaneError::WrongSchema);
        }
        if semver::Version::parse(&self.version).is_err() {
            return Err(ControlPlaneError::BadVersion("version"));
        }
        if self.components.is_empty() {
            return Err(ControlPlaneError::NoComponents);
        }
        let mut seen = BTreeSet::new();
        for (i, c) in self.components.iter().enumerate() {
            if !seen.insert(c.component) {
                return Err(ControlPlaneError::DuplicateComponent(c.component));
            }
            if c.source_repository.trim().is_empty() {
                return Err(ControlPlaneError::BlankRepository(c.component));
            }
            if !digest_ok(&c.index_digest) {
                return Err(ControlPlaneError::BadDigest(
                    INDEX_FIELDS
                        .get(i)
                        .copied()
                        .unwrap_or("components[].index_digest"),
                ));
            }
            if c.platform_digests.is_empty() {
                return Err(ControlPlaneError::NoPlatforms(c.component));
            }
            for (p, pd) in &c.platform_digests {
                if !platform_ok(p) {
                    return Err(ControlPlaneError::BadPlatform(p.clone()));
                }
                if !digest_ok(pd) {
                    return Err(ControlPlaneError::BadDigest(
                        "components[].platform_digests",
                    ));
                }
            }
            if semver::Version::parse(&c.app_version).is_err() {
                return Err(ControlPlaneError::BadVersion(
                    VERSION_FIELDS
                        .get(i)
                        .copied()
                        .unwrap_or("components[].app_version"),
                ));
            }
            if c.schema_head <= 0 {
                return Err(ControlPlaneError::BadSchemaHead(c.component));
            }
        }
        if !digest_ok(&self.chart.digest) {
            return Err(ControlPlaneError::BadDigest("chart.digest"));
        }
        if let Some(req) = &self.upgrade_from
            && semver::VersionReq::parse(req).is_err()
        {
            return Err(ControlPlaneError::BadUpgradeFrom);
        }
        Ok(())
    }

    pub fn component(&self, c: Component) -> Option<&ComponentImage> {
        self.components.iter().find(|x| x.component == c)
    }
}

/// What a component binary knows about itself at build time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentBuildInfo {
    pub component: Component,
    pub app_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_commit: Option<String>,
    pub embedded_schema_head: i64,
}

/// What a RUNNING component reports: its build info, the head of the
/// database it migrated, and — when the chart passed it — its image digest.
///
/// A `None` `db_schema_head` means "unobserved", not "empty". When one
/// component has pending migrations and another is unobserved, consumers
/// deciding on rollback answer "database restore required": that is the
/// stricter answer and it deliberately hides the unknown.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlPlaneObservation {
    #[serde(flatten)]
    pub build: ComponentBuildInfo,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_schema_head: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_digest: Option<String>,
}

pub fn image_pin_name(c: Component) -> String {
    format!("{IMAGE_PIN_PREFIX}{}", c.internal_name())
}

/// The registry-relative reference an envelope names: `<internal name>@<index digest>`.
/// The installation prefixes its own registry; the vendor never learns it.
pub fn internal_ref(c: &ComponentImage) -> String {
    format!("{}@{}", c.component.internal_name(), c.index_digest)
}

/// OCI platform for an installation architecture (a Rust target triple).
pub fn platform_for_target(triple: &str) -> Option<&'static str> {
    if !triple.contains("-linux") {
        return None;
    }
    match triple.split('-').next() {
        Some("x86_64") => Some("linux/amd64"),
        Some("aarch64") => Some("linux/arm64"),
        _ => None,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConsistencyError {
    NotPlatform,
    WrongName,
    VersionMismatch,
    ManifestNotAnArtifact,
    ChartNotAnArtifact,
    ImagePinMismatch(Component),
    UnexpectedImagePin(String),
}

impl std::fmt::Display for ConsistencyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ConsistencyError {}

/// Does `req` register exactly this manifest? `manifest_digest` is the
/// sha256 of the manifest's bytes as uploaded.
pub fn consistent_with(
    m: &ControlPlaneManifest,
    manifest_digest: &str,
    req: &RegisterReleaseRequest,
) -> Result<(), ConsistencyError> {
    if req.kind != ReleaseKind::Platform {
        return Err(ConsistencyError::NotPlatform);
    }
    if req.name != CONTROL_PLANE_RELEASE_NAME {
        return Err(ConsistencyError::WrongName);
    }
    if req.version != m.version {
        return Err(ConsistencyError::VersionMismatch);
    }
    let has = |digest: &str, media: &str| {
        req.artifacts
            .iter()
            .any(|a| a.digest == digest && a.media_type.as_deref() == Some(media))
    };
    if !has(manifest_digest, CONTROL_PLANE_MANIFEST_MEDIA_TYPE) {
        return Err(ConsistencyError::ManifestNotAnArtifact);
    }
    if !has(&m.chart.digest, HELM_CHART_MEDIA_TYPE) {
        return Err(ConsistencyError::ChartNotAnArtifact);
    }
    for c in &m.components {
        let name = image_pin_name(c.component);
        let ok = req.dependencies.iter().any(|p| {
            p.kind == DependencyKind::Runtime
                && p.name == name
                && p.digest.as_deref() == Some(c.index_digest.as_str())
        });
        if !ok {
            return Err(ConsistencyError::ImagePinMismatch(c.component));
        }
    }
    let known: BTreeSet<String> = m
        .components
        .iter()
        .map(|c| image_pin_name(c.component))
        .collect();
    if let Some(stray) = req
        .dependencies
        .iter()
        .find(|p| p.name.starts_with(IMAGE_PIN_PREFIX) && !known.contains(&p.name))
    {
        return Err(ConsistencyError::UnexpectedImagePin(stray.name.clone()));
    }
    Ok(())
}

#[cfg(test)]
#[path = "control_plane_tests.rs"]
mod tests;

#[cfg(test)]
pub(crate) mod tests_support {
    pub(crate) use super::tests::sample;
}
