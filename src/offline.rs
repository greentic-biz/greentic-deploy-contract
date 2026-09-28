//! Offline release envelope v1 (unified release lifecycle, phase 4; design
//! doc §6 "Offline package contract").
//!
//! An [`OfflineReleaseManifest`] is the signed metadata of a package that
//! carries one or more releases to a DISCONNECTED installation: who it is
//! for, what it contains (a digest inventory of every packaged file), where
//! each dependency comes from, and how large it may unpack. The vendor signs
//! it with the release-signing key (never the execution key); the local
//! admin verifies it into quarantine before anything is promoted.
//!
//! **This manifest is portable vendor metadata, not an executable plan.**
//! Importing it never deploys: the local admin resolves its own inventory and
//! signs its own execution authorisations.
//!
//! **Signed schemas never change.** Every type defined here is
//! `deny_unknown_fields`, and no enum has a `#[serde(other)]` catch-all: a
//! field or value this build does not know is one it cannot enforce, so the
//! envelope is refused. A new field is a new schema (`…v2`), never an
//! additive change to v1. The embedded [`RegisterReleaseRequest`] is the
//! catalogue's own wire type and keeps that type's (additive) rules; what
//! pins it is the `release_digest` beside it, which [`validate`] recomputes.
//!
//! [`validate`]: OfflineReleaseManifest::validate

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::execution::{is_clean_identifier, is_sha256_digest};
use crate::release::{DependencyKind, DependencyPin, RegisterReleaseRequest, release_digest};

/// The `schema` value every v1 offline manifest carries.
pub const OFFLINE_RELEASE_SCHEMA: &str = "greentic.offline-release.v1";

/// The DSSE `payloadType` a v1 offline manifest is signed under.
pub const OFFLINE_RELEASE_PAYLOAD_TYPE: &str = "application/vnd.greentic.offline-release.v1+json";

/// Which installations may import the package. Never empty: a package for
/// "anyone" is exactly what a stolen download would be.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Audience {
    pub installation_ids: Vec<String>,
    #[serde(default)]
    pub owner_ref: Option<String>,
}

/// One release carried by the package.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseEntry {
    pub release_id: String,
    /// `sha256:<64 lowercase hex>`; must equal
    /// [`release_digest`]`(&request)`.
    pub release_digest: String,
    pub request: RegisterReleaseRequest,
}

/// What a packaged file is. No catch-all: an unknown role is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactRole {
    Pack,
    Bundle,
    Binary,
    Image,
    Chart,
    Sbom,
    Provenance,
}

/// One file inside the package.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackagedArtifact {
    /// Relative, `/`-separated, no `..`, `.` or empty segment, no backslash.
    pub path: String,
    /// `sha256:<64 lowercase hex>` of the file's bytes.
    pub digest: String,
    pub bytes: u64,
    pub role: ArtifactRole,
    /// The OCI reference an `image` / `chart` is loaded into, when it has one.
    #[serde(default)]
    pub oci_ref: Option<String>,
}

/// Where a dependency comes from on the disconnected side.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClosureSource {
    /// Inside this package; `digest` must be in the inventory.
    Packaged { digest: String },
    /// Present in a registry reachable from the installation.
    InternalRegistry { oci_ref: String },
    /// Already installed; only valid in an [`PackageMode::InventoryBased`]
    /// package, which binds to the inventory it was computed against.
    Installed,
}

/// One resolved dependency. `kind`, `name`, `version_req` and `digest` must
/// equal a release's [`DependencyPin`] exactly for that pin to be resolved.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClosureEntry {
    pub kind: DependencyKind,
    pub name: String,
    #[serde(default)]
    pub version_req: Option<String>,
    #[serde(default)]
    pub digest: Option<String>,
    pub source: ClosureSource,
}

impl ClosureEntry {
    fn resolves(&self, pin: &DependencyPin) -> bool {
        self.kind == pin.kind
            && self.name == pin.name
            && self.version_req == pin.version_req
            && self.digest == pin.digest
    }
}

/// The dependency closure of every release in the package.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyClosure {
    pub entries: Vec<ClosureEntry>,
}

/// Complete (the default) or inventory-based (omits what is installed).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PackageMode {
    Complete,
    /// Bound to the digest of the imported installation inventory it was
    /// computed against; import fails preflight when local content is
    /// missing.
    InventoryBased {
        inventory_digest: String,
    },
}

/// The signed metadata of an offline release package. See the module doc.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineReleaseManifest {
    /// Always [`OFFLINE_RELEASE_SCHEMA`].
    pub schema: String,
    pub envelope_id: String,
    pub created_at: DateTime<Utc>,
    /// Import is refused at or after this instant (the importer's clock).
    pub not_after: DateTime<Utc>,
    pub audience: Audience,
    pub releases: Vec<ReleaseEntry>,
    pub inventory: Vec<PackagedArtifact>,
    pub closure: DependencyClosure,
    /// Supported architectures (Rust target triples); empty for a
    /// portable-only package.
    #[serde(default)]
    pub architectures: Vec<String>,
    pub mode: PackageMode,
    /// Digest of the bundled signed revocation envelope, if any. Bundled
    /// trust material never establishes its own authority: the importer
    /// verifies it against keys it ALREADY trusts.
    #[serde(default)]
    pub revocation: Option<String>,
    /// Digests of bundled signed trust-rotation envelopes; same rule.
    #[serde(default)]
    pub trust_statements: Vec<String>,
    /// Upper bound on everything the package unpacks to; at least the sum of
    /// `inventory[].bytes`. Admission checks disk space against it.
    pub max_unpacked_bytes: u64,
}

/// Why an [`OfflineReleaseManifest`] refuses to validate. Nothing here
/// panics.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OfflineError {
    UnknownSchema(String),
    /// A required identifier is empty or padded with whitespace.
    BadIdentifier(&'static str),
    EmptyAudience,
    DuplicateInstallation(String),
    NoReleases,
    DuplicateRelease(String),
    /// A digest is not `sha256:<64 lowercase hex>`; carries the field name.
    BadDigest(&'static str),
    /// `release_digest` does not equal the digest of `request`.
    ReleaseDigestMismatch(String),
    /// Absolute, backslashed, or with a `..` / `.` / empty segment.
    UnsafePath(String),
    DuplicatePath(String),
    /// A release's dependency pin has no matching closure entry; carries the
    /// release id and the dependency name.
    UnresolvedDependency {
        release_id: String,
        name: String,
    },
    /// A `packaged` closure source names a digest absent from the inventory.
    PackagedDigestMissing(String),
    /// An `installed` source in a `complete` package.
    InstalledInCompletePackage(String),
    EmptyOciRef,
    /// `not_after` is not after `created_at`.
    WindowInverted,
    /// `max_unpacked_bytes` is below the inventory total (or it overflows).
    UnpackedSizeTooSmall,
}

impl std::fmt::Display for OfflineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownSchema(s) => write!(f, "unknown schema `{s}`"),
            Self::BadIdentifier(n) => write!(f, "`{n}` is empty or has surrounding whitespace"),
            Self::EmptyAudience => f.write_str("the audience names no installation"),
            Self::DuplicateInstallation(i) => write!(f, "installation `{i}` is listed twice"),
            Self::NoReleases => f.write_str("the package carries no release"),
            Self::DuplicateRelease(d) => write!(f, "release `{d}` is listed twice"),
            Self::BadDigest(n) => write!(f, "`{n}` is not sha256:<64 lowercase hex>"),
            Self::ReleaseDigestMismatch(id) => {
                write!(f, "release `{id}` digest does not match its request")
            }
            Self::UnsafePath(p) => write!(f, "path `{p}` is not a safe relative path"),
            Self::DuplicatePath(p) => write!(f, "path `{p}` is listed twice"),
            Self::UnresolvedDependency { release_id, name } => write!(
                f,
                "release `{release_id}` dependency `{name}` is not resolved by the closure"
            ),
            Self::PackagedDigestMissing(d) => {
                write!(f, "packaged dependency `{d}` is not in the inventory")
            }
            Self::InstalledInCompletePackage(n) => {
                write!(f, "`{n}` is marked installed in a complete package")
            }
            Self::EmptyOciRef => f.write_str("an oci_ref is empty"),
            Self::WindowInverted => f.write_str("not_after is not after created_at"),
            Self::UnpackedSizeTooSmall => {
                f.write_str("max_unpacked_bytes is below the inventory's total size")
            }
        }
    }
}

impl std::error::Error for OfflineError {}

fn digest(value: &str, field: &'static str) -> Result<(), OfflineError> {
    if is_sha256_digest(value) {
        Ok(())
    } else {
        Err(OfflineError::BadDigest(field))
    }
}

fn ident(value: &str, field: &'static str) -> Result<(), OfflineError> {
    if is_clean_identifier(value) {
        Ok(())
    } else {
        Err(OfflineError::BadIdentifier(field))
    }
}

/// A relative, `/`-separated path with no traversal. Refused rather than
/// normalised: two spellings of one path would be two inventory entries.
pub fn is_safe_relative_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.contains('\0')
        && path
            .split('/')
            .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

impl OfflineReleaseManifest {
    /// Refuse a manifest that is malformed on its own terms. Time admission
    /// (`now < not_after`), the audience matching THIS installation, the
    /// file digests and the availability of `internal_registry` / `installed`
    /// sources are the importer's checks.
    pub fn validate(&self) -> Result<(), OfflineError> {
        if self.schema != OFFLINE_RELEASE_SCHEMA {
            return Err(OfflineError::UnknownSchema(self.schema.clone()));
        }
        ident(&self.envelope_id, "envelope_id")?;
        if self.not_after <= self.created_at {
            return Err(OfflineError::WindowInverted);
        }
        self.validate_audience()?;
        let inventory = self.validate_inventory()?;
        self.validate_releases()?;
        self.validate_closure(&inventory)?;
        for arch in &self.architectures {
            ident(arch, "architectures")?;
        }
        if let PackageMode::InventoryBased { inventory_digest } = &self.mode {
            digest(inventory_digest, "mode.inventory_digest")?;
        }
        if let Some(rev) = &self.revocation {
            digest(rev, "revocation")?;
        }
        for statement in &self.trust_statements {
            digest(statement, "trust_statements")?;
        }
        Ok(())
    }

    fn validate_audience(&self) -> Result<(), OfflineError> {
        if self.audience.installation_ids.is_empty() {
            return Err(OfflineError::EmptyAudience);
        }
        let mut seen = BTreeSet::new();
        for id in &self.audience.installation_ids {
            ident(id, "audience.installation_ids")?;
            if !seen.insert(id.as_str()) {
                return Err(OfflineError::DuplicateInstallation(id.clone()));
            }
        }
        if let Some(owner) = &self.audience.owner_ref {
            ident(owner, "audience.owner_ref")?;
        }
        Ok(())
    }

    /// Returns the set of inventory digests.
    fn validate_inventory(&self) -> Result<BTreeSet<&str>, OfflineError> {
        let mut paths = BTreeSet::new();
        let mut digests = BTreeSet::new();
        let mut total: u64 = 0;
        for item in &self.inventory {
            if !is_safe_relative_path(&item.path) {
                return Err(OfflineError::UnsafePath(item.path.clone()));
            }
            if !paths.insert(item.path.as_str()) {
                return Err(OfflineError::DuplicatePath(item.path.clone()));
            }
            digest(&item.digest, "inventory.digest")?;
            if item.oci_ref.as_deref().is_some_and(|r| r.trim().is_empty()) {
                return Err(OfflineError::EmptyOciRef);
            }
            digests.insert(item.digest.as_str());
            total = total
                .checked_add(item.bytes)
                .ok_or(OfflineError::UnpackedSizeTooSmall)?;
        }
        if self.max_unpacked_bytes < total {
            return Err(OfflineError::UnpackedSizeTooSmall);
        }
        Ok(digests)
    }

    fn validate_releases(&self) -> Result<(), OfflineError> {
        if self.releases.is_empty() {
            return Err(OfflineError::NoReleases);
        }
        let mut seen = BTreeSet::new();
        for entry in &self.releases {
            ident(&entry.release_id, "releases.release_id")?;
            digest(&entry.release_digest, "releases.release_digest")?;
            if !seen.insert(entry.release_digest.as_str()) {
                return Err(OfflineError::DuplicateRelease(entry.release_digest.clone()));
            }
            let computed = release_digest(&entry.request)
                .map_err(|_| OfflineError::ReleaseDigestMismatch(entry.release_id.clone()))?;
            if computed != entry.release_digest {
                return Err(OfflineError::ReleaseDigestMismatch(
                    entry.release_id.clone(),
                ));
            }
            for pin in &entry.request.dependencies {
                if !self.closure.entries.iter().any(|c| c.resolves(pin)) {
                    return Err(OfflineError::UnresolvedDependency {
                        release_id: entry.release_id.clone(),
                        name: pin.name.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    fn validate_closure(&self, inventory: &BTreeSet<&str>) -> Result<(), OfflineError> {
        let complete = matches!(self.mode, PackageMode::Complete);
        for entry in &self.closure.entries {
            ident(&entry.name, "closure.name")?;
            if let Some(d) = &entry.digest {
                digest(d, "closure.digest")?;
            }
            match &entry.source {
                ClosureSource::Packaged { digest: d } => {
                    digest(d, "closure.source.digest")?;
                    if !inventory.contains(d.as_str()) {
                        return Err(OfflineError::PackagedDigestMissing(d.clone()));
                    }
                }
                ClosureSource::InternalRegistry { oci_ref } => {
                    if oci_ref.trim().is_empty() {
                        return Err(OfflineError::EmptyOciRef);
                    }
                }
                ClosureSource::Installed if complete => {
                    return Err(OfflineError::InstalledInCompletePackage(entry.name.clone()));
                }
                ClosureSource::Installed => {}
            }
        }
        Ok(())
    }
}

#[cfg(feature = "signing")]
pub use signing::*;

#[cfg(feature = "signing")]
mod signing {
    use ed25519_dalek::{SigningKey, VerifyingKey};

    use super::{OFFLINE_RELEASE_PAYLOAD_TYPE, OfflineError, OfflineReleaseManifest};
    use crate::dsse::DsseEnvelope;
    use crate::signed::{OpenError, SignError, open_typed, sign_typed};

    /// Validate, then sign `manifest` with every key in `keys` (a k-of-n
    /// vendor quorum signs once each).
    pub fn sign_offline(
        manifest: &OfflineReleaseManifest,
        keys: &[&SigningKey],
    ) -> Result<DsseEnvelope, SignError<OfflineError>> {
        sign_typed(
            OFFLINE_RELEASE_PAYLOAD_TYPE,
            manifest,
            OfflineReleaseManifest::validate,
            keys,
        )
    }

    /// Verify that `threshold` distinct keys from `trusted` (the
    /// installation's VENDOR-RELEASE trust set) signed `env`, then parse and
    /// validate. The audience, the clock and the file digests are the
    /// importer's checks.
    pub fn verify_offline(
        env: &DsseEnvelope,
        trusted: &[VerifyingKey],
        threshold: usize,
    ) -> Result<OfflineReleaseManifest, OpenError<OfflineError>> {
        open_typed(
            env,
            OFFLINE_RELEASE_PAYLOAD_TYPE,
            trusted,
            threshold,
            OfflineReleaseManifest::validate,
        )
        .map(|(manifest, _)| manifest)
    }
}

#[cfg(test)]
#[path = "offline_tests.rs"]
pub(crate) mod tests;
