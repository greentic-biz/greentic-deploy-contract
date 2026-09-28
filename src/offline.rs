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
//! **What stays the importer's:** [`OfflineReleaseManifest::admit`] (the
//! audience names THIS installation, `now < not_after`); hashing every file
//! against the inventory; checking that `internal_registry` / `installed`
//! sources are actually present; verifying bundled trust material (R12
//! layout) against keys it already trusts; and persisting the accepted
//! revocation list it verified with.
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

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::release::{DependencyKind, DependencyPin, RegisterReleaseRequest};

pub use validate::is_safe_relative_path;

/// The `schema` value every v1 offline manifest carries.
pub const OFFLINE_RELEASE_SCHEMA: &str = "greentic.offline-release.v1";

/// The DSSE `payloadType` a v1 offline manifest is signed under.
pub const OFFLINE_RELEASE_PAYLOAD_TYPE: &str = "application/vnd.greentic.offline-release.v1+json";

/// The largest `max_unpacked_bytes` a manifest may declare: 2^50 bytes
/// (1 PiB). Far above any real package, and low enough that an importer's
/// "× 1.1 plus a floor" disk-space arithmetic cannot overflow a `u64`.
pub const MAX_UNPACKED_BYTES: u64 = 1 << 50;

/// The longest inventory path, in bytes.
pub const MAX_PATH_BYTES: usize = 4096;

/// The longest single path segment, in bytes.
pub const MAX_PATH_SEGMENT_BYTES: usize = 255;

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
    /// [`release_digest`](crate::release::release_digest)`(&request)`.
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
    /// See [`is_safe_relative_path`]; unique case-insensitively.
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
    /// Present in a registry reachable from the installation. Always
    /// digest-pinned (`…@sha256:<64 lowercase hex>`): a mutable tag in the
    /// internal registry would satisfy a pin with whatever it points at.
    InternalRegistry { oci_ref: String },
    /// Already installed; only valid in an [`PackageMode::InventoryBased`]
    /// package, which binds to the inventory it was computed against.
    Installed,
}

/// One resolved dependency. `kind`, `name`, `version_req` and `digest` must
/// equal a release's [`DependencyPin`] exactly for that pin to be resolved,
/// and no two entries may share those four (so a pin resolves to exactly one
/// source). When `digest` is set, the source is bound to it: a `packaged`
/// digest must equal it, and an `internal_registry` reference must be pinned
/// to it (`…@sha256:<hex>`).
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
    pub(crate) fn resolves(&self, pin: &DependencyPin) -> bool {
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
///
/// In `complete` mode every artifact of every release request is in
/// `inventory` by digest; an `inventory_based` package may instead rely on
/// the installation inventory it is bound to.
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
    /// `inventory[].bytes`, at most [`MAX_UNPACKED_BYTES`]. Admission checks
    /// disk space against it.
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
    /// Two releases share a `release_id` or a `release_digest`.
    DuplicateRelease(String),
    /// A digest is not `sha256:<64 lowercase hex>`; carries the field name.
    BadDigest(&'static str),
    /// `release_digest` does not equal the digest of `request`.
    ReleaseDigestMismatch(String),
    /// A release's migration declaration fails its own validation.
    BadMigration {
        release_id: String,
        error: crate::migration::MigrationError,
    },
    /// A `complete` package lacks an artifact of one of its releases.
    ArtifactMissing {
        release_id: String,
        digest: String,
    },
    /// An artifact's `target` is not among the declared `architectures`.
    UnsupportedTarget {
        release_id: String,
        target: String,
    },
    /// See [`is_safe_relative_path`].
    UnsafePath(String),
    /// Two paths that are equal, or equal ignoring ASCII case.
    DuplicatePath(String),
    /// A release's dependency pin has no matching closure entry; carries the
    /// release id and the dependency name.
    UnresolvedDependency {
        release_id: String,
        name: String,
    },
    /// Two closure entries for one `(kind, name, version_req, digest)`.
    DuplicateClosureEntry(String),
    /// A `packaged` closure source names a digest absent from the inventory.
    PackagedDigestMissing(String),
    /// A closure source disagrees with the entry's pinned `digest`.
    SourceDigestMismatch(String),
    /// An `internal_registry` reference is not `…@sha256:<64 lowercase hex>`.
    UnpinnedOciRef(String),
    /// An `installed` source in a `complete` package.
    InstalledInCompletePackage(String),
    EmptyOciRef,
    /// A trust-statement digest listed twice, or equal to `revocation`.
    DuplicateTrustMaterial(String),
    /// `not_after` is not after `created_at`.
    WindowInverted,
    /// `max_unpacked_bytes` is below the inventory total (or it overflows).
    UnpackedSizeTooSmall,
    /// `max_unpacked_bytes` exceeds [`MAX_UNPACKED_BYTES`].
    UnpackedSizeTooLarge,
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
            Self::BadMigration { release_id, error } => {
                write!(f, "release `{release_id}` migration: {error}")
            }
            Self::ArtifactMissing { release_id, digest } => write!(
                f,
                "release `{release_id}` artifact `{digest}` is not in the package"
            ),
            Self::UnsupportedTarget { release_id, target } => write!(
                f,
                "release `{release_id}` targets `{target}`, which the package does not declare"
            ),
            Self::UnsafePath(p) => write!(f, "path `{p}` is not a safe relative path"),
            Self::DuplicatePath(p) => write!(f, "path `{p}` is listed twice"),
            Self::UnresolvedDependency { release_id, name } => write!(
                f,
                "release `{release_id}` dependency `{name}` is not resolved by the closure"
            ),
            Self::DuplicateClosureEntry(n) => write!(f, "closure entry `{n}` is listed twice"),
            Self::PackagedDigestMissing(d) => {
                write!(f, "packaged dependency `{d}` is not in the inventory")
            }
            Self::SourceDigestMismatch(n) => {
                write!(
                    f,
                    "closure entry `{n}` source does not match its pinned digest"
                )
            }
            Self::UnpinnedOciRef(r) => write!(f, "`{r}` is not pinned by sha256 digest"),
            Self::InstalledInCompletePackage(n) => {
                write!(f, "`{n}` is marked installed in a complete package")
            }
            Self::EmptyOciRef => f.write_str("an oci_ref is empty"),
            Self::DuplicateTrustMaterial(d) => write!(f, "trust material `{d}` is listed twice"),
            Self::WindowInverted => f.write_str("not_after is not after created_at"),
            Self::UnpackedSizeTooSmall => {
                f.write_str("max_unpacked_bytes is below the inventory's total size")
            }
            Self::UnpackedSizeTooLarge => {
                write!(f, "max_unpacked_bytes exceeds {MAX_UNPACKED_BYTES}")
            }
        }
    }
}

impl std::error::Error for OfflineError {}

/// Why [`OfflineReleaseManifest::admit`] refused a verified manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OfflineAdmitError {
    /// The audience does not name this installation.
    NotForThisInstallation,
    /// `now >= not_after`.
    Expired,
}

impl std::fmt::Display for OfflineAdmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotForThisInstallation => f.write_str("package is for another installation"),
            Self::Expired => f.write_str("package has expired"),
        }
    }
}

impl std::error::Error for OfflineAdmitError {}

#[path = "offline_validate.rs"]
mod validate;

#[cfg(feature = "signing")]
pub use signing::*;

#[cfg(feature = "signing")]
mod signing {
    use ed25519_dalek::SigningKey;

    use super::{OFFLINE_RELEASE_PAYLOAD_TYPE, OfflineError, OfflineReleaseManifest};
    use crate::dsse::DsseEnvelope;
    use crate::revocation::RevocationList;
    use crate::signed::{OpenError, OpenSpec, Opened, SignError, open_typed, sign_typed};
    use crate::trust::{TrustDomain, TrustSet};

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
    /// VENDOR-RELEASE set; any other domain is refused), none revoked by
    /// `revocation`, signed `env`; parse and validate; and refuse a manifest
    /// carrying a release `revocation` revokes. Then call
    /// [`OfflineReleaseManifest::admit`].
    pub fn verify_offline(
        env: &DsseEnvelope,
        trusted: &TrustSet,
        threshold: usize,
        revocation: Option<&RevocationList>,
    ) -> Result<Opened<OfflineReleaseManifest>, OpenError<OfflineError>> {
        let opened = open_typed(
            env,
            OpenSpec {
                payload_type: OFFLINE_RELEASE_PAYLOAD_TYPE,
                domain: TrustDomain::VendorRelease,
                trusted,
                threshold,
                revocation,
            },
            OfflineReleaseManifest::validate,
        )?;
        if let Some(list) = revocation
            && let Some(entry) = opened
                .value
                .releases
                .iter()
                .find(|r| list.is_revoked_release(&r.release_digest))
        {
            return Err(OpenError::RevokedRelease(entry.release_digest.clone()));
        }
        Ok(opened)
    }
}

#[cfg(test)]
#[path = "offline_tests.rs"]
pub(crate) mod tests;
