//! [`OfflineReleaseManifest::validate`] and [`OfflineReleaseManifest::admit`].

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};

use super::{
    ClosureSource, MAX_PATH_BYTES, MAX_PATH_SEGMENT_BYTES, MAX_UNPACKED_BYTES,
    OFFLINE_RELEASE_SCHEMA, OfflineAdmitError, OfflineError, OfflineReleaseManifest, PackageMode,
};
use crate::execution::{is_clean_identifier, is_sha256_digest};
use crate::release::release_digest;

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

/// Windows device names, refused as a segment stem on every platform so a
/// package unpacks identically everywhere.
const RESERVED_STEMS: [&str; 22] = [
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

fn is_safe_segment(seg: &str) -> bool {
    let stem = seg.split('.').next().unwrap_or(seg);
    !seg.is_empty()
        && seg.len() <= MAX_PATH_SEGMENT_BYTES
        && seg != "."
        && seg != ".."
        && !seg.ends_with('.')
        && seg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
        && !RESERVED_STEMS.iter().any(|r| stem.eq_ignore_ascii_case(r))
}

/// A relative, `/`-separated path that unpacks to the same place on every
/// filesystem: at most [`MAX_PATH_BYTES`]; each segment 1..=
/// [`MAX_PATH_SEGMENT_BYTES`] bytes of `[A-Za-z0-9._+-]`, not `.` / `..`,
/// not ending in `.`, not a Windows device name. That excludes absolute
/// paths, backslashes, drive letters and `:` streams, control characters and
/// NUL. Refused rather than normalised: two spellings of one path would be
/// two inventory entries.
pub fn is_safe_relative_path(path: &str) -> bool {
    !path.is_empty() && path.len() <= MAX_PATH_BYTES && path.split('/').all(is_safe_segment)
}

/// The sha256 digest an OCI reference is pinned to, if it is.
fn pinned_digest(oci_ref: &str) -> Option<&str> {
    oci_ref
        .rsplit_once('@')
        .map(|(_, d)| d)
        .filter(|d| is_sha256_digest(d))
}

impl OfflineReleaseManifest {
    /// Refuse a manifest that is malformed on its own terms. Admission
    /// (audience, clock) is [`Self::admit`]; see the module doc for what
    /// else stays the importer's.
    pub fn validate(&self) -> Result<(), OfflineError> {
        if self.schema != OFFLINE_RELEASE_SCHEMA {
            return Err(OfflineError::UnknownSchema(self.schema.clone()));
        }
        ident(&self.envelope_id, "envelope_id")?;
        if self.not_after <= self.created_at {
            return Err(OfflineError::WindowInverted);
        }
        self.validate_audience()?;
        for arch in &self.architectures {
            ident(arch, "architectures")?;
        }
        let inventory = self.validate_inventory()?;
        self.validate_releases(&inventory)?;
        self.validate_closure(&inventory)?;
        if let PackageMode::InventoryBased { inventory_digest } = &self.mode {
            digest(inventory_digest, "mode.inventory_digest")?;
        }
        self.validate_trust_material()
    }

    /// The importer's admission checks for a verified manifest: the audience
    /// names `self_installation_id`, and `now < not_after`.
    pub fn admit(
        &self,
        now: DateTime<Utc>,
        self_installation_id: &str,
    ) -> Result<(), OfflineAdmitError> {
        if !self
            .audience
            .installation_ids
            .iter()
            .any(|id| id == self_installation_id)
        {
            return Err(OfflineAdmitError::NotForThisInstallation);
        }
        if now >= self.not_after {
            return Err(OfflineAdmitError::Expired);
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
            // Case-folded: `A` and `a` are one file on a case-insensitive
            // filesystem.
            if !paths.insert(item.path.to_ascii_lowercase()) {
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
        if self.max_unpacked_bytes > MAX_UNPACKED_BYTES {
            return Err(OfflineError::UnpackedSizeTooLarge);
        }
        if self.max_unpacked_bytes < total {
            return Err(OfflineError::UnpackedSizeTooSmall);
        }
        Ok(digests)
    }

    fn validate_releases(&self, inventory: &BTreeSet<&str>) -> Result<(), OfflineError> {
        if self.releases.is_empty() {
            return Err(OfflineError::NoReleases);
        }
        let complete = matches!(self.mode, PackageMode::Complete);
        let mut ids = BTreeSet::new();
        let mut digests = BTreeSet::new();
        for entry in &self.releases {
            ident(&entry.release_id, "releases.release_id")?;
            digest(&entry.release_digest, "releases.release_digest")?;
            if !ids.insert(entry.release_id.as_str()) {
                return Err(OfflineError::DuplicateRelease(entry.release_id.clone()));
            }
            if !digests.insert(entry.release_digest.as_str()) {
                return Err(OfflineError::DuplicateRelease(entry.release_digest.clone()));
            }
            let computed = release_digest(&entry.request)
                .map_err(|_| OfflineError::ReleaseDigestMismatch(entry.release_id.clone()))?;
            if computed != entry.release_digest {
                return Err(OfflineError::ReleaseDigestMismatch(
                    entry.release_id.clone(),
                ));
            }
            entry
                .request
                .validate()
                .map_err(|error| OfflineError::BadRequest {
                    release_id: entry.release_id.clone(),
                    error,
                })?;
            for artifact in &entry.request.artifacts {
                digest(&artifact.digest, "releases.request.artifacts.digest")?;
                if complete && !inventory.contains(artifact.digest.as_str()) {
                    return Err(OfflineError::ArtifactMissing {
                        release_id: entry.release_id.clone(),
                        digest: artifact.digest.clone(),
                    });
                }
                if let Some(target) = &artifact.target
                    && !self.architectures.is_empty()
                    && !self.architectures.contains(target)
                {
                    return Err(OfflineError::UnsupportedTarget {
                        release_id: entry.release_id.clone(),
                        target: target.clone(),
                    });
                }
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
        let mut seen = BTreeSet::new();
        for entry in &self.closure.entries {
            ident(&entry.name, "closure.name")?;
            if let Some(d) = &entry.digest {
                digest(d, "closure.digest")?;
            }
            let key = (
                entry.kind,
                entry.name.as_str(),
                entry.version_req.as_deref(),
                entry.digest.as_deref(),
            );
            if !seen.insert(key) {
                return Err(OfflineError::DuplicateClosureEntry(entry.name.clone()));
            }
            let pinned_matches = |d: &str| entry.digest.as_deref().is_none_or(|p| p == d);
            match &entry.source {
                ClosureSource::Packaged { digest: d } => {
                    digest(d, "closure.source.digest")?;
                    if !pinned_matches(d) {
                        return Err(OfflineError::SourceDigestMismatch(entry.name.clone()));
                    }
                    if !inventory.contains(d.as_str()) {
                        return Err(OfflineError::PackagedDigestMissing(d.clone()));
                    }
                }
                ClosureSource::InternalRegistry { oci_ref } => {
                    if oci_ref.trim().is_empty() {
                        return Err(OfflineError::EmptyOciRef);
                    }
                    let Some(d) = pinned_digest(oci_ref) else {
                        return Err(OfflineError::UnpinnedOciRef(oci_ref.clone()));
                    };
                    if !pinned_matches(d) {
                        return Err(OfflineError::SourceDigestMismatch(entry.name.clone()));
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

    fn validate_trust_material(&self) -> Result<(), OfflineError> {
        let mut seen = BTreeSet::new();
        if let Some(rev) = &self.revocation {
            digest(rev, "revocation")?;
            seen.insert(rev.as_str());
        }
        for statement in &self.trust_statements {
            digest(statement, "trust_statements")?;
            if !seen.insert(statement.as_str()) {
                return Err(OfflineError::DuplicateTrustMaterial(statement.clone()));
            }
        }
        Ok(())
    }
}
