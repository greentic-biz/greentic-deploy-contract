//! Trust rotation v1 (unified release lifecycle, phase 4; design doc §6
//! "Verification and trust maintenance", §10 "Trust and authorisation").
//!
//! A disconnected installation bootstraps its trust out of band (a key file
//! or environment variable). After that, the only way its trust set for a
//! [`TrustDomain`] changes is a [`TrustRotation`] signed by keys it ALREADY
//! trusts for that same domain, with a sequence strictly greater than the
//! last one it applied. Material bundled in a package never establishes its
//! own authority: `apply_rotation` (feature `signing`) takes the current
//! set from the caller and never from the envelope.
//!
//! **Signed schemas never change.** [`TrustRotation`] is
//! `deny_unknown_fields` and [`TrustDomain`] has no catch-all; a new field is
//! a new schema.
//!
//! **What one key may do alone.** A rotation verified with fewer than two
//! distinct signers — the default `apply_rotation`, threshold 1 — may only
//! ADD keys and/or REMOVE ITS OWN signing key(s). Removing any OTHER key
//! requires `apply_rotation_with_threshold` with a threshold of at least 2,
//! so a single leaked key can never evict its peers and keep sole authority.
//! (It can still add a key of its own; that is what revocation of the leaked
//! key, and then removing both by a quorum, is for.) The resulting set must
//! hold at least `max(1, threshold)` keys, so a rotation can never leave a
//! domain that no later rotation could verify; a domain that got there
//! anyway needs the local recovery procedure.
//!
//! **Rotations are domain-scoped, not installation-scoped.** A rotation
//! names a [`TrustDomain`] and no audience: every installation that trusts
//! its signers for that domain may apply it. That is the intent for
//! `vendor_release`; for `execution` and `status_report` keys, which belong
//! to one installation, keep each installation's keys distinct so a rotation
//! signed by them can only ever apply there.
//!
//! **What stays the caller's:** persisting `rotation.sequence` as the new
//! `last_seq` (replay protection is only as good as that write), auditing
//! the change with the signer ids, and the explicit operator acceptance a
//! bundled rotation needs before it is applied at all.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The `schema` value every v1 trust rotation carries.
pub const TRUST_ROTATION_SCHEMA: &str = "greentic.trust-rotation.v1";

/// The DSSE `payloadType` a v1 trust rotation is signed under.
pub const TRUST_ROTATION_PAYLOAD_TYPE: &str = "application/vnd.greentic.trust-rotation.v1+json";

/// The separate authorities a rotation applies to. Keys are never shared
/// across domains, and a rotation for one never changes another.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustDomain {
    /// Keys that sign offline release envelopes and revocation lists.
    VendorRelease,
    /// Keys that sign execution authorisations.
    Execution,
    /// Keys that sign an installation's status reports.
    StatusReport,
}

/// One signed change to one domain's trust set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustRotation {
    /// Always [`TRUST_ROTATION_SCHEMA`].
    pub schema: String,
    pub domain: TrustDomain,
    /// Strictly greater than the last sequence applied for `domain`; `>= 1`.
    pub sequence: u64,
    /// Keys to trust, each `ed25519:<std base64 of 32 bytes>`.
    #[serde(default)]
    pub add: Vec<String>,
    /// Keys to stop trusting, same format; each must be currently trusted.
    #[serde(default)]
    pub remove: Vec<String>,
    /// Not applicable before this instant.
    pub effective_at: DateTime<Utc>,
    /// Not applicable at or after this instant.
    pub expires_at: DateTime<Utc>,
}

/// Why a [`TrustRotation`] refuses to validate.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrustError {
    UnknownSchema(String),
    /// `0`, or above [`crate::MAX_SEQUENCE`].
    BadSequence,
    /// Neither `add` nor `remove` names a key.
    NoChange,
    /// An entry does not start with `ed25519:` or has nothing after it.
    BadKeyFormat(String),
    DuplicateKey(String),
    /// One key is both added and removed.
    KeyInAddAndRemove(String),
    /// `expires_at` is not after `effective_at`.
    WindowInverted,
}

impl std::fmt::Display for TrustError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownSchema(s) => write!(f, "unknown schema `{s}`"),
            Self::BadSequence => f.write_str("sequence must be in 1..=MAX_SEQUENCE"),
            Self::NoChange => f.write_str("the rotation adds and removes nothing"),
            Self::BadKeyFormat(k) => write!(f, "`{k}` is not an `ed25519:<base64>` key"),
            Self::DuplicateKey(k) => write!(f, "key `{k}` is listed twice"),
            Self::KeyInAddAndRemove(k) => write!(f, "key `{k}` is both added and removed"),
            Self::WindowInverted => f.write_str("expires_at is not after effective_at"),
        }
    }
}

impl std::error::Error for TrustError {}

impl TrustRotation {
    /// Refuse a rotation that is malformed on its own terms. Whether each
    /// key decodes, whether the signers are trusted, the sequence and the
    /// clock are `apply_rotation`'s checks (feature `signing`).
    pub fn validate(&self) -> Result<(), TrustError> {
        if self.schema != TRUST_ROTATION_SCHEMA {
            return Err(TrustError::UnknownSchema(self.schema.clone()));
        }
        if self.sequence == 0 || self.sequence > crate::MAX_SEQUENCE {
            return Err(TrustError::BadSequence);
        }
        if self.add.is_empty() && self.remove.is_empty() {
            return Err(TrustError::NoChange);
        }
        let mut added = BTreeSet::new();
        for key in &self.add {
            check_format(key)?;
            if !added.insert(key.as_str()) {
                return Err(TrustError::DuplicateKey(key.clone()));
            }
        }
        let mut removed = BTreeSet::new();
        for key in &self.remove {
            check_format(key)?;
            if !removed.insert(key.as_str()) {
                return Err(TrustError::DuplicateKey(key.clone()));
            }
            if added.contains(key.as_str()) {
                return Err(TrustError::KeyInAddAndRemove(key.clone()));
            }
        }
        if self.expires_at <= self.effective_at {
            return Err(TrustError::WindowInverted);
        }
        Ok(())
    }

    /// `effective_at <= now < expires_at`.
    pub fn is_applicable_at(&self, now: DateTime<Utc>) -> bool {
        self.effective_at <= now && now < self.expires_at
    }
}

fn check_format(key: &str) -> Result<(), TrustError> {
    match key.strip_prefix("ed25519:") {
        // No comma and no whitespace: one entry is exactly one key, so a
        // list-shaped entry can never smuggle a second key past `validate`.
        Some(rest)
            if !rest.is_empty()
                && !rest.contains(',')
                && !rest.chars().any(char::is_whitespace) =>
        {
            Ok(())
        }
        _ => Err(TrustError::BadKeyFormat(key.to_string())),
    }
}

#[cfg(feature = "signing")]
pub use signing::*;

#[cfg(feature = "signing")]
mod signing {
    use ed25519_dalek::{SigningKey, VerifyingKey};

    use super::{TRUST_ROTATION_PAYLOAD_TYPE, TrustDomain, TrustError, TrustRotation};
    use crate::dsse::{DsseEnvelope, TrustedKeyError, parse_trusted_keys};
    use crate::revocation::RevocationList;
    use crate::signed::{OpenError, OpenSpec, Opened, SignError, open_typed, sign_typed};

    /// A trust set bound to the domain it is for. Every typed `verify_*`
    /// takes one and refuses a set for the wrong domain, so an execution key
    /// set can never verify an offline release even if a key is shared.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct TrustSet {
        pub domain: TrustDomain,
        pub keys: Vec<VerifyingKey>,
    }

    impl TrustSet {
        pub fn new(domain: TrustDomain, keys: Vec<VerifyingKey>) -> Self {
            Self { domain, keys }
        }

        /// Parse a `GREENTIC_*_TRUSTED_KEYS`-shaped list for `domain`.
        pub fn parse(domain: TrustDomain, list: &str) -> Result<Self, TrustedKeyError> {
            parse_trusted_keys(list).map(|keys| Self { domain, keys })
        }
    }

    /// Validate, then sign `rotation` with every key in `keys`.
    pub fn sign_rotation(
        rotation: &TrustRotation,
        keys: &[&SigningKey],
    ) -> Result<DsseEnvelope, SignError<TrustError>> {
        sign_typed(
            TRUST_ROTATION_PAYLOAD_TYPE,
            rotation,
            TrustRotation::validate,
            keys,
        )
    }

    /// Verify, parse and validate a rotation envelope against `trusted`
    /// WITHOUT applying it — for an operator to inspect before accepting.
    /// The rotation must name `trusted.domain`.
    pub fn verify_rotation(
        env: &DsseEnvelope,
        trusted: &TrustSet,
        threshold: usize,
        revocation: Option<&RevocationList>,
    ) -> Result<Opened<TrustRotation>, OpenError<TrustError>> {
        let opened = open_typed(
            env,
            OpenSpec {
                payload_type: TRUST_ROTATION_PAYLOAD_TYPE,
                domain: trusted.domain,
                trusted,
                threshold,
                revocation,
            },
            TrustRotation::validate,
        )?;
        if opened.value.domain != trusted.domain {
            return Err(OpenError::WrongTrustDomain {
                expected: trusted.domain,
                found: opened.value.domain,
            });
        }
        Ok(opened)
    }
}

#[cfg(feature = "signing")]
#[path = "trust_apply.rs"]
mod apply;
#[cfg(feature = "signing")]
pub use apply::*;

#[cfg(test)]
#[path = "trust_tests.rs"]
mod tests;
