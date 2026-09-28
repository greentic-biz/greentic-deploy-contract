//! Trust rotation v1 (unified release lifecycle, phase 4; design doc §6
//! "Verification and trust maintenance", §10 "Trust and authorisation").
//!
//! A disconnected installation bootstraps its trust out of band (a key file
//! or environment variable). After that, the only way its trust set for a
//! [`TrustDomain`] changes is a [`TrustRotation`] signed by keys it ALREADY
//! trusts for that same domain, with a sequence strictly greater than the
//! last one it applied. Material bundled in a package never establishes its
//! own authority: [`apply_rotation`] takes the current set from the caller
//! and never from the envelope.
//!
//! **Signed schemas never change.** [`TrustRotation`] is
//! `deny_unknown_fields` and [`TrustDomain`] has no catch-all; a new field is
//! a new schema.
//!
//! **The self-removal rule.** A rotation may not remove EVERY key that
//! signed it unless the same statement adds a replacement. Otherwise a
//! single statement could retire the authority that issued it and leave the
//! domain governed only by whatever keys it happened not to touch — which is
//! how a leaked-but-not-yet-revoked key would lock its legitimate peers out.
//! A rotation that retires its own signers must name who takes over.
//! Independently, the resulting set is never empty: a domain with no trusted
//! key can never be rotated again and needs the local recovery procedure.
//!
//! [`apply_rotation`]: crate::trust::apply_rotation

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
    ZeroSequence,
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
            Self::ZeroSequence => f.write_str("sequence must be at least 1"),
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
    /// clock are [`apply_rotation`]'s checks.
    pub fn validate(&self) -> Result<(), TrustError> {
        if self.schema != TRUST_ROTATION_SCHEMA {
            return Err(TrustError::UnknownSchema(self.schema.clone()));
        }
        if self.sequence == 0 {
            return Err(TrustError::ZeroSequence);
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
    use chrono::{DateTime, Utc};
    use ed25519_dalek::{SigningKey, VerifyingKey};

    use super::{TRUST_ROTATION_PAYLOAD_TYPE, TrustDomain, TrustError, TrustRotation};
    use crate::dsse::{DsseEnvelope, TrustedKeyError, key_id, parse_trusted_keys};
    use crate::signed::{OpenError, SignError, open_typed, sign_typed};

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
    pub fn verify_rotation(
        env: &DsseEnvelope,
        trusted: &[VerifyingKey],
        threshold: usize,
    ) -> Result<TrustRotation, OpenError<TrustError>> {
        open_typed(
            env,
            TRUST_ROTATION_PAYLOAD_TYPE,
            trusted,
            threshold,
            TrustRotation::validate,
        )
        .map(|(rotation, _)| rotation)
    }

    /// The outcome of [`apply_rotation`]: the new trust set (the caller
    /// persists it) and the rotation it came from (the caller persists
    /// `rotation.sequence` as the new `last_seq`).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct AppliedRotation {
        pub keys: Vec<VerifyingKey>,
        pub rotation: TrustRotation,
        /// [`key_id`]s of the currently trusted keys that signed it.
        pub signer_key_ids: Vec<String>,
    }

    /// Why [`apply_rotation`] refused.
    #[derive(Debug)]
    #[non_exhaustive]
    pub enum RotationError {
        /// The envelope did not verify against the CURRENT set, did not
        /// parse, or failed [`TrustRotation::validate`].
        Envelope(OpenError<TrustError>),
        /// Signed for another domain than the one being rotated.
        WrongDomain {
            expected: TrustDomain,
            found: TrustDomain,
        },
        /// `sequence` is not strictly greater than the last applied one.
        NotNewer { sequence: u64, last: u64 },
        /// `now` is outside `effective_at..expires_at`.
        NotApplicable,
        /// An `add` / `remove` entry does not decode to a key.
        BadKey(TrustedKeyError),
        /// A `remove` entry is not currently trusted; carries its key id.
        UnknownRemoval(String),
        /// An `add` entry is already trusted; carries its key id.
        AlreadyTrusted(String),
        /// Every signer is removed and nothing is added. See the module doc.
        SignersRemovedWithoutReplacement,
        /// The resulting set would be empty.
        EmptyResult,
    }

    impl std::fmt::Display for RotationError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Envelope(e) => write!(f, "rotation envelope refused: {e}"),
                Self::WrongDomain { expected, found } => {
                    write!(f, "rotation is for {found:?}, not {expected:?}")
                }
                Self::NotNewer { sequence, last } => write!(
                    f,
                    "rotation sequence {sequence} is not greater than the last applied {last}"
                ),
                Self::NotApplicable => f.write_str("rotation is not yet effective or has expired"),
                Self::BadKey(e) => write!(f, "rotation names an invalid key: {e}"),
                Self::UnknownRemoval(id) => write!(f, "key {id} to remove is not trusted"),
                Self::AlreadyTrusted(id) => write!(f, "key {id} to add is already trusted"),
                Self::SignersRemovedWithoutReplacement => f.write_str(
                    "the rotation removes every key that signed it without adding a replacement",
                ),
                Self::EmptyResult => f.write_str("the rotation would leave no trusted key"),
            }
        }
    }

    impl std::error::Error for RotationError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::Envelope(e) => Some(e),
                Self::BadKey(e) => Some(e),
                _ => None,
            }
        }
    }

    /// Parse each entry on its own (never a joined list), so an entry's
    /// index in the error is its index in the rotation.
    fn parse_each(entries: &[String]) -> Result<Vec<VerifyingKey>, RotationError> {
        let mut keys = Vec::with_capacity(entries.len());
        for (i, entry) in entries.iter().enumerate() {
            let parsed = parse_trusted_keys(entry).map_err(|e| {
                RotationError::BadKey(match e {
                    TrustedKeyError::UnsupportedAlgorithm(_) => {
                        TrustedKeyError::UnsupportedAlgorithm(i)
                    }
                    TrustedKeyError::BadBase64(_) => TrustedKeyError::BadBase64(i),
                    TrustedKeyError::BadLength(_) => TrustedKeyError::BadLength(i),
                    TrustedKeyError::InvalidKey(_) => TrustedKeyError::InvalidKey(i),
                })
            })?;
            match parsed.as_slice() {
                [key] => keys.push(*key),
                _ => return Err(RotationError::BadKey(TrustedKeyError::BadLength(i))),
            }
        }
        Ok(keys)
    }

    /// [`apply_rotation_with_threshold`] with a threshold of 1.
    pub fn apply_rotation(
        domain: TrustDomain,
        current: &[VerifyingKey],
        env: &DsseEnvelope,
        last_seq: u64,
        now: DateTime<Utc>,
    ) -> Result<AppliedRotation, RotationError> {
        apply_rotation_with_threshold(domain, current, env, last_seq, now, 1)
    }

    /// Verify `env` against `current` (`threshold` distinct signers), check
    /// its domain, sequence and window, and compute the new set: `current`
    /// minus `remove` plus `add`, de-duplicated, in that order. Pure: the
    /// caller persists the result and the sequence, and audits the change.
    pub fn apply_rotation_with_threshold(
        domain: TrustDomain,
        current: &[VerifyingKey],
        env: &DsseEnvelope,
        last_seq: u64,
        now: DateTime<Utc>,
        threshold: usize,
    ) -> Result<AppliedRotation, RotationError> {
        let (rotation, verified) = open_typed(
            env,
            TRUST_ROTATION_PAYLOAD_TYPE,
            current,
            threshold,
            TrustRotation::validate,
        )
        .map_err(RotationError::Envelope)?;
        if rotation.domain != domain {
            return Err(RotationError::WrongDomain {
                expected: domain,
                found: rotation.domain,
            });
        }
        if rotation.sequence <= last_seq {
            return Err(RotationError::NotNewer {
                sequence: rotation.sequence,
                last: last_seq,
            });
        }
        if !rotation.is_applicable_at(now) {
            return Err(RotationError::NotApplicable);
        }
        let add = parse_each(&rotation.add)?;
        let remove = parse_each(&rotation.remove)?;

        let mut keys: Vec<VerifyingKey> = Vec::new();
        for key in current {
            if !keys.contains(key) {
                keys.push(*key);
            }
        }
        for key in &remove {
            if !keys.contains(key) {
                return Err(RotationError::UnknownRemoval(key_id(key)));
            }
        }
        for key in &add {
            if keys.contains(key) {
                return Err(RotationError::AlreadyTrusted(key_id(key)));
            }
        }
        let every_signer_removed = verified
            .signer_key_ids
            .iter()
            .all(|id| remove.iter().any(|k| &key_id(k) == id));
        if every_signer_removed && add.is_empty() {
            return Err(RotationError::SignersRemovedWithoutReplacement);
        }
        keys.retain(|k| !remove.contains(k));
        keys.extend(add);
        if keys.is_empty() {
            return Err(RotationError::EmptyResult);
        }
        Ok(AppliedRotation {
            keys,
            rotation,
            signer_key_ids: verified.signer_key_ids,
        })
    }
}

#[cfg(test)]
#[path = "trust_tests.rs"]
mod tests;
