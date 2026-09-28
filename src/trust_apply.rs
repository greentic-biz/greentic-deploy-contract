//! [`apply_rotation`]: verify a [`TrustRotation`] against the current set
//! and compute the next one. See the `trust` module doc for the rules.

use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;

use super::{TrustError, TrustRotation, TrustSet, verify_rotation};
use crate::dsse::{DsseEnvelope, TrustedKeyError, key_id, parse_trusted_keys};
use crate::revocation::RevocationList;
use crate::signed::OpenError;

/// The outcome of [`apply_rotation`]: the new trust set (the caller persists
/// it) and the rotation it came from (the caller persists
/// `rotation.sequence` as the new `last_seq`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppliedRotation {
    pub keys: TrustSet,
    pub rotation: TrustRotation,
    /// `dsse::key_id`s of the currently trusted keys that signed it.
    pub signer_key_ids: Vec<String>,
}

/// Why [`apply_rotation`] refused.
#[derive(Debug)]
#[non_exhaustive]
pub enum RotationError {
    /// The envelope did not verify against the CURRENT set (including: a
    /// signer the revocation list revokes, a rotation for another domain),
    /// did not parse, or failed [`TrustRotation::validate`].
    Envelope(OpenError<TrustError>),
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
    /// An `add` entry is revoked by the revocation list; carries its key id.
    AddsRevokedKey(String),
    /// The rotation removes a key that did not sign it, and was verified
    /// with a threshold below 2; carries the key id. See the module doc.
    RemovalNeedsQuorum(String),
    /// The resulting set would hold fewer than `max(1, threshold)` keys.
    TooFewKeys { required: usize, remaining: usize },
}

impl std::fmt::Display for RotationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Envelope(e) => write!(f, "rotation envelope refused: {e}"),
            Self::NotNewer { sequence, last } => write!(
                f,
                "rotation sequence {sequence} is not greater than the last applied {last}"
            ),
            Self::NotApplicable => f.write_str("rotation is not yet effective or has expired"),
            Self::BadKey(e) => write!(f, "rotation names an invalid key: {e}"),
            Self::UnknownRemoval(id) => write!(f, "key {id} to remove is not trusted"),
            Self::AlreadyTrusted(id) => write!(f, "key {id} to add is already trusted"),
            Self::AddsRevokedKey(id) => write!(f, "key {id} to add is revoked"),
            Self::RemovalNeedsQuorum(id) => write!(
                f,
                "removing key {id}, which did not sign the rotation, needs a threshold of at least 2"
            ),
            Self::TooFewKeys {
                required,
                remaining,
            } => write!(
                f,
                "the rotation would leave {remaining} trusted key(s), at least {required} required"
            ),
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

/// Parse each entry on its own (never a joined list), so an entry's index in
/// the error is its index in the rotation.
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

/// [`apply_rotation_with_threshold`] with a threshold of 1: the rotation may
/// only add keys and/or remove its own signer.
pub fn apply_rotation(
    current: &TrustSet,
    env: &DsseEnvelope,
    last_seq: u64,
    now: DateTime<Utc>,
    revocation: Option<&RevocationList>,
) -> Result<AppliedRotation, RotationError> {
    apply_rotation_with_threshold(current, env, last_seq, now, revocation, 1)
}

/// Verify `env` against `current` (`threshold` distinct, unrevoked signers,
/// rotation for `current.domain`), check its sequence and window, and compute
/// the new set: `current` minus `remove` plus `add`, de-duplicated, in that
/// order. Pure: the caller persists the result and the sequence, and audits
/// the change.
pub fn apply_rotation_with_threshold(
    current: &TrustSet,
    env: &DsseEnvelope,
    last_seq: u64,
    now: DateTime<Utc>,
    revocation: Option<&RevocationList>,
    threshold: usize,
) -> Result<AppliedRotation, RotationError> {
    let opened =
        verify_rotation(env, current, threshold, revocation).map_err(RotationError::Envelope)?;
    let rotation = opened.value;
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
    for key in &current.keys {
        if !keys.contains(key) {
            keys.push(*key);
        }
    }
    for key in &remove {
        if !keys.contains(key) {
            return Err(RotationError::UnknownRemoval(key_id(key)));
        }
        // Signers are compared as keys, never by their truncated ids.
        if threshold < 2 && !opened.signer_keys.contains(key) {
            return Err(RotationError::RemovalNeedsQuorum(key_id(key)));
        }
    }
    for key in &add {
        if keys.contains(key) {
            return Err(RotationError::AlreadyTrusted(key_id(key)));
        }
        if revocation.is_some_and(|r| r.is_revoked_key(key)) {
            return Err(RotationError::AddsRevokedKey(key_id(key)));
        }
    }
    keys.retain(|k| !remove.contains(k));
    keys.extend(add);
    let required = threshold.max(1);
    if keys.len() < required {
        return Err(RotationError::TooFewKeys {
            required,
            remaining: keys.len(),
        });
    }
    Ok(AppliedRotation {
        keys: TrustSet::new(current.domain, keys),
        rotation,
        signer_key_ids: opened.signer_key_ids,
    })
}
