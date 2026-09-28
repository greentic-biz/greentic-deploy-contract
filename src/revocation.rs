//! Revocation list v1 (unified release lifecycle, phase 4; design doc §6
//! "Verification and trust maintenance").
//!
//! A [`RevocationList`] is signed by the VENDOR-RELEASE trust set and carried
//! to a disconnected installation inside an offline package (by digest) or
//! imported on its own. It names key ids and release digests that must no
//! longer be accepted, with a sequence (replay: the importer refuses one not
//! greater than the last it applied) and a validity window.
//!
//! **Freshness is the importer's policy, reported here as a fact.**
//! [`RevocationList::freshness`] says whether a list is still inside its
//! window and younger than the local `max_age`; what to do with a stale list
//! (refuse imports, or an explicit, audited, expiring freshness exception) is
//! the caller's decision. An offline system cannot learn of a revocation
//! issued after its latest transfer, and nothing here pretends otherwise.
//!
//! **Lists chain.** `verify_revocation` takes the previously accepted list:
//! a key it revoked cannot sign the next one, the next one must have a
//! greater sequence and must keep every revocation (a list can never
//! un-revoke), and a list signed by a key it revokes itself is refused.
//! Persisting the accepted list is the caller's.
//!
//! **Signed schemas never change**: `deny_unknown_fields`, a new field is a
//! new schema.

use std::collections::BTreeSet;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::execution::{is_clean_identifier, is_sha256_digest};

/// The `schema` value every v1 revocation list carries.
pub const REVOCATION_SCHEMA: &str = "greentic.revocation.v1";

/// The DSSE `payloadType` a v1 revocation list is signed under.
pub const REVOCATION_PAYLOAD_TYPE: &str = "application/vnd.greentic.revocation.v1+json";

/// A signed list of revoked keys and releases.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationList {
    /// Always [`REVOCATION_SCHEMA`].
    pub schema: String,
    pub issuer: String,
    /// `>= 1`; strictly greater than the last list the importer applied.
    pub sequence: u64,
    pub issued_at: DateTime<Utc>,
    /// Stale at or after this instant.
    pub valid_until: DateTime<Utc>,
    /// Key ids as `dsse::key_id` computes them: 16 lowercase hex digits.
    #[serde(default)]
    pub revoked_key_ids: Vec<String>,
    /// `sha256:<64 lowercase hex>` release digests.
    #[serde(default)]
    pub revoked_release_digests: Vec<String>,
}

/// Why a list is not fresh.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StaleReason {
    /// `now >= valid_until`.
    Expired,
    /// `now - issued_at > max_age`.
    TooOld,
    /// `issued_at` is more than `skew` after `now`: the importer's clock or
    /// the issuer's is wrong, and a list from the future proves nothing
    /// about the present.
    IssuedInFuture,
}

/// The outcome of [`RevocationList::freshness`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Freshness {
    Fresh,
    Stale { reason: StaleReason },
}

/// Why a [`RevocationList`] refuses to validate.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RevocationError {
    UnknownSchema(String),
    BadIssuer,
    /// `0`, or above [`crate::MAX_SEQUENCE`].
    BadSequence,
    /// `valid_until` is not after `issued_at`.
    WindowInverted,
    /// Not 16 lowercase hex digits.
    BadKeyId(String),
    BadDigest(String),
    Duplicate(String),
    /// The sequence is not greater than the previously accepted list's.
    NotNewer {
        sequence: u64,
        previous: u64,
    },
    /// The list drops an entry the previously accepted list revoked;
    /// revocation is monotonic and never undone.
    DropsRevocation(String),
}

impl std::fmt::Display for RevocationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownSchema(s) => write!(f, "unknown schema `{s}`"),
            Self::BadIssuer => f.write_str("issuer is empty or has surrounding whitespace"),
            Self::BadSequence => f.write_str("sequence must be in 1..=MAX_SEQUENCE"),
            Self::WindowInverted => f.write_str("valid_until is not after issued_at"),
            Self::BadKeyId(k) => write!(f, "`{k}` is not a 16-hex-digit key id"),
            Self::BadDigest(d) => write!(f, "`{d}` is not sha256:<64 lowercase hex>"),
            Self::Duplicate(v) => write!(f, "`{v}` is listed twice"),
            Self::NotNewer { sequence, previous } => write!(
                f,
                "sequence {sequence} is not greater than the accepted list's {previous}"
            ),
            Self::DropsRevocation(v) => {
                write!(f, "`{v}` was revoked by the accepted list and is missing")
            }
        }
    }
}

impl std::error::Error for RevocationError {}

fn is_key_id(s: &str) -> bool {
    s.len() == 16
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl RevocationList {
    /// Refuse a list that is malformed on its own terms. Sequence replay and
    /// freshness are the importer's checks.
    pub fn validate(&self) -> Result<(), RevocationError> {
        if self.schema != REVOCATION_SCHEMA {
            return Err(RevocationError::UnknownSchema(self.schema.clone()));
        }
        if !is_clean_identifier(&self.issuer) {
            return Err(RevocationError::BadIssuer);
        }
        if self.sequence == 0 || self.sequence > crate::MAX_SEQUENCE {
            return Err(RevocationError::BadSequence);
        }
        if self.valid_until <= self.issued_at {
            return Err(RevocationError::WindowInverted);
        }
        let mut seen = BTreeSet::new();
        for id in &self.revoked_key_ids {
            if !is_key_id(id) {
                return Err(RevocationError::BadKeyId(id.clone()));
            }
            if !seen.insert(id.as_str()) {
                return Err(RevocationError::Duplicate(id.clone()));
            }
        }
        for digest in &self.revoked_release_digests {
            if !is_sha256_digest(digest) {
                return Err(RevocationError::BadDigest(digest.clone()));
            }
            if !seen.insert(digest.as_str()) {
                return Err(RevocationError::Duplicate(digest.clone()));
            }
        }
        Ok(())
    }

    /// Whether the list may still be relied on at `now` under the local
    /// `max_age` policy, tolerating `skew` of issuer clock ahead of ours.
    /// Expiry is checked first, then the future, then age. A negative
    /// `max_age` or `skew` is read as zero.
    pub fn freshness(&self, now: DateTime<Utc>, max_age: Duration, skew: Duration) -> Freshness {
        let max_age = max_age.max(Duration::zero());
        let skew = skew.max(Duration::zero());
        let reason = if now >= self.valid_until {
            Some(StaleReason::Expired)
        } else if self.issued_at - now > skew {
            Some(StaleReason::IssuedInFuture)
        } else if now - self.issued_at > max_age {
            Some(StaleReason::TooOld)
        } else {
            None
        };
        match reason {
            Some(reason) => Freshness::Stale { reason },
            None => Freshness::Fresh,
        }
    }

    /// Refuse a list that does not follow `previous`, the last one this
    /// installation accepted: the sequence must grow and nothing `previous`
    /// revoked may be dropped.
    pub fn follows(&self, previous: &RevocationList) -> Result<(), RevocationError> {
        if self.sequence <= previous.sequence {
            return Err(RevocationError::NotNewer {
                sequence: self.sequence,
                previous: previous.sequence,
            });
        }
        let dropped = previous
            .revoked_key_ids
            .iter()
            .find(|k| !self.revoked_key_ids.contains(k))
            .or_else(|| {
                previous
                    .revoked_release_digests
                    .iter()
                    .find(|d| !self.revoked_release_digests.contains(d))
            });
        match dropped {
            Some(v) => Err(RevocationError::DropsRevocation(v.clone())),
            None => Ok(()),
        }
    }

    /// Whether `key_id` (16 lowercase hex, as `dsse::key_id` returns) is
    /// revoked. Compared exactly.
    pub fn is_revoked_key_id(&self, key_id: &str) -> bool {
        self.revoked_key_ids.iter().any(|k| k == key_id)
    }

    /// Whether `release_digest` is revoked. Compared exactly, so it must be
    /// canonical (`sha256:` + lowercase hex).
    pub fn is_revoked_release(&self, release_digest: &str) -> bool {
        self.revoked_release_digests
            .iter()
            .any(|d| d == release_digest)
    }
}

#[cfg(feature = "signing")]
pub use signing::*;

#[cfg(feature = "signing")]
mod signing {
    use ed25519_dalek::{SigningKey, VerifyingKey};

    use super::{REVOCATION_PAYLOAD_TYPE, RevocationError, RevocationList};
    use crate::dsse::{DsseEnvelope, key_id};
    use crate::signed::{OpenError, OpenSpec, Opened, SignError, open_typed, sign_typed};
    use crate::trust::{TrustDomain, TrustSet};

    impl RevocationList {
        /// Whether `key` is revoked (by its [`key_id`]).
        pub fn is_revoked_key(&self, key: &VerifyingKey) -> bool {
            self.is_revoked_key_id(&key_id(key))
        }

        /// `keys` without the revoked ones, order kept.
        pub fn retain_unrevoked(&self, keys: &[VerifyingKey]) -> Vec<VerifyingKey> {
            keys.iter()
                .filter(|k| !self.is_revoked_key(k))
                .copied()
                .collect()
        }
    }

    /// Validate, then sign `list` with every key in `keys`.
    pub fn sign_revocation(
        list: &RevocationList,
        keys: &[&SigningKey],
    ) -> Result<DsseEnvelope, SignError<RevocationError>> {
        sign_typed(
            REVOCATION_PAYLOAD_TYPE,
            list,
            RevocationList::validate,
            keys,
        )
    }

    /// Verify `env` against the VENDOR-RELEASE trust set (`threshold`
    /// distinct signers not revoked by `previous`), parse, validate, refuse a
    /// list signed by a key it revokes itself, and — when `previous` is the
    /// last accepted list — require [`RevocationList::follows`] it.
    pub fn verify_revocation(
        env: &DsseEnvelope,
        trusted: &TrustSet,
        threshold: usize,
        previous: Option<&RevocationList>,
    ) -> Result<Opened<RevocationList>, OpenError<RevocationError>> {
        let opened = open_typed(
            env,
            OpenSpec {
                payload_type: REVOCATION_PAYLOAD_TYPE,
                domain: TrustDomain::VendorRelease,
                trusted,
                threshold,
                revocation: previous,
            },
            RevocationList::validate,
        )?;
        let self_revoked: Vec<String> = opened
            .signer_key_ids
            .iter()
            .filter(|id| opened.value.is_revoked_key_id(id))
            .cloned()
            .collect();
        if !self_revoked.is_empty() {
            return Err(OpenError::RevokedSigner(self_revoked));
        }
        if let Some(prev) = previous {
            opened.value.follows(prev).map_err(OpenError::Invalid)?;
        }
        Ok(opened)
    }
}

#[cfg(test)]
#[path = "revocation_tests.rs"]
mod tests;
