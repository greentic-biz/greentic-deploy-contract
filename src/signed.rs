//! Typed DSSE wrappers shared by every signed schema that is not the
//! execution authorisation (offline release, trust rotation, revocation,
//! status report).
//!
//! Each schema module exposes its own `sign_*` / `verify_*` pair; this module
//! is the one implementation behind them, so all four agree on the order a
//! receiver must follow:
//!
//! 1. the key set is for the domain this schema belongs to ([`TrustSet`]);
//! 2. no key revoked by the caller's current [`RevocationList`] signed it
//!    (refused outright, even beside enough unrevoked signers);
//! 3. `threshold` distinct remaining keys signed the EXACT bytes;
//! 4. parse (`deny_unknown_fields`), then validate.
//!
//! Nothing is ever re-serialised before the signature check.

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::dsse::{self, DsseEnvelope, VerifyError, key_id, verify_signer_keys};
use crate::revocation::RevocationList;
use crate::trust::{TrustDomain, TrustSet};

/// Why a typed `sign_*` refused to sign.
#[derive(Debug)]
#[non_exhaustive]
pub enum SignError<E> {
    /// The document fails its own `validate()`; every receiver would refuse
    /// it, so it is never signed.
    Invalid(E),
    Serialize(serde_json::Error),
    /// No signing key was supplied. An envelope with no signatures is one
    /// every verifier refuses, so it is refused here instead.
    NoKeys,
}

impl<E: std::fmt::Display> std::fmt::Display for SignError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(e) => write!(f, "refusing to sign an invalid document: {e}"),
            Self::Serialize(e) => write!(f, "could not serialise the document: {e}"),
            Self::NoKeys => f.write_str("no signing key supplied"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for SignError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Invalid(e) => Some(e),
            Self::Serialize(e) => Some(e),
            Self::NoKeys => None,
        }
    }
}

/// Why a typed `verify_*` refused an envelope.
#[derive(Debug)]
#[non_exhaustive]
pub enum OpenError<E> {
    /// The key set handed in is for another domain than this schema's (or,
    /// for a trust rotation, the rotation names another domain than the
    /// set it is verified against).
    WrongTrustDomain {
        expected: TrustDomain,
        found: TrustDomain,
    },
    /// A key the revocation list revokes signed the envelope; carries the
    /// key ids.
    RevokedSigner(Vec<String>),
    /// The document names a release the revocation list revokes.
    RevokedRelease(String),
    /// The DSSE layer refused it: wrong payload type, bad encoding, too few
    /// distinct trusted signers, a zero threshold.
    Signature(VerifyError),
    /// The signed bytes are not this schema (malformed JSON, an unknown
    /// field, an unknown enum value).
    BadPayload(serde_json::Error),
    /// The document parsed but fails its own `validate()` (or, for a
    /// revocation list, does not follow the previous one).
    Invalid(E),
}

impl<E: std::fmt::Display> std::fmt::Display for OpenError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongTrustDomain { expected, found } => {
                write!(f, "key set is for {found:?}, expected {expected:?}")
            }
            Self::RevokedSigner(ids) => write!(f, "signed by revoked key(s) {}", ids.join(", ")),
            Self::RevokedRelease(d) => write!(f, "release `{d}` is revoked"),
            Self::Signature(e) => write!(f, "signature refused: {e}"),
            Self::BadPayload(e) => write!(f, "payload does not parse: {e}"),
            Self::Invalid(e) => write!(f, "document is invalid: {e}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for OpenError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Signature(e) => Some(e),
            Self::BadPayload(e) => Some(e),
            Self::Invalid(e) => Some(e),
            _ => None,
        }
    }
}

/// A verified, parsed and validated document, with who signed it. Every
/// importer audits `signer_key_ids`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opened<T> {
    pub value: T,
    /// The distinct trusted keys that signed, in trust-set order.
    pub signer_keys: Vec<VerifyingKey>,
    /// `dsse::key_id` of each of `signer_keys`, same order.
    pub signer_key_ids: Vec<String>,
}

/// Validate, serialise and sign `value` with every key in `keys`.
pub(crate) fn sign_typed<T, E>(
    payload_type: &str,
    value: &T,
    validate: impl FnOnce(&T) -> Result<(), E>,
    keys: &[&SigningKey],
) -> Result<DsseEnvelope, SignError<E>>
where
    T: Serialize,
{
    if keys.is_empty() {
        return Err(SignError::NoKeys);
    }
    validate(value).map_err(SignError::Invalid)?;
    let payload = serde_json::to_vec(value).map_err(SignError::Serialize)?;
    Ok(dsse::sign_bytes(payload_type, &payload, keys))
}

/// What [`open_typed`] checks the envelope against.
pub(crate) struct OpenSpec<'a> {
    pub payload_type: &'a str,
    /// The domain this schema's signers belong to.
    pub domain: TrustDomain,
    pub trusted: &'a TrustSet,
    pub threshold: usize,
    pub revocation: Option<&'a RevocationList>,
}

/// Steps 1–4 of the module doc.
pub(crate) fn open_typed<T, E>(
    env: &DsseEnvelope,
    spec: OpenSpec<'_>,
    validate: impl FnOnce(&T) -> Result<(), E>,
) -> Result<Opened<T>, OpenError<E>>
where
    T: DeserializeOwned,
{
    if spec.trusted.domain != spec.domain {
        return Err(OpenError::WrongTrustDomain {
            expected: spec.domain,
            found: spec.trusted.domain,
        });
    }
    let (allowed, revoked): (Vec<VerifyingKey>, Vec<VerifyingKey>) = spec
        .trusted
        .keys
        .iter()
        .partition(|k| !spec.revocation.is_some_and(|r| r.is_revoked_key(k)));
    // A revoked key's signature is refused outright, even beside enough
    // unrevoked ones: a statement a revoked key vouched for is suspect.
    if !revoked.is_empty()
        && let Ok((_, by_revoked)) = verify_signer_keys(env, spec.payload_type, &revoked, 1)
    {
        return Err(OpenError::RevokedSigner(
            by_revoked.iter().map(key_id).collect(),
        ));
    }
    let (payload, signer_keys) =
        verify_signer_keys(env, spec.payload_type, &allowed, spec.threshold)
            .map_err(OpenError::Signature)?;
    let value: T = serde_json::from_slice(&payload).map_err(OpenError::BadPayload)?;
    validate(&value).map_err(OpenError::Invalid)?;
    Ok(Opened {
        value,
        signer_key_ids: signer_keys.iter().map(key_id).collect(),
        signer_keys,
    })
}
