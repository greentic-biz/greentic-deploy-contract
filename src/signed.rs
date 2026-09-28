//! Typed DSSE wrappers shared by every signed schema that is not the
//! execution authorisation (offline release, trust rotation, revocation,
//! status report).
//!
//! Each schema module exposes its own `sign_*` / `verify_*` pair; this module
//! is the one implementation behind them, so all four agree on the order a
//! receiver must follow: check the signatures over the EXACT signed bytes
//! first ([`dsse::verify_bytes`]), then parse (`deny_unknown_fields`), then
//! validate. Nothing is ever re-serialised before the signature check.

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::dsse::{self, DsseEnvelope, Verified, VerifyError};
use ed25519_dalek::{SigningKey, VerifyingKey};

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
    /// The DSSE layer refused it: wrong payload type, bad encoding, too few
    /// distinct trusted signers, a zero threshold.
    Signature(VerifyError),
    /// The signed bytes are not this schema (malformed JSON, an unknown
    /// field, an unknown enum value).
    BadPayload(serde_json::Error),
    /// The document parsed but fails its own `validate()`.
    Invalid(E),
}

impl<E: std::fmt::Display> std::fmt::Display for OpenError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
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
        }
    }
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

/// Verify k-of-n, then parse, then validate. Returns the document and the
/// verification outcome (the signer key ids) for callers that need them.
pub(crate) fn open_typed<T, E>(
    env: &DsseEnvelope,
    payload_type: &str,
    trusted: &[VerifyingKey],
    threshold: usize,
    validate: impl FnOnce(&T) -> Result<(), E>,
) -> Result<(T, Verified), OpenError<E>>
where
    T: DeserializeOwned,
{
    let verified =
        dsse::verify_bytes(env, payload_type, trusted, threshold).map_err(OpenError::Signature)?;
    let value: T = serde_json::from_slice(&verified.payload).map_err(OpenError::BadPayload)?;
    validate(&value).map_err(OpenError::Invalid)?;
    Ok((value, verified))
}
