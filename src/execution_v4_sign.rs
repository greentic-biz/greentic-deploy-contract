//! DSSE sign/verify for execution authorisation v4, and [`verify_any_v4`],
//! the entry that routes EVERY known schema. `verify_any` and `verify_any_v3`
//! are untouched and refuse a v4 payload type (`WrongPayloadType`).

use ed25519_dalek::{SigningKey, VerifyingKey};

use super::{EXECUTION_AUTHORISATION_V4_PAYLOAD_TYPE, ExecutionAuthorisationV4, ValidationErrorV4};
use crate::dsse::{DsseEnvelope, VerifyError, sign_bytes, verify_bytes};
use crate::execution_v3::VerifiedAny;

/// Why [`sign_v4`] refused to sign.
#[derive(Debug)]
pub enum SignV4Error {
    Invalid(ValidationErrorV4),
    Serialize(serde_json::Error),
}

impl std::fmt::Display for SignV4Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(e) => write!(f, "refusing to sign an invalid authorisation: {e}"),
            Self::Serialize(e) => write!(f, "could not serialise the authorisation: {e}"),
        }
    }
}

impl std::error::Error for SignV4Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Invalid(e) => Some(e),
            Self::Serialize(e) => Some(e),
        }
    }
}

/// Validate, then sign `auth` under the v4 payload type.
pub fn sign_v4(
    auth: &ExecutionAuthorisationV4,
    key: &SigningKey,
) -> Result<DsseEnvelope, SignV4Error> {
    auth.validate().map_err(SignV4Error::Invalid)?;
    let payload = serde_json::to_vec(auth).map_err(SignV4Error::Serialize)?;
    Ok(sign_bytes(
        EXECUTION_AUTHORISATION_V4_PAYLOAD_TYPE,
        &payload,
        &[key],
    ))
}

/// Verify a v4 envelope (only), then parse and validate it.
pub fn verify_v4(
    env: &DsseEnvelope,
    trusted: &[VerifyingKey],
) -> Result<ExecutionAuthorisationV4, VerifyError> {
    let verified = verify_bytes(env, EXECUTION_AUTHORISATION_V4_PAYLOAD_TYPE, trusted, 1)?;
    let auth: ExecutionAuthorisationV4 =
        serde_json::from_slice(&verified.payload).map_err(VerifyError::BadPayload)?;
    auth.validate().map_err(VerifyError::InvalidV4)?;
    Ok(auth)
}

/// Verify an envelope of ANY known version (v1-v4). The payload type is a
/// routing hint until the signature verifies, and the signature covers it.
pub fn verify_any_v4(
    env: &DsseEnvelope,
    trusted: &[VerifyingKey],
) -> Result<VerifiedAny, VerifyError> {
    if env.payload_type == EXECUTION_AUTHORISATION_V4_PAYLOAD_TYPE {
        return verify_v4(env, trusted).map(VerifiedAny::Channelled);
    }
    crate::execution_v3::verify_any_v3(env, trusted)
}
