//! DSSE sign/verify for execution authorisation v3, and [`verify_any_v3`],
//! the entry that routes EVERY known schema. The v1/v2 [`verify_any`] is left
//! untouched and still refuses a v3 payload type (`WrongPayloadType`), so a
//! designer built before v3 can never run a runtime change as an application
//! update.
//!
//! [`verify_any`]: crate::execution_v2::verify_any

use ed25519_dalek::{SigningKey, VerifyingKey};

use super::{
    EXECUTION_AUTHORISATION_V3_PAYLOAD_TYPE, ExecutionAuthorisationV3, ValidationErrorV3,
    VerifiedAny,
};
use crate::dsse::{DsseEnvelope, VerifyError, sign_bytes, verify_bytes};

/// Why [`sign_v3`] refused to sign.
#[derive(Debug)]
pub enum SignV3Error {
    /// The authorisation fails [`ExecutionAuthorisationV3::validate`].
    Invalid(ValidationErrorV3),
    Serialize(serde_json::Error),
}

impl std::fmt::Display for SignV3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(e) => write!(f, "refusing to sign an invalid authorisation: {e}"),
            Self::Serialize(e) => write!(f, "could not serialise the authorisation: {e}"),
        }
    }
}

impl std::error::Error for SignV3Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Invalid(e) => Some(e),
            Self::Serialize(e) => Some(e),
        }
    }
}

/// Validate, then sign `auth` under the v3 payload type.
pub fn sign_v3(
    auth: &ExecutionAuthorisationV3,
    key: &SigningKey,
) -> Result<DsseEnvelope, SignV3Error> {
    auth.validate().map_err(SignV3Error::Invalid)?;
    let payload = serde_json::to_vec(auth).map_err(SignV3Error::Serialize)?;
    Ok(sign_bytes(
        EXECUTION_AUTHORISATION_V3_PAYLOAD_TYPE,
        &payload,
        &[key],
    ))
}

/// Verify a v3 envelope (only), then parse and validate it.
pub fn verify_v3(
    env: &DsseEnvelope,
    trusted: &[VerifyingKey],
) -> Result<ExecutionAuthorisationV3, VerifyError> {
    let verified = verify_bytes(env, EXECUTION_AUTHORISATION_V3_PAYLOAD_TYPE, trusted, 1)?;
    let auth: ExecutionAuthorisationV3 =
        serde_json::from_slice(&verified.payload).map_err(VerifyError::BadPayload)?;
    auth.validate().map_err(VerifyError::InvalidV3)?;
    Ok(auth)
}

/// Verify an envelope of ANY known version. The payload type is only a
/// routing hint until the signature verifies, and the signature covers it
/// (DSSE PAE). v1/v2 go through the unchanged `verify_any`.
pub fn verify_any_v3(
    env: &DsseEnvelope,
    trusted: &[VerifyingKey],
) -> Result<VerifiedAny, VerifyError> {
    if env.payload_type == EXECUTION_AUTHORISATION_V3_PAYLOAD_TYPE {
        return verify_v3(env, trusted).map(VerifiedAny::Runtime);
    }
    crate::execution_v2::verify_any(env, trusted).map(VerifiedAny::Change)
}
