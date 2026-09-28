//! DSSE sign/verify for execution authorisation v2, and the version-agnostic
//! [`verify_any`]. Built on [`crate::dsse::sign_bytes`] /
//! [`crate::dsse::verify_bytes`]; the v1 [`crate::dsse::sign`] /
//! [`crate::dsse::verify`] are untouched and still accept only v1.

use ed25519_dalek::{SigningKey, VerifyingKey};

use super::{
    EXECUTION_AUTHORISATION_V2_PAYLOAD_TYPE, ExecutionAuthorisationV2, ValidationErrorV2,
    VerifiedAuthorisation,
};
use crate::dsse::{DsseEnvelope, VerifyError, sign_bytes, verify_bytes};
use crate::execution::{EXECUTION_AUTHORISATION_PAYLOAD_TYPE, ExecutionAuthorisation};

/// Why [`sign_v2`] refused to sign.
#[derive(Debug)]
pub enum SignV2Error {
    /// The authorisation fails [`ExecutionAuthorisationV2::validate`].
    Invalid(ValidationErrorV2),
    Serialize(serde_json::Error),
}

impl std::fmt::Display for SignV2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(e) => write!(f, "refusing to sign an invalid authorisation: {e}"),
            Self::Serialize(e) => write!(f, "could not serialise the authorisation: {e}"),
        }
    }
}

impl std::error::Error for SignV2Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Invalid(e) => Some(e),
            Self::Serialize(e) => Some(e),
        }
    }
}

/// Validate, then sign `auth` under the v2 payload type.
pub fn sign_v2(
    auth: &ExecutionAuthorisationV2,
    key: &SigningKey,
) -> Result<DsseEnvelope, SignV2Error> {
    auth.validate().map_err(SignV2Error::Invalid)?;
    let payload = serde_json::to_vec(auth).map_err(SignV2Error::Serialize)?;
    Ok(sign_bytes(
        EXECUTION_AUTHORISATION_V2_PAYLOAD_TYPE,
        &payload,
        &[key],
    ))
}

/// Verify a v2 envelope (only), then parse and validate it.
pub fn verify_v2(
    env: &DsseEnvelope,
    trusted: &[VerifyingKey],
) -> Result<ExecutionAuthorisationV2, VerifyError> {
    let verified = verify_bytes(env, EXECUTION_AUTHORISATION_V2_PAYLOAD_TYPE, trusted, 1)?;
    let auth: ExecutionAuthorisationV2 =
        serde_json::from_slice(&verified.payload).map_err(VerifyError::BadPayload)?;
    auth.validate().map_err(VerifyError::InvalidV2)?;
    Ok(auth)
}

/// Verify an envelope of EITHER version against `trusted`, then parse it as
/// the version its payload type names.
///
/// The payload type is only a routing hint until the signature verifies —
/// and the signature covers it (DSSE PAE), so a v1 signature cannot be
/// replayed as a v2 envelope or the other way round. An unknown type is
/// `WrongPayloadType`. The payload's own `schema` must then match the type,
/// or validation refuses it (`UnknownSchema`).
pub fn verify_any(
    env: &DsseEnvelope,
    trusted: &[VerifyingKey],
) -> Result<VerifiedAuthorisation, VerifyError> {
    match env.payload_type.as_str() {
        EXECUTION_AUTHORISATION_PAYLOAD_TYPE => {
            let verified = verify_bytes(env, EXECUTION_AUTHORISATION_PAYLOAD_TYPE, trusted, 1)?;
            let auth: ExecutionAuthorisation =
                serde_json::from_slice(&verified.payload).map_err(VerifyError::BadPayload)?;
            auth.validate().map_err(VerifyError::Invalid)?;
            Ok(VerifiedAuthorisation::V1(auth))
        }
        EXECUTION_AUTHORISATION_V2_PAYLOAD_TYPE => {
            verify_v2(env, trusted).map(VerifiedAuthorisation::V2)
        }
        _ => Err(VerifyError::WrongPayloadType),
    }
}
