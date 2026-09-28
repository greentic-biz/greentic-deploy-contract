//! DSSE envelope for [`ExecutionAuthorisation`](crate::execution::ExecutionAuthorisation), signed with Ed25519.
//!
//! The envelope type and [`pae`] are always available (serde only). Signing,
//! verification, key ids and trusted-key parsing need the cargo feature
//! `signing`, which pulls in `ed25519-dalek` and `base64`.
//!
//! **The signature covers the EXACT payload bytes.** `verify` checks the
//! signature over `pae(payloadType, decoded payload)` first, and only then
//! parses and validates. It never re-serialises: a verifier that reparsed and
//! re-encoded before checking would be checking a different byte string than
//! the one that was signed.
//!
//! **Trust comes only from the caller.** `verify` accepts a signature only
//! from a key in `trusted`, whatever `keyid` the envelope claims — `keyid` is
//! advisory, and a key named by the envelope itself establishes nothing. An
//! empty `trusted` list accepts nothing.
//!
//! [`sign_bytes`] / [`verify_bytes`] are the payload-agnostic core: any
//! schema can be signed by several keys and verified k-of-n without this
//! module knowing its shape. [`sign`] / [`verify`] are the execution
//! authorisation wrappers over them (one key, threshold 1).

use serde::{Deserialize, Serialize};

/// One signature in a [`DsseEnvelope`]. `sig` is standard base64.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DsseSignature {
    #[serde(default)]
    pub keyid: String,
    pub sig: String,
}

/// A DSSE envelope. `payload` is the standard base64 of the signed bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DsseEnvelope {
    pub payload_type: String,
    pub payload: String,
    pub signatures: Vec<DsseSignature>,
}

/// DSSE v1 pre-authentication encoding:
/// `"DSSEv1" SP len(type) SP type SP len(payload) SP payload`, lengths in
/// ASCII decimal bytes.
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload_type.len() + payload.len() + 32);
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

#[cfg(feature = "signing")]
pub use signing::*;

#[cfg(feature = "signing")]
mod signing {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
    use sha2::{Digest, Sha256};

    use super::{DsseEnvelope, DsseSignature, pae};
    use crate::execution::{
        EXECUTION_AUTHORISATION_PAYLOAD_TYPE, ExecutionAuthorisation, ValidationError,
    };
    use crate::release::hex_lower;

    /// The most signatures [`verify`] will look at. Each one costs up to
    /// `trusted.len()` Ed25519 verifications, so an envelope carrying more is
    /// refused outright rather than verified.
    pub const MAX_SIGNATURES: usize = 8;

    /// Why [`sign`] refused to sign.
    #[derive(Debug)]
    pub enum SignError {
        /// The authorisation fails [`ExecutionAuthorisation::validate`]; every
        /// receiver would refuse it, so it is never signed.
        Invalid(ValidationError),
        Serialize(serde_json::Error),
    }

    impl std::fmt::Display for SignError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Invalid(e) => write!(f, "refusing to sign an invalid authorisation: {e}"),
                Self::Serialize(e) => write!(f, "could not serialise the authorisation: {e}"),
            }
        }
    }

    impl std::error::Error for SignError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::Invalid(e) => Some(e),
                Self::Serialize(e) => Some(e),
            }
        }
    }

    /// Why [`verify`] refused an envelope. Each is a distinct outcome so a
    /// receiver can report a distinct reason code.
    ///
    /// `#[non_exhaustive]` because this enum grew twice already (C1 added
    /// `ZeroThreshold` and `BelowThreshold`) and every new signed schema may
    /// add a refusal of its own. A consumer's exhaustive `match` turned each
    /// of those additions into a compile break in a crate that did not care
    /// about the new case; a consumer must now carry a wildcard arm, which
    /// should map to a generic "signature refused" code rather than to
    /// acceptance.
    #[derive(Debug)]
    #[non_exhaustive]
    pub enum VerifyError {
        /// `payloadType` is not the v1 execution-authorisation type.
        WrongPayloadType,
        /// `payload` is not valid standard base64.
        BadEncoding,
        /// [`verify_bytes`] was asked for a threshold of 0. Refused rather
        /// than read as "accept anything".
        ZeroThreshold,
        /// The envelope carries more than [`MAX_SIGNATURES`] signatures.
        TooManySignatures,
        /// No signature verifies under any trusted key (including: no
        /// trusted key configured, or no signatures at all).
        NoTrustedSignature,
        /// Some trusted keys signed, but fewer DISTINCT ones than the
        /// threshold asked for.
        BelowThreshold { required: usize, found: usize },
        /// The signed bytes are not a v1 authorisation (malformed JSON, an
        /// unknown field, an unknown operation).
        BadPayload(serde_json::Error),
        /// The authorisation parsed but fails [`ExecutionAuthorisation::validate`].
        Invalid(ValidationError),
    }

    impl std::fmt::Display for VerifyError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::WrongPayloadType => f.write_str("wrong DSSE payload type"),
                Self::BadEncoding => f.write_str("payload is not valid base64"),
                Self::ZeroThreshold => f.write_str("a signature threshold of 0 is refused"),
                Self::BelowThreshold { required, found } => write!(
                    f,
                    "{found} distinct trusted key(s) signed, {required} required"
                ),
                Self::TooManySignatures => {
                    write!(f, "envelope carries more than {MAX_SIGNATURES} signatures")
                }
                Self::NoTrustedSignature => f.write_str("no signature from a trusted key"),
                Self::BadPayload(e) => write!(f, "payload is not a v1 authorisation: {e}"),
                Self::Invalid(e) => write!(f, "authorisation is invalid: {e}"),
            }
        }
    }

    impl std::error::Error for VerifyError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::BadPayload(e) => Some(e),
                Self::Invalid(e) => Some(e),
                _ => None,
            }
        }
    }

    /// Why [`parse_trusted_keys`] refused its input; carries the offending
    /// entry's zero-based index among the NON-EMPTY entries.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum TrustedKeyError {
        /// The entry does not start with `ed25519:`.
        UnsupportedAlgorithm(usize),
        BadBase64(usize),
        /// The decoded key is not 32 bytes.
        BadLength(usize),
        /// 32 bytes that are not a valid Ed25519 point.
        InvalidKey(usize),
    }

    impl std::fmt::Display for TrustedKeyError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::UnsupportedAlgorithm(i) => {
                    write!(f, "trusted key #{i} does not start with `ed25519:`")
                }
                Self::BadBase64(i) => write!(f, "trusted key #{i} is not valid base64"),
                Self::BadLength(i) => write!(f, "trusted key #{i} is not 32 bytes"),
                Self::InvalidKey(i) => write!(f, "trusted key #{i} is not a valid Ed25519 key"),
            }
        }
    }

    impl std::error::Error for TrustedKeyError {}

    /// `hex(sha256(public key bytes))[..16]`.
    pub fn key_id(key: &VerifyingKey) -> String {
        let mut hex = hex_lower(&Sha256::digest(key.as_bytes()));
        hex.truncate(16);
        hex
    }

    /// Validate, then sign `auth` as a DSSE envelope. The payload is
    /// `serde_json::to_vec` of the struct, whose field order is fixed by its
    /// declaration.
    ///
    /// An authorisation that fails [`ExecutionAuthorisation::validate`] is
    /// refused here rather than surfacing as `Invalid` on every receiver.
    /// Serialising these types cannot fail in practice, but the error is
    /// returned rather than assumed.
    pub fn sign(
        auth: &ExecutionAuthorisation,
        key: &SigningKey,
    ) -> Result<DsseEnvelope, SignError> {
        auth.validate().map_err(SignError::Invalid)?;
        let payload = serde_json::to_vec(auth).map_err(SignError::Serialize)?;
        Ok(sign_bytes(
            EXECUTION_AUTHORISATION_PAYLOAD_TYPE,
            &payload,
            &[key],
        ))
    }

    /// Verify `env` against `trusted`, then parse and validate. See the
    /// module doc for the order and why it matters. Time admission, the
    /// installation id and sequence replay are the receiver's checks.
    pub fn verify(
        env: &DsseEnvelope,
        trusted: &[VerifyingKey],
    ) -> Result<ExecutionAuthorisation, VerifyError> {
        let verified = verify_bytes(env, EXECUTION_AUTHORISATION_PAYLOAD_TYPE, trusted, 1)?;
        let auth: ExecutionAuthorisation =
            serde_json::from_slice(&verified.payload).map_err(VerifyError::BadPayload)?;
        auth.validate().map_err(VerifyError::Invalid)?;
        Ok(auth)
    }

    /// The outcome of a successful [`verify_bytes`]: the exact signed bytes,
    /// and the [`key_id`] of every distinct trusted key that signed them, in
    /// `trusted` order.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Verified {
        pub payload: Vec<u8>,
        pub signer_key_ids: Vec<String>,
    }

    /// Sign `payload` as `payload_type` with every key in `keys`, one
    /// signature each, in order. Nothing about the payload is checked: a
    /// typed caller validates before it gets here.
    pub fn sign_bytes(payload_type: &str, payload: &[u8], keys: &[&SigningKey]) -> DsseEnvelope {
        let message = pae(payload_type, payload);
        DsseEnvelope {
            payload_type: payload_type.to_string(),
            payload: STANDARD.encode(payload),
            signatures: keys
                .iter()
                .map(|key| DsseSignature {
                    keyid: key_id(&key.verifying_key()),
                    sig: STANDARD.encode(key.sign(&message).to_bytes()),
                })
                .collect(),
        }
    }

    /// Verify that at least `threshold` DISTINCT keys from `trusted` signed
    /// `env`, and that it is of `expected_type`. Signatures are checked over
    /// the PAE of the decoded bytes; the payload is never parsed here.
    ///
    /// `keyid` is advisory: each signature is tried against every trusted
    /// key. A key that signed twice counts once, and a key listed twice in
    /// `trusted` counts once. `threshold == 0` is an error, never "accept
    /// anything"; an empty `trusted` accepts nothing.
    pub fn verify_bytes(
        env: &DsseEnvelope,
        expected_type: &str,
        trusted: &[VerifyingKey],
        threshold: usize,
    ) -> Result<Verified, VerifyError> {
        if threshold == 0 {
            return Err(VerifyError::ZeroThreshold);
        }
        if env.payload_type != expected_type {
            return Err(VerifyError::WrongPayloadType);
        }
        let payload = STANDARD
            .decode(env.payload.as_bytes())
            .map_err(|_| VerifyError::BadEncoding)?;
        if env.signatures.len() > MAX_SIGNATURES {
            return Err(VerifyError::TooManySignatures);
        }
        let message = pae(&env.payload_type, &payload);
        // A malformed signature is simply not a trusted one; it must not
        // stop a valid signature beside it from counting.
        let signatures: Vec<Signature> = env
            .signatures
            .iter()
            .filter_map(|s| STANDARD.decode(s.sig.as_bytes()).ok())
            .filter_map(|bytes| Signature::from_slice(&bytes).ok())
            .collect();
        let mut signers: Vec<&VerifyingKey> = Vec::new();
        for key in trusted {
            if signers.contains(&key) {
                continue;
            }
            if signatures
                .iter()
                .any(|sig| key.verify_strict(&message, sig).is_ok())
            {
                signers.push(key);
            }
        }
        match signers.len() {
            0 => Err(VerifyError::NoTrustedSignature),
            found if found < threshold => Err(VerifyError::BelowThreshold {
                required: threshold,
                found,
            }),
            _ => Ok(Verified {
                payload,
                signer_key_ids: signers.into_iter().map(key_id).collect(),
            }),
        }
    }

    /// Parse a comma-separated `ed25519:<std base64 of 32 bytes>` list, the
    /// shape of `GREENTIC_EXECUTION_TRUSTED_KEYS`. Whitespace around entries
    /// and empty entries are ignored, so an empty string yields an empty
    /// list — which [`verify`] treats as "trust nothing". Any malformed entry
    /// refuses the whole list rather than silently trusting fewer keys.
    pub fn parse_trusted_keys(s: &str) -> Result<Vec<VerifyingKey>, TrustedKeyError> {
        s.split(',')
            .map(str::trim)
            .filter(|e| !e.is_empty())
            .enumerate()
            .map(|(i, entry)| {
                let b64 = entry
                    .strip_prefix("ed25519:")
                    .ok_or(TrustedKeyError::UnsupportedAlgorithm(i))?;
                let bytes = STANDARD
                    .decode(b64.as_bytes())
                    .map_err(|_| TrustedKeyError::BadBase64(i))?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| TrustedKeyError::BadLength(i))?;
                VerifyingKey::from_bytes(&arr).map_err(|_| TrustedKeyError::InvalidKey(i))
            })
            .collect()
    }

    /// Format a key the way [`parse_trusted_keys`] reads it, for an operator
    /// to copy.
    pub fn format_trusted_key(key: &VerifyingKey) -> String {
        format!("ed25519:{}", STANDARD.encode(key.as_bytes()))
    }
}

#[cfg(test)]
#[path = "dsse_tests.rs"]
mod tests;

#[cfg(all(test, feature = "signing"))]
#[path = "dsse_bytes_tests.rs"]
mod bytes_tests;
