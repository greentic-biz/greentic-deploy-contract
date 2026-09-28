//! Generic [`sign_bytes`] / [`verify_bytes`]: k-of-n, distinct signers, and
//! byte-identical wrappers.

use super::*;
use crate::execution::EXECUTION_AUTHORISATION_PAYLOAD_TYPE;
use crate::execution::tests::sample;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

const TYPE: &str = "application/vnd.greentic.test+json";
const PAYLOAD: &[u8] = br#"{"hello":"world"}"#;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn vks(seeds: &[u8]) -> Vec<VerifyingKey> {
    seeds.iter().map(|s| key(*s).verifying_key()).collect()
}

#[test]
fn two_of_three_passes_with_two_signers() {
    let (a, b) = (key(1), key(2));
    let env = sign_bytes(TYPE, PAYLOAD, &[&a, &b]);
    let v = verify_bytes(&env, TYPE, &vks(&[1, 2, 3]), 2).unwrap();
    assert_eq!(v.payload, PAYLOAD);
    assert_eq!(
        v.signer_key_ids,
        vec![key_id(&a.verifying_key()), key_id(&b.verifying_key())]
    );
}

#[test]
fn two_of_three_fails_with_one_signer() {
    let env = sign_bytes(TYPE, PAYLOAD, &[&key(1)]);
    assert!(matches!(
        verify_bytes(&env, TYPE, &vks(&[1, 2, 3]), 2),
        Err(VerifyError::BelowThreshold {
            required: 2,
            found: 1
        })
    ));
}

#[test]
fn an_untrusted_second_signer_does_not_count() {
    let env = sign_bytes(TYPE, PAYLOAD, &[&key(1), &key(9)]);
    assert!(matches!(
        verify_bytes(&env, TYPE, &vks(&[1, 2, 3]), 2),
        Err(VerifyError::BelowThreshold { found: 1, .. })
    ));
}

#[test]
fn one_key_signing_twice_counts_once() {
    let a = key(1);
    let env = sign_bytes(TYPE, PAYLOAD, &[&a, &a]);
    assert_eq!(env.signatures.len(), 2);
    assert!(matches!(
        verify_bytes(&env, TYPE, &vks(&[1, 2]), 2),
        Err(VerifyError::BelowThreshold { found: 1, .. })
    ));
    let v = verify_bytes(&env, TYPE, &vks(&[1, 2]), 1).unwrap();
    assert_eq!(v.signer_key_ids.len(), 1);
}

#[test]
fn a_key_listed_twice_in_trusted_counts_once() {
    let env = sign_bytes(TYPE, PAYLOAD, &[&key(1)]);
    assert!(matches!(
        verify_bytes(&env, TYPE, &vks(&[1, 1]), 2),
        Err(VerifyError::BelowThreshold { found: 1, .. })
    ));
}

#[test]
fn keyid_is_advisory() {
    let mut env = sign_bytes(TYPE, PAYLOAD, &[&key(1), &key(2)]);
    env.signatures[0].keyid = "bogus".to_string();
    env.signatures[1].keyid = String::new();
    assert!(verify_bytes(&env, TYPE, &vks(&[1, 2]), 2).is_ok());
}

#[test]
fn a_wrong_payload_type_is_refused() {
    let env = sign_bytes(TYPE, PAYLOAD, &[&key(1)]);
    assert!(matches!(
        verify_bytes(&env, "application/vnd.greentic.other+json", &vks(&[1]), 1),
        Err(VerifyError::WrongPayloadType)
    ));
}

#[test]
fn a_tampered_payload_is_untrusted() {
    let mut env = sign_bytes(TYPE, PAYLOAD, &[&key(1), &key(2)]);
    env.payload = STANDARD.encode(br#"{"hello":"World"}"#);
    assert!(matches!(
        verify_bytes(&env, TYPE, &vks(&[1, 2]), 1),
        Err(VerifyError::NoTrustedSignature)
    ));
}

#[test]
fn malformed_base64_is_refused_cleanly() {
    let mut env = sign_bytes(TYPE, PAYLOAD, &[&key(1)]);
    env.payload = "%%%".to_string();
    assert!(matches!(
        verify_bytes(&env, TYPE, &vks(&[1]), 1),
        Err(VerifyError::BadEncoding)
    ));
    let mut env = sign_bytes(TYPE, PAYLOAD, &[&key(1)]);
    env.signatures[0].sig = "***".to_string();
    assert!(matches!(
        verify_bytes(&env, TYPE, &vks(&[1]), 1),
        Err(VerifyError::NoTrustedSignature)
    ));
}

#[test]
fn an_empty_trust_list_accepts_nothing() {
    let env = sign_bytes(TYPE, PAYLOAD, &[&key(1)]);
    assert!(matches!(
        verify_bytes(&env, TYPE, &[], 1),
        Err(VerifyError::NoTrustedSignature)
    ));
}

#[test]
fn a_zero_threshold_is_refused() {
    let env = sign_bytes(TYPE, PAYLOAD, &[&key(1)]);
    assert!(matches!(
        verify_bytes(&env, TYPE, &vks(&[1]), 0),
        Err(VerifyError::ZeroThreshold)
    ));
    assert!(matches!(
        verify_bytes(&env, TYPE, &[], 0),
        Err(VerifyError::ZeroThreshold)
    ));
}

#[test]
fn max_signatures_still_applies() {
    let a = key(1);
    let keys: Vec<&SigningKey> = std::iter::repeat_n(&a, MAX_SIGNATURES + 1).collect();
    let env = sign_bytes(TYPE, PAYLOAD, &keys);
    assert!(matches!(
        verify_bytes(&env, TYPE, &vks(&[1]), 1),
        Err(VerifyError::TooManySignatures)
    ));
}

/// The wrapper must emit exactly what the pre-generic `sign` did: one
/// signature over `pae(type, serde_json::to_vec(auth))`.
#[test]
fn the_sign_wrapper_is_byte_identical_to_the_old_construction() {
    let k = key(1);
    let payload = serde_json::to_vec(&sample()).unwrap();
    let old = DsseEnvelope {
        payload_type: EXECUTION_AUTHORISATION_PAYLOAD_TYPE.to_string(),
        payload: STANDARD.encode(&payload),
        signatures: vec![DsseSignature {
            keyid: key_id(&k.verifying_key()),
            sig: STANDARD.encode(
                k.sign(&pae(EXECUTION_AUTHORISATION_PAYLOAD_TYPE, &payload))
                    .to_bytes(),
            ),
        }],
    };
    let new = sign(&sample(), &k).unwrap();
    assert_eq!(new, old);
    assert_eq!(
        serde_json::to_vec(&new).unwrap(),
        serde_json::to_vec(&old).unwrap()
    );
    assert_eq!(
        sign_bytes(EXECUTION_AUTHORISATION_PAYLOAD_TYPE, &payload, &[&k]),
        old
    );
}

#[test]
fn the_verify_wrapper_agrees_with_verify_bytes() {
    let k = key(1);
    let env = sign(&sample(), &k).unwrap();
    let v = verify_bytes(
        &env,
        EXECUTION_AUTHORISATION_PAYLOAD_TYPE,
        &[k.verifying_key()],
        1,
    )
    .unwrap();
    let parsed: crate::execution::ExecutionAuthorisation =
        serde_json::from_slice(&v.payload).unwrap();
    assert_eq!(parsed, verify(&env, &[k.verifying_key()]).unwrap());
}

#[test]
fn a_threshold_above_max_signatures_is_unreachable() {
    let keys: Vec<SigningKey> = (1..=8).map(key).collect();
    let refs: Vec<&SigningKey> = keys.iter().collect();
    let env = sign_bytes(TYPE, PAYLOAD, &refs);
    let trusted = vks(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
    assert!(verify_bytes(&env, TYPE, &trusted, MAX_SIGNATURES).is_ok());
    assert!(matches!(
        verify_bytes(&env, TYPE, &trusted, MAX_SIGNATURES + 1),
        Err(VerifyError::ThresholdUnreachable { threshold: 9 })
    ));
}
