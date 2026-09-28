//! Signing and verification of the offline envelope.

use super::*;
use crate::dsse::{VerifyError, key_id};
use crate::revocation::{REVOCATION_SCHEMA, RevocationList};
use crate::signed::{OpenError, SignError};
use crate::trust::{TrustDomain, TrustSet};
use ed25519_dalek::SigningKey;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn vendor(seeds: &[u8]) -> TrustSet {
    TrustSet::new(
        TrustDomain::VendorRelease,
        seeds.iter().map(|s| key(*s).verifying_key()).collect(),
    )
}

fn revoking(key_ids: Vec<String>, releases: Vec<String>) -> RevocationList {
    RevocationList {
        schema: REVOCATION_SCHEMA.into(),
        issuer: "greentic".into(),
        sequence: 1,
        issued_at: ts(9),
        valid_until: ts(23),
        revoked_key_ids: key_ids,
        revoked_release_digests: releases,
    }
}

#[test]
fn round_trips_two_of_two_with_signers() {
    let (a, b) = (key(1), key(2));
    let env = sign_offline(&sample(), &[&a, &b]).unwrap();
    assert_eq!(env.payload_type, OFFLINE_RELEASE_PAYLOAD_TYPE);
    let opened = verify_offline(&env, &vendor(&[1, 2]), 2, None).unwrap();
    assert_eq!(opened.value, sample());
    assert_eq!(
        opened.signer_key_ids,
        vec![key_id(&a.verifying_key()), key_id(&b.verifying_key())]
    );
}

#[test]
fn a_key_set_for_another_domain_is_refused() {
    let env = sign_offline(&sample(), &[&key(1)]).unwrap();
    let exec = TrustSet::new(TrustDomain::Execution, vec![key(1).verifying_key()]);
    assert!(matches!(
        verify_offline(&env, &exec, 1, None),
        Err(OpenError::WrongTrustDomain { .. })
    ));
}

#[test]
fn below_threshold_is_refused() {
    let env = sign_offline(&sample(), &[&key(1)]).unwrap();
    assert!(matches!(
        verify_offline(&env, &vendor(&[1, 2]), 2, None),
        Err(OpenError::Signature(VerifyError::BelowThreshold { .. }))
    ));
}

#[test]
fn an_untrusted_signer_is_refused() {
    let env = sign_offline(&sample(), &[&key(1)]).unwrap();
    assert!(matches!(
        verify_offline(&env, &vendor(&[9]), 1, None),
        Err(OpenError::Signature(VerifyError::NoTrustedSignature))
    ));
}

#[test]
fn a_revoked_signer_is_refused_even_beside_a_good_one() {
    let env = sign_offline(&sample(), &[&key(1), &key(2)]).unwrap();
    let list = revoking(vec![key_id(&key(2).verifying_key())], vec![]);
    assert!(matches!(
        verify_offline(&env, &vendor(&[1, 2]), 1, Some(&list)),
        Err(OpenError::RevokedSigner(ids)) if ids == vec![key_id(&key(2).verifying_key())]
    ));
}

#[test]
fn a_revoked_release_is_refused() {
    let env = sign_offline(&sample(), &[&key(1)]).unwrap();
    let list = revoking(vec![], vec![sample().releases[0].release_digest.clone()]);
    assert!(matches!(
        verify_offline(&env, &vendor(&[1]), 1, Some(&list)),
        Err(OpenError::RevokedRelease(_))
    ));
    let unrelated = revoking(vec![], vec![digest('7')]);
    assert!(verify_offline(&env, &vendor(&[1]), 1, Some(&unrelated)).is_ok());
}

#[test]
fn an_invalid_manifest_is_never_signed() {
    let mut m = sample();
    m.audience.installation_ids.clear();
    assert!(matches!(
        sign_offline(&m, &[&key(1)]),
        Err(SignError::Invalid(OfflineError::EmptyAudience))
    ));
    assert!(matches!(
        sign_offline(&sample(), &[]),
        Err(SignError::NoKeys)
    ));
}

#[test]
fn a_signed_but_invalid_payload_is_refused_after_the_signature() {
    let mut m = sample();
    m.audience.installation_ids.clear();
    let payload = serde_json::to_vec(&m).unwrap();
    let env = crate::dsse::sign_bytes(OFFLINE_RELEASE_PAYLOAD_TYPE, &payload, &[&key(1)]);
    assert!(matches!(
        verify_offline(&env, &vendor(&[1]), 1, None),
        Err(OpenError::Invalid(OfflineError::EmptyAudience))
    ));
}

#[test]
fn another_schema_type_is_refused() {
    let env = crate::dsse::sign_bytes(
        "application/vnd.greentic.status-report.v1+json",
        &serde_json::to_vec(&sample()).unwrap(),
        &[&key(1)],
    );
    assert!(matches!(
        verify_offline(&env, &vendor(&[1]), 1, None),
        Err(OpenError::Signature(VerifyError::WrongPayloadType))
    ));
}
