use super::*;
use chrono::TimeZone;
use serde_json::json;

fn ts(hour: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 28, hour, 0, 0).unwrap()
}

// A syntactically valid entry; `validate` does not decode it.
const K1: &str = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const K2: &str = "ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";

fn rotation(add: &[&str], remove: &[&str]) -> TrustRotation {
    TrustRotation {
        schema: TRUST_ROTATION_SCHEMA.into(),
        domain: TrustDomain::Execution,
        sequence: 1,
        add: add.iter().map(|s| s.to_string()).collect(),
        remove: remove.iter().map(|s| s.to_string()).collect(),
        effective_at: ts(10),
        expires_at: ts(20),
    }
}

#[test]
fn a_well_formed_rotation_validates() {
    assert_eq!(rotation(&[K1], &[K2]).validate(), Ok(()));
}

#[test]
fn shape_refusals() {
    let mut r = rotation(&[K1], &[]);
    r.schema = "greentic.trust-rotation.v2".into();
    assert!(matches!(r.validate(), Err(TrustError::UnknownSchema(_))));
    let mut r = rotation(&[K1], &[]);
    r.sequence = 0;
    assert_eq!(r.validate(), Err(TrustError::BadSequence));
    r.sequence = u64::MAX;
    assert_eq!(r.validate(), Err(TrustError::BadSequence));
    assert_eq!(rotation(&[], &[]).validate(), Err(TrustError::NoChange));
    let mut r = rotation(&[K1], &[]);
    r.expires_at = r.effective_at;
    assert_eq!(r.validate(), Err(TrustError::WindowInverted));
}

#[test]
fn key_list_refusals() {
    for bad in [
        "rsa:AAAA",
        "ed25519:",
        "ed25519: AAAA",
        "ed25519:AAAA,ed25519:BBBB",
    ] {
        assert!(
            matches!(
                rotation(&[bad], &[]).validate(),
                Err(TrustError::BadKeyFormat(_))
            ),
            "{bad}"
        );
    }
    assert!(matches!(
        rotation(&[K1, K1], &[]).validate(),
        Err(TrustError::DuplicateKey(_))
    ));
    assert!(matches!(
        rotation(&[K1], &[K1]).validate(),
        Err(TrustError::KeyInAddAndRemove(_))
    ));
}

#[test]
fn the_window_is_half_open() {
    let r = rotation(&[K1], &[]);
    assert!(!r.is_applicable_at(ts(9)));
    assert!(r.is_applicable_at(ts(10)));
    assert!(!r.is_applicable_at(ts(20)));
}

#[test]
fn unknown_fields_and_domains_are_refused() {
    let mut v = serde_json::to_value(rotation(&[K1], &[])).unwrap();
    assert_eq!(v["domain"], "execution");
    v["extra"] = json!(1);
    assert!(serde_json::from_value::<TrustRotation>(v).is_err());
    let mut v = serde_json::to_value(rotation(&[K1], &[])).unwrap();
    v["domain"] = json!("everything");
    assert!(serde_json::from_value::<TrustRotation>(v).is_err());
}

#[cfg(feature = "signing")]
mod apply {
    use super::*;
    use crate::dsse::{DsseEnvelope, VerifyError, format_trusted_key, key_id};
    use crate::revocation::{REVOCATION_SCHEMA, RevocationList};
    use crate::signed::OpenError;
    use ed25519_dalek::{SigningKey, VerifyingKey};

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn vk(seed: u8) -> VerifyingKey {
        key(seed).verifying_key()
    }

    fn fmt(seed: u8) -> String {
        format_trusted_key(&vk(seed))
    }

    fn set(seeds: &[u8]) -> TrustSet {
        TrustSet::new(
            TrustDomain::Execution,
            seeds.iter().map(|s| vk(*s)).collect(),
        )
    }

    fn signed(add: &[u8], remove: &[u8], seq: u64, signers: &[u8]) -> DsseEnvelope {
        let mut r = rotation(&[], &[]);
        r.sequence = seq;
        r.add = add.iter().map(|s| fmt(*s)).collect();
        r.remove = remove.iter().map(|s| fmt(*s)).collect();
        let keys: Vec<SigningKey> = signers.iter().map(|s| key(*s)).collect();
        let refs: Vec<&SigningKey> = keys.iter().collect();
        sign_rotation(&r, &refs).unwrap()
    }

    fn apply1(current: &[u8], env: &DsseEnvelope) -> Result<AppliedRotation, RotationError> {
        apply_rotation(&set(current), env, 0, ts(12), None)
    }

    fn apply2(current: &[u8], env: &DsseEnvelope) -> Result<AppliedRotation, RotationError> {
        apply_rotation_with_threshold(&set(current), env, 0, ts(12), None, 2)
    }

    fn revoking(seeds: &[u8]) -> RevocationList {
        RevocationList {
            schema: REVOCATION_SCHEMA.into(),
            issuer: "greentic".into(),
            sequence: 1,
            issued_at: ts(9),
            valid_until: ts(23),
            revoked_key_ids: seeds.iter().map(|s| key_id(&vk(*s))).collect(),
            revoked_release_digests: vec![],
        }
    }

    #[test]
    fn a_trusted_key_rotates_in_a_new_key() {
        let out = apply1(&[1], &signed(&[2], &[], 1, &[1])).unwrap();
        assert_eq!(out.keys, set(&[1, 2]));
        assert_eq!(out.rotation.sequence, 1);
        assert_eq!(out.signer_key_ids, vec![key_id(&vk(1))]);
    }

    #[test]
    fn a_single_key_may_retire_itself() {
        let out = apply1(&[1, 2], &signed(&[], &[1], 1, &[1])).unwrap();
        assert_eq!(out.keys, set(&[2]));
        let out = apply1(&[1], &signed(&[2], &[1], 1, &[1])).unwrap();
        assert_eq!(out.keys, set(&[2]));
    }

    #[test]
    fn a_single_leaked_key_cannot_evict_its_peers() {
        // H2: A holds {A, B, C} and signs `remove: [B, C]` alone.
        let env = signed(&[], &[2, 3], 1, &[1]);
        assert!(matches!(
            apply1(&[1, 2, 3], &env),
            Err(RotationError::RemovalNeedsQuorum(_))
        ));
        // Even with a replacement of its own.
        let env = signed(&[9], &[2], 1, &[1]);
        assert!(matches!(
            apply1(&[1, 2, 3], &env),
            Err(RotationError::RemovalNeedsQuorum(_))
        ));
    }

    #[test]
    fn a_quorum_of_two_may_remove_a_peer() {
        let env = signed(&[], &[3], 1, &[1, 2]);
        let out = apply2(&[1, 2, 3], &env).unwrap();
        assert_eq!(out.keys, set(&[1, 2]));
        // Two signers are not enough when the threshold asked for is 1.
        assert!(matches!(
            apply1(&[1, 2, 3], &env),
            Err(RotationError::RemovalNeedsQuorum(_))
        ));
    }

    #[test]
    fn the_result_keeps_at_least_threshold_keys() {
        let env = signed(&[], &[2], 1, &[1, 2]);
        assert!(matches!(
            apply2(&[1, 2], &env),
            Err(RotationError::TooFewKeys {
                required: 2,
                remaining: 1
            })
        ));
        let env = signed(&[], &[1], 1, &[1]);
        assert!(matches!(
            apply1(&[1], &env),
            Err(RotationError::TooFewKeys {
                required: 1,
                remaining: 0
            })
        ));
    }

    #[test]
    fn an_untrusted_signer_cannot_establish_its_own_authority() {
        let env = signed(&[9], &[], 1, &[9]);
        assert!(matches!(
            apply1(&[1], &env),
            Err(RotationError::Envelope(OpenError::Signature(
                VerifyError::NoTrustedSignature
            )))
        ));
    }

    #[test]
    fn a_threshold_of_two_needs_two_current_signers() {
        assert!(matches!(
            apply2(&[1, 2], &signed(&[3], &[], 1, &[1])),
            Err(RotationError::Envelope(OpenError::Signature(
                VerifyError::BelowThreshold { .. }
            )))
        ));
        assert!(apply2(&[1, 2], &signed(&[3], &[], 1, &[1, 2])).is_ok());
    }

    #[test]
    fn an_unreachable_threshold_is_refused() {
        let env = signed(&[3], &[], 1, &[1, 2]);
        assert!(matches!(
            apply_rotation_with_threshold(&set(&[1, 2]), &env, 0, ts(12), None, 9),
            Err(RotationError::Envelope(OpenError::Signature(
                VerifyError::ThresholdUnreachable { threshold: 9 }
            )))
        ));
    }

    #[test]
    fn a_replayed_or_older_sequence_is_refused() {
        let env = signed(&[2], &[], 5, &[1]);
        for last in [5, 6] {
            assert!(matches!(
                apply_rotation(&set(&[1]), &env, last, ts(12), None),
                Err(RotationError::NotNewer { sequence: 5, .. })
            ));
        }
    }

    #[test]
    fn another_domain_is_refused() {
        let env = signed(&[2], &[], 1, &[1]);
        let vendor = TrustSet::new(TrustDomain::VendorRelease, vec![vk(1)]);
        assert!(matches!(
            apply_rotation(&vendor, &env, 0, ts(12), None),
            Err(RotationError::Envelope(OpenError::WrongTrustDomain { .. }))
        ));
    }

    #[test]
    fn outside_the_window_is_refused() {
        let env = signed(&[2], &[], 1, &[1]);
        for now in [ts(9), ts(20)] {
            assert!(matches!(
                apply_rotation(&set(&[1]), &env, 0, now, None),
                Err(RotationError::NotApplicable)
            ));
        }
    }

    #[test]
    fn unknown_removals_and_duplicate_adds_are_refused() {
        assert!(matches!(
            apply1(&[1], &signed(&[], &[7], 1, &[1])),
            Err(RotationError::UnknownRemoval(_))
        ));
        assert!(matches!(
            apply1(&[1], &signed(&[1], &[], 1, &[1])),
            Err(RotationError::AlreadyTrusted(_))
        ));
    }

    #[test]
    fn revoked_keys_neither_sign_nor_get_added() {
        let list = revoking(&[1]);
        let env = signed(&[3], &[], 1, &[1]);
        assert!(matches!(
            apply_rotation(&set(&[1, 2]), &env, 0, ts(12), Some(&list)),
            Err(RotationError::Envelope(OpenError::RevokedSigner(_)))
        ));
        let list = revoking(&[3]);
        let env = signed(&[3], &[], 1, &[1]);
        assert!(matches!(
            apply_rotation(&set(&[1]), &env, 0, ts(12), Some(&list)),
            Err(RotationError::AddsRevokedKey(_))
        ));
    }

    #[test]
    fn a_duplicated_current_set_is_deduplicated() {
        let out = apply1(&[1, 1], &signed(&[2], &[], 1, &[1])).unwrap();
        assert_eq!(out.keys, set(&[1, 2]));
    }

    #[test]
    fn a_syntactically_valid_but_undecodable_key_is_refused() {
        let mut r = rotation(&["ed25519:not-base64!"], &[]);
        r.sequence = 1;
        let env = sign_rotation(&r, &[&key(1)]).unwrap();
        assert!(matches!(apply1(&[1], &env), Err(RotationError::BadKey(_))));
    }

    #[test]
    fn verify_rotation_inspects_without_applying() {
        let env = signed(&[2], &[], 3, &[1]);
        let r = verify_rotation(&env, &set(&[1]), 1, None).unwrap();
        assert_eq!(r.value.sequence, 3);
        assert_eq!(r.value.add, vec![fmt(2)]);
        assert_eq!(r.signer_keys, vec![vk(1)]);
    }
}
