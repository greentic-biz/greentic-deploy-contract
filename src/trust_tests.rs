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
    assert_eq!(r.validate(), Err(TrustError::ZeroSequence));
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
    use crate::dsse::{VerifyError, format_trusted_key};
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

    fn signed(add: &[u8], remove: &[u8], seq: u64, signers: &[u8]) -> crate::dsse::DsseEnvelope {
        let mut r = rotation(&[], &[]);
        r.sequence = seq;
        r.add = add.iter().map(|s| fmt(*s)).collect();
        r.remove = remove.iter().map(|s| fmt(*s)).collect();
        let keys: Vec<SigningKey> = signers.iter().map(|s| key(*s)).collect();
        let refs: Vec<&SigningKey> = keys.iter().collect();
        sign_rotation(&r, &refs).unwrap()
    }

    #[test]
    fn a_trusted_key_rotates_in_a_new_key() {
        let env = signed(&[2], &[], 1, &[1]);
        let out = apply_rotation(TrustDomain::Execution, &[vk(1)], &env, 0, ts(12)).unwrap();
        assert_eq!(out.keys, vec![vk(1), vk(2)]);
        assert_eq!(out.rotation.sequence, 1);
        assert_eq!(out.signer_key_ids.len(), 1);
    }

    #[test]
    fn a_signer_may_retire_itself_when_it_names_a_successor() {
        let env = signed(&[2], &[1], 1, &[1]);
        let out = apply_rotation(TrustDomain::Execution, &[vk(1)], &env, 0, ts(12)).unwrap();
        assert_eq!(out.keys, vec![vk(2)]);
    }

    #[test]
    fn removing_every_signer_without_a_replacement_is_refused() {
        let env = signed(&[], &[1], 1, &[1]);
        assert!(matches!(
            apply_rotation(TrustDomain::Execution, &[vk(1), vk(2)], &env, 0, ts(12)),
            Err(RotationError::SignersRemovedWithoutReplacement)
        ));
        // Removing a peer (not a signer) is fine.
        let env = signed(&[], &[2], 1, &[1]);
        let out = apply_rotation(TrustDomain::Execution, &[vk(1), vk(2)], &env, 0, ts(12)).unwrap();
        assert_eq!(out.keys, vec![vk(1)]);
    }

    #[test]
    fn an_untrusted_signer_cannot_establish_its_own_authority() {
        // Signed by key 9, which adds itself: the current set does not trust it.
        let env = signed(&[9], &[], 1, &[9]);
        assert!(matches!(
            apply_rotation(TrustDomain::Execution, &[vk(1)], &env, 0, ts(12)),
            Err(RotationError::Envelope(OpenError::Signature(
                VerifyError::NoTrustedSignature
            )))
        ));
    }

    #[test]
    fn a_threshold_of_two_needs_two_current_signers() {
        let env = signed(&[3], &[], 1, &[1]);
        assert!(matches!(
            apply_rotation_with_threshold(
                TrustDomain::Execution,
                &[vk(1), vk(2)],
                &env,
                0,
                ts(12),
                2
            ),
            Err(RotationError::Envelope(OpenError::Signature(
                VerifyError::BelowThreshold { .. }
            )))
        ));
        let env = signed(&[3], &[], 1, &[1, 2]);
        assert!(
            apply_rotation_with_threshold(
                TrustDomain::Execution,
                &[vk(1), vk(2)],
                &env,
                0,
                ts(12),
                2
            )
            .is_ok()
        );
    }

    #[test]
    fn a_replayed_or_older_sequence_is_refused() {
        let env = signed(&[2], &[], 5, &[1]);
        for last in [5, 6] {
            assert!(matches!(
                apply_rotation(TrustDomain::Execution, &[vk(1)], &env, last, ts(12)),
                Err(RotationError::NotNewer { sequence: 5, .. })
            ));
        }
    }

    #[test]
    fn another_domain_is_refused() {
        let env = signed(&[2], &[], 1, &[1]);
        assert!(matches!(
            apply_rotation(TrustDomain::VendorRelease, &[vk(1)], &env, 0, ts(12)),
            Err(RotationError::WrongDomain { .. })
        ));
    }

    #[test]
    fn outside_the_window_is_refused() {
        let env = signed(&[2], &[], 1, &[1]);
        for now in [ts(9), ts(20)] {
            assert!(matches!(
                apply_rotation(TrustDomain::Execution, &[vk(1)], &env, 0, now),
                Err(RotationError::NotApplicable)
            ));
        }
    }

    #[test]
    fn unknown_removals_and_duplicate_adds_are_refused() {
        let env = signed(&[], &[7], 1, &[1]);
        assert!(matches!(
            apply_rotation(TrustDomain::Execution, &[vk(1)], &env, 0, ts(12)),
            Err(RotationError::UnknownRemoval(_))
        ));
        let env = signed(&[1], &[], 1, &[1]);
        assert!(matches!(
            apply_rotation(TrustDomain::Execution, &[vk(1)], &env, 0, ts(12)),
            Err(RotationError::AlreadyTrusted(_))
        ));
    }

    #[test]
    fn a_rotation_never_leaves_an_empty_set() {
        // Two signers each remove the other and themselves with no add:
        // refused by the self-removal rule before the empty check.
        let env = signed(&[], &[1, 2], 1, &[1, 2]);
        assert!(matches!(
            apply_rotation(TrustDomain::Execution, &[vk(1), vk(2)], &env, 0, ts(12)),
            Err(RotationError::SignersRemovedWithoutReplacement)
        ));
    }

    #[test]
    fn a_duplicated_current_set_is_deduplicated() {
        let env = signed(&[2], &[], 1, &[1]);
        let out = apply_rotation(TrustDomain::Execution, &[vk(1), vk(1)], &env, 0, ts(12)).unwrap();
        assert_eq!(out.keys, vec![vk(1), vk(2)]);
    }

    #[test]
    fn a_syntactically_valid_but_undecodable_key_is_refused() {
        let mut r = rotation(&["ed25519:not-base64!"], &[]);
        r.sequence = 1;
        let env = sign_rotation(&r, &[&key(1)]).unwrap();
        assert!(matches!(
            apply_rotation(TrustDomain::Execution, &[vk(1)], &env, 0, ts(12)),
            Err(RotationError::BadKey(_))
        ));
    }

    #[test]
    fn verify_rotation_inspects_without_applying() {
        let env = signed(&[2], &[], 3, &[1]);
        let r = verify_rotation(&env, &[vk(1)], 1).unwrap();
        assert_eq!(r.sequence, 3);
        assert_eq!(r.add, vec![fmt(2)]);
    }
}
