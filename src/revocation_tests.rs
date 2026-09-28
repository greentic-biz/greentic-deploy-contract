use super::*;
use crate::execution::tests::digest;
use chrono::TimeZone;
use serde_json::json;

fn ts(hour: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 28, hour, 0, 0).unwrap()
}

fn sample() -> RevocationList {
    RevocationList {
        schema: REVOCATION_SCHEMA.into(),
        issuer: "greentic".into(),
        sequence: 4,
        issued_at: ts(10),
        valid_until: ts(20),
        revoked_key_ids: vec!["0123456789abcdef".into()],
        revoked_release_digests: vec![digest('a')],
    }
}

#[test]
fn a_well_formed_list_validates() {
    assert_eq!(sample().validate(), Ok(()));
}

#[test]
fn shape_refusals() {
    let mut l = sample();
    l.schema = "greentic.revocation.v2".into();
    assert!(matches!(
        l.validate(),
        Err(RevocationError::UnknownSchema(_))
    ));
    let mut l = sample();
    l.issuer = " greentic".into();
    assert_eq!(l.validate(), Err(RevocationError::BadIssuer));
    let mut l = sample();
    l.sequence = 0;
    assert_eq!(l.validate(), Err(RevocationError::BadSequence));
    l.sequence = crate::MAX_SEQUENCE + 1;
    assert_eq!(l.validate(), Err(RevocationError::BadSequence));
    l.sequence = crate::MAX_SEQUENCE;
    assert_eq!(l.validate(), Ok(()));
    let mut l = sample();
    l.valid_until = l.issued_at;
    assert_eq!(l.validate(), Err(RevocationError::WindowInverted));
}

#[test]
fn entry_refusals() {
    for bad in ["0123456789ABCDEF", "0123", "0123456789abcdefg"] {
        let mut l = sample();
        l.revoked_key_ids = vec![bad.into()];
        assert!(matches!(l.validate(), Err(RevocationError::BadKeyId(_))));
    }
    let mut l = sample();
    l.revoked_release_digests.push("sha256:nope".into());
    assert!(matches!(l.validate(), Err(RevocationError::BadDigest(_))));
    let mut l = sample();
    l.revoked_key_ids.push("0123456789abcdef".into());
    assert!(matches!(l.validate(), Err(RevocationError::Duplicate(_))));
    let mut l = sample();
    l.revoked_release_digests.push(digest('a'));
    assert!(matches!(l.validate(), Err(RevocationError::Duplicate(_))));
}

#[test]
fn an_empty_list_is_valid() {
    let mut l = sample();
    l.revoked_key_ids.clear();
    l.revoked_release_digests.clear();
    assert_eq!(l.validate(), Ok(()));
}

#[test]
fn freshness() {
    let l = sample();
    let day = Duration::hours(24);
    let none = Duration::zero();
    assert_eq!(l.freshness(ts(12), day, none), Freshness::Fresh);
    assert_eq!(
        l.freshness(ts(20), day, none),
        Freshness::Stale {
            reason: StaleReason::Expired
        }
    );
    assert_eq!(
        l.freshness(ts(9), day, none),
        Freshness::Stale {
            reason: StaleReason::IssuedInFuture
        }
    );
    assert_eq!(
        l.freshness(ts(13), Duration::hours(2), none),
        Freshness::Stale {
            reason: StaleReason::TooOld
        }
    );
    assert_eq!(
        l.freshness(ts(12), Duration::hours(2), none),
        Freshness::Fresh
    );
}

#[test]
fn skew_tolerates_a_slightly_early_issuer_clock() {
    let l = sample();
    let early = ts(10) - Duration::minutes(2);
    assert_eq!(
        l.freshness(early, Duration::hours(24), Duration::minutes(5)),
        Freshness::Fresh
    );
    assert_eq!(
        l.freshness(early, Duration::hours(24), Duration::minutes(1)),
        Freshness::Stale {
            reason: StaleReason::IssuedInFuture
        }
    );
    // Negative parameters read as zero.
    assert_eq!(
        l.freshness(ts(12), Duration::hours(-1), Duration::zero()),
        Freshness::Stale {
            reason: StaleReason::TooOld
        }
    );
}

#[test]
fn a_list_must_follow_the_previous_one() {
    let prev = sample();
    let mut next = sample();
    next.sequence = 5;
    assert_eq!(next.follows(&prev), Ok(()));
    next.sequence = 4;
    assert!(matches!(
        next.follows(&prev),
        Err(RevocationError::NotNewer { .. })
    ));
    let mut next = sample();
    next.sequence = 5;
    next.revoked_key_ids.clear();
    assert_eq!(
        next.follows(&prev),
        Err(RevocationError::DropsRevocation("0123456789abcdef".into()))
    );
    let mut next = sample();
    next.sequence = 5;
    next.revoked_release_digests.clear();
    assert!(matches!(
        next.follows(&prev),
        Err(RevocationError::DropsRevocation(_))
    ));
}

#[test]
fn lookups_are_exact() {
    let l = sample();
    assert!(l.is_revoked_key_id("0123456789abcdef"));
    assert!(!l.is_revoked_key_id("0123456789ABCDEF"));
    assert!(l.is_revoked_release(&digest('a')));
    assert!(!l.is_revoked_release(&digest('b')));
}

#[test]
fn unknown_fields_are_refused() {
    let mut v = serde_json::to_value(sample()).unwrap();
    v["extra"] = json!(true);
    assert!(serde_json::from_value::<RevocationList>(v).is_err());
}

#[cfg(feature = "signing")]
mod signing_tests {
    use super::*;
    use crate::dsse::{VerifyError, key_id};
    use crate::signed::OpenError;
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

    #[test]
    fn round_trip_and_key_checks() {
        let signer = key(1);
        let revoked = key(2).verifying_key();
        let mut l = sample();
        l.revoked_key_ids = vec![key_id(&revoked)];
        let env = sign_revocation(&l, &[&signer]).unwrap();
        let back = verify_revocation(&env, &vendor(&[1]), 1, None).unwrap();
        assert_eq!(back.value, l);
        assert_eq!(back.signer_key_ids, vec![key_id(&signer.verifying_key())]);
        assert!(back.value.is_revoked_key(&revoked));
        assert!(!back.value.is_revoked_key(&signer.verifying_key()));
        assert_eq!(
            back.value
                .retain_unrevoked(&[signer.verifying_key(), revoked]),
            vec![signer.verifying_key()]
        );
    }

    #[test]
    fn an_untrusted_issuer_or_wrong_domain_is_refused() {
        let env = sign_revocation(&sample(), &[&key(1)]).unwrap();
        assert!(matches!(
            verify_revocation(&env, &vendor(&[3]), 1, None),
            Err(OpenError::Signature(VerifyError::NoTrustedSignature))
        ));
        let status = TrustSet::new(TrustDomain::StatusReport, vec![key(1).verifying_key()]);
        assert!(matches!(
            verify_revocation(&env, &status, 1, None),
            Err(OpenError::WrongTrustDomain { .. })
        ));
    }

    #[test]
    fn a_revoked_key_cannot_sign_the_next_list_and_un_revoke_itself() {
        let leaked = key(2);
        let mut prev = sample();
        prev.revoked_key_ids = vec![key_id(&leaked.verifying_key())];
        let mut next = sample();
        next.sequence = 5;
        next.revoked_key_ids.clear();
        let env = sign_revocation(&next, &[&leaked]).unwrap();
        assert!(matches!(
            verify_revocation(&env, &vendor(&[1, 2]), 1, Some(&prev)),
            Err(OpenError::RevokedSigner(_))
        ));
    }

    #[test]
    fn a_list_signed_by_a_key_it_revokes_is_refused() {
        let k = key(1);
        let mut l = sample();
        l.revoked_key_ids = vec![key_id(&k.verifying_key())];
        let env = sign_revocation(&l, &[&k]).unwrap();
        assert!(matches!(
            verify_revocation(&env, &vendor(&[1]), 1, None),
            Err(OpenError::RevokedSigner(_))
        ));
    }

    #[test]
    fn the_next_list_must_be_newer_and_a_superset() {
        let prev = sample();
        let env = sign_revocation(&sample(), &[&key(1)]).unwrap();
        assert!(matches!(
            verify_revocation(&env, &vendor(&[1]), 1, Some(&prev)),
            Err(OpenError::Invalid(RevocationError::NotNewer { .. }))
        ));
        let mut next = sample();
        next.sequence = 5;
        next.revoked_release_digests.clear();
        let env = sign_revocation(&next, &[&key(1)]).unwrap();
        assert!(matches!(
            verify_revocation(&env, &vendor(&[1]), 1, Some(&prev)),
            Err(OpenError::Invalid(RevocationError::DropsRevocation(_)))
        ));
        let mut next = sample();
        next.sequence = 5;
        next.revoked_release_digests.push(digest('b'));
        let env = sign_revocation(&next, &[&key(1)]).unwrap();
        assert!(verify_revocation(&env, &vendor(&[1]), 1, Some(&prev)).is_ok());
    }
}
