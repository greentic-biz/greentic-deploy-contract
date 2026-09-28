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
    assert_eq!(l.validate(), Err(RevocationError::ZeroSequence));
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
    assert_eq!(l.freshness(ts(12), day), Freshness::Fresh);
    assert_eq!(
        l.freshness(ts(20), day),
        Freshness::Stale {
            reason: StaleReason::Expired
        }
    );
    assert_eq!(
        l.freshness(ts(9), day),
        Freshness::Stale {
            reason: StaleReason::IssuedInFuture
        }
    );
    assert_eq!(
        l.freshness(ts(13), Duration::hours(2)),
        Freshness::Stale {
            reason: StaleReason::TooOld
        }
    );
    assert_eq!(l.freshness(ts(12), Duration::hours(2)), Freshness::Fresh);
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
    use ed25519_dalek::SigningKey;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn round_trip_and_key_checks() {
        let signer = key(1);
        let revoked = key(2).verifying_key();
        let mut l = sample();
        l.revoked_key_ids = vec![key_id(&revoked)];
        let env = sign_revocation(&l, &[&signer]).unwrap();
        let back = verify_revocation(&env, &[signer.verifying_key()], 1).unwrap();
        assert_eq!(back, l);
        assert!(back.is_revoked_key(&revoked));
        assert!(!back.is_revoked_key(&signer.verifying_key()));
        assert_eq!(
            back.retain_unrevoked(&[signer.verifying_key(), revoked]),
            vec![signer.verifying_key()]
        );
    }

    #[test]
    fn an_untrusted_issuer_is_refused() {
        let env = sign_revocation(&sample(), &[&key(1)]).unwrap();
        assert!(matches!(
            verify_revocation(&env, &[key(3).verifying_key()], 1),
            Err(OpenError::Signature(VerifyError::NoTrustedSignature))
        ));
    }
}
