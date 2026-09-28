use super::*;
use crate::execution::tests::digest;
use chrono::TimeZone;
use serde_json::json;

fn ts(hour: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 28, hour, 0, 0).unwrap()
}

fn entry() -> StatusEntry {
    StatusEntry {
        rollout_id: "ro-1".into(),
        authorisation_id: Some("auth-1".into()),
        release_digest: digest('a'),
        environment_id: "prod".into(),
        unit_id: "env:bundle-a".into(),
        state: ExecState::Healthy,
        reason: None,
        recorded_at: ts(10),
    }
}

fn sample() -> StatusReport {
    StatusReport {
        schema: STATUS_REPORT_SCHEMA.into(),
        installation_id: "inst-1".into(),
        report_id: "rep-1".into(),
        sequence: 1,
        observed_at: ts(11),
        entries: vec![entry()],
    }
}

#[test]
fn a_well_formed_report_validates() {
    assert_eq!(sample().validate(), Ok(()));
}

#[test]
fn an_empty_report_is_valid() {
    let mut r = sample();
    r.entries.clear();
    assert_eq!(r.validate(), Ok(()));
}

#[test]
fn report_level_refusals() {
    let mut r = sample();
    r.schema = "greentic.status-report.v2".into();
    assert!(matches!(r.validate(), Err(StatusError::UnknownSchema(_))));
    let mut r = sample();
    r.sequence = 0;
    assert_eq!(r.validate(), Err(StatusError::ZeroSequence));
    let mut r = sample();
    r.installation_id = "".into();
    assert_eq!(
        r.validate(),
        Err(StatusError::BadIdentifier("installation_id"))
    );
    let mut r = sample();
    r.report_id = "rep-1 ".into();
    assert_eq!(r.validate(), Err(StatusError::BadIdentifier("report_id")));
}

#[test]
fn the_entry_cap_is_inclusive() {
    let mut r = sample();
    r.entries = vec![entry(); MAX_STATUS_ENTRIES];
    assert_eq!(r.validate(), Ok(()));
    r.entries.push(entry());
    assert_eq!(r.validate(), Err(StatusError::TooManyEntries));
}

#[test]
fn entry_level_refusals() {
    type Case = (fn(&mut StatusEntry), StatusError);
    let cases: Vec<Case> = vec![
        (
            |e| e.release_digest = "sha256:ABC".into(),
            StatusError::BadDigest,
        ),
        (
            |e| e.rollout_id = " ".into(),
            StatusError::BadIdentifier("rollout_id"),
        ),
        (
            |e| e.authorisation_id = Some("".into()),
            StatusError::BadIdentifier("authorisation_id"),
        ),
        (
            |e| e.environment_id = "".into(),
            StatusError::BadIdentifier("environment_id"),
        ),
        (
            |e| e.unit_id = "".into(),
            StatusError::BadIdentifier("unit_id"),
        ),
        (
            |e| e.reason = Some("Not A Code".into()),
            StatusError::BadReason,
        ),
        (
            |e| e.recorded_at = ts(12),
            StatusError::RecordedAfterObservation,
        ),
    ];
    for (mutate, expected) in cases {
        let mut r = sample();
        mutate(&mut r.entries[0]);
        assert_eq!(r.validate(), Err(expected));
    }
}

#[test]
fn a_reason_code_and_no_authorisation_are_fine() {
    let mut r = sample();
    r.entries[0].authorisation_id = None;
    r.entries[0].state = ExecState::Rejected;
    r.entries[0].reason = Some("baseline_changed".into());
    assert_eq!(r.validate(), Ok(()));
}

#[test]
fn no_free_form_field_is_accepted() {
    let mut v = serde_json::to_value(sample()).unwrap();
    assert_eq!(v["entries"][0]["state"], "healthy");
    v["entries"][0]["detail"] = json!("secret stuff");
    assert!(serde_json::from_value::<StatusReport>(v).is_err());
    let mut v = serde_json::to_value(sample()).unwrap();
    v["health"] = json!({});
    assert!(serde_json::from_value::<StatusReport>(v).is_err());
    let mut v = serde_json::to_value(sample()).unwrap();
    v["entries"][0]["state"] = json!("mostly_fine");
    assert!(serde_json::from_value::<StatusReport>(v).is_err());
}

#[cfg(feature = "signing")]
mod signing_tests {
    use super::*;
    use crate::dsse::VerifyError;
    use crate::signed::{OpenError, SignError};
    use ed25519_dalek::SigningKey;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn round_trip() {
        let k = key(4);
        let env = sign_status(&sample(), &[&k]).unwrap();
        assert_eq!(env.payload_type, STATUS_REPORT_PAYLOAD_TYPE);
        assert_eq!(
            verify_status(&env, &[k.verifying_key()], 1).unwrap(),
            sample()
        );
    }

    #[test]
    fn another_installations_key_is_refused() {
        let env = sign_status(&sample(), &[&key(4)]).unwrap();
        assert!(matches!(
            verify_status(&env, &[key(5).verifying_key()], 1),
            Err(OpenError::Signature(VerifyError::NoTrustedSignature))
        ));
    }

    #[test]
    fn an_invalid_report_is_never_signed() {
        let mut r = sample();
        r.sequence = 0;
        assert!(matches!(
            sign_status(&r, &[&key(4)]),
            Err(SignError::Invalid(StatusError::ZeroSequence))
        ));
    }

    #[test]
    fn a_tampered_payload_is_refused() {
        let k = key(4);
        let mut env = sign_status(&sample(), &[&k]).unwrap();
        let mut r = sample();
        r.entries[0].state = ExecState::RolledBack;
        use base64::Engine;
        env.payload =
            base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&r).unwrap());
        assert!(matches!(
            verify_status(&env, &[k.verifying_key()], 1),
            Err(OpenError::Signature(VerifyError::NoTrustedSignature))
        ));
    }
}
