use super::*;
use crate::execution_v2::tests::{remove_sample, sample_v2};
use serde_json::json;

pub(crate) fn sample_v4(channel: ReleaseChannel) -> ExecutionAuthorisationV4 {
    let v2 = sample_v2(ExecOperationV2::Update);
    from_v2(v2, channel)
}

fn from_v2(v2: ExecutionAuthorisationV2, channel: ReleaseChannel) -> ExecutionAuthorisationV4 {
    ExecutionAuthorisationV4 {
        schema: EXECUTION_AUTHORISATION_V4_SCHEMA.to_string(),
        authorisation_id: v2.authorisation_id,
        installation_id: v2.installation_id,
        tenant_id: v2.tenant_id,
        environment_id: v2.environment_id,
        rollout_id: v2.rollout_id,
        release_id: v2.release_id,
        release_digest: v2.release_digest,
        channel,
        operation: v2.operation,
        units: v2.units,
        policy_generation: v2.policy_generation,
        sequence: v2.sequence,
        fence: v2.fence,
        not_before: v2.not_before,
        expires_at: v2.expires_at,
        traffic: v2.traffic,
    }
}

#[test]
fn update_rollback_and_remove_validate() {
    assert_eq!(sample_v4(ReleaseChannel::Stable).validate(), Ok(()));
    let mut rb = sample_v4(ReleaseChannel::Dev);
    rb.operation = ExecOperationV2::Rollback;
    assert_eq!(rb.validate(), Ok(()));
    let rm = from_v2(remove_sample(), ReleaseChannel::Stable);
    assert_eq!(rm.validate(), Ok(()));
}

#[test]
fn v2_rules_apply_to_v4() {
    let mut rm = from_v2(remove_sample(), ReleaseChannel::Stable);
    rm.traffic.steps = vec![50, 100];
    assert_eq!(
        rm.validate(),
        Err(ValidationErrorV4::Shared(
            ValidationErrorV2::RemoveTrafficSplit
        ))
    );
}

#[test]
fn a_wrong_schema_string_is_refused() {
    let mut a = sample_v4(ReleaseChannel::Stable);
    a.schema = "greentic.execution-authorisation.v2".into();
    assert_eq!(a.validate(), Err(ValidationErrorV4::WrongSchema));
}

#[test]
fn channel_serialises_as_a_lowercase_string() {
    let v = serde_json::to_value(sample_v4(ReleaseChannel::Dev)).unwrap();
    assert_eq!(v["channel"], json!("dev"));
}

#[test]
fn an_unknown_channel_does_not_parse() {
    let mut v = serde_json::to_value(sample_v4(ReleaseChannel::Stable)).unwrap();
    v["channel"] = json!("beta");
    assert!(serde_json::from_value::<ExecutionAuthorisationV4>(v).is_err());
}

#[test]
fn a_missing_channel_does_not_parse() {
    let mut v = serde_json::to_value(sample_v4(ReleaseChannel::Stable)).unwrap();
    v.as_object_mut().unwrap().remove("channel");
    assert!(serde_json::from_value::<ExecutionAuthorisationV4>(v).is_err());
}

#[cfg(feature = "signing")]
mod signing {
    use super::*;
    use crate::dsse::{DsseEnvelope, VerifyError, sign_bytes};
    use crate::execution_v2::verify_any;
    use crate::execution_v3::{VerifiedAny, verify_any_v3};
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use ed25519_dalek::SigningKey;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn a_v4_envelope_round_trips_through_verify_v4_and_verify_any_v4() {
        let a = sample_v4(ReleaseChannel::Dev);
        let env = sign_v4(&a, &key()).expect("signs");
        let trusted = [key().verifying_key()];
        assert_eq!(verify_v4(&env, &trusted).expect("verifies"), a);
        let any = verify_any_v4(&env, &trusted).expect("verifies");
        assert_eq!(any, VerifiedAny::Channelled(a.clone()));
        assert_eq!(any.channel(), Some(ReleaseChannel::Dev));
        assert_eq!(any.sequence(), a.sequence);
    }

    #[test]
    fn older_versions_still_route_through_verify_any_v4() {
        let env = crate::execution_v2::sign_v2(&remove_sample(), &key()).expect("signs");
        let got = verify_any_v4(&env, &[key().verifying_key()]).expect("verifies");
        assert!(matches!(got, VerifiedAny::Change(_)));
        assert_eq!(got.channel(), None);
    }

    #[test]
    fn the_channel_is_covered_by_the_signature() {
        let env = sign_v4(&sample_v4(ReleaseChannel::Stable), &key()).expect("signs");
        let raw = STANDARD.decode(&env.payload).expect("base64");
        let text = String::from_utf8(raw).expect("utf8");
        assert!(text.contains("\"channel\":\"stable\""));
        let tampered = text.replace("\"channel\":\"stable\"", "\"channel\":\"dev\"");
        let forged = DsseEnvelope {
            payload: STANDARD.encode(tampered),
            ..env
        };
        assert!(matches!(
            verify_v4(&forged, &[key().verifying_key()]),
            Err(VerifyError::NoTrustedSignature)
        ));
        assert!(matches!(
            verify_any_v4(&forged, &[key().verifying_key()]),
            Err(VerifyError::NoTrustedSignature)
        ));
    }

    #[test]
    fn a_signed_unknown_channel_is_refused_as_a_bad_payload() {
        let mut v = serde_json::to_value(sample_v4(ReleaseChannel::Stable)).unwrap();
        v["channel"] = json!("beta");
        let env = sign_bytes(
            EXECUTION_AUTHORISATION_V4_PAYLOAD_TYPE,
            &serde_json::to_vec(&v).unwrap(),
            &[&key()],
        );
        assert!(matches!(
            verify_v4(&env, &[key().verifying_key()]),
            Err(VerifyError::BadPayload(_))
        ));
    }

    #[test]
    fn an_invalid_v4_is_not_signed() {
        let mut a = sample_v4(ReleaseChannel::Stable);
        a.schema = "nope".into();
        assert!(matches!(
            sign_v4(&a, &key()),
            Err(SignV4Error::Invalid(ValidationErrorV4::WrongSchema))
        ));
    }

    /// An older verifier knows no v4 payload type: the envelope is refused
    /// before anything is parsed, which is how a pre-v4 designer stays safe.
    #[test]
    fn older_verifiers_refuse_a_v4_envelope() {
        let env = sign_v4(&sample_v4(ReleaseChannel::Stable), &key()).expect("signs");
        let trusted = [key().verifying_key()];
        assert!(matches!(
            verify_any(&env, &trusted),
            Err(VerifyError::WrongPayloadType)
        ));
        assert!(matches!(
            verify_any_v3(&env, &trusted),
            Err(VerifyError::WrongPayloadType)
        ));
    }

    #[test]
    fn an_unknown_schema_payload_type_is_refused() {
        let payload = serde_json::to_vec(&sample_v4(ReleaseChannel::Stable)).unwrap();
        let env = sign_bytes(
            "application/vnd.greentic.execution-authorisation.v99+json",
            &payload,
            &[&key()],
        );
        assert!(matches!(
            verify_any_v4(&env, &[key().verifying_key()]),
            Err(VerifyError::WrongPayloadType)
        ));
    }
}
