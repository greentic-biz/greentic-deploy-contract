use super::*;
use crate::execution::tests::{digest, sample as v1_sample};
use crate::execution::{EXECUTION_AUTHORISATION_SCHEMA, ValidationError};
use serde_json::json;

pub(crate) fn sample_v2(operation: ExecOperationV2) -> ExecutionAuthorisationV2 {
    let v1 = v1_sample();
    ExecutionAuthorisationV2 {
        schema: EXECUTION_AUTHORISATION_V2_SCHEMA.to_string(),
        authorisation_id: v1.authorisation_id,
        installation_id: v1.installation_id,
        tenant_id: v1.tenant_id,
        environment_id: v1.environment_id,
        rollout_id: v1.rollout_id,
        release_id: v1.release_id,
        release_digest: v1.release_digest,
        operation,
        units: v1.units,
        policy_generation: v1.policy_generation,
        sequence: v1.sequence,
        fence: v1.fence,
        not_before: v1.not_before,
        expires_at: v1.expires_at,
        traffic: v1.traffic,
    }
}

pub(crate) fn remove_sample() -> ExecutionAuthorisationV2 {
    let mut a = sample_v2(ExecOperationV2::Remove {
        retain_data: true,
        drain_seconds: 120,
    });
    for u in &mut a.units {
        u.target = UnitBaseline::default();
    }
    a
}

#[test]
fn update_and_remove_validate() {
    assert_eq!(sample_v2(ExecOperationV2::Update).validate(), Ok(()));
    assert_eq!(remove_sample().validate(), Ok(()));
}

#[test]
fn remove_serialises_as_a_tagged_object() {
    let v = serde_json::to_value(remove_sample()).unwrap();
    assert_eq!(
        v["operation"],
        json!({"remove": {"retain_data": true, "drain_seconds": 120}})
    );
    assert_eq!(
        serde_json::to_value(ExecOperationV2::Update).unwrap(),
        json!("update")
    );
}

#[test]
fn unknown_fields_in_remove_do_not_parse() {
    let r: Result<ExecOperationV2, _> = serde_json::from_value(
        json!({"remove": {"retain_data": true, "drain_seconds": 1, "purge": true}}),
    );
    assert!(r.is_err());
    let r: Result<ExecOperationV2, _> = serde_json::from_value(json!("destroy"));
    assert!(r.is_err());
}

#[test]
fn v1_schema_does_not_validate_as_v2() {
    let mut a = remove_sample();
    a.schema = EXECUTION_AUTHORISATION_SCHEMA.to_string();
    assert!(matches!(
        a.validate(),
        Err(ValidationErrorV2::Common(ValidationError::UnknownSchema(_)))
    ));
}

#[test]
fn v1_does_not_accept_remove() {
    let mut v = serde_json::to_value(v1_sample()).unwrap();
    v["operation"] = json!({"remove": {"retain_data": true, "drain_seconds": 1}});
    assert!(serde_json::from_value::<crate::execution::ExecutionAuthorisation>(v).is_err());
}

#[test]
fn remove_rules() {
    let mut a = remove_sample();
    a.operation = ExecOperationV2::Remove {
        retain_data: false,
        drain_seconds: MAX_DRAIN_SECONDS + 1,
    };
    assert_eq!(a.validate(), Err(ValidationErrorV2::DrainTooLong));

    let mut a = remove_sample();
    a.units[0].target.bundle_digest = Some(digest('e'));
    assert!(matches!(
        a.validate(),
        Err(ValidationErrorV2::RemoveTargetNotEmpty(_))
    ));

    let mut a = remove_sample();
    a.units[0].expected_baseline.bundle_digest = None;
    assert!(matches!(
        a.validate(),
        Err(ValidationErrorV2::RemoveNothingDeployed(_))
    ));
}

#[test]
fn shared_rules_still_apply() {
    let mut a = remove_sample();
    a.units.clear();
    assert_eq!(
        a.validate(),
        Err(ValidationErrorV2::Common(ValidationError::NoUnits))
    );
    let mut a = sample_v2(ExecOperationV2::Update);
    a.units[0].target.bundle_digest = None;
    assert!(matches!(
        a.validate(),
        Err(ValidationErrorV2::Common(
            ValidationError::MissingTargetDigest(_)
        ))
    ));
}

#[test]
fn unified_view_maps_v1_operations() {
    let v = VerifiedAuthorisation::V1(v1_sample());
    assert_eq!(v.operation(), ExecOperationV2::Update);
    assert_eq!(v.schema_version(), 1);
    assert_eq!(v.authorisation_id(), "auth-1");
    assert_eq!(v.sequence(), 7);
    let r = VerifiedAuthorisation::V2(remove_sample());
    assert_eq!(r.schema_version(), 2);
    assert!(matches!(r.operation(), ExecOperationV2::Remove { .. }));
    assert_eq!(r.units().len(), 1);
}

#[cfg(feature = "signing")]
mod signing {
    use super::*;
    use crate::dsse::{DsseEnvelope, VerifyError, sign, verify};
    use ed25519_dalek::SigningKey;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// Captured from the v1 signer BEFORE v2 existed. If this moves, v1's
    /// signed bytes changed and every deployed verifier breaks.
    const V1_GOLDEN: &str = r#"{"payloadType":"application/vnd.greentic.execution-authorisation.v1+json","payload":"eyJzY2hlbWEiOiJncmVlbnRpYy5leGVjdXRpb24tYXV0aG9yaXNhdGlvbi52MSIsImF1dGhvcmlzYXRpb25faWQiOiJhdXRoLTEiLCJpbnN0YWxsYXRpb25faWQiOiJpbnN0LTEiLCJ0ZW5hbnRfaWQiOiJhY21lIiwiZW52aXJvbm1lbnRfaWQiOiJwcm9kIiwicm9sbG91dF9pZCI6InJvLTEiLCJyZWxlYXNlX2lkIjoicmVsLTEiLCJyZWxlYXNlX2RpZ2VzdCI6InNoYTI1NjphYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhIiwib3BlcmF0aW9uIjoidXBkYXRlIiwidW5pdHMiOlt7InVuaXRfaWQiOiJlbnY6YnVuZGxlLWEiLCJleHBlY3RlZF9iYXNlbGluZSI6eyJidW5kbGVfZGlnZXN0Ijoic2hhMjU2OmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmIiLCJydW50aW1lX2ltYWdlX2RpZ2VzdCI6InNoYTI1NjpjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjIiwib3ZlcnJpZGVzX2RpZ2VzdCI6InNoYTI1NjpkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkIn0sInRhcmdldCI6eyJidW5kbGVfZGlnZXN0Ijoic2hhMjU2OmVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWUiLCJydW50aW1lX2ltYWdlX2RpZ2VzdCI6InNoYTI1NjpjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjIiwib3ZlcnJpZGVzX2RpZ2VzdCI6InNoYTI1NjpkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkIn19XSwicG9saWN5X2dlbmVyYXRpb24iOjMsInNlcXVlbmNlIjo3LCJmZW5jZSI6NDIsIm5vdF9iZWZvcmUiOiIyMDI2LTA5LTI3VDEwOjAwOjAwWiIsImV4cGlyZXNfYXQiOiIyMDI2LTA5LTI3VDEyOjAwOjAwWiIsInRyYWZmaWMiOnsic3RlcHMiOlsxMCw1MCwxMDBdLCJzdGVwX3dhaXRfc2VjcyI6MzAwLCJtYXhfZXJyb3JfcmF0ZSI6MC4wNSwiYXV0b19yb2xsYmFjayI6ZmFsc2V9fQ==","signatures":[{"keyid":"fe812c12f3ab4ce6","sig":"llOuQe+YYb8B0N92djEGcXLQuBT9Ydxn/XtKfhVNv4edDQccnQBm2J6WJTc/oJBhyH6+l9MzzBZRVusaTqyxCw=="}]}"#;

    #[test]
    fn v1_sign_output_is_unchanged() {
        let env = sign(&v1_sample(), &key(7)).unwrap();
        assert_eq!(serde_json::to_string(&env).unwrap(), V1_GOLDEN);
    }

    #[test]
    fn verify_any_accepts_both_versions() {
        let k = key(1);
        let trusted = [k.verifying_key()];
        let v1 = sign(&v1_sample(), &k).unwrap();
        assert_eq!(
            verify_any(&v1, &trusted).unwrap(),
            VerifiedAuthorisation::V1(v1_sample())
        );
        let v2 = sign_v2(&remove_sample(), &k).unwrap();
        assert_eq!(v2.payload_type, EXECUTION_AUTHORISATION_V2_PAYLOAD_TYPE);
        assert_eq!(
            verify_any(&v2, &trusted).unwrap(),
            VerifiedAuthorisation::V2(remove_sample())
        );
    }

    #[test]
    fn v1_verify_refuses_a_v2_envelope() {
        let k = key(1);
        let v2 = sign_v2(&remove_sample(), &k).unwrap();
        assert!(matches!(
            verify(&v2, &[k.verifying_key()]),
            Err(VerifyError::WrongPayloadType)
        ));
    }

    #[test]
    fn relabelling_the_payload_type_breaks_the_signature() {
        let k = key(1);
        let mut env: DsseEnvelope = sign(&v1_sample(), &k).unwrap();
        env.payload_type = EXECUTION_AUTHORISATION_V2_PAYLOAD_TYPE.to_string();
        assert!(matches!(
            verify_any(&env, &[k.verifying_key()]),
            Err(VerifyError::NoTrustedSignature)
        ));
    }

    #[test]
    fn unknown_payload_type_and_untrusted_key_are_refused() {
        let k = key(1);
        let mut env = sign_v2(&remove_sample(), &k).unwrap();
        assert!(matches!(
            verify_any(&env, &[key(2).verifying_key()]),
            Err(VerifyError::NoTrustedSignature)
        ));
        env.payload_type = "application/json".into();
        assert!(matches!(
            verify_any(&env, &[k.verifying_key()]),
            Err(VerifyError::WrongPayloadType)
        ));
    }

    #[test]
    fn an_invalid_v2_is_never_signed() {
        let mut a = remove_sample();
        a.units[0].expected_baseline.bundle_digest = None;
        assert!(matches!(sign_v2(&a, &key(1)), Err(SignV2Error::Invalid(_))));
    }
}
