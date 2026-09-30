use chrono::{Duration, TimeZone, Utc};

use super::*;
use crate::execution::{TrafficPolicy, UnitBaseline, UnitTarget};

fn d(c: char) -> String {
    format!("sha256:{}", c.to_string().repeat(64))
}

pub(crate) fn runtime_update() -> ExecutionAuthorisationV3 {
    let now = Utc
        .with_ymd_and_hms(2026, 9, 30, 0, 0, 0)
        .single()
        .expect("time");
    ExecutionAuthorisationV3 {
        schema: EXECUTION_AUTHORISATION_V3_SCHEMA.into(),
        authorisation_id: "a-1".into(),
        installation_id: "inst".into(),
        tenant_id: "t".into(),
        environment_id: "env".into(),
        rollout_id: "r".into(),
        release_id: "rel-start-1.3.0".into(),
        release_digest: d('9'),
        operation: ExecOperationV3::RuntimeUpdate,
        units: vec![UnitTarget {
            unit_id: "canvas:bot".into(),
            expected_baseline: UnitBaseline {
                bundle_digest: Some(d('b')),
                runtime_image_digest: Some(d('e')),
                overrides_digest: Some(d('d')),
            },
            target: UnitBaseline {
                bundle_digest: Some(d('b')),
                runtime_image_digest: Some(d('f')),
                overrides_digest: Some(d('d')),
            },
        }],
        policy_generation: 1,
        sequence: 7,
        fence: 3,
        not_before: now,
        expires_at: now + Duration::hours(1),
        traffic: TrafficPolicy {
            steps: vec![10, 50, 100],
            step_wait_secs: 300,
            max_error_rate: 0.05,
            auto_rollback: false,
        },
    }
}

#[test]
fn a_well_formed_runtime_update_validates() {
    assert_eq!(runtime_update().validate(), Ok(()));
}

#[test]
fn the_bundle_may_not_change() {
    let mut a = runtime_update();
    a.units[0].target.bundle_digest = Some(d('c'));
    assert_eq!(
        a.validate(),
        Err(ValidationErrorV3::BundleChanged("canvas:bot".into()))
    );
}

#[test]
fn the_overrides_may_not_change() {
    let mut a = runtime_update();
    a.units[0].target.overrides_digest = None;
    assert_eq!(
        a.validate(),
        Err(ValidationErrorV3::OverridesChanged("canvas:bot".into()))
    );
}

#[test]
fn a_unit_that_runs_nothing_has_no_runtime_to_change() {
    let mut a = runtime_update();
    a.units[0].expected_baseline.bundle_digest = None;
    a.units[0].target.bundle_digest = None;
    assert_eq!(
        a.validate(),
        Err(ValidationErrorV3::NothingDeployed("canvas:bot".into()))
    );
}

#[test]
fn both_runtimes_are_required_and_must_differ() {
    let mut a = runtime_update();
    a.units[0].expected_baseline.runtime_image_digest = None;
    assert_eq!(
        a.validate(),
        Err(ValidationErrorV3::RuntimeMissing("canvas:bot".into()))
    );
    let mut b = runtime_update();
    b.units[0].target.runtime_image_digest = Some(d('e'));
    assert_eq!(
        b.validate(),
        Err(ValidationErrorV3::RuntimeUnchanged("canvas:bot".into()))
    );
}

#[test]
fn a_missing_target_runtime_is_refused() {
    let mut a = runtime_update();
    a.units[0].target.runtime_image_digest = None;
    assert_eq!(
        a.validate(),
        Err(ValidationErrorV3::RuntimeMissing("canvas:bot".into()))
    );
}

#[test]
fn the_error_names_the_second_unit_when_only_it_is_bad() {
    let mut a = runtime_update();
    let mut second = a.units[0].clone();
    second.unit_id = "canvas:other".into();
    second.target.bundle_digest = Some(d('c'));
    a.units.push(second);
    assert_eq!(
        a.validate(),
        Err(ValidationErrorV3::BundleChanged("canvas:other".into()))
    );
}

#[test]
fn verified_any_accessors_read_both_arms() {
    use crate::execution_v3::VerifiedAny;
    let v3 = runtime_update();
    let any = VerifiedAny::Runtime(v3.clone());
    assert_eq!(any.sequence(), 7);
    assert_eq!(any.fence(), 3);
    assert_eq!(any.installation_id(), "inst");
    assert_eq!(any.environment_id(), "env");
    assert_eq!(any.authorisation_id(), "a-1");
    assert_eq!(any.tenant_id(), "t");
    assert_eq!(any.expires_at(), v3.expires_at);

    let v2 = crate::execution_v2::tests::remove_sample();
    let any = VerifiedAny::Change(crate::execution_v2::VerifiedAuthorisation::V2(v2.clone()));
    assert_eq!(any.sequence(), v2.sequence);
    assert_eq!(any.fence(), v2.fence);
    assert_eq!(any.installation_id(), v2.installation_id);
    assert_eq!(any.environment_id(), v2.environment_id);
    assert_eq!(any.authorisation_id(), v2.authorisation_id);
    assert_eq!(any.tenant_id(), v2.tenant_id);
    assert_eq!(any.expires_at(), v2.expires_at);
}

#[test]
fn a_rollback_follows_the_same_rules() {
    let mut a = runtime_update();
    a.operation = ExecOperationV3::RuntimeRollback;
    assert_eq!(a.validate(), Ok(()));
}

#[test]
fn an_unknown_operation_or_field_does_not_parse() {
    let mut v = serde_json::to_value(runtime_update()).expect("ser");
    v["operation"] = serde_json::json!("update");
    assert!(serde_json::from_value::<ExecutionAuthorisationV3>(v.clone()).is_err());
    v["operation"] = serde_json::json!("runtime_update");
    v["extra"] = serde_json::json!(1);
    assert!(serde_json::from_value::<ExecutionAuthorisationV3>(v).is_err());
}

#[test]
fn the_wrong_schema_is_refused() {
    let mut a = runtime_update();
    a.schema = "greentic.execution-authorisation.v2".into();
    assert!(matches!(a.validate(), Err(ValidationErrorV3::Common(_))));
}

#[cfg(feature = "signing")]
mod signing {
    use ed25519_dalek::SigningKey;

    use super::runtime_update;
    use crate::dsse::{VerifyError, sign_bytes};
    use crate::execution_v2::verify_any;
    use crate::execution_v3::{
        EXECUTION_AUTHORISATION_V3_PAYLOAD_TYPE, SignV3Error, ValidationErrorV3, VerifiedAny,
        sign_v3, verify_any_v3, verify_v3,
    };

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn a_v3_envelope_round_trips_through_verify_any_v3() {
        let env = sign_v3(&runtime_update(), &key()).expect("signs");
        let got = verify_any_v3(&env, &[key().verifying_key()]).expect("verifies");
        assert_eq!(got, VerifiedAny::Runtime(runtime_update()));
    }

    /// A designer built before v3 calls `verify_any`; it must refuse a v3
    /// envelope rather than parse it as something it knows.
    #[test]
    fn the_v1_v2_verifier_refuses_a_v3_envelope() {
        let env = sign_v3(&runtime_update(), &key()).expect("signs");
        assert!(matches!(
            verify_any(&env, &[key().verifying_key()]),
            Err(crate::dsse::VerifyError::WrongPayloadType)
        ));
    }

    #[test]
    fn a_v2_envelope_still_verifies_as_a_change() {
        let v2 = crate::execution_v2::tests::remove_sample();
        let env = crate::execution_v2::sign_v2(&v2, &key()).expect("signs");
        assert!(matches!(
            verify_any_v3(&env, &[key().verifying_key()]),
            Ok(VerifiedAny::Change(_))
        ));
    }

    #[test]
    fn an_invalid_v3_is_not_signed() {
        let mut a = runtime_update();
        a.units[0].target.bundle_digest = None;
        assert!(matches!(
            sign_v3(&a, &key()),
            Err(SignV3Error::Invalid(ValidationErrorV3::BundleChanged(_)))
        ));
    }

    /// Well-signed but invalid: both entry points refuse it as InvalidV3.
    #[test]
    fn a_well_signed_invalid_v3_is_refused_by_both_verifiers() {
        let mut a = runtime_update();
        a.units[0].target.bundle_digest = Some(super::d('c'));
        let payload = serde_json::to_vec(&a).expect("ser");
        let env = sign_bytes(EXECUTION_AUTHORISATION_V3_PAYLOAD_TYPE, &payload, &[&key()]);
        let trusted = [key().verifying_key()];
        assert!(matches!(
            verify_v3(&env, &trusted),
            Err(VerifyError::InvalidV3(_))
        ));
        assert!(matches!(
            verify_any_v3(&env, &trusted),
            Err(VerifyError::InvalidV3(_))
        ));
    }
}
