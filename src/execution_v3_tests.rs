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
