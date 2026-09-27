use super::*;
use crate::health::{Evidence, Latency, Readiness, RequestCounts};
use chrono::TimeZone;
use serde_json::json;

pub(crate) fn digest(c: char) -> String {
    format!("sha256:{}", c.to_string().repeat(64))
}

fn ts(hour: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 27, hour, 0, 0).unwrap()
}

pub(crate) fn sample() -> ExecutionAuthorisation {
    ExecutionAuthorisation {
        schema: EXECUTION_AUTHORISATION_SCHEMA.to_string(),
        authorisation_id: "auth-1".to_string(),
        installation_id: "inst-1".to_string(),
        tenant_id: "acme".to_string(),
        environment_id: "prod".to_string(),
        rollout_id: "ro-1".to_string(),
        release_id: "rel-1".to_string(),
        release_digest: digest('a'),
        operation: ExecOperation::Update,
        units: vec![UnitTarget {
            unit_id: "env:bundle-a".to_string(),
            expected_baseline: UnitBaseline {
                bundle_digest: Some(digest('b')),
                runtime_image_digest: Some(digest('c')),
                overrides_digest: Some(digest('d')),
            },
            target: UnitBaseline {
                bundle_digest: Some(digest('e')),
                runtime_image_digest: Some(digest('c')),
                overrides_digest: Some(digest('d')),
            },
        }],
        policy_generation: 3,
        sequence: 7,
        fence: 42,
        not_before: ts(10),
        expires_at: ts(12),
        traffic: TrafficPolicy {
            steps: vec![10, 50, 100],
            step_wait_secs: 300,
            max_error_rate: 0.05,
            auto_rollback: false,
        },
    }
}

#[test]
fn a_well_formed_authorisation_validates() {
    assert_eq!(sample().validate(), Ok(()));
}

#[test]
fn an_unknown_schema_is_refused() {
    let mut a = sample();
    a.schema = "greentic.execution-authorisation.v2".to_string();
    assert_eq!(
        a.validate(),
        Err(ValidationError::UnknownSchema(
            "greentic.execution-authorisation.v2".to_string()
        ))
    );
}

#[test]
fn an_unknown_operation_does_not_parse() {
    let mut v = serde_json::to_value(sample()).unwrap();
    v["operation"] = json!("delete");
    assert!(serde_json::from_value::<ExecutionAuthorisation>(v).is_err());
}

#[test]
fn an_unknown_field_does_not_parse() {
    let mut v = serde_json::to_value(sample()).unwrap();
    v["skip_checks"] = json!(true);
    assert!(serde_json::from_value::<ExecutionAuthorisation>(v).is_err());
}

#[test]
fn operations_serialise_snake_case() {
    assert_eq!(json!(ExecOperation::Rollback), json!("rollback"));
    assert_eq!(json!(ExecOperation::Update), json!("update"));
}

#[test]
fn bad_traffic_steps_are_refused() {
    for steps in [
        vec![],
        vec![10, 50],
        vec![50, 10, 100],
        vec![10, 10, 100],
        vec![0, 100],
        vec![10, 101],
    ] {
        let mut a = sample();
        a.traffic.steps = steps.clone();
        assert_eq!(
            a.validate(),
            Err(ValidationError::BadTrafficSteps),
            "{steps:?}"
        );
    }
    let mut a = sample();
    a.traffic.steps = vec![100];
    assert_eq!(a.validate(), Ok(()));
}

#[test]
fn step_wait_and_error_rate_bounds() {
    let mut a = sample();
    a.traffic.step_wait_secs = 29;
    assert_eq!(a.validate(), Err(ValidationError::BadStepWait));
    a.traffic.step_wait_secs = 3601;
    assert_eq!(a.validate(), Err(ValidationError::BadStepWait));
    a.traffic.step_wait_secs = 30;
    a.traffic.max_error_rate = 1.5;
    assert_eq!(a.validate(), Err(ValidationError::BadMaxErrorRate));
    a.traffic.max_error_rate = f64::NAN;
    assert_eq!(a.validate(), Err(ValidationError::BadMaxErrorRate));
    a.traffic.max_error_rate = -0.1;
    assert_eq!(a.validate(), Err(ValidationError::BadMaxErrorRate));
}

#[test]
fn duplicate_units_are_refused() {
    let mut a = sample();
    a.units.push(a.units[0].clone());
    assert_eq!(
        a.validate(),
        Err(ValidationError::DuplicateUnit("env:bundle-a".to_string()))
    );
}

#[test]
fn no_units_are_refused() {
    let mut a = sample();
    a.units.clear();
    assert_eq!(a.validate(), Err(ValidationError::NoUnits));
}

#[test]
fn digests_must_be_canonical_sha256() {
    let mut a = sample();
    a.release_digest = format!("sha256:{}", "A".repeat(64));
    assert_eq!(
        a.validate(),
        Err(ValidationError::BadDigest("release_digest"))
    );
    let mut a = sample();
    a.units[0].target.bundle_digest = Some("sha256:abc".to_string());
    assert_eq!(
        a.validate(),
        Err(ValidationError::BadDigest("bundle_digest"))
    );
    let mut a = sample();
    a.units[0].expected_baseline.overrides_digest = Some("a".repeat(64));
    assert_eq!(
        a.validate(),
        Err(ValidationError::BadDigest("overrides_digest"))
    );
}

#[test]
fn a_not_previously_deployed_baseline_is_valid() {
    let mut a = sample();
    a.units[0].expected_baseline = UnitBaseline::default();
    assert_eq!(a.validate(), Ok(()));
}

#[test]
fn the_validity_window_is_bounded() {
    let mut a = sample();
    a.expires_at = a.not_before;
    assert_eq!(a.validate(), Err(ValidationError::WindowInverted));
    a.expires_at = a.not_before + Duration::hours(24);
    assert_eq!(a.validate(), Ok(()));
    a.expires_at = a.not_before + Duration::hours(24) + Duration::seconds(1);
    assert_eq!(a.validate(), Err(ValidationError::WindowTooLong));
}

#[test]
fn empty_identifiers_are_refused() {
    let mut a = sample();
    a.installation_id = " ".to_string();
    assert_eq!(
        a.validate(),
        Err(ValidationError::EmptyField("installation_id"))
    );
}

#[test]
fn terminal_states() {
    use ExecState::*;
    for s in [Healthy, RolledBack, RecoveryRequired, Rejected] {
        assert!(s.is_terminal(), "{s:?}");
    }
    for s in [
        Staged,
        Applying,
        DesiredStateApplied,
        Reconciling,
        Verifying,
        RollbackPending,
        RollingBack,
    ] {
        assert!(!s.is_terminal(), "{s:?}");
    }
    assert_eq!(json!(DesiredStateApplied), json!("desired_state_applied"));
}

fn checkpoint() -> ExecutionCheckpoint {
    ExecutionCheckpoint {
        authorisation_id: "auth-1".to_string(),
        unit_id: "env:bundle-a".to_string(),
        state: ExecState::Verifying,
        fence: 42,
        traffic_percent: Some(10),
        reason: Some("insufficient_evidence".to_string()),
        detail: Some("waiting for traffic".to_string()),
        observed_revision: Some("svc-00002".to_string()),
        health: Some(crate::health::UnitHealthReport {
            unit_id: "env:bundle-a".to_string(),
            revision: Some("svc-00002".to_string()),
            readiness: Readiness::Ready,
            window_start: Some(ts(10)),
            window_end: Some(ts(11)),
            requests: Some(RequestCounts::default()),
            latency_ms: Latency::default(),
            server_error_rate: None,
            idle: true,
            evidence: Evidence::Insufficient {
                reason: crate::health::InsufficientReason::Idle,
                detail: None,
                remediation: None,
            },
            reported_at: ts(11),
        }),
        seq: 3,
        recorded_at: ts(11),
    }
}

#[test]
fn a_checkpoint_round_trips_and_validates() {
    let c = checkpoint();
    assert_eq!(c.validate(), Ok(()));
    let back: ExecutionCheckpoint = serde_json::from_value(json!(c)).unwrap();
    assert_eq!(back, c);
}

#[test]
fn checkpoint_rules() {
    let mut c = checkpoint();
    c.traffic_percent = Some(101);
    assert_eq!(c.validate(), Err(CheckpointError::TrafficPercentOutOfRange));

    let mut c = checkpoint();
    c.reason = Some("Baseline Changed".to_string());
    assert_eq!(c.validate(), Err(CheckpointError::BadReason));

    let mut c = checkpoint();
    c.detail = Some("x".repeat(MAX_CHECKPOINT_DETAIL_CHARS + 1));
    assert_eq!(c.validate(), Err(CheckpointError::DetailTooLong));

    let mut c = checkpoint();
    if let Some(h) = c.health.as_mut() {
        h.unit_id = "other".to_string();
    }
    assert_eq!(c.validate(), Err(CheckpointError::HealthUnitMismatch));

    let mut c = checkpoint();
    if let Some(h) = c.health.as_mut() {
        h.evidence = Evidence::Sufficient;
    }
    assert!(matches!(c.validate(), Err(CheckpointError::Health(_))));
}
