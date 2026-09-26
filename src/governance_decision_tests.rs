//! Policy normalisation, the latest-decision rule, output order and wire
//! shape of the governance types.

use super::*;
use chrono::TimeZone;

const RELEASE: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

fn target() -> String {
    target_scope_digest(&["unit-a".to_string(), "unit-b".to_string()])
}

fn ops() -> Vec<String> {
    vec!["deploy".to_string()]
}

fn policy(kind: ScopeKind, id: Option<&str>, mode: PolicyMode, generation: u64) -> ReleasePolicy {
    ReleasePolicy {
        scope_kind: kind,
        scope_id: id.map(str::to_string),
        mode,
        generation,
    }
}

/// A decision recorded `second` seconds into a fixed day.
fn decided(
    kind: ScopeKind,
    id: Option<&str>,
    generation: u64,
    decision: Decision,
    second: u32,
) -> ApprovalRecord {
    ApprovalRecord {
        approval_id: format!("apr-{second:03}"),
        rollout_id: "ro-1".to_string(),
        scope_kind: kind,
        scope_id: id.map(str::to_string),
        release_digest: RELEASE.to_string(),
        target_scope_digest: target(),
        operations: ops(),
        policy_generation: generation,
        decision,
        actor: "admin@example.com".to_string(),
        decided_at: Utc
            .with_ymd_and_hms(2026, 9, 26, 12, 0, second)
            .single()
            .expect("valid fixed timestamp"),
    }
}

fn eval(policies: &[ReleasePolicy], approvals: &[ApprovalRecord]) -> Vec<GateStatus> {
    evaluate_gates(policies, approvals, RELEASE, &target(), &ops())
}

fn manual_tenant() -> Vec<ReleasePolicy> {
    vec![policy(
        ScopeKind::Tenant,
        Some("acme"),
        PolicyMode::Manual,
        1,
    )]
}

// --- Normalisation ---------------------------------------------------------

#[test]
fn a_superseded_manual_row_produces_no_gate_under_a_current_auto_row() {
    let policies = vec![
        policy(ScopeKind::Tenant, Some("acme"), PolicyMode::Manual, 1),
        policy(ScopeKind::Tenant, Some("acme"), PolicyMode::Auto, 2),
    ];
    let gates = eval(&policies, &[]);
    assert!(gates.is_empty(), "{gates:?}");
    assert!(is_authorised(&gates));
}

#[test]
fn two_manual_rows_for_one_scope_yield_one_gate_at_the_newest_generation() {
    let policies = vec![
        policy(ScopeKind::Tenant, Some("acme"), PolicyMode::Manual, 2),
        policy(ScopeKind::Tenant, Some("acme"), PolicyMode::Manual, 1),
    ];
    let approvals = [decided(
        ScopeKind::Tenant,
        Some("acme"),
        2,
        Decision::Approved,
        1,
    )];
    assert_eq!(
        eval(&policies, &approvals),
        vec![GateStatus::Satisfied {
            scope_kind: ScopeKind::Tenant,
            scope_id: Some("acme".into()),
        }]
    );
}

#[test]
fn a_hold_at_a_superseded_generation_of_the_newest_row_does_not_block() {
    let policies = vec![
        policy(ScopeKind::Tenant, Some("acme"), PolicyMode::Auto, 1),
        policy(ScopeKind::Tenant, Some("acme"), PolicyMode::Auto, 2),
    ];
    let approvals = [decided(
        ScopeKind::Tenant,
        Some("acme"),
        1,
        Decision::Hold,
        1,
    )];
    assert!(is_authorised(&eval(&policies, &approvals)));
}

// --- The latest decision is the scope's state ------------------------------

#[test]
fn hold_then_approve_releases_the_scope() {
    let approvals = [
        decided(ScopeKind::Tenant, Some("acme"), 1, Decision::Hold, 1),
        decided(ScopeKind::Tenant, Some("acme"), 1, Decision::Approved, 2),
    ];
    assert!(is_authorised(&eval(&manual_tenant(), &approvals)));
}

#[test]
fn approve_then_hold_blocks_again() {
    let approvals = [
        decided(ScopeKind::Tenant, Some("acme"), 1, Decision::Approved, 1),
        decided(ScopeKind::Tenant, Some("acme"), 1, Decision::Hold, 2),
    ];
    assert_eq!(
        eval(&manual_tenant(), &approvals),
        vec![GateStatus::Blocked {
            scope_kind: ScopeKind::Tenant,
            scope_id: Some("acme".into()),
            decision: Decision::Hold,
        }]
    );
}

#[test]
fn reject_then_approve_in_the_same_scope_is_authorised() {
    let approvals = [
        decided(ScopeKind::Tenant, Some("acme"), 1, Decision::Rejected, 1),
        decided(ScopeKind::Tenant, Some("acme"), 1, Decision::Approved, 2),
    ];
    assert!(is_authorised(&eval(&manual_tenant(), &approvals)));
}

#[test]
fn the_latest_decision_wins_whatever_the_input_order() {
    let hold = decided(ScopeKind::Tenant, Some("acme"), 1, Decision::Hold, 5);
    let approve = decided(ScopeKind::Tenant, Some("acme"), 1, Decision::Approved, 1);
    assert!(!is_authorised(&eval(
        &manual_tenant(),
        &[hold.clone(), approve.clone()]
    )));
    assert!(!is_authorised(&eval(&manual_tenant(), &[approve, hold])));
}

#[test]
fn equal_timestamps_are_settled_by_the_higher_approval_id() {
    let mut hold = decided(ScopeKind::Tenant, Some("acme"), 1, Decision::Hold, 1);
    let mut approve = decided(ScopeKind::Tenant, Some("acme"), 1, Decision::Approved, 1);
    hold.approval_id = "apr-a".into();
    approve.approval_id = "apr-b".into();
    assert!(is_authorised(&eval(
        &manual_tenant(),
        &[approve.clone(), hold.clone()]
    )));
    hold.approval_id = "apr-c".into();
    assert!(!is_authorised(&eval(&manual_tenant(), &[approve, hold])));
}

#[test]
fn a_stale_approval_does_not_mask_a_current_hold() {
    // The approval is newer but at a superseded generation, so it does not
    // match and cannot be the latest matching decision.
    let policies = vec![policy(
        ScopeKind::Tenant,
        Some("acme"),
        PolicyMode::Manual,
        2,
    )];
    let approvals = [
        decided(ScopeKind::Tenant, Some("acme"), 2, Decision::Hold, 1),
        decided(ScopeKind::Tenant, Some("acme"), 1, Decision::Approved, 2),
    ];
    assert!(!is_authorised(&eval(&policies, &approvals)));
}

#[test]
fn a_policy_less_scope_follows_the_same_rule_at_any_generation() {
    let held = [decided(ScopeKind::Platform, None, 7, Decision::Hold, 1)];
    assert!(!is_authorised(&eval(&[], &held)));

    let released = [
        decided(ScopeKind::Platform, None, 7, Decision::Hold, 1),
        decided(ScopeKind::Platform, None, 3, Decision::Approved, 2),
    ];
    let gates = eval(&[], &released);
    assert!(gates.is_empty(), "{gates:?}");
}

#[test]
fn an_approval_at_an_auto_scope_adds_no_gate() {
    let policies = vec![policy(ScopeKind::Tenant, Some("acme"), PolicyMode::Auto, 1)];
    let approvals = [decided(
        ScopeKind::Tenant,
        Some("acme"),
        1,
        Decision::Approved,
        1,
    )];
    assert!(eval(&policies, &approvals).is_empty());
}

// --- Operations ------------------------------------------------------------

#[test]
fn duplicated_operations_compare_as_a_set() {
    let mut a = decided(ScopeKind::Tenant, Some("acme"), 1, Decision::Approved, 1);
    a.operations = vec!["deploy".into(), "deploy".into()];
    assert!(is_authorised(&eval(&manual_tenant(), &[a])));
}

#[test]
fn an_empty_request_binds_only_to_an_empty_operation_set() {
    let mut empty = decided(ScopeKind::Tenant, Some("acme"), 1, Decision::Approved, 1);
    empty.operations = vec![];
    let full = decided(ScopeKind::Tenant, Some("acme"), 1, Decision::Approved, 1);
    let run = |a: ApprovalRecord| evaluate_gates(&manual_tenant(), &[a], RELEASE, &target(), &[]);
    assert!(is_authorised(&run(empty)));
    assert!(!is_authorised(&run(full)));
}

// --- Output order ----------------------------------------------------------

#[test]
fn mixed_states_come_out_platform_partnership_tenant_then_by_id() {
    let policies = vec![
        policy(ScopeKind::Tenant, Some("zeta"), PolicyMode::Manual, 1),
        policy(ScopeKind::Tenant, Some("acme"), PolicyMode::Manual, 1),
        policy(ScopeKind::Partnership, Some("p1"), PolicyMode::Manual, 1),
        policy(ScopeKind::Platform, None, PolicyMode::Auto, 1),
    ];
    let approvals = [
        decided(ScopeKind::Tenant, Some("acme"), 1, Decision::Approved, 1),
        decided(ScopeKind::Platform, None, 1, Decision::Hold, 2),
    ];
    assert_eq!(
        eval(&policies, &approvals),
        vec![
            GateStatus::Blocked {
                scope_kind: ScopeKind::Platform,
                scope_id: None,
                decision: Decision::Hold,
            },
            GateStatus::Pending {
                scope_kind: ScopeKind::Partnership,
                scope_id: Some("p1".into()),
            },
            GateStatus::Satisfied {
                scope_kind: ScopeKind::Tenant,
                scope_id: Some("acme".into()),
            },
            GateStatus::Pending {
                scope_kind: ScopeKind::Tenant,
                scope_id: Some("zeta".into()),
            },
        ]
    );
}

// --- Wire shape ------------------------------------------------------------

#[test]
fn gate_status_satisfied_and_pending_carry_a_null_platform_id() {
    let satisfied = serde_json::to_value(GateStatus::Satisfied {
        scope_kind: ScopeKind::Platform,
        scope_id: None,
    })
    .expect("serialise");
    assert_eq!(
        satisfied,
        serde_json::json!({"status": "satisfied", "scope_kind": "platform", "scope_id": null})
    );
    let pending = serde_json::to_value(GateStatus::Pending {
        scope_kind: ScopeKind::Partnership,
        scope_id: Some("p1".into()),
    })
    .expect("serialise");
    assert_eq!(
        pending,
        serde_json::json!({"status": "pending", "scope_kind": "partnership", "scope_id": "p1"})
    );
}

#[test]
fn release_policy_approval_record_and_selection_have_a_fixed_shape() {
    let p = policy(ScopeKind::Tenant, Some("acme"), PolicyMode::Manual, 3);
    let p_json = serde_json::to_value(&p).expect("serialise");
    assert_eq!(
        p_json,
        serde_json::json!({"scope_kind": "tenant", "scope_id": "acme", "mode": "manual", "generation": 3})
    );
    assert_eq!(
        serde_json::from_value::<ReleasePolicy>(p_json).expect("parse"),
        p
    );

    let a = decided(ScopeKind::Tenant, Some("acme"), 3, Decision::Hold, 9);
    let a_json = serde_json::to_value(&a).expect("serialise");
    assert_eq!(a_json["decision"], "hold");
    assert_eq!(a_json["decided_at"], "2026-09-26T12:00:09Z");
    assert_eq!(a_json["policy_generation"], 3);
    assert_eq!(
        serde_json::from_value::<ApprovalRecord>(a_json).expect("parse"),
        a
    );

    assert_eq!(
        serde_json::to_value(bps_select(20, 500)).expect("serialise"),
        serde_json::json!({"count": 1, "rounds_to_zero": false, "effective_bps": 500})
    );
}
