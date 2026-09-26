use super::*;
use chrono::Utc;

const RELEASE: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const OTHER_RELEASE: &str =
    "sha256:2222222222222222222222222222222222222222222222222222222222222222";

fn target() -> String {
    target_scope_digest(&["unit-a".to_string(), "unit-b".to_string()])
}

fn ops() -> Vec<String> {
    vec!["deploy".to_string(), "migrate".to_string()]
}

fn policy(kind: ScopeKind, id: Option<&str>, mode: PolicyMode, generation: u64) -> ReleasePolicy {
    ReleasePolicy {
        scope_kind: kind,
        scope_id: id.map(str::to_string),
        mode,
        generation,
    }
}

fn approval(
    kind: ScopeKind,
    id: Option<&str>,
    generation: u64,
    decision: Decision,
) -> ApprovalRecord {
    ApprovalRecord {
        approval_id: format!("apr-{kind:?}-{generation}-{decision:?}"),
        rollout_id: "ro-1".to_string(),
        scope_kind: kind,
        scope_id: id.map(str::to_string),
        release_digest: RELEASE.to_string(),
        target_scope_digest: target(),
        operations: ops(),
        policy_generation: generation,
        decision,
        actor: "admin@example.com".to_string(),
        decided_at: Utc::now(),
    }
}

fn eval(policies: &[ReleasePolicy], approvals: &[ApprovalRecord]) -> Vec<GateStatus> {
    evaluate_gates(policies, approvals, RELEASE, &target(), &ops())
}

fn hierarchy() -> Vec<ReleasePolicy> {
    vec![
        policy(ScopeKind::Tenant, Some("acme"), PolicyMode::Auto, 1),
        policy(ScopeKind::Partnership, Some("p1"), PolicyMode::Manual, 1),
    ]
}

// --- §12 Hierarchical approval -------------------------------------------

#[test]
fn tenant_auto_cannot_bypass_partnership_manual() {
    let gates = eval(&hierarchy(), &[]);
    assert_eq!(
        gates,
        vec![GateStatus::Pending {
            scope_kind: ScopeKind::Partnership,
            scope_id: Some("p1".into()),
        }]
    );
    assert!(!is_authorised(&gates));
}

#[test]
fn a_tenant_approval_does_not_satisfy_the_partnership_gate() {
    let gates = eval(
        &hierarchy(),
        &[approval(
            ScopeKind::Tenant,
            Some("acme"),
            1,
            Decision::Approved,
        )],
    );
    assert!(!is_authorised(&gates));
}

#[test]
fn partnership_approval_authorises() {
    let gates = eval(
        &hierarchy(),
        &[approval(
            ScopeKind::Partnership,
            Some("p1"),
            1,
            Decision::Approved,
        )],
    );
    assert_eq!(
        gates,
        vec![GateStatus::Satisfied {
            scope_kind: ScopeKind::Partnership,
            scope_id: Some("p1".into()),
        }]
    );
    assert!(is_authorised(&gates));
}

#[test]
fn all_auto_policies_produce_no_gate_and_authorise() {
    let policies = vec![
        policy(ScopeKind::Platform, None, PolicyMode::Auto, 1),
        policy(ScopeKind::Tenant, Some("acme"), PolicyMode::Auto, 1),
    ];
    let gates = eval(&policies, &[]);
    assert!(gates.is_empty());
    assert!(is_authorised(&gates));
}

#[test]
fn gates_are_ordered_platform_partnership_tenant() {
    let policies = vec![
        policy(ScopeKind::Tenant, Some("acme"), PolicyMode::Manual, 1),
        policy(ScopeKind::Partnership, Some("p1"), PolicyMode::Manual, 1),
        policy(ScopeKind::Platform, None, PolicyMode::Manual, 1),
    ];
    let kinds: Vec<ScopeKind> = eval(&policies, &[])
        .iter()
        .map(|g| match g {
            GateStatus::Pending { scope_kind, .. } => *scope_kind,
            other => panic!("unexpected {other:?}"),
        })
        .collect();
    assert_eq!(
        kinds,
        vec![
            ScopeKind::Platform,
            ScopeKind::Partnership,
            ScopeKind::Tenant
        ]
    );
}

#[test]
fn approval_order_does_not_change_the_result() {
    let policies = vec![
        policy(ScopeKind::Platform, None, PolicyMode::Manual, 1),
        policy(ScopeKind::Tenant, Some("acme"), PolicyMode::Manual, 1),
    ];
    let a = approval(ScopeKind::Platform, None, 1, Decision::Approved);
    let b = approval(ScopeKind::Tenant, Some("acme"), 1, Decision::Approved);
    let forward = eval(&policies, &[a.clone(), b.clone()]);
    let backward = eval(&policies, &[b, a]);
    assert_eq!(forward, backward);
    assert!(is_authorised(&forward));
}

// --- Binding: generation, digest, target, operations ---------------------

#[test]
fn a_policy_change_invalidates_an_older_generation_approval() {
    let policies = vec![policy(
        ScopeKind::Partnership,
        Some("p1"),
        PolicyMode::Manual,
        2,
    )];
    let gates = eval(
        &policies,
        &[approval(
            ScopeKind::Partnership,
            Some("p1"),
            1,
            Decision::Approved,
        )],
    );
    assert!(matches!(gates.as_slice(), [GateStatus::Pending { .. }]));
}

#[test]
fn a_different_release_digest_does_not_count() {
    let mut a = approval(ScopeKind::Partnership, Some("p1"), 1, Decision::Approved);
    a.release_digest = OTHER_RELEASE.to_string();
    assert!(!is_authorised(&eval(&hierarchy(), &[a])));
}

#[test]
fn a_different_target_scope_does_not_count() {
    let mut a = approval(ScopeKind::Partnership, Some("p1"), 1, Decision::Approved);
    a.target_scope_digest = target_scope_digest(&["unit-a".to_string()]);
    assert!(!is_authorised(&eval(&hierarchy(), &[a])));
}

#[test]
fn a_different_operations_set_does_not_count() {
    let mut a = approval(ScopeKind::Partnership, Some("p1"), 1, Decision::Approved);
    a.operations = vec!["deploy".to_string()];
    assert!(!is_authorised(&eval(&hierarchy(), &[a])));
}

#[test]
fn a_different_scope_id_does_not_count() {
    let a = approval(ScopeKind::Partnership, Some("p2"), 1, Decision::Approved);
    assert!(!is_authorised(&eval(&hierarchy(), &[a])));
}

#[test]
fn operations_are_compared_as_a_set() {
    let mut a = approval(ScopeKind::Partnership, Some("p1"), 1, Decision::Approved);
    a.operations = vec!["migrate".to_string(), "deploy".to_string()];
    assert!(is_authorised(&eval(&hierarchy(), &[a])));
}

// --- Blocking decisions ---------------------------------------------------

#[test]
fn a_tenant_rejection_blocks_even_when_every_manual_gate_is_approved() {
    let gates = eval(
        &hierarchy(),
        &[
            approval(ScopeKind::Partnership, Some("p1"), 1, Decision::Approved),
            approval(ScopeKind::Tenant, Some("acme"), 1, Decision::Rejected),
        ],
    );
    assert!(gates.contains(&GateStatus::Blocked {
        scope_kind: ScopeKind::Tenant,
        scope_id: Some("acme".into()),
        decision: Decision::Rejected,
    }));
    assert!(!is_authorised(&gates));
}

#[test]
fn a_hold_blocks() {
    let gates = eval(
        &hierarchy(),
        &[
            approval(ScopeKind::Partnership, Some("p1"), 1, Decision::Approved),
            approval(ScopeKind::Platform, None, 1, Decision::Hold),
        ],
    );
    assert!(gates.contains(&GateStatus::Blocked {
        scope_kind: ScopeKind::Platform,
        scope_id: None,
        decision: Decision::Hold,
    }));
    assert!(!is_authorised(&gates));
}

#[test]
fn a_rejection_at_a_superseded_generation_no_longer_blocks() {
    let policies = vec![
        policy(ScopeKind::Partnership, Some("p1"), PolicyMode::Manual, 1),
        policy(ScopeKind::Tenant, Some("acme"), PolicyMode::Auto, 3),
    ];
    let gates = eval(
        &policies,
        &[
            approval(ScopeKind::Partnership, Some("p1"), 1, Decision::Approved),
            approval(ScopeKind::Tenant, Some("acme"), 2, Decision::Rejected),
        ],
    );
    assert!(is_authorised(&gates));
}

#[test]
fn a_rejection_for_another_release_does_not_block() {
    let mut r = approval(ScopeKind::Tenant, Some("acme"), 1, Decision::Rejected);
    r.release_digest = OTHER_RELEASE.to_string();
    let gates = eval(
        &hierarchy(),
        &[
            approval(ScopeKind::Partnership, Some("p1"), 1, Decision::Approved),
            r,
        ],
    );
    assert!(is_authorised(&gates));
}

#[test]
fn gate_status_serialises_with_a_status_tag() {
    let json = serde_json::to_value(GateStatus::Blocked {
        scope_kind: ScopeKind::Tenant,
        scope_id: Some("acme".into()),
        decision: Decision::Hold,
    })
    .expect("serialise");
    assert_eq!(
        json,
        serde_json::json!({
            "status": "blocked",
            "scope_kind": "tenant",
            "scope_id": "acme",
            "decision": "hold"
        })
    );
}

// --- §4 Basis points ------------------------------------------------------

#[test]
fn ten_bps_of_twenty_units_rounds_to_zero_and_says_so() {
    let s = bps_select(20, 10);
    assert_eq!(s.count, 0);
    assert!(s.rounds_to_zero);
    assert_eq!(s.effective_bps, 0);
}

#[test]
fn ten_bps_of_a_thousand_units_selects_one() {
    let s = bps_select(1000, 10);
    assert_eq!(s.count, 1);
    assert!(!s.rounds_to_zero);
    assert_eq!(s.effective_bps, 10);
}

#[test]
fn one_unit_of_twenty_is_five_percent() {
    let s = bps_select(20, 500);
    assert_eq!(s.count, 1);
    assert_eq!(s.effective_bps, 500);
}

#[test]
fn full_target_selects_every_unit() {
    let s = bps_select(7, 10_000);
    assert_eq!(s.count, 7);
    assert_eq!(s.effective_bps, 10_000);
}

#[test]
fn a_target_above_ten_thousand_is_clamped() {
    assert_eq!(bps_select(7, u16::MAX), bps_select(7, 10_000));
}

#[test]
fn never_rounds_up() {
    // 3 units at 50% is 1.5 units: floor, never 2.
    assert_eq!(bps_select(3, 5_000).count, 1);
}

#[test]
fn zero_target_and_empty_fleet_do_not_round_to_zero() {
    assert_eq!(
        bps_select(20, 0),
        Selection {
            count: 0,
            rounds_to_zero: false,
            effective_bps: 0
        }
    );
    assert_eq!(
        bps_select(0, 500),
        Selection {
            count: 0,
            rounds_to_zero: false,
            effective_bps: 0
        }
    );
}

// --- §4 Stable ordering ---------------------------------------------------

fn fleet(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("tenant-{i}/env/unit")).collect()
}

#[test]
fn raising_the_target_extends_the_prefix() {
    // The first selection is taken from one freeze, the second from a
    // re-freeze of the same audience fed in a different order: the earlier
    // cohort must survive intact and the new units must follow it.
    let first = order_units("ro-1", "seed", &fleet(200));
    let mut shuffled = fleet(200);
    shuffled.reverse();
    shuffled.rotate_left(37);
    let second = order_units("ro-1", "seed", &shuffled);
    let five = bps_select(first.len(), 500).count;
    let ten = bps_select(second.len(), 1_000).count;
    assert_eq!((five, ten), (10, 20));
    assert_eq!(first[..five], second[..five]);
    let earlier: BTreeSet<&String> = first[..five].iter().collect();
    assert!(second[five..ten].iter().all(|u| !earlier.contains(u)));
    // And the order really is the sort-key order, not the input order.
    let keys: Vec<String> = second[..ten]
        .iter()
        .map(|u| sort_key("ro-1", "seed", u))
        .collect();
    assert!(keys.windows(2).all(|w| w[0] <= w[1]));
}

#[test]
fn ordering_ignores_input_order() {
    let mut reversed = fleet(50);
    reversed.reverse();
    assert_eq!(
        order_units("ro-1", "seed", &fleet(50)),
        order_units("ro-1", "seed", &reversed)
    );
}

#[test]
fn the_canary_is_the_first_unit_of_the_stable_order() {
    let units = fleet(20);
    let order = order_units("ro-1", "seed", &units);
    assert!(bps_select(order.len(), 10).rounds_to_zero);
    let minimum = units
        .iter()
        .min_by_key(|u| sort_key("ro-1", "seed", u))
        .cloned();
    assert_eq!(order.first().cloned(), minimum);
}

#[test]
fn sort_key_is_hex_sha256_of_the_joined_triple() {
    let k = sort_key("ro-1", "seed", "u1");
    assert_eq!(k.len(), 64);
    assert!(
        k.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
    assert_eq!(k, sort_key("ro-1", "seed", "u1"));
    assert_ne!(k, sort_key("ro-1", "seed2", "u1"));
    // Known vector: `printf 'a:b:c' | sha256sum`.
    assert_eq!(
        sort_key("a", "b", "c"),
        "b0ee04f880c4ff4261479e2e7822b7410aee4c7159f4185ad5b0d88a312b495e"
    );
}

#[test]
fn audience_digest_is_order_sensitive() {
    let a = vec!["u1".to_string(), "u2".to_string()];
    let b = vec!["u2".to_string(), "u1".to_string()];
    assert!(audience_digest(&a).starts_with("sha256:"));
    assert_eq!(audience_digest(&a).len(), 71);
    // Known vector: `printf 'u1\nu2' | sha256sum`.
    assert_eq!(
        audience_digest(&a),
        "sha256:c9abf63c8b58c51cc0c51b6f08269fd967546364f57033de39723f9d52c41f78"
    );
    assert_ne!(audience_digest(&a), audience_digest(&b));
}

#[test]
fn target_scope_digest_is_order_insensitive() {
    let a = vec!["u1".to_string(), "u2".to_string()];
    let b = vec!["u2".to_string(), "u1".to_string()];
    assert!(target_scope_digest(&a).starts_with("sha256:"));
    assert_eq!(target_scope_digest(&a), target_scope_digest(&b));
    assert_ne!(
        target_scope_digest(&a),
        target_scope_digest(&["u1".to_string()])
    );
}
