use super::*;
use crate::execution_v2::DataDisposition;
use serde_json::json;

fn demand(operation: ExecOperationV2, steps: &[u8]) -> PlanDemand<'_> {
    PlanDemand {
        operation,
        traffic_steps: steps,
        exposes_ingress: false,
        private_registry: false,
        max_instances: 1,
    }
}

#[test]
fn an_absent_report_declares_nothing() {
    let caps: AdapterCapabilities = serde_json::from_value(json!({})).unwrap();
    assert_eq!(caps, AdapterCapabilities::default());
    assert!(ALL.iter().all(|n| !caps.has(n)));
}

#[test]
fn unknown_capabilities_are_ignored_and_unknown_names_are_false() {
    let caps: AdapterCapabilities =
        serde_json::from_value(json!({"drain": true, "teleport": true})).unwrap();
    assert!(caps.has(DRAIN));
    assert!(!caps.has("teleport"));
}

#[test]
fn a_straight_update_needs_nothing() {
    assert!(required_capabilities_for(&demand(ExecOperationV2::Update, &[100])).is_empty());
}

#[test]
fn a_percentage_rollout_needs_traffic_split() {
    assert_eq!(
        required_capabilities_for(&demand(ExecOperationV2::Update, &[10, 50, 100])),
        vec![TRAFFIC_SPLIT]
    );
}

#[test]
fn a_removal_needs_remove_and_drain_when_draining() {
    let op = ExecOperationV2::Remove {
        data: DataDisposition::Retain,
        drain_seconds: 60,
    };
    assert_eq!(
        required_capabilities_for(&demand(op, &[100])),
        vec![DRAIN, REMOVE]
    );
    let op = ExecOperationV2::Remove {
        data: DataDisposition::Retain,
        drain_seconds: 0,
    };
    assert_eq!(required_capabilities_for(&demand(op, &[100])), vec![REMOVE]);
}

#[test]
fn environment_facts_add_their_capabilities() {
    let mut d = demand(ExecOperationV2::Rollback, &[100]);
    d.exposes_ingress = true;
    d.private_registry = true;
    d.max_instances = 3;
    assert_eq!(
        required_capabilities_for(&d),
        vec![INGRESS_MANAGED, PRIVATE_REGISTRY_AUTH, MULTI_INSTANCE_SAFE]
    );
}

#[test]
fn missing_names_what_the_adapter_lacks() {
    let caps = AdapterCapabilities {
        traffic_split: true,
        ..AdapterCapabilities::default()
    };
    assert_eq!(
        missing(&caps, &[DRAIN, TRAFFIC_SPLIT, REMOVE]),
        vec![DRAIN, REMOVE]
    );
    assert!(missing(&caps, &[TRAFFIC_SPLIT]).is_empty());
}

#[test]
fn every_named_capability_maps_to_its_field() {
    for name in ALL {
        let mut v = serde_json::to_value(AdapterCapabilities::default()).unwrap();
        v[name] = json!(true);
        let caps: AdapterCapabilities = serde_json::from_value(v).unwrap();
        assert!(caps.has(name), "{name}");
        assert_eq!(ALL.iter().filter(|n| caps.has(n)).count(), 1, "{name}");
    }
}

#[test]
fn runtime_pin_is_absent_from_an_old_report() {
    let old: AdapterCapabilities =
        serde_json::from_str(r#"{"drain":true,"traffic_split":true,"remove":true}"#)
            .expect("parses");
    assert!(!old.runtime_pin);
    assert!(!old.has(RUNTIME_PIN));
}

#[test]
fn a_runtime_change_needs_runtime_pin_and_split_when_stepping() {
    assert_eq!(
        required_for_runtime_change(&[10, 50, 100]),
        vec![TRAFFIC_SPLIT, RUNTIME_PIN]
    );
    assert_eq!(required_for_runtime_change(&[100]), vec![RUNTIME_PIN]);
}

#[test]
fn all_lists_runtime_pin_last() {
    assert_eq!(ALL.last(), Some(&RUNTIME_PIN));
    assert_eq!(ALL.len(), 7);
}
