use super::*;

fn ownership() -> ApplicationOwnership {
    ApplicationOwnership {
        application_id: "app-1".into(),
        release_id: None,
        release_digest: format!("sha256:{}", "a".repeat(64)),
        owned_resources: vec!["pack:guest".into(), "flow:main".into()],
        overrides_digest: None,
        owned_resource_versions: BTreeMap::new(),
    }
}

/// Captured before `owned_resource_versions` existed.
#[test]
fn an_ownership_without_versions_serialises_as_before() {
    assert_eq!(
        serde_json::to_string(&ownership()).unwrap(),
        format!(
            r#"{{"application_id":"app-1","release_digest":"sha256:{}","owned_resources":["pack:guest","flow:main"]}}"#,
            "a".repeat(64)
        )
    );
}

#[test]
fn versions_round_trip() {
    let mut o = ownership();
    o.owned_resource_versions
        .insert("pack:guest".into(), "2.4.0".into());
    let back: ApplicationOwnership =
        serde_json::from_str(&serde_json::to_string(&o).unwrap()).unwrap();
    assert_eq!(back, o);
}

#[test]
fn default_is_the_empty_ownership() {
    let o = ApplicationOwnership {
        application_id: "app-1".into(),
        release_digest: format!("sha256:{}", "a".repeat(64)),
        owned_resources: vec!["pack:guest".into(), "flow:main".into()],
        ..Default::default()
    };
    assert_eq!(o, ownership());
}

fn unit_report() -> UnitReport {
    UnitReport {
        adapter: "k8s".into(),
        observed_revision: Some("gtc-worker-01".into()),
        expected_generation: 3,
        ..Default::default()
    }
}

/// Captured before `capabilities` existed.
#[test]
fn a_unit_report_without_capabilities_serialises_as_before() {
    assert_eq!(
        serde_json::to_string(&unit_report()).unwrap(),
        r#"{"adapter":"k8s","shared":false,"observed_revision":"gtc-worker-01","applications":[],"expected_generation":3}"#
    );
}

#[test]
fn an_old_report_reads_as_capabilities_not_reported() {
    let back: UnitReport =
        serde_json::from_str(r#"{"adapter":"k8s","expected_generation":3}"#).unwrap();
    assert_eq!(back.capabilities, None);
}

#[test]
fn reported_capabilities_round_trip_and_tolerate_unknown_names() {
    let mut r = unit_report();
    r.capabilities = Some(AdapterCapabilities {
        drain: true,
        traffic_split: true,
        remove: true,
        ..Default::default()
    });
    let back: UnitReport = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
    assert_eq!(back, r);

    // A newer deployer's extra capability is ignored, and an omitted one
    // reads as `false`.
    let newer: UnitReport = serde_json::from_str(
        r#"{"adapter":"k8s","expected_generation":3,
            "capabilities":{"drain":true,"teleport":true}}"#,
    )
    .unwrap();
    assert_eq!(
        newer.capabilities,
        Some(AdapterCapabilities {
            drain: true,
            ..Default::default()
        })
    );
}
