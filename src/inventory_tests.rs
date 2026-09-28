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
