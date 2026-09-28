use super::*;

fn sample() -> RegisterReleaseRequest {
    RegisterReleaseRequest {
        kind: ReleaseKind::Application,
        publisher: "tenant:acme".into(),
        name: "guest-assistant".into(),
        version: "2.4.0".into(),
        artifacts: vec![
            ReleaseArtifact {
                name: "b.gtpack".into(),
                version: "2.4.0".into(),
                digest: format!("sha256:{}", "b".repeat(64)),
                target: None,
                media_type: None,
                source: None,
            },
            ReleaseArtifact {
                name: "a.gtpack".into(),
                version: "2.4.0".into(),
                digest: format!("sha256:{}", "a".repeat(64)),
                target: None,
                media_type: None,
                source: None,
            },
        ],
        dependencies: vec![],
        compatibility: Compatibility {
            min_runtime: None,
            abi: None,
            required_capabilities: vec!["z".into(), "a".into()],
        },
        provenance: Provenance {
            source_repo: None,
            source_revision: Some("s1".into()),
            builder: "designer".into(),
            built_at: None,
        },
        rollback: RollbackDeclaration {
            supported: true,
            notes: None,
        },
        migrations: Vec::new(),
    }
}

#[test]
fn digest_is_order_independent() {
    let a = sample();
    let mut b = sample();
    b.artifacts.reverse();
    b.compatibility.required_capabilities.reverse();
    assert_eq!(release_digest(&a).ok(), release_digest(&b).ok());
}

#[test]
fn digest_ignores_provenance() {
    let a = sample();
    let mut b = sample();
    b.provenance.source_revision = Some("s2".into());
    b.provenance.built_at = Some(chrono::Utc::now());
    assert_eq!(release_digest(&a).ok(), release_digest(&b).ok());
}

#[test]
fn digest_changes_with_an_artifact_digest() {
    let a = sample();
    let mut b = sample();
    b.artifacts[0].digest = format!("sha256:{}", "c".repeat(64));
    assert_ne!(release_digest(&a).ok(), release_digest(&b).ok());
}

#[test]
fn digest_ignores_artifact_source_and_media_type() {
    let a = sample();
    let mut b = sample();
    b.artifacts[0].source = Some("https://example.com/b.gtpack".into());
    b.artifacts[0].media_type = Some("application/vnd.greentic.pack".into());
    assert_eq!(release_digest(&a).ok(), release_digest(&b).ok());
}

fn sample_dependencies() -> Vec<DependencyPin> {
    vec![
        DependencyPin {
            kind: DependencyKind::Extension,
            name: "hubspot".into(),
            version_req: Some(">=1.0.0".into()),
            digest: Some(format!("sha256:{}", "d".repeat(64))),
            shared: false,
            coexistence: None,
        },
        DependencyPin {
            kind: DependencyKind::Runtime,
            name: "greentic-start".into(),
            version_req: Some(">=1.2.0".into()),
            digest: None,
            shared: false,
            coexistence: None,
        },
    ]
}

#[test]
fn digest_is_order_independent_for_dependencies() {
    let mut a = sample();
    a.dependencies = sample_dependencies();
    let mut b = sample();
    b.dependencies = sample_dependencies();
    b.dependencies.reverse();
    assert_eq!(release_digest(&a).ok(), release_digest(&b).ok());
}

#[test]
fn digest_changes_with_a_dependency_digest() {
    let mut a = sample();
    a.dependencies = sample_dependencies();
    let mut b = sample();
    b.dependencies = sample_dependencies();
    b.dependencies[0].digest = Some(format!("sha256:{}", "e".repeat(64)));
    assert_ne!(release_digest(&a).ok(), release_digest(&b).ok());
}

#[test]
fn digest_is_prefixed_lower_hex() {
    let d = release_digest(&sample()).unwrap_or_default();
    assert!(d.starts_with("sha256:"));
    assert_eq!(d.len(), 7 + 64);
    assert!(
        d[7..]
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
}

#[test]
fn sha256_prefixed_accepts_only_64_hex() {
    assert_eq!(
        sha256_prefixed(&"A".repeat(64)),
        Some(format!("sha256:{}", "a".repeat(64)))
    );
    assert_eq!(sha256_prefixed("abc"), None);
    assert_eq!(
        sha256_prefixed(&format!("sha256:{}", "a".repeat(64))),
        Some(format!("sha256:{}", "a".repeat(64)))
    );
}

#[test]
fn missing_capability_is_incompatible() {
    let c = Compatibility {
        min_runtime: None,
        abi: None,
        required_capabilities: vec!["x".into()],
    };
    let host = HostFacts {
        runtime_version: None,
        abi: vec![],
        capabilities: vec![],
    };
    assert!(matches!(
        check_compatibility(&c, &host),
        CompatVerdict::Incompatible { .. }
    ));
}

#[test]
fn unknown_runtime_version_is_unverified_not_incompatible() {
    let c = Compatibility {
        min_runtime: Some("1.2.0".into()),
        abi: None,
        required_capabilities: vec![],
    };
    let host = HostFacts {
        runtime_version: None,
        abi: vec![],
        capabilities: vec![],
    };
    assert!(matches!(
        check_compatibility(&c, &host),
        CompatVerdict::Unverified { .. }
    ));
}

#[test]
fn older_runtime_is_incompatible() {
    let c = Compatibility {
        min_runtime: Some("1.3.0".into()),
        abi: None,
        required_capabilities: vec![],
    };
    let host = HostFacts {
        runtime_version: Some("1.2.9".into()),
        abi: vec![],
        capabilities: vec![],
    };
    assert!(matches!(
        check_compatibility(&c, &host),
        CompatVerdict::Incompatible { .. }
    ));
}

#[test]
fn abi_must_match_exactly() {
    let c = Compatibility {
        min_runtime: None,
        abi: Some("greentic:component@0.6.0".into()),
        required_capabilities: vec![],
    };
    let ok = HostFacts {
        runtime_version: None,
        abi: vec!["greentic:component@0.6.0".into()],
        capabilities: vec![],
    };
    let bad = HostFacts {
        runtime_version: None,
        abi: vec!["greentic:component@0.5.0".into()],
        capabilities: vec![],
    };
    assert_eq!(check_compatibility(&c, &ok), CompatVerdict::Compatible);
    assert!(matches!(
        check_compatibility(&c, &bad),
        CompatVerdict::Incompatible { .. }
    ));
}

#[test]
fn request_round_trips_through_json() {
    let s = serde_json::to_string(&sample()).expect("serialize");
    let back: RegisterReleaseRequest = serde_json::from_str(&s).expect("deserialize");
    assert_eq!(back, sample());
    assert!(s.contains("\"kind\":\"application\""));
}

/// Captured BEFORE the migration field existed. An absent migration must
/// leave both the wire JSON and the digest byte-identical.
#[test]
fn existing_requests_keep_their_digest_and_bytes() {
    let mut s = sample();
    assert_eq!(
        release_digest(&s).unwrap(),
        "sha256:08ee234c3285bc4a0bcc128c33cdba1ab284f3f2d2ec4959f34156ed1bcdb6fd"
    );
    assert_eq!(
        serde_json::to_string(&s).unwrap(),
        r#"{"kind":"application","publisher":"tenant:acme","name":"guest-assistant","version":"2.4.0","artifacts":[{"name":"b.gtpack","version":"2.4.0","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},{"name":"a.gtpack","version":"2.4.0","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"dependencies":[],"compatibility":{"required_capabilities":["z","a"]},"provenance":{"source_revision":"s1","builder":"designer"},"rollback":{"supported":true}}"#
    );
    s.dependencies = sample_dependencies();
    assert_eq!(
        release_digest(&s).unwrap(),
        "sha256:0fd322b1bd97aa10dce17c356148f88fcbb35cda4e0b840c8b4f2303e56796af"
    );
    assert_eq!(
        serde_json::to_string(&s).unwrap(),
        r#"{"kind":"application","publisher":"tenant:acme","name":"guest-assistant","version":"2.4.0","artifacts":[{"name":"b.gtpack","version":"2.4.0","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},{"name":"a.gtpack","version":"2.4.0","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"dependencies":[{"kind":"extension","name":"hubspot","version_req":">=1.0.0","digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},{"kind":"runtime","name":"greentic-start","version_req":">=1.2.0"}],"compatibility":{"required_capabilities":["z","a"]},"provenance":{"source_revision":"s1","builder":"designer"},"rollback":{"supported":true}}"#
    );
}

#[test]
fn migrations_enter_the_digest_in_order() {
    use crate::migration::tests::declaration;
    let a = sample();
    let mut b = sample();
    b.migrations = vec![declaration()];
    assert_ne!(release_digest(&a).ok(), release_digest(&b).ok());
    let mut c = b.clone();
    c.migrations[0].to_schema = "v4".into();
    assert_ne!(release_digest(&b).ok(), release_digest(&c).ok());
    let json = serde_json::to_string(&b).unwrap();
    let back: RegisterReleaseRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(back, b);
    assert_eq!(a.validate(), Ok(()));
    assert_eq!(b.validate(), Ok(()));

    // Two owners: order is part of the digest.
    let mut other = declaration();
    other.owner = "app:billing".into();
    let mut d = sample();
    d.migrations = vec![declaration(), other.clone()];
    let mut e = sample();
    e.migrations = vec![other, declaration()];
    assert_eq!(d.validate(), Ok(()));
    assert_ne!(release_digest(&d).ok(), release_digest(&e).ok());
}

#[test]
fn a_migration_chain_must_be_continuous_per_owner() {
    use crate::migration::tests::declaration;
    let mut next = declaration();
    next.from_schema = "v3".into();
    next.to_schema = "v4".into();
    let mut r = sample();
    r.migrations = vec![declaration(), next.clone()];
    assert_eq!(r.validate(), Ok(()));
    next.from_schema = "v9".into();
    r.migrations = vec![declaration(), next];
    assert_eq!(
        r.validate(),
        Err(ReleaseRequestError::MigrationChainBroken { index: 1 })
    );
    let mut bad = declaration();
    bad.reversible = false;
    r.migrations = vec![bad];
    assert!(matches!(
        r.validate(),
        Err(ReleaseRequestError::Migration { index: 0, .. })
    ));
}

#[test]
fn dependency_policy_enters_the_digest_only_when_declared() {
    let mut a = sample();
    a.dependencies = sample_dependencies();
    let mut b = a.clone();
    b.dependencies[0].shared = true;
    assert_ne!(release_digest(&a).ok(), release_digest(&b).ok());
    let mut c = a.clone();
    c.dependencies[1].coexistence = Some(Coexistence::Exclusive);
    assert_ne!(release_digest(&a).ok(), release_digest(&c).ok());
    let mut d = a.clone();
    d.dependencies[1].coexistence = Some(Coexistence::SideBySide);
    assert_ne!(release_digest(&c).ok(), release_digest(&d).ok());
    // Order-independent, like the pins themselves.
    let mut e = c.clone();
    e.dependencies.reverse();
    assert_eq!(release_digest(&c).ok(), release_digest(&e).ok());
    let json = serde_json::to_value(&c).unwrap();
    assert_eq!(json["dependencies"][1]["coexistence"], "exclusive");
    assert!(json["dependencies"][0].get("shared").is_none());
    let back: RegisterReleaseRequest = serde_json::from_value(json).unwrap();
    assert_eq!(back, c);
}

#[test]
fn dependency_pin_new_has_the_default_policy() {
    let p = DependencyPin::new(
        DependencyKind::Runtime,
        "greentic-start",
        Some(">=1.2.0".into()),
    );
    assert_eq!(p, sample_dependencies()[1]);
    assert!(p.has_default_policy());
}
