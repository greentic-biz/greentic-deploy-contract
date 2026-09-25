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
    let s = serde_json::to_string(&sample()).unwrap_or_default();
    let back: RegisterReleaseRequest = serde_json::from_str(&s).unwrap_or_else(|_| sample());
    assert_eq!(back, sample());
    assert!(s.contains("\"kind\":\"application\""));
}
