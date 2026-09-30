use super::*;
use crate::release::{
    Compatibility, DependencyKind, DependencyPin, Provenance, RegisterReleaseRequest,
    ReleaseArtifact, ReleaseKind, RollbackDeclaration,
};

fn d(c: char) -> String {
    format!("sha256:{}", c.to_string().repeat(64))
}

pub(crate) fn sample() -> ControlPlaneManifest {
    ControlPlaneManifest {
        schema: CONTROL_PLANE_SCHEMA.into(),
        version: "1.3.0-dev.1".into(),
        components: vec![
            ComponentImage {
                component: Component::Admin,
                source_repository: "ghcr.io/greentic-biz/greentic-admin-deploy".into(),
                index_digest: d('a'),
                platform_digests: [
                    ("linux/amd64".into(), d('b')),
                    ("linux/arm64".into(), d('c')),
                ]
                .into_iter()
                .collect(),
                app_version: "1.2.57-dev".into(),
                schema_head: 20260929060000,
            },
            ComponentImage {
                component: Component::Designer,
                source_repository: "ghcr.io/greentic-biz/greentic-designer".into(),
                index_digest: d('e'),
                platform_digests: [("linux/amd64".into(), d('f'))].into_iter().collect(),
                app_version: "1.2.541-dev".into(),
                schema_head: 20260930090000,
            },
        ],
        chart: ChartRef {
            name: "greentic".into(),
            version: "0.2.0".into(),
            digest: d('9'),
        },
        upgrade_from: Some(">=1.2.0-dev".into()),
    }
}

pub(crate) fn request_for(
    m: &ControlPlaneManifest,
    manifest_digest: &str,
) -> RegisterReleaseRequest {
    RegisterReleaseRequest {
        kind: ReleaseKind::Platform,
        publisher: "github:greentic-biz/greentic-designer-admin".into(),
        name: CONTROL_PLANE_RELEASE_NAME.into(),
        version: m.version.clone(),
        artifacts: vec![
            ReleaseArtifact {
                name: "control-plane.json".into(),
                version: m.version.clone(),
                digest: manifest_digest.into(),
                target: None,
                media_type: Some(CONTROL_PLANE_MANIFEST_MEDIA_TYPE.into()),
                source: None,
            },
            ReleaseArtifact {
                name: format!("{}-{}.tgz", m.chart.name, m.chart.version),
                version: m.chart.version.clone(),
                digest: m.chart.digest.clone(),
                target: None,
                media_type: Some(HELM_CHART_MEDIA_TYPE.into()),
                source: None,
            },
        ],
        dependencies: m
            .components
            .iter()
            .map(|c| {
                let mut p = DependencyPin::new(
                    DependencyKind::Runtime,
                    image_pin_name(c.component),
                    Some(format!("={}", c.app_version)),
                );
                p.digest = Some(c.index_digest.clone());
                p
            })
            .collect(),
        compatibility: Compatibility::default(),
        provenance: Provenance {
            source_repo: None,
            source_revision: None,
            builder: "github-actions".into(),
            built_at: None,
        },
        rollback: RollbackDeclaration {
            supported: true,
            notes: None,
        },
        migrations: vec![],
    }
}

#[test]
fn sample_validates() {
    assert_eq!(sample().validate(), Ok(()));
}

#[test]
fn wrong_schema_is_refused() {
    let mut m = sample();
    m.schema = "greentic.control-plane-release.v0".into();
    assert_eq!(m.validate(), Err(ControlPlaneError::WrongSchema));
}

#[test]
fn duplicate_component_is_refused() {
    let mut m = sample();
    let first = m.components[0].clone();
    m.components.push(first);
    assert_eq!(
        m.validate(),
        Err(ControlPlaneError::DuplicateComponent(Component::Admin))
    );
}

#[test]
fn bad_platform_and_bad_digest_are_refused() {
    let mut m = sample();
    m.components[0]
        .platform_digests
        .insert("amd64".into(), d('1'));
    assert_eq!(
        m.validate(),
        Err(ControlPlaneError::BadPlatform("amd64".into()))
    );
    let mut m = sample();
    m.components[1].index_digest = "sha256:XYZ".into();
    assert_eq!(
        m.validate(),
        Err(ControlPlaneError::BadDigest("components[1].index_digest"))
    );
}

#[test]
fn a_component_needs_a_platform_and_a_positive_schema_head() {
    let mut m = sample();
    m.components[1].platform_digests.clear();
    assert_eq!(
        m.validate(),
        Err(ControlPlaneError::NoPlatforms(Component::Designer))
    );
    let mut m = sample();
    m.components[0].schema_head = 0;
    assert_eq!(
        m.validate(),
        Err(ControlPlaneError::BadSchemaHead(Component::Admin))
    );
}

#[test]
fn versions_must_be_semver() {
    let mut m = sample();
    m.components[0].app_version = "latest".into();
    assert_eq!(
        m.validate(),
        Err(ControlPlaneError::BadVersion("components[0].app_version"))
    );
    let mut m = sample();
    m.upgrade_from = Some("not a req".into());
    assert_eq!(m.validate(), Err(ControlPlaneError::BadUpgradeFrom));
}

#[test]
fn wire_is_stable_snake_case() {
    let v = serde_json::to_value(sample()).unwrap_or_default();
    assert_eq!(v["components"][0]["component"], "admin");
    assert_eq!(
        v["components"][1]["platform_digests"]["linux/amd64"],
        d('f')
    );
    let mut with_extra = serde_json::to_value(sample()).unwrap_or_default();
    with_extra["extra"] = serde_json::json!(1);
    let back: Result<ControlPlaneManifest, _> = serde_json::from_value(with_extra);
    assert!(back.is_err(), "deny_unknown_fields");
}

#[test]
fn internal_ref_and_pin_name() {
    let m = sample();
    assert_eq!(
        internal_ref(&m.components[0]),
        format!("greentic-admin@{}", d('a'))
    );
    assert_eq!(
        image_pin_name(Component::Designer),
        "image:greentic-designer"
    );
}

#[test]
fn platform_for_target_maps_linux_triples_only() {
    assert_eq!(
        platform_for_target("x86_64-unknown-linux-gnu"),
        Some("linux/amd64")
    );
    assert_eq!(
        platform_for_target("aarch64-unknown-linux-musl"),
        Some("linux/arm64")
    );
    assert_eq!(platform_for_target("x86_64-pc-windows-msvc"), None);
}

#[test]
fn consistent_request_passes() {
    let m = sample();
    let md = d('7');
    assert_eq!(consistent_with(&m, &md, &request_for(&m, &md)), Ok(()));
}

#[test]
fn consistency_catches_each_mismatch() {
    let m = sample();
    let md = d('7');

    let mut r = request_for(&m, &md);
    r.kind = ReleaseKind::Application;
    assert_eq!(
        consistent_with(&m, &md, &r),
        Err(ConsistencyError::NotPlatform)
    );

    let mut r = request_for(&m, &md);
    r.version = "9.9.9".into();
    assert_eq!(
        consistent_with(&m, &md, &r),
        Err(ConsistencyError::VersionMismatch)
    );

    let r = request_for(&m, &d('8'));
    assert_eq!(
        consistent_with(&m, &md, &r),
        Err(ConsistencyError::ManifestNotAnArtifact)
    );

    let mut r = request_for(&m, &md);
    r.artifacts
        .retain(|a| a.media_type.as_deref() != Some(HELM_CHART_MEDIA_TYPE));
    assert_eq!(
        consistent_with(&m, &md, &r),
        Err(ConsistencyError::ChartNotAnArtifact)
    );

    let mut r = request_for(&m, &md);
    r.dependencies[1].digest = Some(d('0'));
    assert_eq!(
        consistent_with(&m, &md, &r),
        Err(ConsistencyError::ImagePinMismatch(Component::Designer))
    );

    let mut r = request_for(&m, &md);
    let mut stray = DependencyPin::new(DependencyKind::Runtime, "image:greentic-edge", None);
    stray.digest = Some(d('5'));
    r.dependencies.push(stray);
    assert_eq!(
        consistent_with(&m, &md, &r),
        Err(ConsistencyError::UnexpectedImagePin(
            "image:greentic-edge".into()
        ))
    );
}

#[test]
fn observation_flattens_build_info() {
    let o = ControlPlaneObservation {
        build: ComponentBuildInfo {
            component: Component::Designer,
            app_version: "1.2.541-dev".into(),
            git_commit: Some("784879d".into()),
            embedded_schema_head: 20260930090000,
        },
        db_schema_head: Some(20260930090000),
        image_digest: None,
    };
    let v = serde_json::to_value(&o).unwrap_or_default();
    assert_eq!(v["component"], "designer");
    assert_eq!(v["embedded_schema_head"], 20260930090000_i64);
    assert!(v.get("image_digest").is_none());
}

#[test]
fn short_names_round_trip() {
    for c in Component::ALL {
        assert_eq!(Component::from_short(c.short_name()), Some(c));
    }
    assert_eq!(Component::Admin.short_name(), "admin");
    assert_eq!(Component::from_short("edge"), None);
}
