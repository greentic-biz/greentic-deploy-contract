use super::*;
use crate::control_plane::tests_support::sample;

fn bytes(v: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap_or_default()
}

fn sample_value() -> serde_json::Value {
    serde_json::to_value(sample()).unwrap_or_default()
}

#[test]
fn parse_round_trips_a_known_manifest() {
    assert_eq!(
        ControlPlaneManifest::parse(&bytes(&sample_value())),
        Ok(sample())
    );
}

#[test]
fn parse_reports_an_unsupported_schema() {
    let mut v = sample_value();
    v["schema"] = serde_json::json!("greentic.control-plane-release.v2");
    assert_eq!(
        ControlPlaneManifest::parse(&bytes(&v)),
        Err(ManifestParseError::UnsupportedSchema {
            schema: "greentic.control-plane-release.v2".into()
        })
    );
}

#[test]
fn an_unknown_component_reads_as_newer_than_this_reader() {
    let mut v = sample_value();
    v["components"][1]["component"] = serde_json::json!("edge");
    assert_eq!(
        ControlPlaneManifest::parse(&bytes(&v)),
        Err(ManifestParseError::NewerThanThisReader {
            schema: CONTROL_PLANE_SCHEMA.into(),
            upgrade_from: Some(">=1.2.0-dev".into()),
        })
    );
}

#[test]
fn an_unknown_field_reads_as_newer_than_this_reader() {
    let mut v = sample_value();
    v["signing_hint"] = serde_json::json!("x");
    if let Some(o) = v.as_object_mut() {
        o.remove("upgrade_from");
    }
    assert_eq!(
        ControlPlaneManifest::parse(&bytes(&v)),
        Err(ManifestParseError::NewerThanThisReader {
            schema: CONTROL_PLANE_SCHEMA.into(),
            upgrade_from: None,
        })
    );
}

#[test]
fn unreadable_bytes_are_malformed() {
    assert!(matches!(
        ControlPlaneManifest::parse(b"not json"),
        Err(ManifestParseError::Malformed(_))
    ));
    assert!(matches!(
        ControlPlaneManifest::parse(br#"{"version":"1.0.0"}"#),
        Err(ManifestParseError::Malformed(_))
    ));
}

fn observation() -> ControlPlaneObservation {
    ControlPlaneObservation {
        build: ComponentBuildInfo {
            component: Component::Admin,
            app_version: "1.2.57-dev".into(),
            git_commit: None,
            embedded_schema_head: 20260929060000,
        },
        db_schema_head: Some(20260929060000),
        image_digest: Some(format!("sha256:{}", "a".repeat(64))),
    }
}

#[test]
fn a_well_formed_observation_validates() {
    assert_eq!(observation().validate(), Ok(()));
    let mut o = observation();
    o.image_digest = None;
    o.db_schema_head = None;
    assert_eq!(o.validate(), Ok(()));
}

#[test]
fn observation_validate_refuses_each_bad_field() {
    let mut o = observation();
    o.image_digest = Some("sha256:XYZ".into());
    assert_eq!(o.validate(), Err(ObservationError::BadImageDigest));

    let mut o = observation();
    o.build.app_version = "latest".into();
    assert_eq!(o.validate(), Err(ObservationError::BadVersion));

    let mut o = observation();
    o.build.embedded_schema_head = 0;
    assert_eq!(o.validate(), Err(ObservationError::BadEmbeddedSchemaHead));

    let mut o = observation();
    o.db_schema_head = Some(-1);
    assert_eq!(o.validate(), Err(ObservationError::BadDbSchemaHead));
}
