use super::*;
use crate::execution::tests::digest;
use crate::release::{
    Compatibility, Provenance, ReleaseArtifact, ReleaseKind, RollbackDeclaration,
};
use chrono::TimeZone;
use serde_json::json;

fn ts(hour: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 28, hour, 0, 0).unwrap()
}

fn request() -> RegisterReleaseRequest {
    RegisterReleaseRequest {
        kind: ReleaseKind::Application,
        publisher: "tenant:acme".into(),
        name: "guest-assistant".into(),
        version: "2.4.0".into(),
        artifacts: vec![ReleaseArtifact {
            name: "guest.gtpack".into(),
            version: "2.4.0".into(),
            digest: digest('a'),
            target: None,
            media_type: None,
            source: None,
        }],
        dependencies: vec![DependencyPin {
            kind: DependencyKind::Extension,
            name: "greentic.llm-openai".into(),
            version_req: Some("^1".into()),
            digest: Some(digest('b')),
        }],
        compatibility: Compatibility::default(),
        provenance: Provenance {
            source_repo: None,
            source_revision: None,
            builder: "designer".into(),
            built_at: None,
        },
        rollback: RollbackDeclaration {
            supported: true,
            notes: None,
        },
    }
}

pub(crate) fn sample() -> OfflineReleaseManifest {
    let req = request();
    OfflineReleaseManifest {
        schema: OFFLINE_RELEASE_SCHEMA.into(),
        envelope_id: "env-1".into(),
        created_at: ts(10),
        not_after: ts(20),
        audience: Audience {
            installation_ids: vec!["inst-1".into()],
            owner_ref: Some("acme".into()),
        },
        releases: vec![ReleaseEntry {
            release_id: "rel-1".into(),
            release_digest: release_digest(&req).unwrap(),
            request: req,
        }],
        inventory: vec![
            PackagedArtifact {
                path: "files/guest.gtpack".into(),
                digest: digest('a'),
                bytes: 100,
                role: ArtifactRole::Pack,
                oci_ref: None,
            },
            PackagedArtifact {
                path: "files/ext/llm-openai.gtxpack".into(),
                digest: digest('b'),
                bytes: 50,
                role: ArtifactRole::Bundle,
                oci_ref: None,
            },
        ],
        closure: DependencyClosure {
            entries: vec![ClosureEntry {
                kind: DependencyKind::Extension,
                name: "greentic.llm-openai".into(),
                version_req: Some("^1".into()),
                digest: Some(digest('b')),
                source: ClosureSource::Packaged {
                    digest: digest('b'),
                },
            }],
        },
        architectures: vec!["x86_64-unknown-linux-gnu".into()],
        mode: PackageMode::Complete,
        revocation: Some(digest('c')),
        trust_statements: vec![digest('d')],
        max_unpacked_bytes: 150,
    }
}

#[test]
fn a_well_formed_manifest_validates() {
    assert_eq!(sample().validate(), Ok(()));
}

#[test]
fn an_unknown_schema_is_refused() {
    let mut m = sample();
    m.schema = "greentic.offline-release.v2".into();
    assert!(matches!(m.validate(), Err(OfflineError::UnknownSchema(_))));
}

#[test]
fn an_empty_audience_is_refused() {
    let mut m = sample();
    m.audience.installation_ids.clear();
    assert_eq!(m.validate(), Err(OfflineError::EmptyAudience));
}

#[test]
fn a_blank_or_duplicate_installation_is_refused() {
    let mut m = sample();
    m.audience.installation_ids.push(" ".into());
    assert!(matches!(m.validate(), Err(OfflineError::BadIdentifier(_))));
    let mut m = sample();
    m.audience.installation_ids.push("inst-1".into());
    assert!(matches!(
        m.validate(),
        Err(OfflineError::DuplicateInstallation(_))
    ));
}

#[test]
fn unsafe_paths_are_refused() {
    for bad in [
        "",
        "/etc/passwd",
        "../x",
        "files/../../x",
        "files/./x",
        "files//x",
        "files\\x",
        "files/x/",
        "files/..",
        "a\0b",
    ] {
        let mut m = sample();
        m.inventory[0].path = bad.into();
        assert!(
            matches!(m.validate(), Err(OfflineError::UnsafePath(_))),
            "{bad:?} should be refused"
        );
    }
}

#[test]
fn a_dotted_file_name_is_not_traversal() {
    let mut m = sample();
    m.inventory[0].path = "files/..hidden/a..b".into();
    assert_eq!(m.validate(), Ok(()));
}

#[test]
fn a_duplicate_path_is_refused() {
    let mut m = sample();
    m.inventory[1].path = m.inventory[0].path.clone();
    assert!(matches!(m.validate(), Err(OfflineError::DuplicatePath(_))));
}

#[test]
fn a_non_canonical_digest_is_refused() {
    let mut m = sample();
    m.inventory[0].digest = format!("sha256:{}", "A".repeat(64));
    assert_eq!(
        m.validate(),
        Err(OfflineError::BadDigest("inventory.digest"))
    );
    let mut m = sample();
    m.revocation = Some("md5:abc".into());
    assert_eq!(m.validate(), Err(OfflineError::BadDigest("revocation")));
    let mut m = sample();
    m.trust_statements.push("x".into());
    assert_eq!(
        m.validate(),
        Err(OfflineError::BadDigest("trust_statements"))
    );
    let mut m = sample();
    m.mode = PackageMode::InventoryBased {
        inventory_digest: "nope".into(),
    };
    assert_eq!(
        m.validate(),
        Err(OfflineError::BadDigest("mode.inventory_digest"))
    );
}

#[test]
fn a_release_digest_that_does_not_match_its_request_is_refused() {
    let mut m = sample();
    m.releases[0].release_digest = digest('f');
    assert!(matches!(
        m.validate(),
        Err(OfflineError::ReleaseDigestMismatch(_))
    ));
}

#[test]
fn no_releases_and_duplicate_releases_are_refused() {
    let mut m = sample();
    m.releases.clear();
    assert_eq!(m.validate(), Err(OfflineError::NoReleases));
    let mut m = sample();
    m.releases.push(m.releases[0].clone());
    assert!(matches!(
        m.validate(),
        Err(OfflineError::DuplicateRelease(_))
    ));
}

#[test]
fn an_unresolved_dependency_is_refused() {
    let mut m = sample();
    m.closure.entries.clear();
    assert!(matches!(
        m.validate(),
        Err(OfflineError::UnresolvedDependency { .. })
    ));
}

#[test]
fn a_closure_entry_must_match_the_pin_exactly() {
    let mut m = sample();
    m.closure.entries[0].version_req = Some("^2".into());
    assert!(matches!(
        m.validate(),
        Err(OfflineError::UnresolvedDependency { .. })
    ));
    let mut m = sample();
    m.closure.entries[0].kind = DependencyKind::Pack;
    assert!(matches!(
        m.validate(),
        Err(OfflineError::UnresolvedDependency { .. })
    ));
}

#[test]
fn a_packaged_digest_absent_from_the_inventory_is_refused() {
    let mut m = sample();
    m.closure.entries[0].source = ClosureSource::Packaged {
        digest: digest('e'),
    };
    assert!(matches!(
        m.validate(),
        Err(OfflineError::PackagedDigestMissing(_))
    ));
}

#[test]
fn installed_is_only_valid_in_an_inventory_based_package() {
    let mut m = sample();
    m.closure.entries[0].source = ClosureSource::Installed;
    assert!(matches!(
        m.validate(),
        Err(OfflineError::InstalledInCompletePackage(_))
    ));
    m.mode = PackageMode::InventoryBased {
        inventory_digest: digest('9'),
    };
    assert_eq!(m.validate(), Ok(()));
}

#[test]
fn an_internal_registry_source_needs_a_reference() {
    let mut m = sample();
    m.closure.entries[0].source = ClosureSource::InternalRegistry {
        oci_ref: " ".into(),
    };
    assert_eq!(m.validate(), Err(OfflineError::EmptyOciRef));
    m.closure.entries[0].source = ClosureSource::InternalRegistry {
        oci_ref: "registry.local/ext/llm-openai@sha256:x".into(),
    };
    assert_eq!(m.validate(), Ok(()));
}

#[test]
fn not_after_must_follow_created_at() {
    let mut m = sample();
    m.not_after = m.created_at;
    assert_eq!(m.validate(), Err(OfflineError::WindowInverted));
}

#[test]
fn max_unpacked_bytes_covers_the_inventory() {
    let mut m = sample();
    m.max_unpacked_bytes = 149;
    assert_eq!(m.validate(), Err(OfflineError::UnpackedSizeTooSmall));
    let mut m = sample();
    m.inventory[0].bytes = u64::MAX;
    m.max_unpacked_bytes = u64::MAX;
    assert_eq!(m.validate(), Err(OfflineError::UnpackedSizeTooSmall));
}

#[test]
fn an_unknown_field_is_refused_at_every_level() {
    let mut v = serde_json::to_value(sample()).unwrap();
    v["extra"] = json!(1);
    assert!(serde_json::from_value::<OfflineReleaseManifest>(v).is_err());
    let mut v = serde_json::to_value(sample()).unwrap();
    v["inventory"][0]["extra"] = json!(1);
    assert!(serde_json::from_value::<OfflineReleaseManifest>(v).is_err());
    let mut v = serde_json::to_value(sample()).unwrap();
    v["closure"]["entries"][0]["source"]["extra"] = json!(1);
    assert!(serde_json::from_value::<OfflineReleaseManifest>(v).is_err());
    let mut v = serde_json::to_value(sample()).unwrap();
    v["inventory"][0]["role"] = json!("script");
    assert!(serde_json::from_value::<OfflineReleaseManifest>(v).is_err());
}

#[test]
fn the_wire_shape_is_tagged_snake_case() {
    let v = serde_json::to_value(sample()).unwrap();
    assert_eq!(v["mode"], json!({"kind": "complete"}));
    assert_eq!(v["closure"]["entries"][0]["source"]["kind"], "packaged");
    assert_eq!(v["inventory"][0]["role"], "pack");
    let back: OfflineReleaseManifest = serde_json::from_value(v).unwrap();
    assert_eq!(back, sample());
}

#[cfg(feature = "signing")]
mod signing_tests {
    use super::*;
    use crate::dsse::VerifyError;
    use crate::signed::{OpenError, SignError};
    use ed25519_dalek::SigningKey;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn round_trips_two_of_two() {
        let (a, b) = (key(1), key(2));
        let env = sign_offline(&sample(), &[&a, &b]).unwrap();
        assert_eq!(env.payload_type, OFFLINE_RELEASE_PAYLOAD_TYPE);
        let trusted = [a.verifying_key(), b.verifying_key()];
        assert_eq!(verify_offline(&env, &trusted, 2).unwrap(), sample());
    }

    #[test]
    fn below_threshold_is_refused() {
        let a = key(1);
        let env = sign_offline(&sample(), &[&a]).unwrap();
        let trusted = [a.verifying_key(), key(2).verifying_key()];
        assert!(matches!(
            verify_offline(&env, &trusted, 2),
            Err(OpenError::Signature(VerifyError::BelowThreshold { .. }))
        ));
    }

    #[test]
    fn an_untrusted_signer_is_refused() {
        let env = sign_offline(&sample(), &[&key(1)]).unwrap();
        assert!(matches!(
            verify_offline(&env, &[key(9).verifying_key()], 1),
            Err(OpenError::Signature(VerifyError::NoTrustedSignature))
        ));
    }

    #[test]
    fn an_invalid_manifest_is_never_signed() {
        let mut m = sample();
        m.audience.installation_ids.clear();
        assert!(matches!(
            sign_offline(&m, &[&key(1)]),
            Err(SignError::Invalid(OfflineError::EmptyAudience))
        ));
        assert!(matches!(
            sign_offline(&sample(), &[]),
            Err(SignError::NoKeys)
        ));
    }

    #[test]
    fn a_signed_but_invalid_payload_is_refused_after_the_signature() {
        let mut m = sample();
        m.audience.installation_ids.clear();
        let payload = serde_json::to_vec(&m).unwrap();
        let a = key(1);
        let env = crate::dsse::sign_bytes(OFFLINE_RELEASE_PAYLOAD_TYPE, &payload, &[&a]);
        assert!(matches!(
            verify_offline(&env, &[a.verifying_key()], 1),
            Err(OpenError::Invalid(OfflineError::EmptyAudience))
        ));
    }

    #[test]
    fn another_schema_type_is_refused() {
        let a = key(1);
        let env = crate::dsse::sign_bytes(
            "application/vnd.greentic.status-report.v1+json",
            &serde_json::to_vec(&sample()).unwrap(),
            &[&a],
        );
        assert!(matches!(
            verify_offline(&env, &[a.verifying_key()], 1),
            Err(OpenError::Signature(VerifyError::WrongPayloadType))
        ));
    }
}
