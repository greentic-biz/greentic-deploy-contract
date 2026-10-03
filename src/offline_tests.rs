use super::*;
use crate::execution::tests::digest;
use crate::release::{
    Compatibility, Provenance, ReleaseArtifact, ReleaseKind, RollbackDeclaration, release_digest,
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
            shared: false,
            coexistence: None,
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
        migrations: Vec::new(),
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
        "C:/x",
        "files/a:stream",
        "files/line\nbreak",
        "files/trailing.",
        "files/with space",
        "files/CON",
        "files/nul.txt",
        "files/café",
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
fn path_length_limits() {
    let mut m = sample();
    m.inventory[0].path = format!("files/{}", "a".repeat(MAX_PATH_SEGMENT_BYTES));
    assert_eq!(m.validate(), Ok(()));
    m.inventory[0].path = format!("files/{}", "a".repeat(MAX_PATH_SEGMENT_BYTES + 1));
    assert!(matches!(m.validate(), Err(OfflineError::UnsafePath(_))));
    m.inventory[0].path = vec!["a".repeat(200); 21].join("/");
    assert!(m.inventory[0].path.len() > MAX_PATH_BYTES);
    assert!(matches!(m.validate(), Err(OfflineError::UnsafePath(_))));
}

#[test]
fn a_dotted_file_name_is_not_traversal() {
    let mut m = sample();
    m.inventory[0].path = "files/..hidden/a..b".into();
    assert_eq!(m.validate(), Ok(()));
}

#[test]
fn a_duplicate_path_is_refused_case_insensitively() {
    let mut m = sample();
    m.inventory[1].path = m.inventory[0].path.clone();
    assert!(matches!(m.validate(), Err(OfflineError::DuplicatePath(_))));
    let mut m = sample();
    m.inventory[1].path = m.inventory[0].path.to_ascii_uppercase();
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
    m.releases[0].request.dependencies[0].digest = Some(digest('e'));
    m.releases[0].release_digest = release_digest(&m.releases[0].request).unwrap();
    m.closure.entries[0].digest = Some(digest('e'));
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
        oci_ref: format!("registry.local/ext/llm-openai@{}", digest('b')),
    };
    assert_eq!(m.validate(), Ok(()));
}

#[test]
fn an_internal_registry_reference_must_be_digest_pinned_to_the_entry() {
    let mut m = sample();
    m.closure.entries[0].source = ClosureSource::InternalRegistry {
        oci_ref: "registry.local/ext/llm-openai:1.0".into(),
    };
    assert!(matches!(m.validate(), Err(OfflineError::UnpinnedOciRef(_))));
    m.closure.entries[0].source = ClosureSource::InternalRegistry {
        oci_ref: format!("registry.local/ext/llm-openai@{}", digest('9')),
    };
    assert!(matches!(
        m.validate(),
        Err(OfflineError::SourceDigestMismatch(_))
    ));
}

#[test]
fn a_packaged_source_must_match_the_pinned_digest() {
    let mut m = sample();
    // `a` is in the inventory, but the entry pins `b`.
    m.closure.entries[0].source = ClosureSource::Packaged {
        digest: digest('a'),
    };
    assert!(matches!(
        m.validate(),
        Err(OfflineError::SourceDigestMismatch(_))
    ));
}

#[test]
fn a_duplicate_closure_entry_is_refused() {
    let mut m = sample();
    let mut dup = m.closure.entries[0].clone();
    dup.source = ClosureSource::InternalRegistry {
        oci_ref: format!("registry.local/x@{}", digest('b')),
    };
    m.closure.entries.push(dup);
    assert!(matches!(
        m.validate(),
        Err(OfflineError::DuplicateClosureEntry(_))
    ));
}

#[test]
fn a_complete_package_carries_every_release_artifact() {
    let mut m = sample();
    m.inventory.remove(0);
    m.max_unpacked_bytes = 50;
    assert!(matches!(
        m.validate(),
        Err(OfflineError::ArtifactMissing { .. })
    ));
    // An inventory-based package may rely on its bound inventory.
    m.mode = PackageMode::InventoryBased {
        inventory_digest: digest('9'),
    };
    assert_eq!(m.validate(), Ok(()));
}

#[test]
fn a_non_canonical_artifact_digest_is_refused() {
    let mut m = sample();
    let req = &mut m.releases[0].request;
    req.artifacts[0].digest = "a".repeat(64);
    m.releases[0].release_digest = release_digest(&m.releases[0].request).unwrap();
    assert_eq!(
        m.validate(),
        Err(OfflineError::BadDigest("releases.request.artifacts.digest"))
    );
}

#[test]
fn an_artifact_target_must_be_a_declared_architecture() {
    let mut m = sample();
    m.releases[0].request.artifacts[0].target = Some("aarch64-unknown-linux-gnu".into());
    m.releases[0].release_digest = release_digest(&m.releases[0].request).unwrap();
    assert!(matches!(
        m.validate(),
        Err(OfflineError::UnsupportedTarget { .. })
    ));
    m.architectures.push("aarch64-unknown-linux-gnu".into());
    assert_eq!(m.validate(), Ok(()));
}

#[test]
fn duplicate_trust_material_is_refused() {
    let mut m = sample();
    m.trust_statements.push(digest('d'));
    assert!(matches!(
        m.validate(),
        Err(OfflineError::DuplicateTrustMaterial(_))
    ));
    let mut m = sample();
    m.trust_statements = vec![digest('c')];
    assert!(matches!(
        m.validate(),
        Err(OfflineError::DuplicateTrustMaterial(_))
    ));
}

#[test]
fn admit_checks_audience_and_expiry() {
    let m = sample();
    assert_eq!(m.admit(ts(12), "inst-1"), Ok(()));
    assert_eq!(
        m.admit(ts(12), "inst-2"),
        Err(OfflineAdmitError::NotForThisInstallation)
    );
    assert_eq!(m.admit(ts(20), "inst-1"), Err(OfflineAdmitError::Expired));
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
    m.max_unpacked_bytes = MAX_UNPACKED_BYTES;
    assert_eq!(m.validate(), Err(OfflineError::UnpackedSizeTooSmall));
    let mut m = sample();
    m.max_unpacked_bytes = MAX_UNPACKED_BYTES + 1;
    assert_eq!(m.validate(), Err(OfflineError::UnpackedSizeTooLarge));
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
#[path = "offline_sign_tests.rs"]
mod signing_tests;

#[test]
fn an_invalid_migration_declaration_is_refused() {
    let mut m = sample();
    let mut decl = crate::migration::tests::declaration();
    decl.reversible = false;
    m.releases[0].request.migrations = vec![decl];
    m.releases[0].release_digest = release_digest(&m.releases[0].request).unwrap();
    assert!(matches!(m.validate(), Err(OfflineError::BadRequest { .. })));
}

fn runtime_manifest(artifact_name: &str, entry_digest: char) -> OfflineReleaseManifest {
    use crate::release_runtime::OCI_IMAGE_INDEX_MEDIA_TYPE;
    let mut req = request();
    req.kind = ReleaseKind::Platform;
    req.artifacts = vec![ReleaseArtifact {
        name: artifact_name.into(),
        version: "1.3.0".into(),
        digest: digest('e'),
        target: None,
        media_type: Some(OCI_IMAGE_INDEX_MEDIA_TYPE.into()),
        source: Some("registry.internal/start".into()),
    }];
    req.dependencies.clear();
    let mut m = sample();
    m.releases[0].release_digest = release_digest(&req).unwrap();
    m.releases[0].request = req;
    m.inventory.clear();
    m.max_unpacked_bytes = 0;
    m.closure.entries = vec![ClosureEntry {
        kind: DependencyKind::Runtime,
        name: "greentic-start-runtime".into(),
        version_req: None,
        digest: None,
        source: ClosureSource::InternalRegistry {
            oci_ref: format!("registry.internal/start@{}", digest(entry_digest)),
        },
    }];
    m
}

#[test]
fn complete_accepts_runtime_artifact_covered_by_internal_registry_entry() {
    let m = runtime_manifest(crate::release_runtime::RUNTIME_IMAGE_ARTIFACT, 'e');
    assert_eq!(m.validate(), Ok(()));
}

#[test]
fn complete_rejects_when_oci_ref_digest_differs() {
    let m = runtime_manifest(crate::release_runtime::RUNTIME_IMAGE_ARTIFACT, 'f');
    assert!(matches!(
        m.validate(),
        Err(OfflineError::ArtifactMissing { .. })
    ));
}

#[test]
fn complete_rejects_internal_registry_for_non_runtime_artifact() {
    let m = runtime_manifest("greentic-start-binary", 'e');
    assert!(matches!(
        m.validate(),
        Err(OfflineError::ArtifactMissing { .. })
    ));
}
