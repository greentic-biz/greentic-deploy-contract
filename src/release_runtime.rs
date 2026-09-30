//! Which artifact of a PLATFORM release is the runtime image a unit runs
//! (unified update L2, decision D4). A platform release carrying no such
//! artifact — the scanner's per-target binaries — is not executable.

use crate::release::{RegisterReleaseRequest, ReleaseArtifact, ReleaseKind};

pub const RUNTIME_IMAGE_ARTIFACT: &str = "greentic-start-distroless";
/// The runtime digest is the image INDEX digest (multi-arch), which is what
/// the designer pins; a single-platform manifest is accepted too.
pub const OCI_MEDIA_TYPES: [&str; 2] = [
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.oci.image.manifest.v1+json",
];

/// Why a release has no single identifiable runtime image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeImageError {
    NotPlatform,
    NoRuntimeImage,
    Ambiguous,
}

impl std::fmt::Display for RuntimeImageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotPlatform => "the release is not a platform release",
            Self::NoRuntimeImage => "the release carries no runtime image artifact",
            Self::Ambiguous => "the release carries more than one runtime image artifact",
        })
    }
}

impl std::error::Error for RuntimeImageError {}

/// The one artifact of a platform release that is its runtime image.
pub fn runtime_image_artifact(
    req: &RegisterReleaseRequest,
) -> Result<&ReleaseArtifact, RuntimeImageError> {
    if req.kind != ReleaseKind::Platform {
        return Err(RuntimeImageError::NotPlatform);
    }
    let mut found = req.artifacts.iter().filter(|a| {
        a.name == RUNTIME_IMAGE_ARTIFACT
            && a.media_type
                .as_deref()
                .is_some_and(|m| OCI_MEDIA_TYPES.contains(&m))
    });
    match (found.next(), found.next()) {
        (Some(a), None) => Ok(a),
        (None, _) => Err(RuntimeImageError::NoRuntimeImage),
        (Some(_), Some(_)) => Err(RuntimeImageError::Ambiguous),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::release::{Compatibility, Provenance, RollbackDeclaration};

    fn art(name: &str, media: Option<&str>, c: char) -> ReleaseArtifact {
        ReleaseArtifact {
            name: name.into(),
            version: "1.3.0".into(),
            digest: format!("sha256:{}", c.to_string().repeat(64)),
            target: None,
            media_type: media.map(str::to_string),
            source: Some("ghcr.io/greenticai/greentic-start-distroless".into()),
        }
    }

    fn req(kind: ReleaseKind, artifacts: Vec<ReleaseArtifact>) -> RegisterReleaseRequest {
        RegisterReleaseRequest {
            kind,
            publisher: "greentic".into(),
            name: "greentic-platform".into(),
            version: "1.3.0".into(),
            artifacts,
            dependencies: Vec::new(),
            compatibility: Compatibility::default(),
            provenance: Provenance {
                source_repo: None,
                source_revision: None,
                builder: "test".into(),
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
    fn the_image_index_artifact_is_the_runtime() {
        let r = req(
            ReleaseKind::Platform,
            vec![
                art("greentic-start", None, 'a'),
                art(RUNTIME_IMAGE_ARTIFACT, Some(OCI_MEDIA_TYPES[0]), 'f'),
            ],
        );
        assert_eq!(
            runtime_image_artifact(&r).map(|a| a.digest.clone()),
            Ok(format!("sha256:{}", "f".repeat(64)))
        );
    }

    #[test]
    fn a_binary_only_platform_release_has_no_runtime_image() {
        let r = req(
            ReleaseKind::Platform,
            vec![art("greentic-start", None, 'a')],
        );
        assert_eq!(
            runtime_image_artifact(&r).err(),
            Some(RuntimeImageError::NoRuntimeImage)
        );
    }

    #[test]
    fn a_right_name_with_a_non_oci_media_type_is_not_a_runtime_image() {
        let r = req(
            ReleaseKind::Platform,
            vec![art(RUNTIME_IMAGE_ARTIFACT, Some("application/gzip"), 'a')],
        );
        assert_eq!(
            runtime_image_artifact(&r).err(),
            Some(RuntimeImageError::NoRuntimeImage)
        );
    }

    #[test]
    fn two_runtime_images_are_ambiguous() {
        let r = req(
            ReleaseKind::Platform,
            vec![
                art(RUNTIME_IMAGE_ARTIFACT, Some(OCI_MEDIA_TYPES[0]), 'a'),
                art(RUNTIME_IMAGE_ARTIFACT, Some(OCI_MEDIA_TYPES[1]), 'b'),
            ],
        );
        assert_eq!(
            runtime_image_artifact(&r).err(),
            Some(RuntimeImageError::Ambiguous)
        );
    }

    #[test]
    fn an_application_release_is_not_a_platform_one() {
        let r = req(
            ReleaseKind::Application,
            vec![art(RUNTIME_IMAGE_ARTIFACT, Some(OCI_MEDIA_TYPES[0]), 'a')],
        );
        assert_eq!(
            runtime_image_artifact(&r).err(),
            Some(RuntimeImageError::NotPlatform)
        );
    }
}
