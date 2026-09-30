//! Can this installation move to a control-plane release, and what does a
//! rollback cost afterwards? Pure: the caller supplies what it observed.
//!
//! The one rule that makes this more than a version compare: both
//! components migrate their database at boot and refuse to start against a
//! database migrated past their own embedded head (sqlx `VersionMissing`).
//! So a target whose head is BELOW the database's is a crash loop, and a
//! target whose head is ABOVE it makes "roll back to the previous image"
//! impossible until the database is restored.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::control_plane::{Component, ComponentImage, ControlPlaneManifest};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ImagePresence {
    /// Found in the registry the installation pulls from, at this digest
    /// (the index, or one platform's manifest).
    Present {
        digest: String,
    },
    Absent,
    /// Nobody could ask (no registry configured, or it did not answer).
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedComponent {
    pub component: Component,
    pub app_version: String,
    pub db_schema_head: Option<i64>,
}

#[derive(Debug)]
pub struct PreflightInput<'a> {
    pub manifest: &'a ControlPlaneManifest,
    pub observed: &'a [ObservedComponent],
    /// A component absent from this map is treated as
    /// [`ImagePresence::Unknown`] (a warning, never a blocker).
    pub presence: &'a BTreeMap<Component, ImagePresence>,
    /// OCI platforms of the nodes the chart schedules onto (`linux/amd64`).
    pub node_platforms: &'a [String],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum Blocker {
    ImageAbsent {
        component: Component,
    },
    PlatformUnavailable {
        component: Component,
        platform: String,
    },
    Downgrade {
        component: Component,
        running: String,
        target: String,
    },
    SchemaAhead {
        component: Component,
        database: i64,
        target: i64,
    },
    UpgradePathUnsupported {
        running: String,
        requires: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum Warning {
    ComponentUnobserved {
        component: Component,
    },
    ImagePresenceUnknown {
        component: Component,
    },
    MigrationsPending {
        component: Component,
        database: i64,
        target: i64,
    },
    AlreadyRunning {
        component: Component,
    },
    VersionUnreadable {
        component: Component,
        running: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Rollback {
    PreviousImage,
    DatabaseRestoreRequired { components: Vec<Component> },
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Preflight {
    pub blockers: Vec<Blocker>,
    pub warnings: Vec<Warning>,
    pub rollback: Rollback,
}

impl Preflight {
    pub fn admissible(&self) -> bool {
        self.blockers.is_empty()
    }
}

/// `found` = digests the registry answered 200 for.
pub fn presence_from_digests(img: &ComponentImage, found: &[String]) -> ImagePresence {
    let wanted = std::iter::once(&img.index_digest).chain(img.platform_digests.values());
    for w in wanted {
        if found.iter().any(|f| f == w) {
            return ImagePresence::Present { digest: w.clone() };
        }
    }
    ImagePresence::Absent
}

pub fn preflight(i: &PreflightInput<'_>) -> Preflight {
    let mut blockers = Vec::new();
    let mut warnings = Vec::new();
    let mut pending = Vec::new();
    let mut unknown_rollback = false;

    if let (Some(req), Some(admin)) = (
        i.manifest.upgrade_from.as_deref(),
        i.observed.iter().find(|o| o.component == Component::Admin),
    ) && !upgrade_path_ok(req, &admin.app_version)
    {
        blockers.push(Blocker::UpgradePathUnsupported {
            running: admin.app_version.clone(),
            requires: req.to_string(),
        });
    }

    for img in &i.manifest.components {
        let c = img.component;
        let presence = i.presence.get(&c).unwrap_or(&ImagePresence::Unknown);
        match presence {
            ImagePresence::Present { .. } => {}
            ImagePresence::Absent => blockers.push(Blocker::ImageAbsent { component: c }),
            ImagePresence::Unknown => warnings.push(Warning::ImagePresenceUnknown { component: c }),
        }
        let only_platform = single_platform_present(img, presence);
        for p in i.node_platforms {
            let available = img.platform_digests.contains_key(p)
                && only_platform.is_none_or(|only| only == p.as_str());
            if !available {
                blockers.push(Blocker::PlatformUnavailable {
                    component: c,
                    platform: p.clone(),
                });
            }
        }
        let Some(o) = i.observed.iter().find(|o| o.component == c) else {
            warnings.push(Warning::ComponentUnobserved { component: c });
            unknown_rollback = true;
            continue;
        };
        match (
            parse_ignoring_build(&o.app_version),
            parse_ignoring_build(&img.app_version),
        ) {
            (Ok(run), Ok(tgt)) if tgt < run => blockers.push(Blocker::Downgrade {
                component: c,
                running: o.app_version.clone(),
                target: img.app_version.clone(),
            }),
            (Ok(run), Ok(tgt)) if tgt == run => {
                warnings.push(Warning::AlreadyRunning { component: c })
            }
            (Ok(_), Ok(_)) => {}
            _ => warnings.push(Warning::VersionUnreadable {
                component: c,
                running: o.app_version.clone(),
            }),
        }
        match o.db_schema_head {
            Some(db) if db > img.schema_head => blockers.push(Blocker::SchemaAhead {
                component: c,
                database: db,
                target: img.schema_head,
            }),
            Some(db) if db < img.schema_head => {
                warnings.push(Warning::MigrationsPending {
                    component: c,
                    database: db,
                    target: img.schema_head,
                });
                pending.push(c);
            }
            Some(_) => {}
            None => unknown_rollback = true,
        }
    }

    // A component whose schema will move needs a database restore to roll
    // back. That is reported even when another component is unobserved or
    // its head unknown: restore is the stricter answer, so it deliberately
    // hides the unknown (which still shows as a warning).
    let rollback = if !pending.is_empty() {
        Rollback::DatabaseRestoreRequired {
            components: pending,
        }
    } else if unknown_rollback {
        Rollback::Unknown
    } else {
        Rollback::PreviousImage
    };
    Preflight {
        blockers,
        warnings,
        rollback,
    }
}

/// When the registry holds a single platform's manifest (not the index),
/// the platform that digest belongs to; only that platform can be pulled.
fn single_platform_present<'m>(
    img: &'m ComponentImage,
    presence: &ImagePresence,
) -> Option<&'m str> {
    match presence {
        ImagePresence::Present { digest } if *digest != img.index_digest => img
            .platform_digests
            .iter()
            .find(|(_, d)| *d == digest)
            .map(|(p, _)| p.as_str()),
        _ => None,
    }
}

/// Build metadata carries no precedence (`1.2.0+a` → `1.2.0+b` is not a
/// downgrade), but the semver crate orders on it; drop it before comparing.
fn parse_ignoring_build(v: &str) -> Result<semver::Version, semver::Error> {
    let mut parsed = semver::Version::parse(v)?;
    parsed.build = semver::BuildMetadata::EMPTY;
    Ok(parsed)
}

/// A requirement or version that cannot be parsed does not satisfy it.
fn upgrade_path_ok(req: &str, running: &str) -> bool {
    match (
        semver::VersionReq::parse(req),
        semver::Version::parse(running),
    ) {
        (Ok(r), Ok(v)) => r.matches(&v) || matches_ignoring_pre(&r, &v),
        _ => false,
    }
}

/// `>=1.2.0-dev` must admit `1.2.50-dev`; semver only matches a prerelease
/// against a comparator of the same major.minor.patch, so compare the
/// release parts instead.
///
/// This over-admits within one major.minor.patch (`>=1.2.0-rc.2` admits
/// `1.2.0-rc.1`). Acceptable: `upgrade_from` is a floor, and the stricter
/// checks (downgrade, schema head) still run per component.
fn matches_ignoring_pre(r: &semver::VersionReq, v: &semver::Version) -> bool {
    let mut stripped = v.clone();
    stripped.pre = semver::Prerelease::EMPTY;
    let comparators = r
        .comparators
        .iter()
        .cloned()
        .map(|mut c| {
            c.pre = semver::Prerelease::EMPTY;
            c
        })
        .collect();
    semver::VersionReq { comparators }.matches(&stripped)
}

#[cfg(test)]
#[path = "control_plane_preflight_tests.rs"]
mod tests;
