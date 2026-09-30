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

pub struct PreflightInput<'a> {
    pub manifest: &'a ControlPlaneManifest,
    pub observed: &'a [ObservedComponent],
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
        match i.presence.get(&c).unwrap_or(&ImagePresence::Unknown) {
            ImagePresence::Present { .. } => {}
            ImagePresence::Absent => blockers.push(Blocker::ImageAbsent { component: c }),
            ImagePresence::Unknown => warnings.push(Warning::ImagePresenceUnknown { component: c }),
        }
        for p in i.node_platforms {
            if !img.platform_digests.contains_key(p) {
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
            semver::Version::parse(&o.app_version),
            semver::Version::parse(&img.app_version),
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
