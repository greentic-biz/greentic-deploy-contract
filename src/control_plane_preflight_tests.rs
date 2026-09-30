use std::collections::BTreeMap;

use super::*;
use crate::control_plane::{Component, ControlPlaneManifest};

fn m() -> ControlPlaneManifest {
    crate::control_plane::tests_support::sample()
}

fn obs(c: Component, v: &str, head: Option<i64>) -> ObservedComponent {
    ObservedComponent {
        component: c,
        app_version: v.into(),
        db_schema_head: head,
    }
}

fn present_all(m: &ControlPlaneManifest) -> BTreeMap<Component, ImagePresence> {
    m.components
        .iter()
        .map(|c| {
            (
                c.component,
                ImagePresence::Present {
                    digest: c.index_digest.clone(),
                },
            )
        })
        .collect()
}

fn run(
    m: &ControlPlaneManifest,
    o: &[ObservedComponent],
    p: &BTreeMap<Component, ImagePresence>,
) -> Preflight {
    preflight(&PreflightInput {
        manifest: m,
        observed: o,
        presence: p,
        node_platforms: &["linux/amd64".to_string()],
    })
}

#[test]
fn same_schema_upgrade_is_admissible_with_previous_image_rollback() {
    let m = m();
    let o = [
        obs(Component::Admin, "1.2.50-dev", Some(20260929060000)),
        obs(Component::Designer, "1.2.500-dev", Some(20260930090000)),
    ];
    let p = run(&m, &o, &present_all(&m));
    assert!(p.admissible(), "{p:?}");
    assert_eq!(p.rollback, Rollback::PreviousImage);
}

#[test]
fn pending_migrations_warn_and_require_db_restore_for_rollback() {
    let m = m();
    let o = [
        obs(Component::Admin, "1.2.50-dev", Some(20260901000000)),
        obs(Component::Designer, "1.2.500-dev", Some(20260930090000)),
    ];
    let p = run(&m, &o, &present_all(&m));
    assert!(p.admissible());
    assert!(p.warnings.contains(&Warning::MigrationsPending {
        component: Component::Admin,
        database: 20260901000000,
        target: 20260929060000,
    }));
    assert_eq!(
        p.rollback,
        Rollback::DatabaseRestoreRequired {
            components: vec![Component::Admin]
        }
    );
}

#[test]
fn schema_ahead_blocks() {
    let m = m();
    let o = [
        obs(Component::Admin, "1.2.50-dev", Some(20261231000000)),
        obs(Component::Designer, "1.2.500-dev", Some(20260930090000)),
    ];
    let p = run(&m, &o, &present_all(&m));
    assert!(p.blockers.contains(&Blocker::SchemaAhead {
        component: Component::Admin,
        database: 20261231000000,
        target: 20260929060000,
    }));
}

#[test]
fn downgrade_blocks_and_equal_version_warns() {
    let m = m();
    let o = [
        obs(Component::Admin, "1.2.99-dev", Some(20260929060000)),
        obs(Component::Designer, "1.2.541-dev", Some(20260930090000)),
    ];
    let p = run(&m, &o, &present_all(&m));
    assert!(p.blockers.contains(&Blocker::Downgrade {
        component: Component::Admin,
        running: "1.2.99-dev".into(),
        target: "1.2.57-dev".into(),
    }));
    assert!(p.warnings.contains(&Warning::AlreadyRunning {
        component: Component::Designer
    }));
}

#[test]
fn absent_image_blocks_and_unknown_presence_warns() {
    let m = m();
    let o = [
        obs(Component::Admin, "1.2.50-dev", Some(20260929060000)),
        obs(Component::Designer, "1.2.500-dev", Some(20260930090000)),
    ];
    let mut pr = present_all(&m);
    pr.insert(Component::Admin, ImagePresence::Absent);
    pr.insert(Component::Designer, ImagePresence::Unknown);
    let p = run(&m, &o, &pr);
    assert!(p.blockers.contains(&Blocker::ImageAbsent {
        component: Component::Admin
    }));
    assert!(p.warnings.contains(&Warning::ImagePresenceUnknown {
        component: Component::Designer
    }));
}

#[test]
fn a_missing_node_platform_blocks() {
    let m = m();
    let o = [
        obs(Component::Admin, "1.2.50-dev", Some(20260929060000)),
        obs(Component::Designer, "1.2.500-dev", Some(20260930090000)),
    ];
    let p = preflight(&PreflightInput {
        manifest: &m,
        observed: &o,
        presence: &present_all(&m),
        node_platforms: &["linux/arm64".to_string()],
    });
    assert!(p.blockers.contains(&Blocker::PlatformUnavailable {
        component: Component::Designer,
        platform: "linux/arm64".into(),
    }));
}

#[test]
fn upgrade_path_unsupported_blocks() {
    let mut m = m();
    m.upgrade_from = Some(">=1.2.55-dev".into());
    let o = [
        obs(Component::Admin, "1.2.50-dev", Some(20260929060000)),
        obs(Component::Designer, "1.2.500-dev", Some(20260930090000)),
    ];
    let p = run(&m, &o, &present_all(&m));
    assert!(p.blockers.contains(&Blocker::UpgradePathUnsupported {
        running: "1.2.50-dev".into(),
        requires: ">=1.2.55-dev".into(),
    }));
}

#[test]
fn unobserved_component_warns_and_rollback_unknown() {
    let m = m();
    let o = [obs(Component::Admin, "1.2.50-dev", Some(20260929060000))];
    let p = run(&m, &o, &present_all(&m));
    assert!(p.admissible());
    assert!(p.warnings.contains(&Warning::ComponentUnobserved {
        component: Component::Designer
    }));
    assert_eq!(p.rollback, Rollback::Unknown);
}

#[test]
fn a_platform_digest_counts_as_present() {
    let m = m();
    let admin = &m.components[0];
    let child = admin.platform_digests["linux/amd64"].clone();
    assert_eq!(
        presence_from_digests(admin, std::slice::from_ref(&child)),
        ImagePresence::Present { digest: child }
    );
    assert_eq!(presence_from_digests(admin, &[]), ImagePresence::Absent);
}

#[test]
fn pending_plus_unobserved_reports_restore_the_stricter_answer() {
    let m = m();
    let o = [obs(Component::Admin, "1.2.50-dev", Some(20260901000000))];
    let p = run(&m, &o, &present_all(&m));
    assert!(p.warnings.contains(&Warning::ComponentUnobserved {
        component: Component::Designer
    }));
    assert_eq!(
        p.rollback,
        Rollback::DatabaseRestoreRequired {
            components: vec![Component::Admin]
        }
    );
}
