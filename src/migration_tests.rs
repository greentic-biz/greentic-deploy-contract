use super::*;

pub(crate) fn declaration() -> MigrationDeclaration {
    MigrationDeclaration {
        from_schema: "v2".into(),
        to_schema: "v3".into(),
        owner: "app:guest-assistant".into(),
        reversible: true,
        lock_scope: LockScope::Application,
        backup_required: true,
        old_code_compatible: true,
        forward_recovery_ref: None,
    }
}

#[test]
fn a_reversible_compatible_migration_validates_and_does_not_block() {
    let m = declaration();
    assert_eq!(m.validate(), Ok(()));
    assert_eq!(rollback_blocked(std::slice::from_ref(&m)), None);
}

#[test]
fn irreversible_requires_forward_recovery() {
    let mut m = declaration();
    m.reversible = false;
    assert_eq!(m.validate(), Err(MigrationError::MissingForwardRecovery));
    m.forward_recovery_ref = Some("runbook:guest-v3".into());
    assert_eq!(m.validate(), Ok(()));
    assert!(matches!(
        rollback_blocked(std::slice::from_ref(&m)),
        Some(RollbackBlockReason::Irreversible { forward_recovery_ref: Some(r), .. }) if r == "runbook:guest-v3"
    ));
}

#[test]
fn irreversibility_outranks_old_code_incompatibility() {
    let mut m = declaration();
    m.old_code_compatible = false;
    assert!(matches!(
        rollback_blocked(std::slice::from_ref(&m)),
        Some(RollbackBlockReason::OldCodeIncompatible { .. })
    ));
    m.reversible = false;
    assert!(matches!(
        rollback_blocked(std::slice::from_ref(&m)),
        Some(RollbackBlockReason::Irreversible { .. })
    ));
}

#[test]
fn identifier_and_schema_rules() {
    let mut m = declaration();
    m.to_schema = "v2".into();
    assert_eq!(m.validate(), Err(MigrationError::NoSchemaChange));
    let mut m = declaration();
    m.owner = " ".into();
    assert_eq!(m.validate(), Err(MigrationError::BadIdentifier("owner")));
    let mut m = declaration();
    m.forward_recovery_ref = Some("".into());
    assert_eq!(
        m.validate(),
        Err(MigrationError::BadIdentifier("forward_recovery_ref"))
    );
}

#[test]
fn wire_shape_is_snake_case_and_strict() {
    let v = serde_json::to_value(declaration()).unwrap();
    assert_eq!(v["lock_scope"], "application");
    assert!(v.get("forward_recovery_ref").is_none());
    let mut bad = v.clone();
    bad["extra"] = serde_json::json!(1);
    assert!(serde_json::from_value::<MigrationDeclaration>(bad).is_err());
}

#[test]
fn every_declaration_is_considered() {
    let ok = declaration();
    let mut incompatible = declaration();
    incompatible.owner = "app:b".into();
    incompatible.old_code_compatible = false;
    let mut irreversible = declaration();
    irreversible.owner = "app:c".into();
    irreversible.reversible = false;
    irreversible.forward_recovery_ref = Some("runbook:c".into());
    let all = [ok.clone(), incompatible.clone(), irreversible];
    assert!(matches!(
        rollback_blocked(&all),
        Some(RollbackBlockReason::Irreversible { .. })
    ));
    assert!(matches!(
        rollback_blocked(&all[..2]),
        Some(RollbackBlockReason::OldCodeIncompatible { .. })
    ));
    assert_eq!(rollback_blocked(&all[..1]), None);
    assert_eq!(rollback_blocked(&[]), None);
    assert_eq!(coexistence_blocked(&all), Some(&incompatible));
    assert_eq!(coexistence_blocked(&all[..1]), None);
}

#[test]
fn online_lock_scope_keeps_its_wire_name() {
    assert_eq!(serde_json::to_value(LockScope::Online).unwrap(), "none");
    assert_eq!(
        serde_json::from_value::<LockScope>(serde_json::json!("none")).unwrap(),
        LockScope::Online
    );
}
