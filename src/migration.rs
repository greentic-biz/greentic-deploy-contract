//! Data-migration declarations on a release (design doc §8, "Data
//! compatibility"; P5-R4).
//!
//! A release that changes the shape of data it owns declares it here, so a
//! rollout can present the limitation before approval and a rollback can be
//! refused across a committed irreversible migration. The declaration is an
//! OPTIONAL field of [`RegisterReleaseRequest`](crate::release::RegisterReleaseRequest):
//! absent, it is not serialised and does not enter
//! [`release_digest`](crate::release::release_digest), so every release
//! registered before it existed keeps its digest byte for byte.
//!
//! Restoring a database backup is NOT code rollback, and nothing here models
//! it: that is a separate recovery action with its own data-loss
//! implications.

use serde::{Deserialize, Serialize};

use crate::execution::is_clean_identifier;

/// What a running migration locks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockScope {
    /// Online: old and new code keep reading and writing throughout.
    None,
    /// Only the data of the one application being migrated.
    Application,
    /// Every application in the deployment unit.
    Unit,
    /// The whole environment.
    Environment,
}

/// One schema change a release makes. See the module doc.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationDeclaration {
    /// The schema version the migration starts from.
    pub from_schema: String,
    /// The schema version it produces. Must differ from `from_schema`.
    pub to_schema: String,
    /// The data owner the migration affects (an application or resource id).
    pub owner: String,
    /// Whether the migration can be reversed. An irreversible migration
    /// blocks ordinary rollback once committed.
    pub reversible: bool,
    pub lock_scope: LockScope,
    /// A backup must exist before the migration runs.
    pub backup_required: bool,
    /// The PREVIOUS release's code still works against the migrated data —
    /// what makes a rolling upgrade (old and new side by side) and a code
    /// rollback safe.
    pub old_code_compatible: bool,
    /// Where the forward-recovery procedure lives (a URL or document id).
    /// Required when `reversible` is `false`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forward_recovery_ref: Option<String>,
}

/// Why a [`MigrationDeclaration`] refuses to validate.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MigrationError {
    /// An identifier is empty or padded with whitespace; carries the field.
    BadIdentifier(&'static str),
    /// `from_schema == to_schema`.
    NoSchemaChange,
    /// An irreversible migration names no `forward_recovery_ref`.
    MissingForwardRecovery,
}

impl std::fmt::Display for MigrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadIdentifier(n) => write!(f, "`{n}` is empty or padded with whitespace"),
            Self::NoSchemaChange => f.write_str("from_schema equals to_schema"),
            Self::MissingForwardRecovery => {
                f.write_str("an irreversible migration requires a forward_recovery_ref")
            }
        }
    }
}

impl std::error::Error for MigrationError {}

impl MigrationDeclaration {
    /// Refuse a declaration that contradicts itself. Never panics.
    pub fn validate(&self) -> Result<(), MigrationError> {
        for (value, field) in [
            (&self.from_schema, "from_schema"),
            (&self.to_schema, "to_schema"),
            (&self.owner, "owner"),
        ] {
            if !is_clean_identifier(value) {
                return Err(MigrationError::BadIdentifier(field));
            }
        }
        if self.from_schema == self.to_schema {
            return Err(MigrationError::NoSchemaChange);
        }
        match &self.forward_recovery_ref {
            Some(r) if !is_clean_identifier(r) => {
                Err(MigrationError::BadIdentifier("forward_recovery_ref"))
            }
            None if !self.reversible => Err(MigrationError::MissingForwardRecovery),
            _ => Ok(()),
        }
    }
}

/// Why rolling back across a committed migration is not an ordinary code
/// rollback.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RollbackBlockReason {
    /// The migration cannot be reversed; recovery is forward, through the
    /// named procedure.
    Irreversible {
        from_schema: String,
        to_schema: String,
        forward_recovery_ref: Option<String>,
    },
    /// The migration can be reversed, but the previous code cannot run
    /// against the migrated data, so the data must be reversed first — a
    /// code-only rollback would break it.
    OldCodeIncompatible {
        from_schema: String,
        to_schema: String,
    },
}

impl std::fmt::Display for RollbackBlockReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Irreversible {
                from_schema,
                to_schema,
                ..
            } => write!(
                f,
                "migration {from_schema} -> {to_schema} is irreversible; recover forward"
            ),
            Self::OldCodeIncompatible {
                from_schema,
                to_schema,
            } => write!(
                f,
                "the previous code cannot run on schema {to_schema}; reverse the migration to {from_schema} first"
            ),
        }
    }
}

/// Whether ordinary rollback across this COMMITTED migration is blocked, and
/// why. `None` means a code rollback is safe. Irreversibility outranks
/// old-code incompatibility. Pure; whether the migration has committed is
/// the caller's journal to consult.
pub fn rollback_blocked(migration: &MigrationDeclaration) -> Option<RollbackBlockReason> {
    if !migration.reversible {
        return Some(RollbackBlockReason::Irreversible {
            from_schema: migration.from_schema.clone(),
            to_schema: migration.to_schema.clone(),
            forward_recovery_ref: migration.forward_recovery_ref.clone(),
        });
    }
    if !migration.old_code_compatible {
        return Some(RollbackBlockReason::OldCodeIncompatible {
            from_schema: migration.from_schema.clone(),
            to_schema: migration.to_schema.clone(),
        });
    }
    None
}

#[cfg(test)]
#[path = "migration_tests.rs"]
pub(crate) mod tests;
