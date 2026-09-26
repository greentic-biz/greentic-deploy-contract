//! Release governance: hierarchical approval policy and rollout audience
//! selection (design doc §3, §4, §12).
//!
//! Everything here is pure. The admin decides and stores; the designer and
//! the update service only read — but all three must agree on what "this
//! rollout is authorised" and "these units are selected" mean, so the rules
//! live in the contract rather than in any one consumer.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::release::hex_lower;

/// A level of the approval hierarchy. The derived order IS the evaluation
/// order: platform, then partnership, then tenant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeKind {
    Platform,
    Partnership,
    Tenant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMode {
    /// The policy supplies the approval itself. It never grants permission to
    /// deploy on its own, and never satisfies another scope's manual gate.
    Auto,
    /// A person at this scope must approve.
    Manual,
}

/// One scope's approval policy. The caller supplies at most one row per
/// `(scope_kind, scope_id)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleasePolicy {
    pub scope_kind: ScopeKind,
    /// `None` for the platform scope.
    #[serde(default)]
    pub scope_id: Option<String>,
    pub mode: PolicyMode,
    /// Bumped on every policy change; approvals recorded at an older
    /// generation stop counting.
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Approved,
    Rejected,
    /// An explicit hold. Blocks exactly like a rejection.
    Hold,
}

/// A recorded decision. It binds to everything that makes it meaningful: a
/// change to any of these fields is a different request that needs its own
/// decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRecord {
    pub approval_id: String,
    pub rollout_id: String,
    pub scope_kind: ScopeKind,
    #[serde(default)]
    pub scope_id: Option<String>,
    /// `sha256:<64 lowercase hex>`.
    pub release_digest: String,
    /// See [`target_scope_digest`].
    pub target_scope_digest: String,
    /// Compared as a set: order and duplicates do not matter.
    pub operations: Vec<String>,
    pub policy_generation: u64,
    pub decision: Decision,
    pub actor: String,
    pub decided_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum GateStatus {
    /// This scope's manual gate has a current approval.
    Satisfied {
        scope_kind: ScopeKind,
        scope_id: Option<String>,
    },
    /// This scope's manual gate has no current approval.
    Pending {
        scope_kind: ScopeKind,
        scope_id: Option<String>,
    },
    /// A current rejection or hold at this scope, whatever its policy mode.
    Blocked {
        scope_kind: ScopeKind,
        scope_id: Option<String>,
        decision: Decision,
    },
}

impl GateStatus {
    fn scope_kind(&self) -> ScopeKind {
        match self {
            GateStatus::Satisfied { scope_kind, .. }
            | GateStatus::Pending { scope_kind, .. }
            | GateStatus::Blocked { scope_kind, .. } => *scope_kind,
        }
    }
}

/// Evaluate every approval gate for one request (§3).
///
/// Each `Manual` policy yields exactly one gate, `Satisfied` or `Pending`,
/// and only an approval AT THAT SCOPE can satisfy it — which is why a lower
/// `Auto` policy structurally cannot bypass a higher manual gate. An approval
/// counts only when its release digest, target scope digest, operation set
/// and policy generation all match the request and the scope's current
/// policy.
///
/// Independently, a `Rejected` or `Hold` decision at ANY scope that matches
/// the request yields `Blocked`. Its generation must equal that scope's
/// current policy generation; a scope with no policy row has no generation to
/// supersede it, so any generation counts there.
///
/// Output is ordered platform, partnership, tenant; within a scope the gate
/// precedes its blocks. Approval order in the input never matters.
pub fn evaluate_gates(
    policies: &[ReleasePolicy],
    approvals: &[ApprovalRecord],
    release_digest: &str,
    target_scope_digest: &str,
    operations: &[String],
) -> Vec<GateStatus> {
    let requested_ops: BTreeSet<&str> = operations.iter().map(String::as_str).collect();
    let binds = |a: &ApprovalRecord| {
        a.release_digest == release_digest
            && a.target_scope_digest == target_scope_digest
            && a.operations
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                == requested_ops
    };
    let current_generation = |kind: ScopeKind, id: &Option<String>| {
        policies
            .iter()
            .filter(|p| p.scope_kind == kind && &p.scope_id == id)
            .map(|p| p.generation)
            .max()
    };

    let mut gates = Vec::new();
    for p in policies.iter().filter(|p| p.mode == PolicyMode::Manual) {
        let approved = approvals.iter().any(|a| {
            a.decision == Decision::Approved
                && a.scope_kind == p.scope_kind
                && a.scope_id == p.scope_id
                && a.policy_generation == p.generation
                && binds(a)
        });
        let scope_kind = p.scope_kind;
        let scope_id = p.scope_id.clone();
        gates.push(if approved {
            GateStatus::Satisfied {
                scope_kind,
                scope_id,
            }
        } else {
            GateStatus::Pending {
                scope_kind,
                scope_id,
            }
        });
    }

    let mut blocks: Vec<GateStatus> = Vec::new();
    for a in approvals {
        if a.decision == Decision::Approved || !binds(a) {
            continue;
        }
        let current = current_generation(a.scope_kind, &a.scope_id);
        if current.is_some_and(|g| g != a.policy_generation) {
            continue;
        }
        let block = GateStatus::Blocked {
            scope_kind: a.scope_kind,
            scope_id: a.scope_id.clone(),
            decision: a.decision,
        };
        if !blocks.contains(&block) {
            blocks.push(block);
        }
    }
    // Deterministic regardless of the order approvals arrived in.
    blocks.sort_by(|x, y| block_key(x).cmp(&block_key(y)));
    gates.extend(blocks);

    // Stable: a scope's gate stays ahead of its blocks.
    gates.sort_by_key(GateStatus::scope_kind);
    gates
}

fn block_key(g: &GateStatus) -> (ScopeKind, Option<&str>, u8) {
    match g {
        GateStatus::Blocked {
            scope_kind,
            scope_id,
            decision,
        } => (
            *scope_kind,
            scope_id.as_deref(),
            match decision {
                Decision::Approved => 0,
                Decision::Rejected => 1,
                Decision::Hold => 2,
            },
        ),
        other => (other.scope_kind(), None, 0),
    }
}

/// Authorised only when no manual gate is pending and nothing blocks.
/// Authorisation is necessary, not sufficient, to deploy (§3).
pub fn is_authorised(gates: &[GateStatus]) -> bool {
    gates
        .iter()
        .all(|g| matches!(g, GateStatus::Satisfied { .. }))
}

/// Upper bound of a basis-point target: 100 %.
pub const MAX_BPS: u16 = 10_000;

/// How many units a basis-point target selects (§4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Selection {
    pub count: usize,
    /// A nonzero target over a nonempty audience selected nothing. The
    /// caller must say so and offer an explicit one-unit canary; it must
    /// never round up on its own.
    pub rounds_to_zero: bool,
    /// What `count` actually is, in basis points of the audience (floored).
    /// `0` for an empty audience.
    pub effective_bps: u16,
}

/// `K = floor(N × B / 10000)`, never rounded up. `B = 10000` selects all `N`.
/// A target above 10000 is clamped to 10000 rather than refused, so it can
/// never select more units than exist.
pub fn bps_select(n: usize, bps: u16) -> Selection {
    let bps = bps.min(MAX_BPS);
    let n_wide = n as u128;
    // u128 so `n × 10000` cannot overflow for any `usize`.
    let count = (n_wide * u128::from(bps) / u128::from(MAX_BPS)) as usize;
    let effective_bps = if n == 0 {
        0
    } else {
        (count as u128 * u128::from(MAX_BPS) / n_wide) as u16
    };
    Selection {
        count,
        rounds_to_zero: bps > 0 && count == 0 && n > 0,
        effective_bps,
    }
}

/// A unit's position key in a rollout's stable order: lowercase hex
/// `sha256(rollout_id ":" cohort_seed ":" unit_key)`, no prefix. Persisted
/// when the audience is frozen.
pub fn sort_key(rollout_id: &str, cohort_seed: &str, unit_key: &str) -> String {
    let mut h = Sha256::new();
    h.update(rollout_id.as_bytes());
    h.update(b":");
    h.update(cohort_seed.as_bytes());
    h.update(b":");
    h.update(unit_key.as_bytes());
    hex_lower(&h.finalize())
}

/// Sort an audience into its stable order: by `(sort_key, unit_key)`, so the
/// input order never matters. Raising the target extends a prefix of this
/// order; the first element is the explicit canary.
pub fn order_units(rollout_id: &str, cohort_seed: &str, unit_keys: &[String]) -> Vec<String> {
    let mut keyed: Vec<(String, &String)> = unit_keys
        .iter()
        .map(|u| (sort_key(rollout_id, cohort_seed, u), u))
        .collect();
    keyed.sort();
    keyed.into_iter().map(|(_, u)| u.clone()).collect()
}

/// Digest of a frozen audience IN ITS STORED ORDER: `sha256:` + hex sha256 of
/// the keys joined with `\n`. Order-sensitive on purpose — it pins the order,
/// not just the membership.
pub fn audience_digest(ordered_unit_keys: &[String]) -> String {
    digest_joined(ordered_unit_keys.iter().map(String::as_str))
}

/// Digest identifying an approved SET of units: `sha256:` + hex sha256 of the
/// sorted keys joined with `\n`. Order-insensitive, so an approval survives a
/// reordering of the same units but not a change of membership.
pub fn target_scope_digest(unit_keys: &[String]) -> String {
    let mut sorted: Vec<&str> = unit_keys.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    digest_joined(sorted.into_iter())
}

fn digest_joined<'a>(keys: impl Iterator<Item = &'a str>) -> String {
    let mut h = Sha256::new();
    for (i, k) in keys.enumerate() {
        if i > 0 {
            h.update(b"\n");
        }
        h.update(k.as_bytes());
    }
    format!("sha256:{}", hex_lower(&h.finalize()))
}

#[cfg(test)]
#[path = "governance_tests.rs"]
mod tests;
