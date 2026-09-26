//! Release governance: hierarchical approval policy and rollout audience
//! selection (design doc §3, §4, §12).
//!
//! Everything here is pure. The admin decides and stores; the designer and
//! the update service only read — but all three must agree on what "this
//! rollout is authorised" and "these units are selected" mean, so the rules
//! live in the contract rather than in any one consumer.

use std::collections::{BTreeMap, BTreeSet};

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

/// One scope's approval policy. The caller may pass a scope's history:
/// [`evaluate_gates`] keeps only the highest `generation` per
/// `(scope_kind, scope_id)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleasePolicy {
    pub scope_kind: ScopeKind,
    /// `None` for the platform scope, `Some(non-empty id)` otherwise. Not
    /// validated here: the writer must normalise, because scopes are matched
    /// by exact equality and a mismatch is silently a different scope.
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
///
/// Decisions are an append-only log per scope: the LATEST matching one
/// (`decided_at`, then `approval_id`) is the scope's state, so recording
/// `Approved` after a `Hold` or `Rejected` lifts it, and recording `Hold`
/// after `Approved` blocks again. See [`evaluate_gates`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRecord {
    pub approval_id: String,
    pub rollout_id: String,
    pub scope_kind: ScopeKind,
    /// Same normalisation as [`ReleasePolicy::scope_id`].
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
    /// This scope's manual gate: its latest matching decision is `Approved`.
    Satisfied {
        scope_kind: ScopeKind,
        scope_id: Option<String>,
    },
    /// This scope's manual gate has no matching decision yet.
    Pending {
        scope_kind: ScopeKind,
        scope_id: Option<String>,
    },
    /// This scope's latest matching decision is a rejection or hold,
    /// whatever its policy mode.
    Blocked {
        scope_kind: ScopeKind,
        scope_id: Option<String>,
        decision: Decision,
    },
}

/// Evaluate every approval gate for one request (§3).
///
/// **Policies are normalised first.** Only the newest row per
/// `(scope_kind, scope_id)` — the highest `generation` — counts; older rows
/// are history, so passing a scope's full policy history is safe.
///
/// **Each scope's state is its LATEST matching decision.** A decision
/// matches when its release digest, target scope digest and operation set
/// equal the request's (operations compared as a set), and its
/// `policy_generation` equals the scope's current generation. A scope with
/// no policy row has no generation to supersede a decision, so there any
/// generation matches. Among the matching decisions of one scope, the one
/// with the highest `decided_at` wins; on a tie, the higher `approval_id`.
///
/// - `Approved` means the scope agrees. A later `Approved` therefore
///   RELEASES an earlier `Hold` or `Rejected` from the same scope — the same
///   authority reversed its decision — and a later `Hold` blocks again.
/// - `Rejected` or `Hold` yields `Blocked` at any level, whatever the scope's
///   policy mode. There is no bypass.
///
/// A `Manual` scope yields exactly one entry: `Satisfied` (latest is
/// `Approved`), `Blocked` (latest is `Rejected`/`Hold`) or `Pending` (no
/// matching decision). An `Auto` scope, or one with no policy row, yields an
/// entry only when its latest matching decision blocks. Only a decision AT a
/// scope can satisfy that scope's manual gate, which is why a lower `Auto`
/// policy structurally cannot bypass a higher manual gate.
///
/// An empty `operations` request binds only to decisions with an empty
/// operation set; callers should never send one.
///
/// Output holds at most one entry per scope, ordered platform, partnership,
/// tenant, then by `scope_id`. Input order never matters.
pub fn evaluate_gates(
    policies: &[ReleasePolicy],
    approvals: &[ApprovalRecord],
    release_digest: &str,
    target_scope_digest: &str,
    operations: &[String],
) -> Vec<GateStatus> {
    type Scope = (ScopeKind, Option<String>);

    let mut current: BTreeMap<Scope, &ReleasePolicy> = BTreeMap::new();
    for p in policies {
        let key = (p.scope_kind, p.scope_id.clone());
        let newer = current
            .get(&key)
            .is_none_or(|existing| p.generation > existing.generation);
        if newer {
            current.insert(key, p);
        }
    }

    let requested_ops: BTreeSet<&str> = operations.iter().map(String::as_str).collect();
    let mut latest: BTreeMap<Scope, &ApprovalRecord> = BTreeMap::new();
    for a in approvals {
        let key = (a.scope_kind, a.scope_id.clone());
        let binds = a.release_digest == release_digest
            && a.target_scope_digest == target_scope_digest
            && a.operations
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                == requested_ops
            && current
                .get(&key)
                .is_none_or(|p| p.generation == a.policy_generation);
        if !binds {
            continue;
        }
        let newer = latest.get(&key).is_none_or(|prev| {
            (a.decided_at, a.approval_id.as_str()) > (prev.decided_at, prev.approval_id.as_str())
        });
        if newer {
            latest.insert(key, a);
        }
    }

    let scopes: BTreeSet<&Scope> = current.keys().chain(latest.keys()).collect();
    scopes
        .into_iter()
        .filter_map(|scope| {
            let (scope_kind, scope_id) = (scope.0, scope.1.clone());
            let manual = current
                .get(scope)
                .is_some_and(|p| p.mode == PolicyMode::Manual);
            match latest.get(scope).map(|a| a.decision) {
                Some(decision @ (Decision::Rejected | Decision::Hold)) => {
                    Some(GateStatus::Blocked {
                        scope_kind,
                        scope_id,
                        decision,
                    })
                }
                Some(Decision::Approved) if manual => Some(GateStatus::Satisfied {
                    scope_kind,
                    scope_id,
                }),
                None if manual => Some(GateStatus::Pending {
                    scope_kind,
                    scope_id,
                }),
                _ => None,
            }
        })
        .collect()
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

/// Unit keys passed to this, [`audience_digest`] and [`target_scope_digest`]
/// must be non-empty, free of `\n` (the digests join on it without escaping)
/// and deduplicated by the caller; none of this is re-checked here.
///
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

#[cfg(test)]
#[path = "governance_decision_tests.rs"]
mod decision_tests;
