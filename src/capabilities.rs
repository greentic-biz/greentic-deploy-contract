//! Adapter capabilities (unified update lifecycle, phase 5, P5-R3).
//!
//! Every deployment adapter (Cloud Run, k8s, local, …) reports what it can
//! actually do, and a plan that needs a capability the adapter lacks is
//! refused with the capability's NAME. Feature exposure follows declared
//! capability, never the presence of a command name.
//!
//! One type, shared by the deployer's report and the admin's gate, so the two
//! cannot disagree about what "supports traffic split" means.
//!
//! Every flag defaults to `false` and unknown fields are ignored: a report
//! from an older adapter that never mentions a capability reads as "cannot",
//! and a newer adapter's extra capability is simply unused here. Both
//! directions fail safe.

use serde::{Deserialize, Serialize};

use crate::execution_v2::ExecOperationV2;

/// Wait for in-flight work before retiring a revision.
pub const DRAIN: &str = "drain";
/// Serve two revisions at once with weighted traffic.
pub const TRAFFIC_SPLIT: &str = "traffic_split";
/// Create and manage the ingress / public address itself.
pub const INGRESS_MANAGED: &str = "ingress_managed";
/// Pull bundles from a registry that requires credentials.
pub const PRIVATE_REGISTRY_AUTH: &str = "private_registry_auth";
/// Run more than one instance of a unit safely (shared state, no
/// per-process singletons).
pub const MULTI_INSTANCE_SAFE: &str = "multi_instance_safe";
/// Remove (retire) a unit explicitly.
pub const REMOVE: &str = "remove";
/// Run a revision on a runtime image pinned per REVISION rather than per
/// environment (unified update L2). Needed to change one unit's runtime
/// without re-staging every unit of its environment.
pub const RUNTIME_PIN: &str = "runtime_pin";

/// Every capability name, in declaration order.
pub const ALL: [&str; 7] = [
    DRAIN,
    TRAFFIC_SPLIT,
    INGRESS_MANAGED,
    PRIVATE_REGISTRY_AUTH,
    MULTI_INSTANCE_SAFE,
    REMOVE,
    RUNTIME_PIN,
];

/// What one adapter can do. See the module doc for the defaults.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AdapterCapabilities {
    pub drain: bool,
    pub traffic_split: bool,
    pub ingress_managed: bool,
    pub private_registry_auth: bool,
    pub multi_instance_safe: bool,
    pub remove: bool,
    pub runtime_pin: bool,
}

impl AdapterCapabilities {
    /// Whether the adapter declares `name`. An unknown name is `false`.
    pub fn has(&self, name: &str) -> bool {
        match name {
            DRAIN => self.drain,
            TRAFFIC_SPLIT => self.traffic_split,
            INGRESS_MANAGED => self.ingress_managed,
            PRIVATE_REGISTRY_AUTH => self.private_registry_auth,
            MULTI_INSTANCE_SAFE => self.multi_instance_safe,
            REMOVE => self.remove,
            RUNTIME_PIN => self.runtime_pin,
            _ => false,
        }
    }
}

/// The facts about a plan that decide which capabilities it needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanDemand<'a> {
    pub operation: ExecOperationV2,
    /// The traffic policy's steps. Anything other than a single `[100]`
    /// step serves two revisions at once.
    pub traffic_steps: &'a [u8],
    /// The plan expects the adapter to publish an address for the unit.
    pub exposes_ingress: bool,
    /// The unit's bundle lives in a registry that requires credentials.
    pub private_registry: bool,
    /// The most instances the unit may scale to.
    pub max_instances: u32,
}

/// The capability names a plan needs, in [`ALL`] order, without duplicates.
pub fn required_capabilities_for(demand: &PlanDemand<'_>) -> Vec<&'static str> {
    let (removes, drains) = match demand.operation {
        ExecOperationV2::Remove { drain_seconds, .. } => (true, drain_seconds > 0),
        ExecOperationV2::Update | ExecOperationV2::Rollback => (false, false),
    };
    let splits = demand.traffic_steps.iter().any(|s| *s < 100);
    let needs = [
        (DRAIN, drains),
        (TRAFFIC_SPLIT, splits && !removes),
        (INGRESS_MANAGED, demand.exposes_ingress),
        (PRIVATE_REGISTRY_AUTH, demand.private_registry),
        (MULTI_INSTANCE_SAFE, demand.max_instances > 1),
        (REMOVE, removes),
    ];
    needs
        .into_iter()
        .filter_map(|(name, needed)| needed.then_some(name))
        .collect()
}

/// The capability names a runtime (platform) change needs, in [`ALL`] order:
/// `traffic_split` when a step is below 100, and always `runtime_pin`.
pub fn required_for_runtime_change(traffic_steps: &[u8]) -> Vec<&'static str> {
    let splits = traffic_steps.iter().any(|s| *s < 100);
    [(TRAFFIC_SPLIT, splits), (RUNTIME_PIN, true)]
        .into_iter()
        .filter_map(|(name, needed)| needed.then_some(name))
        .collect()
}

/// The names in `required` the adapter does not declare, in `required`
/// order. Empty means the plan may proceed.
pub fn missing(caps: &AdapterCapabilities, required: &[&'static str]) -> Vec<&'static str> {
    required
        .iter()
        .copied()
        .filter(|name| !caps.has(name))
        .collect()
}

#[cfg(test)]
#[path = "capabilities_tests.rs"]
mod tests;
