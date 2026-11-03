//! The non-secret configuration of a `vm` environment.
//!
//! Mirrors the keys greentic-admin stores for a `vm` target
//! (`deploy_env/vm_target`), which are the answer names of the deployer's
//! `greentic.deployer.ssh-host` env-pack, so the designer can forward them by
//! name.
//!
//! Deliberately absent: the SSH private key (a sealed credential, resolved only
//! through the admin's `credentials/resolve`) and `identity_file`,
//! `known_hosts_file`, `start_binary` (paths on the machine running the
//! deployer, which the admin refuses to store).
//!
//! Every field is optional and `Option::None` means "the operator left it
//! blank": the deployer applies its own default (SSH port 22, `/opt/greentic`,
//! `greentic-<environment>`, listen port 8080, binding 127.0.0.1). This crate
//! does not restate those defaults, so they cannot drift from the deployer's.
//!
//! No `deny_unknown_fields`: the admin upgrades independently of the designer,
//! and a strict type here would make an older designer reject the whole
//! environment list the day the admin adds a key. Unknown keys are ignored.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A tunnel the deployer opens to reach a `vm` that has no direct route.
///
/// `kind` is a free string (for example a provider name); validating it is the
/// admin's and the deployer's job, so adding a provider needs no release of
/// this contract. `settings` holds NON-SECRET values only (host, server, port,
/// protocol, user name, peer public key, ...). Secret material (private keys,
/// passwords, auth keys) never appears here: it is a sealed credential in the
/// admin. A `BTreeMap` keeps the key order stable on the wire. Not
/// `deny_unknown_fields`, so admin and designer can be upgraded separately.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmTunnel {
    /// Tunnel provider kind. Free-form; validated downstream.
    pub kind: String,
    /// Non-secret provider settings.
    #[serde(default)]
    pub settings: BTreeMap<String, String>,
}

/// Non-secret config of a `vm` environment. See the module docs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmEnvConfig {
    /// Hostname or IPv4 address to connect to (no IPv6 literals).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// SSH port. `None` = 22.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// SSH login user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// The VM's host key as a `known_hosts` line. Public, but required for a
    /// working environment: there is no trust-on-first-use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_key: Option<String>,
    /// Optional `SHA256:…` fingerprint the operator verified out of band.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_key_fingerprint: Option<String>,
    /// Absolute install directory on the VM.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_dir: Option<String>,
    /// systemd service name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,
    /// Port the runtime serves on. `None` = 8080.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
    /// `true` binds 0.0.0.0 over plain HTTP; `None`/`false` binds 127.0.0.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expose: Option<bool>,
    /// Use passwordless sudo for systemd. `None` = on unless the login user is root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub use_sudo: Option<bool>,
    /// Account the service runs as. `None` = the login user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_user: Option<String>,
    /// Optional tunnel used to reach the VM. `None` = connect directly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel: Option<VmTunnel>,
}
