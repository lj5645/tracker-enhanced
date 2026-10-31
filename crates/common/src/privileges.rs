use std::path::PathBuf;
use std::sync::Arc;
#[cfg(unix)]
use std::sync::Barrier;

use serde::{Deserialize, Serialize};

use aquatic_toml_config::TomlConfig;

/// Privilege dropping is only implemented on Unix, but the fields are always
/// present: a merged config file is meant to be shared between a Linux host
/// that can drop privileges and a Windows host that cannot. Leaving the fields
/// out on Windows turned any `[privileges]` table into an "unknown field" error,
/// which defeated the point of a shared file. The flag is checked at runtime
/// instead, so asking for something the platform cannot do still fails loudly.
#[derive(Clone, Debug, PartialEq, TomlConfig, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PrivilegeConfig {
    /// Chroot and switch group and user after binding to sockets
    pub drop_privileges: bool,
    /// Chroot to this path
    pub chroot_path: PathBuf,
    /// Group to switch to after chrooting
    pub group: String,
    /// User to switch to after chrooting
    pub user: String,
}

impl Default for PrivilegeConfig {
    fn default() -> Self {
        Self {
            drop_privileges: false,
            chroot_path: ".".into(),
            user: "nobody".to_string(),
            group: "nogroup".to_string(),
        }
    }
}

#[derive(Clone)]
pub struct PrivilegeDropper {
    #[cfg(unix)]
    barrier: Arc<Barrier>,
    /// Kept on every platform so the unsupported-option check below can read it.
    #[allow(dead_code)]
    config: Arc<PrivilegeConfig>,
}

impl PrivilegeDropper {
    #[cfg(unix)]
    pub fn new(config: PrivilegeConfig, num_sockets: usize) -> Self {
        Self {
            barrier: Arc::new(Barrier::new(num_sockets)),
            config: Arc::new(config),
        }
    }

    #[cfg(not(unix))]
    pub fn new(config: PrivilegeConfig, _num_sockets: usize) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    #[cfg(unix)]
    pub fn after_socket_creation(self) -> anyhow::Result<()> {
        use anyhow::Context;
        use privdrop::PrivDrop;

        if self.config.drop_privileges && self.barrier.wait().is_leader() {
            PrivDrop::default()
                .chroot(self.config.chroot_path.clone())
                .group(self.config.group.clone())
                .user(self.config.user.clone())
                .apply()
                .with_context(|| "couldn't drop privileges after socket creation")?;
        }

        Ok(())
    }

    /// Privilege dropping is not available here. Accepting the setting
    /// silently would leave the operator believing the server runs with
    /// reduced privileges, so refuse to start instead.
    #[cfg(not(unix))]
    pub fn after_socket_creation(self) -> anyhow::Result<()> {
        if self.config.drop_privileges {
            return Err(anyhow::anyhow!(
                "privileges are not supported on this platform: set \
                 [privileges] drop_privileges = false"
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::PrivilegeConfig;

    ::aquatic_toml_config::gen_serialize_deserialize_test!(PrivilegeConfig);

    #[test]
    fn test_privileges_section_is_accepted_on_every_platform() {
        // The full section, as a shared config file would spell it.
        let text = "\
drop_privileges = false
chroot_path = \".\"
group = \"nogroup\"
user = \"nobody\"
";

        let parsed: PrivilegeConfig = ::aquatic_toml_config::toml::de::from_str(text).unwrap();

        assert_eq!(parsed, PrivilegeConfig::default());
    }

    #[cfg(not(unix))]
    #[test]
    fn test_enabling_privileges_fails_on_this_platform() {
        use super::PrivilegeDropper;

        let config = PrivilegeConfig {
            drop_privileges: true,
            ..Default::default()
        };

        let result = PrivilegeDropper::new(config, 1).after_socket_creation();

        assert!(result.is_err());
    }
}
