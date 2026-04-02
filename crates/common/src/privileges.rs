#[cfg(unix)]
use std::sync::{Arc, Barrier};

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use aquatic_toml_config::TomlConfig;

#[derive(Clone, Debug, PartialEq, TomlConfig, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PrivilegeConfig {
    /// Chroot and switch group and user after binding to sockets
    #[cfg(unix)]
    pub drop_privileges: bool,
    /// Chroot to this path
    #[cfg(unix)]
    pub chroot_path: PathBuf,
    /// Group to switch to after chrooting
    #[cfg(unix)]
    pub group: String,
    /// User to switch to after chrooting
    #[cfg(unix)]
    pub user: String,
}

impl Default for PrivilegeConfig {
    fn default() -> Self {
        Self {
            #[cfg(unix)]
            drop_privileges: false,
            #[cfg(unix)]
            chroot_path: ".".into(),
            #[cfg(unix)]
            user: "nobody".to_string(),
            #[cfg(unix)]
            group: "nogroup".to_string(),
        }
    }
}

#[derive(Clone)]
pub struct PrivilegeDropper {
    #[cfg(unix)]
    barrier: Arc<Barrier>,
    #[cfg(unix)]
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
    pub fn new(_config: PrivilegeConfig, _num_sockets: usize) -> Self {
        Self {}
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

    #[cfg(not(unix))]
    pub fn after_socket_creation(self) -> anyhow::Result<()> {
        Ok(())
    }
}
