use super::KubeVirtCloudConfig;
use crate::{network, providers::MetadataProvider};
use anyhow::{bail, Context, Result};
use openssh_keys::PublicKey;
use slog_scope::error;
use std::process::Command;
use std::{collections::HashMap, path::Path};
use tempfile::TempDir;

const CONFIG_DRIVE_LABEL: &str = "config-2";
const TARGET_FS: &str = "iso9660";

#[derive(Debug)]
pub struct KubeVirtConfigDrive {
    mount_dir: TempDir,
    config: KubeVirtCloudConfig,
}

impl KubeVirtConfigDrive {
    fn find_config_device() -> Result<String> {
        let output = Command::new("blkid")
            .args(["--cache-file", "/dev/null", "-L", CONFIG_DRIVE_LABEL])
            .output()
            .context("failed to execute blkid command")?;

        if output.status.success() {
            let device = String::from_utf8_lossy(&output.stdout).trim().to_string();
            slog_scope::info!("Found config device: {}", device);
            return Ok(device);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        slog_scope::warn!(
            "Failed to find config device - exit code: {}, stdout: {}, stderr: {}",
            output.status.code().unwrap_or(-1),
            stdout.trim(),
            stderr.trim()
        );
        bail!("could not find config device")
    }

    pub fn try_new() -> Result<Self> {
        let mount_dir = tempfile::Builder::new()
            .prefix("afterburn-")
            .tempdir()
            .context("failed to create temporary directory")?;

        let device_path = Self::find_config_device()?;

        crate::util::mount_ro(Path::new(&device_path), mount_dir.path(), TARGET_FS, 3)?;

        let config = KubeVirtCloudConfig::try_new(mount_dir.path())
            .context("failed to read KubeVirt cloud config")?;

        Ok(Self { config, mount_dir })
    }
}

impl MetadataProvider for KubeVirtConfigDrive {
    fn attributes(&self) -> Result<HashMap<String, String>> {
        self.config.attributes()
    }

    fn hostname(&self) -> Result<Option<String>> {
        self.config.hostname()
    }

    fn ssh_keys(&self) -> Result<Vec<PublicKey>> {
        self.config.ssh_keys()
    }

    fn networks(&self) -> Result<Vec<network::Interface>> {
        self.config.networks()
    }

    fn rd_network_kargs(&self) -> Result<Option<String>> {
        self.config.rd_network_kargs()
    }

    fn virtual_network_devices(&self) -> Result<Vec<network::VirtualNetDev>> {
        self.config.virtual_network_devices()
    }

    fn boot_checkin(&self) -> Result<()> {
        self.config.boot_checkin()
    }
}

impl Drop for KubeVirtConfigDrive {
    fn drop(&mut self) {
        if let Err(e) = crate::util::unmount(self.mount_dir.path(), 3) {
            error!("failed to cleanup KubeVirt config-drive: {:?}", e);
        };
    }
}
