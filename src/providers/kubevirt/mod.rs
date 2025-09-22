//! Metadata fetcher for KubeVirt instances.
//!
//! This provider supports platforms based on KubeVirt.
//! It provides a config-drive as the only metadata source, whose layout
//! follows the `cloud-init ConfigDrive v2` [datasource][configdrive], with
//! the following details:
//!  - disk filesystem label is `config-2` (lowercase)
//!  - filesystem is `iso9660`
//!  - drive contains a single directory at `/openstack/latest/`
//!  - content is exposed as JSON files called `meta_data.json`.
//!
//! configdrive: https://cloudinit.readthedocs.io/en/latest/topics/datasources/configdrive.html

use anyhow::{bail, Context, Result};
use openssh_keys::PublicKey;
use serde::Deserialize;
use serde_yaml;
use slog_scope::warn;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::{process::Command, path::{Path, PathBuf}};
use tempfile::TempDir;
use ipnetwork::IpNetwork;

use crate::network::{self, DhcpSetting};
use crate::providers::MetadataProvider;

mod networkdata;
use networkdata::{NetworkData, network_interfaces};

// Filesystem label for the Config Drive.
static CONFIG_DRIVE_FS_LABEL: &str = "config-2";

// Filesystem type for the Config Drive.
static CONFIG_DRIVE_FS_TYPE: &str = "iso9660";

///KubeVirt provider.
#[derive(Debug)]
pub struct KubeVirtProvider {
    /// Path to the top directory of the mounted config-drive.
    drive_path: PathBuf,
    /// Temporary directory for own mountpoint.
    temp_dir: TempDir,
}

/// Partial object for `meta_data.json`
#[derive(Debug, Deserialize)]
pub struct MetaDataJSON {
    /// Local hostname
    pub hostname: String,
    /// Instance ID (UUID).
    #[serde(rename = "uuid")]
    pub instance_id: String,
    /// Instance type.
    pub instance_type: Option<String>,
    /// SSH public keys.
    pub public_keys: Option<HashMap<String, String>>,
}


impl KubeVirtProvider {
    fn find_config_device() -> Result<String> {
        // Diagnostic commands to understand the environment
        slog_scope::info!("Starting config device detection diagnostics");

        // Check available vd devices
        if let Ok(output) = Command::new("ls").args(["-la", "/dev/vd*"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            slog_scope::info!("Available vd devices: {}", stdout.trim());
        }

        // Check available sr devices
        if let Ok(output) = Command::new("ls").args(["-la", "/dev/sr*"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            slog_scope::info!("Available sr devices: {}", stdout.trim());
        }

        // Check partition table
        if let Ok(output) = Command::new("cat").arg("/proc/partitions").output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            slog_scope::info!("Partition table: {}", stdout.trim());
        }

        // Check sysfs block devices
        if let Ok(output) = Command::new("ls").args(["-la", "/sys/block/"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            slog_scope::info!("Block devices in sysfs: {}", stdout.trim());
        }

        // Check all block devices without filter
        if let Ok(output) = Command::new("blkid").args(["--cache-file", "/dev/null"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            slog_scope::info!("All blkid devices - stdout: {}, stderr: {}", stdout.trim(), stderr.trim());
        }

        // Try to find config device with label (single attempt)
        slog_scope::info!("Finding config device with label {}", CONFIG_DRIVE_FS_LABEL);

        let output = Command::new("blkid")
            .args(["--cache-file", "/dev/null", "-L", CONFIG_DRIVE_FS_LABEL])
            .output()
            .context("failed to execute blkid command")?;

        if output.status.success() {
            let device = String::from_utf8_lossy(&output.stdout).trim().to_string();
            slog_scope::info!("Found config device: {}", device);
            return Ok(device);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        slog_scope::warn!("Failed to find config device - exit code: {}, stdout: {}, stderr: {}",
                        output.status.code().unwrap_or(-1), stdout.trim(), stderr.trim());

        // Final diagnostic: try to examine specific devices directly
        for device in ["/dev/vdb", "/dev/sr0", "/dev/sr1"] {
            if std::path::Path::new(device).exists() {
                slog_scope::info!("Checking device {} directly", device);

                if let Ok(output) = Command::new("blkid").args(["--cache-file", "/dev/null", device]).output() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    slog_scope::info!("Device {} blkid output: {}", device, stdout.trim());
                }

                if let Ok(output) = Command::new("file").args(["-s", device]).output() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    slog_scope::info!("Device {} file output: {}", device, stdout.trim());
                }
            }
        }

        bail!("could not find config device")
    }

    /// Try to build a new provider client.
    ///
    /// This internally tries to mount (and own) the config-drive.
    pub fn try_new() -> Result<Self> {
        let target = tempfile::Builder::new()
            .prefix("afterburn-")
            .tempdir()
            .context("failed to create temporary directory")?;

        let device_path = Self::find_config_device()?;

        crate::util::mount_ro(
            Path::new(&device_path),
            target.path(),
            CONFIG_DRIVE_FS_TYPE,
            3, // maximum retries
        )?;

        let provider = Self {
            drive_path: target.path().to_owned(),
            temp_dir: target,
        };
        Ok(provider)
    }

    /// Return the path to the metadata directory.
    fn metadata_dir(&self) -> PathBuf {
        let drive = self.drive_path.clone();
        drive.join("openstack").join("latest")
    }

    /// Read and parse metadata file.
    fn read_metadata(&self) -> Result<MetaDataJSON> {
        let filename = self.metadata_dir().join("meta_data.json");
        let file =
            File::open(&filename).with_context(|| format!("failed to open file '{filename:?}'"))?;
        let bufrd = BufReader::new(file);
        Self::parse_metadata(bufrd)
    }

    /// Parse metadata attributes.
    ///
    /// Metadata file contains a JSON object, corresponding to `MetaDataJSON`.
    fn parse_metadata<T: Read>(input: BufReader<T>) -> Result<MetaDataJSON> {
        serde_json::from_reader(input).context("failed to parse JSON metadata")
    }

    /// Read and parse network configuration.
    fn read_network_data(&self) -> Result<NetworkData> {
        let filename = self.metadata_dir().join("network_data.json");
        let file =
            File::open(&filename).with_context(|| format!("failed to open file '{filename:?}'"))?;
        let bufrd = BufReader::new(file);
        Self::parse_network_data(bufrd)
    }

    /// Parse network configuration.
    ///
    /// Network configuration file contains a JSON or YAML object, corresponding to `NetworkData`.
    /// Supports both cloud-init network data version 1 and version 2 formats with automatic
    /// version detection. The parser first determines the format (JSON vs YAML), then detects
    /// the version number to use the appropriate data structures.
    ///
    /// # Supported Formats
    /// - **JSON and YAML**: Both input formats are supported for both versions
    /// - **Version 1**: Legacy flat config array format
    /// - **Version 2**: Modern structured format with ethernets section
    ///
    /// # Version Detection
    /// The version is extracted from the parsed content. If no version is specified,
    /// defaults to version 1 for backward compatibility.
    fn parse_network_data<T: Read>(mut input: BufReader<T>) -> Result<NetworkData> {
        let mut content = String::new();
        input.read_to_string(&mut content)
            .context("failed to read network data content")?;

        let trimmed_content = content.trim();

        // Parse as either JSON or YAML to get a generic Value first for version detection
        // This two-step approach allows us to inspect the version field before committing
        // to a specific data structure for deserialization
        let parsed_value: serde_json::Value = if trimmed_content.starts_with('{') || trimmed_content.starts_with('[') {
            // Try JSON first - most common format
            serde_json::from_str(&content)
                .context("failed to parse JSON network data")?
        } else {
            // Try YAML and convert to JSON Value for uniform processing
            let yaml_value: serde_yaml::Value = serde_yaml::from_str(&content)
                .context("failed to parse YAML network data")?;
            serde_json::to_value(yaml_value)
                .context("failed to convert YAML to JSON for processing")?
        };

        // Extract version to determine parsing strategy
        // Default to version 1 if not specified (backward compatibility)
        let version = parsed_value
            .get("version")
            .and_then(|v| v.as_u64())
            .unwrap_or(1) as u32;

        // Parse according to detected version using appropriate data structures
        match version {
            1 => {
                // Cloud-init network data v1: flat config array with type-based entries
                let v1_data: networkdata::NetworkDataV1 = serde_json::from_value(parsed_value)
                    .context("failed to parse version 1 network data")?;
                Ok(NetworkData::V1(v1_data))
            }
            2 => {
                // Cloud-init network data v2: structured format with ethernets section
                let v2_data: networkdata::NetworkDataV2 = serde_json::from_value(parsed_value)
                    .context("failed to parse version 2 network data")?;
                Ok(NetworkData::V2(v2_data))
            }
            _ => Err(anyhow::anyhow!("unsupported network data version: {}", version)),
        }
    }


    /// Extract supported metadata values and convert to Afterburn attributes.
    ///
    /// The `AFTERBURN_` prefix is added later on, so it is not part of the
    /// key-labels here.
    fn known_attributes(metadata: MetaDataJSON) -> Result<HashMap<String, String>> {
        if metadata.instance_id.is_empty() {
            bail!("empty instance ID");
        }

        if metadata.hostname.is_empty() {
            bail!("empty local hostname");
        }

        let mut attrs = maplit::hashmap! {
            "KUBEVIRT_INSTANCE_ID".to_string() => metadata.instance_id,
            "KUBEVIRT_HOSTNAME".to_string() => metadata.hostname,
        };
        if let Some(instance_type) = metadata.instance_type {
            attrs.insert("KUBEVIRT_INSTANCE_TYPE".to_string(), instance_type);
        }
        Ok(attrs)
    }

    /// The public key is stored as key:value pair in openstack/latest/meta_data.json file
    fn public_keys(metadata: MetaDataJSON) -> Result<Vec<PublicKey>> {
        let public_keys_map = metadata.public_keys.unwrap_or_default();
        let public_keys_vec: Vec<&std::string::String> = public_keys_map.values().collect();
        let mut out = vec![];
        for key in public_keys_vec {
            let key = PublicKey::parse(key)?;
            out.push(key);
        }
        Ok(out)
    }

    fn read_rd_network_kargs(network_data: &NetworkData) -> Result<Option<String>> {
        let mut kargs = Vec::new();

        if let Ok(networks) = network_interfaces(network_data) {
            for iface in networks {
                let iface_name = iface.name.unwrap_or("".to_string());

                // Add IP configuration if static
                for addr in iface.ip_addresses {
                    match addr {
                        IpNetwork::V4(network) => {
                            if let Some(gateway) = iface
                                .routes
                                .iter()
                                .find(|r| r.destination.is_ipv4() && r.destination.prefix() == 0)
                            {
                                kargs.push(format!(
                                    "ip={}::{}:{}::{}:none",
                                    network.ip(),
                                    gateway.gateway,
                                    network.mask(),
                                    iface_name
                                ));
                            } else {
                                kargs.push(format!("ip={}:::{}::{}:none", network.ip(), network.mask(), iface_name));
                            }
                        }
                        IpNetwork::V6(network) => {
                            if let Some(gateway) = iface
                                .routes
                                .iter()
                                .find(|r| r.destination.is_ipv6() && r.destination.prefix() == 0)
                            {
                                kargs.push(format!(
                                    "ip={}::{}:{}::{}:none",
                                    network.ip(),
                                    gateway.gateway,
                                    network.prefix(),
                                    iface_name
                                ));
                            } else {
                                kargs.push(format!("ip={}:::{}::{}:none", network.ip(), network.prefix(), iface_name));
                            }
                        }
                    }
                }

                // Add DHCP configuration
                if let Some(dhcp) = iface.dhcp {
                    match dhcp {
                        DhcpSetting::V4 => kargs.push(format!("ip={}:dhcp", iface_name)),
                        DhcpSetting::V6 => kargs.push(format!("ip={}:dhcp6", iface_name)),
                        DhcpSetting::Both => kargs.push(format!("ip={}:dhcp,dhcp6", iface_name)),
                    }
                }

                // Add nameservers
                if !iface.nameservers.is_empty() {
                    let nameservers = iface
                        .nameservers
                        .iter()
                        .map(|ns| ns.to_string())
                        .collect::<Vec<_>>()
                        .join(",");
                    kargs.push(format!("nameserver={}", nameservers));
                }
            }
        }

        if kargs.is_empty() {
            Ok(None)
        } else {
            Ok(Some(kargs.join(" ")))
        }
    }


}

impl MetadataProvider for KubeVirtProvider {
    fn attributes(&self) -> Result<HashMap<String, String>> {
        let metadata = self.read_metadata()?;
        let mut out = Self::known_attributes(metadata)?;

        if let Some(first_interface) = self.networks()?.first() {
            first_interface.ip_addresses.iter().for_each(|ip| match ip {
                IpNetwork::V4(network) => {
                    out.insert("KUBEVIRT_IPV4".to_owned(), network.ip().to_string());
                }
                IpNetwork::V6(network) => {
                    out.insert("KUBEVIRT_IPV6".to_owned(), network.ip().to_string());
                }
            });
        }

        Ok(out)
    }

    fn hostname(&self) -> Result<Option<String>> {
        let metadata = self.read_metadata()?;
        let hostname = if metadata.hostname.is_empty() {
            None
        } else {
            Some(metadata.hostname)
        };
        Ok(hostname)
    }

    fn ssh_keys(&self) -> Result<Vec<PublicKey>> {
        let metadata = self.read_metadata()?;
        Self::public_keys(metadata)
    }

    fn networks(&self) -> Result<Vec<network::Interface>> {
        let data = self.read_network_data()?;
        let interfaces = network_interfaces(&data)?;
        Ok(interfaces)
    }

    fn virtual_network_devices(&self) -> Result<Vec<network::VirtualNetDev>> {
        warn!("virtual network devices metadata requested, but not supported on this platform");
        Ok(vec![])
    }

    fn boot_checkin(&self) -> Result<()> {
        warn!("boot check-in requested, but not supported on this platform");
        Ok(())
    }

    fn rd_network_kargs(&self) -> Result<Option<String>> {
        Self::read_rd_network_kargs(&self.read_network_data()?)
    }

}

impl Drop for KubeVirtProvider {
    fn drop(&mut self) {
        if let Err(e) = crate::util::unmount(
            self.temp_dir.path(),
            3, // maximum retries
        ) {
            slog_scope::error!("failed to unmount kubevirt config-drive: {}", e);
        };
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::IpAddr;
    use std::str::FromStr;
    use ipnetwork::IpNetwork;
    use pnet_base::MacAddr;
    use crate::network::DhcpSetting;

    #[test]
    fn test_kubevirt_basic_attributes() {
        let metadata = r#"
{
  "hostname": "test_instance-kubevirt.foo.cloud",
  "uuid": "41b4fb82-ca29-11eb-b8bc-0242ac130003"
}
"#;

        let bufrd = BufReader::new(Cursor::new(metadata));
        let parsed = KubeVirtProvider::parse_metadata(bufrd).unwrap();
        assert_eq!(parsed.instance_id, "41b4fb82-ca29-11eb-b8bc-0242ac130003");
        assert_eq!(parsed.hostname, "test_instance-kubevirt.foo.cloud");

        let attrs = KubeVirtProvider::known_attributes(parsed).unwrap();
        assert_eq!(attrs.len(), 2);
        assert_eq!(
            attrs.get("KUBEVIRT_INSTANCE_ID"),
            Some(&"41b4fb82-ca29-11eb-b8bc-0242ac130003".to_string())
        );
        assert_eq!(
            attrs.get("KUBEVIRT_HOSTNAME"),
            Some(&"test_instance-kubevirt.foo.cloud".to_string())
        );
    }

    #[test]
    fn test_kubevirt_extended_attributes() {
        let metadata = r#"
{
  "hostname": "test_instance-kubevirt.foo.cloud",
  "uuid": "41b4fb82-ca29-11eb-b8bc-0242ac130003",
  "instance_type": "some_type"
}
"#;

        let bufrd = BufReader::new(Cursor::new(metadata));
        let parsed = KubeVirtProvider::parse_metadata(bufrd).unwrap();
        assert_eq!(parsed.instance_id, "41b4fb82-ca29-11eb-b8bc-0242ac130003");
        assert_eq!(parsed.hostname, "test_instance-kubevirt.foo.cloud");
        assert_eq!(parsed.instance_type.as_deref().unwrap(), "some_type");

        let attrs = KubeVirtProvider::known_attributes(parsed).unwrap();
        assert_eq!(attrs.len(), 3);
        assert_eq!(
            attrs.get("KUBEVIRT_INSTANCE_ID"),
            Some(&"41b4fb82-ca29-11eb-b8bc-0242ac130003".to_string())
        );
        assert_eq!(
            attrs.get("KUBEVIRT_HOSTNAME"),
            Some(&"test_instance-kubevirt.foo.cloud".to_string())
        );
        assert_eq!(
            attrs.get("KUBEVIRT_INSTANCE_TYPE"),
            Some(&"some_type".to_string())
        );
    }

    #[test]
    fn test_kubevirt_parse_metadata_json() {
        let fixture = File::open("./tests/fixtures/kubevirt/meta_data.json").unwrap();
        let bufrd = BufReader::new(fixture);
        let parsed = KubeVirtProvider::parse_metadata(bufrd).unwrap();

        assert!(!parsed.instance_id.is_empty());
        assert!(!parsed.hostname.is_empty());
        assert!(parsed.public_keys.is_some());
    }

    #[test]
    fn test_kubevirt_ssh_keys() {
        let fixture = File::open("./tests/fixtures/kubevirt/meta_data.json").unwrap();

        let bufrd = BufReader::new(fixture);
        let parsed = KubeVirtProvider::parse_metadata(bufrd).unwrap();
        let keys = KubeVirtProvider::public_keys(parsed).unwrap();
        let expect = PublicKey::parse("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDYVEprvtYJXVOBN0XNKVVRNCRX6BlnNbI+USLGais1sUWPwtSg7z9K9vhbYAPUZcq8c/s5S9dg5vTHbsiyPCIDOKyeHba4MUJq8Oh5b2i71/3BISpyxTBH/uZDHdslW2a+SrPDCeuMMoss9NFhBdKtDkdG9zyi0ibmCP6yMdEX8Q== Generated by Nova").unwrap();

        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], expect);
    }

    #[test]
    fn test_kubevirt_network_data() {
        let versions = ["v1", "v2"];
        let formats = ["json", "yaml"];
        for version in &versions {
            for format in &formats {
                let fixture_path= format!("./tests/fixtures/kubevirt/network_data_{}.{}", version, format);
                let fixture = File::open(&fixture_path).unwrap();
                let bufrd = BufReader::new(fixture);
                let parsed = KubeVirtProvider::parse_network_data(bufrd).unwrap();
                let interfaces = network_interfaces(&parsed).unwrap();

                assert_eq!(interfaces.len(),2, "{}", fixture_path);
                let (eth0_idx, eth1_idx) = if interfaces[0].name == Some("eth0".to_string()) {
                    (0, 1)
                } else {
                    (1, 0)
                };
                assert_eq!(interfaces[eth0_idx].name, Some("eth0".to_string()), "{}", fixture_path);
                assert_eq!(interfaces[eth0_idx].mac_address, Some(MacAddr::from_str("06:52:db:01:ff:d9").unwrap()), "{}", fixture_path);
                assert_eq!(interfaces[eth0_idx].ip_addresses.len(), 1, "{}", fixture_path);
                assert_eq!(interfaces[eth0_idx].ip_addresses[0], IpNetwork::from_str("192.168.1.10/24").unwrap(), "{}", fixture_path);
                assert_eq!(interfaces[eth0_idx].routes.len(), 1, "{}", fixture_path);
                assert_eq!(interfaces[eth0_idx].routes[0].gateway, IpAddr::from_str("192.168.1.1").unwrap(), "{}", fixture_path);
                assert_eq!(interfaces[eth0_idx].nameservers.len(), 2, "{}", fixture_path);
                assert_eq!(interfaces[eth0_idx].nameservers[0], IpAddr::from_str("8.8.8.8").unwrap(), "{}", fixture_path);
                assert_eq!(interfaces[eth0_idx].nameservers[1], IpAddr::from_str("8.8.4.4").unwrap(), "{}", fixture_path);
                assert_eq!(interfaces[eth1_idx].name, Some("eth1".to_string()), "{}", fixture_path);
                assert_eq!(interfaces[eth1_idx].mac_address, Some(MacAddr::from_str("06:f6:71:3b:64:01").unwrap()), "{}", fixture_path);
                assert_eq!(interfaces[eth1_idx].dhcp, Some(DhcpSetting::V4), "{}", fixture_path);
                assert_eq!(interfaces[eth1_idx].ip_addresses.len(), 0, "{}", fixture_path);
                assert_eq!(interfaces[eth1_idx].nameservers.len(), 0, "{}", fixture_path);
                let kargs = KubeVirtProvider::read_rd_network_kargs(&parsed).unwrap().unwrap();
                let kargs_parts: Vec<&str> = kargs.split_whitespace().collect();
                assert_eq!(kargs_parts.len(), 3, "{}", fixture_path);
                assert!(kargs.contains("ip=eth1:dhcp"), "{}", fixture_path);
                assert!(kargs.contains("ip=192.168.1.10::192.168.1.1:255.255.255.0::eth0:none"), "{}", fixture_path);
                assert!(kargs.contains("nameserver=8.8.8.8,8.8.4.4"), "{}", fixture_path);
            }
        }
    }
}
