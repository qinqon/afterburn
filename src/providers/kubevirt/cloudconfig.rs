//! KubeVirt cloud config parsing.
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

use crate::{
    network::{DhcpSetting, Interface, VirtualNetDev},
    providers::{
        kubevirt::networkdata::{network_interfaces, NetworkData, NetworkDataV1, NetworkDataV2},
        MetadataProvider,
    },
};
use anyhow::{bail, Context, Result};
use ipnetwork::IpNetwork;
use openssh_keys::PublicKey;
use serde::Deserialize;
use slog_scope::warn;
use std::{
    collections::HashMap,
    fs::File,
    io::{BufReader, Read},
    path::Path,
};

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

#[derive(Debug)]
pub struct KubeVirtCloudConfig {
    pub meta_data: MetaDataJSON,
    pub network_data: Option<NetworkData>,
}

impl KubeVirtCloudConfig {
    pub fn try_new(path: &Path) -> Result<Self> {
        let meta_data = match Self::read_cloud_config_file(path, "meta_data.json")? {
            Some(reader) => Self::parse_metadata(reader)?,
            None => bail!("meta_data.json file not found"),
        };

        let network_data = Self::read_cloud_config_file(path, "network_data.json")?
            .map(Self::parse_network_data)
            .transpose()?;

        Ok(Self {
            meta_data,
            network_data,
        })
    }
    pub fn read_cloud_config_file(path: &Path, file: &str) -> Result<Option<BufReader<File>>> {
        let cloudconfig_dir = path.join("openstack").join("latest");
        let filename = cloudconfig_dir.join(file);
        if !filename.exists() {
            return Ok(None);
        }
        let file =
            File::open(&filename).with_context(|| format!("failed to open file '{filename:?}'"))?;
        Ok(Some(BufReader::new(file)))
    }

    /// Parse metadata attributes.
    ///
    /// Metadata file contains a JSON object, corresponding to `MetaDataJSON`.
    pub fn parse_metadata(input: BufReader<File>) -> Result<MetaDataJSON> {
        serde_json::from_reader(input).context("failed to parse JSON metadata")
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
    fn parse_network_data(mut input: BufReader<File>) -> Result<NetworkData> {
        let mut content = String::new();
        input
            .read_to_string(&mut content)
            .context("failed to read network data content")?;

        let trimmed_content = content.trim();

        // Parse as either JSON or YAML to get a generic Value first for version detection
        // This two-step approach allows us to inspect the version field before committing
        // to a specific data structure for deserialization
        let parsed_value: serde_json::Value =
            if trimmed_content.starts_with('{') || trimmed_content.starts_with('[') {
                // Try JSON first - most common format
                serde_json::from_str(&content).context("failed to parse JSON network data")?
            } else {
                // Try YAML and convert to JSON Value for uniform processing
                let yaml_value: serde_yaml::Value =
                    serde_yaml::from_str(&content).context("failed to parse YAML network data")?;
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
                let v1_data: NetworkDataV1 = serde_json::from_value(parsed_value)
                    .context("failed to parse version 1 network data")?;
                Ok(NetworkData::V1(v1_data))
            }
            2 => {
                // Cloud-init network data v2: structured format with ethernets section
                let v2_data: NetworkDataV2 = serde_json::from_value(parsed_value)
                    .context("failed to parse version 2 network data")?;
                Ok(NetworkData::V2(v2_data))
            }
            _ => Err(anyhow::anyhow!(
                "unsupported network data version: {}",
                version
            )),
        }
    }
}

impl MetadataProvider for KubeVirtCloudConfig {
    /// Extract supported cloud config values and convert to Afterburn attributes.
    ///
    /// The `AFTERBURN_` prefix is added later on, so it is not part of the
    /// key-labels here.
    fn attributes(&self) -> Result<HashMap<String, String>> {
        if self.meta_data.instance_id.is_empty() {
            bail!("empty instance ID");
        }

        if self.meta_data.hostname.is_empty() {
            bail!("empty local hostname");
        }

        let mut attrs = maplit::hashmap! {
            "KUBEVIRT_INSTANCE_ID".to_string() => self.meta_data.instance_id.clone(),
            "KUBEVIRT_HOSTNAME".to_string() => self.meta_data.hostname.clone(),
        };
        if let Some(instance_type) = &self.meta_data.instance_type {
            attrs.insert("KUBEVIRT_INSTANCE_TYPE".to_string(), instance_type.clone());
        }
        Ok(attrs)
    }

    fn hostname(&self) -> Result<Option<String>> {
        let hostname = if self.meta_data.hostname.is_empty() {
            None
        } else {
            Some(self.meta_data.hostname.clone())
        };
        Ok(hostname)
    }

    /// The public key is stored as key:value pair in openstack/latest/meta_data.json file
    fn ssh_keys(&self) -> Result<Vec<PublicKey>> {
        self.meta_data
            .public_keys
            .as_ref()
            .unwrap_or(&HashMap::new())
            .values()
            .map(|key| PublicKey::parse(key).map_err(anyhow::Error::from))
            .collect()
    }

    fn networks(&self) -> Result<Vec<Interface>> {
        match &self.network_data {
            Some(network_data) => network_interfaces(network_data),
            None => Ok(Vec::<Interface>::new()),
        }
    }

    fn rd_network_kargs(&self) -> Result<Option<String>> {
        let mut kargs = Vec::new();

        if let Ok(networks) = self.networks() {
            for iface in networks {
                // Use mac address as identifier if there is one
                // else us name or continue
                let id = if let Some(iface_mac) = iface.mac_address {
                    format!("{}", iface_mac)
                } else if let Some(iface_name) = iface.name {
                    iface_name
                } else {
                    continue;
                };

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
                                    "ip={}::{}:{}::{}:static",
                                    network.ip(),
                                    gateway.gateway,
                                    network.mask(),
                                    id,
                                ));
                            } else {
                                kargs.push(format!(
                                    "ip={}:::{}::{}:static",
                                    network.ip(),
                                    network.mask(),
                                    id
                                ));
                            }
                        }
                        IpNetwork::V6(network) => {
                            if let Some(gateway) = iface
                                .routes
                                .iter()
                                .find(|r| r.destination.is_ipv6() && r.destination.prefix() == 0)
                            {
                                kargs.push(format!(
                                    "ip={}::{}:{}::{}:static",
                                    network.ip(),
                                    gateway.gateway,
                                    network.prefix(),
                                    id
                                ));
                            } else {
                                kargs.push(format!(
                                    "ip={}:::{}::{}:static",
                                    network.ip(),
                                    network.prefix(),
                                    id
                                ));
                            }
                        }
                    }
                }

                // Add DHCP configuration
                if let Some(dhcp) = iface.dhcp {
                    match dhcp {
                        DhcpSetting::V4 => kargs.push(format!("ip={}:dhcp", id)),
                        DhcpSetting::V6 => kargs.push(format!("ip={}:dhcp6", id)),
                        DhcpSetting::Both => kargs.push(format!("ip={}:dhcp,dhcp6", id)),
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

    fn virtual_network_devices(&self) -> Result<Vec<VirtualNetDev>> {
        warn!("virtual network devices metadata requested, but not supported on this platform");
        Ok(vec![])
    }

    fn boot_checkin(&self) -> Result<()> {
        warn!("boot check-in requested, but not supported on this platform");
        Ok(())
    }
}
