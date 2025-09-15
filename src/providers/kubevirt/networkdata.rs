use anyhow::Result;
use serde::Deserialize;
use slog_scope::warn;
use std::collections::HashMap;
use std::net::{AddrParseError, IpAddr};
use std::str::FromStr;
use ipnetwork::IpNetwork;
use pnet_base::MacAddr;

use crate::network::{self, DhcpSetting, NetworkRoute};

/// Partial object for `network_data.json` - Version 1 format
///
/// Cloud-init network data version 1 uses a flat `config` array with type-based entries.
/// This format is the original cloud-init network configuration schema.
#[derive(Debug, Deserialize)]
pub struct NetworkDataV1 {
    #[allow(dead_code)]
    pub version: u32,
    pub config: Vec<NetworkConfigEntry>,
}

/// Partial object for `network_data.json` - Version 2 format (subset for physical interfaces only)
///
/// Cloud-init network data version 2 uses a structured format with separate sections
/// for different interface types. We only support the `ethernets` section since
/// that's what translates to dracut kernel arguments for physical interfaces.
#[derive(Debug, Deserialize)]
pub struct NetworkDataV2 {
    #[allow(dead_code)]
    pub version: u32,
    /// Physical ethernet interfaces keyed by interface name
    #[serde(default)]
    pub ethernets: HashMap<String, EthernetV2>,
}

/// Version 2 ethernet interface configuration (subset)
///
/// Supports the subset of cloud-init v2 ethernet configuration that maps
/// to dracut kernel arguments: static IPs, DHCP, gateways, and nameservers.
#[derive(Debug, Deserialize)]
pub struct EthernetV2 {
    /// Interface matching criteria (MAC address, name)
    #[serde(rename = "match")]
    pub match_config: Option<MatchV2>,
    /// Static IP addresses in CIDR notation (e.g., "192.168.1.10/24")
    #[serde(default)]
    pub addresses: Vec<String>,
    /// Enable DHCP for IPv4
    pub dhcp4: Option<bool>,
    /// Enable DHCP for IPv6
    pub dhcp6: Option<bool>,
    /// IPv4 default gateway
    pub gateway4: Option<String>,
    /// IPv6 default gateway
    pub gateway6: Option<String>,
    /// DNS nameserver configuration
    pub nameservers: Option<NameserversV2>,
}

/// Version 2 match configuration for identifying interfaces
///
/// Used to match network interfaces by MAC address or name.
#[derive(Debug, Deserialize)]
pub struct MatchV2 {
    /// MAC address to match (e.g., "06:52:db:01:ff:d9")
    pub macaddress: Option<String>,
    /// Interface name to match (e.g., "eth0")
    pub name: Option<String>,
}

/// Version 2 nameservers configuration
///
/// DNS nameserver addresses for the interface.
#[derive(Debug, Deserialize)]
pub struct NameserversV2 {
    /// List of DNS server IP addresses
    #[serde(default)]
    pub addresses: Vec<String>,
}

/// Unified NetworkData that can handle both versions
///
/// This enum allows the parser to handle both cloud-init network data
/// v1 and v2 formats transparently, with version detection at parse time.
#[derive(Debug)]
pub enum NetworkData {
    /// Cloud-init network data version 1 format
    V1(NetworkDataV1),
    /// Cloud-init network data version 2 format
    V2(NetworkDataV2),
}

/// JSON entry in `config` array.
#[derive(Debug, Deserialize)]
pub struct NetworkConfigEntry {
    #[serde(rename = "type")]
    pub network_type: String,
    pub name: Option<String>,
    pub mac_address: Option<String>,
    #[serde(default)]
    pub address: Vec<String>,
    #[serde(default)]
    pub subnets: Vec<NetworkConfigSubnet>,
}

/// JSON entry in `config.subnets` array.
#[derive(Debug, Deserialize)]
pub struct NetworkConfigSubnet {
    #[serde(rename = "type")]
    pub subnet_type: String,
    pub address: Option<String>,
    pub netmask: Option<String>,
    pub gateway: Option<String>,
}

impl NetworkConfigEntry {
    pub fn to_interface(&self) -> Result<network::Interface> {
        if self.network_type != "physical" {
            return Err(anyhow::anyhow!(
                "cannot convert config to interface: unsupported config type \"{}\"",
                self.network_type
            ));
        }

        let mut iface = network::Interface {
            name: self.name.clone(),

            // filled later
            nameservers: vec![],
            // filled below
            ip_addresses: vec![],
            // filled below
            routes: vec![],
            // filled below
            dhcp: None,
            // filled below because Option::try_map doesn't exist yet
            mac_address: None,

            // unsupported by kubevirt
            bond: None,

            // default values
            path: None,
            priority: 20,
            unmanaged: false,
            required_for_online: None,
        };

        for subnet in &self.subnets {
            if subnet.subnet_type.contains("static") {
                if subnet.address.is_none() {
                    return Err(anyhow::anyhow!(
                        "cannot convert static subnet to interface: missing address"
                    ));
                }

                if let Some(netmask) = &subnet.netmask {
                    iface.ip_addresses.push(IpNetwork::with_netmask(
                        IpAddr::from_str(subnet.address.as_ref().unwrap())?,
                        IpAddr::from_str(netmask)?,
                    )?);
                } else {
                    iface
                        .ip_addresses
                        .push(IpNetwork::from_str(subnet.address.as_ref().unwrap())?);
                }

                if let Some(gateway) = &subnet.gateway {
                    let gateway = IpAddr::from_str(gateway)?;

                    let destination = if gateway.is_ipv6() {
                        IpNetwork::from_str("::/0")?
                    } else {
                        IpNetwork::from_str("0.0.0.0/0")?
                    };

                    iface.routes.push(NetworkRoute {
                        destination,
                        gateway,
                    });
                } else {
                    warn!("found subnet type \"static\" without gateway");
                }
            }

            if subnet.subnet_type == "dhcp" || subnet.subnet_type == "dhcp4" {
                iface.dhcp = Some(DhcpSetting::V4)
            }
            if subnet.subnet_type == "dhcp6" {
                iface.dhcp = Some(DhcpSetting::V6)
            }
            if subnet.subnet_type == "ipv6_slaac" {
                warn!("subnet type \"ipv6_slaac\" not supported, ignoring");
            }
        }

        if let Some(mac) = &self.mac_address {
            iface.mac_address = Some(MacAddr::from_str(mac)?);
        }

        Ok(iface)
    }
}


impl EthernetV2 {
    /// Convert V2 ethernet config to network interface
    ///
    /// Transforms cloud-init v2 ethernet configuration into the common
    /// network::Interface format used by afterburn for generating dracut
    /// kernel arguments.
    pub fn to_interface(&self, name: &str) -> Result<network::Interface> {
        let mut iface = network::Interface {
            name: Some(name.to_string()),
            nameservers: vec![],
            ip_addresses: vec![],
            routes: vec![],
            dhcp: None,
            mac_address: None,
            bond: None,
            path: None,
            priority: 20,
            unmanaged: false,
            required_for_online: None,
        };

        // Handle MAC address from match config
        if let Some(match_config) = &self.match_config {
            if let Some(mac) = &match_config.macaddress {
                iface.mac_address = Some(MacAddr::from_str(mac)?);
            }
            // If name is specified in match, override the interface name
            if let Some(match_name) = &match_config.name {
                iface.name = Some(match_name.clone());
            }
        }

        // Handle static addresses
        for addr_str in &self.addresses {
            let ip_network = IpNetwork::from_str(addr_str)?;
            iface.ip_addresses.push(ip_network);
        }

        // Handle gateways
        if let Some(gateway4) = &self.gateway4 {
            let gateway = IpAddr::from_str(gateway4)?;
            let destination = IpNetwork::from_str("0.0.0.0/0")?;
            iface.routes.push(NetworkRoute {
                destination,
                gateway,
            });
        }

        if let Some(gateway6) = &self.gateway6 {
            let gateway = IpAddr::from_str(gateway6)?;
            let destination = IpNetwork::from_str("::/0")?;
            iface.routes.push(NetworkRoute {
                destination,
                gateway,
            });
        }

        // Handle DHCP
        let dhcp4 = self.dhcp4.unwrap_or(false);
        let dhcp6 = self.dhcp6.unwrap_or(false);

        if dhcp4 && dhcp6 {
            iface.dhcp = Some(DhcpSetting::Both);
        } else if dhcp4 {
            iface.dhcp = Some(DhcpSetting::V4);
        } else if dhcp6 {
            iface.dhcp = Some(DhcpSetting::V6);
        }

        // Handle nameservers
        if let Some(nameservers) = &self.nameservers {
            iface.nameservers = nameservers
                .addresses
                .iter()
                .map(|ip| IpAddr::from_str(ip))
                .collect::<Result<Vec<IpAddr>, AddrParseError>>()?;
        }

        Ok(iface)
    }
}

/// Transform network data (any version) into a set of interface configurations.
///
/// This is the main entry point for converting parsed network data into
/// afterburn's common interface format. It automatically dispatches to
/// the appropriate version-specific handler based on the detected format.
pub fn network_interfaces(input: &NetworkData) -> Result<Vec<network::Interface>> {
    match input {
        NetworkData::V1(v1_data) => network_interfaces_v1(v1_data),
        NetworkData::V2(v2_data) => network_interfaces_v2(v2_data),
    }
}

/// Transform version 1 network data into interfaces (original implementation)
///
/// Handles cloud-init v1 format with flat config array containing
/// "physical" and "nameserver" type entries.
fn network_interfaces_v1(input: &NetworkDataV1) -> Result<Vec<network::Interface>> {
    let nameservers = input
        .config
        .iter()
        .filter(|config| config.network_type == "nameserver")
        .collect::<Vec<_>>();

    if nameservers.len() > 1 {
        return Err(anyhow::anyhow!("too many nameservers, only one supported"));
    }

    let mut interfaces = input
        .config
        .iter()
        .filter(|config| config.network_type == "physical")
        .map(|entry| entry.to_interface())
        .collect::<Result<Vec<_>, _>>()?;

    if let Some(iface) = interfaces.first_mut() {
        if let Some(nameserver) = nameservers.first() {
            iface.nameservers = nameserver
                .address
                .iter()
                .map(|ip| IpAddr::from_str(ip))
                .collect::<Result<Vec<IpAddr>, AddrParseError>>()?;
        }
    }

    Ok(interfaces)
}

/// Transform version 2 network data into interfaces
///
/// Handles cloud-init v2 format with structured ethernets section.
/// Each ethernet interface is converted to a network::Interface with
/// its own configuration (DHCP, static IPs, nameservers, etc.).
fn network_interfaces_v2(input: &NetworkDataV2) -> Result<Vec<network::Interface>> {
    let mut interfaces = Vec::new();

    for (name, ethernet) in &input.ethernets {
        let interface = ethernet.to_interface(name)?;
        interfaces.push(interface);
    }

    Ok(interfaces)
}
