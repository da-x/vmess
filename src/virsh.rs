use fstrings::*;
use std::collections::HashMap;

use crate::{ibash_stdout, Error};

// Type aliases for network information
pub type InterfaceName = String;
pub type MacAddress = String;
pub type IpAddress = String;
pub type VmName = String;

fn get_network_interface_info() -> Result<HashMap<InterfaceName, MacAddress>, Error> {
    // Parse: ip -o link show | awk '{ for (i=1; i<=NF; i++) if ($i == "link/ether") { gsub(/:$/, "", $2); print $2, $(i+1) } }'
    // Output: interface_name mac_address
    let mut result = HashMap::new();

    let output = ibash_stdout!(
        "ip -o link show | awk '{{ for (i=1; i<=NF; i++) if ($i == \"link/ether\") {{ gsub(/:$/, \"\", $2); print $2, $(i+1) }} }}'"
    )?;

    for line in output.lines() {
        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        if parts.len() == 2 {
            let interface = parts[0].to_string();
            let mac = parts[1].to_string();
            result.insert(interface, mac);
        }
    }

    Ok(result)
}

fn get_vm_interface_mappings() -> Result<HashMap<VmName, Vec<InterfaceName>>, Error> {
    // Parse: virsh domstats --list-running --interface | grep -E 'Domain|.name'
    // Output: Domain: 'vmname' followed by net.X.name=interface_name lines

    let mut result = HashMap::new();

    let output =
        ibash_stdout!("virsh domstats --list-running --interface | grep -E 'Domain|\\.name'")?;
    let mut current_domain = String::new();

    for line in output.lines() {
        let line = line.trim();

        // Parse domain line: Domain: 'vmname'
        if line.starts_with("Domain: '") && line.ends_with("'") {
            current_domain = line[9..line.len() - 1].to_string();
            continue;
        }

        // Parse interface line: net.0.name=vnet1
        if line.contains(".name=") && !current_domain.is_empty() {
            if let Some(eq_pos) = line.find('=') {
                let interface = &line[eq_pos + 1..];
                if !interface.is_empty() {
                    result
                        .entry(current_domain.clone())
                        .or_insert_with(Vec::new)
                        .push(interface.to_string());
                }
            }
        }
    }

    Ok(result)
}

fn get_dhcp_leases() -> Result<HashMap<MacAddress, IpAddress>, Error> {
    // Parse: virsh net-dhcp-leases default
    // Extract MAC address to IP mapping
    let mut result = HashMap::new();

    let output = ibash_stdout!("virsh net-dhcp-leases default")?;

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("Expiry") || line.starts_with("---") {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 5 {
            println!("{:?}", parts);
            let mac = parts[2];
            let ip_with_subnet = parts[4];

            // Extract IP without subnet mask (e.g., "192.168.124.210/24" -> "192.168.124.210")
            if let Some(slash_pos) = ip_with_subnet.find('/') {
                let ip = &ip_with_subnet[..slash_pos];
                result.insert(mac.to_string(), ip.to_string());
            }
        }
    }

    Ok(result)
}

pub fn get_batch_network_info() -> Result<HashMap<VmName, IpAddress>, Error> {
    // Combine all network information to create a mapping from VM name to IP address
    let interface_to_mac = get_network_interface_info()?;
    let vm_to_interfaces = get_vm_interface_mappings()?;
    let mac_to_ip = get_dhcp_leases()?;

    let mut vm_to_ip = HashMap::new();

    for (vm_name, interfaces) in vm_to_interfaces {
        for interface in interfaces {
            if let Some(mac) = interface_to_mac.get(&interface) {
                // Normalize MAC address format - DHCP leases might have different format
                let normalized_mac = mac.to_lowercase();

                // Try to find IP by exact MAC match first
                if let Some(ip) = mac_to_ip.get(&normalized_mac) {
                    vm_to_ip.insert(vm_name.clone(), ip.clone());
                    break;
                }

                // Try alternative MAC formats (with/without colons, different prefixes)
                for (lease_mac, ip) in &mac_to_ip {
                    let lease_mac_clean = lease_mac.replace(":", "").to_lowercase();
                    let our_mac_clean = normalized_mac.replace(":", "").to_lowercase();

                    // Check if the MAC addresses match (ignoring format differences)
                    if lease_mac_clean == our_mac_clean ||
                       lease_mac.to_lowercase() == normalized_mac ||
                       // Handle prefix differences (e.g., fe:54:00... vs 52:54:00...)
                       lease_mac_clean.ends_with(&our_mac_clean[6..]) ||
                       our_mac_clean.ends_with(&lease_mac_clean[6..])
                    {
                        vm_to_ip.insert(vm_name.clone(), ip.clone());
                        break;
                    }
                }

                if vm_to_ip.contains_key(&vm_name) {
                    break;
                }
            }
        }
    }

    Ok(vm_to_ip)
}

pub fn get_batch_block_info(vm_names: &[VmName]) -> Result<HashMap<VmName, Vec<String>>, Error> {
    let mut result = HashMap::new();

    if vm_names.is_empty() {
        return Ok(result);
    }

    // Run virsh domstats --block on all VMs at once
    let vm_list = vm_names.join(" ");
    let output = ibash_stdout!("virsh domstats --block {vm_list}")?;

    let mut current_domain = String::new();

    for line in output.lines() {
        let line = line.trim();

        // Parse domain line: Domain: 'vmname'
        if line.starts_with("Domain: '") && line.ends_with("'") {
            current_domain = line[9..line.len() - 1].to_string();
            continue;
        }

        // Parse block device path: block.0.path=/var/lib/libvirt/images/mstest1.qcow2
        if line.starts_with("block.") && line.contains(".path=") {
            if let Some(eq_pos) = line.find('=') {
                let path = &line[eq_pos + 1..];
                if !path.is_empty() && !current_domain.is_empty() {
                    result
                        .entry(current_domain.clone())
                        .or_insert_with(Vec::new)
                        .push(path.to_string());
                }
            }
        }
    }

    Ok(result)
}
