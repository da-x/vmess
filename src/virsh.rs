use fstrings::*;
use std::collections::HashMap;
use std::thread;
use std::time::Duration;

use crate::{ibash_stdout, utils::bash_stdout, Error};

// Type aliases for network information
pub type InterfaceName = String;
pub type MacAddress = String;
pub type IpAddress = String;
pub type VmName = String;

#[derive(Debug, Clone, PartialEq)]
pub enum VirDomainState {
    NoState = 0,
    Running = 1,
    Blocked = 2,
    Paused = 3,
    Shutdown = 4,
    Shutoff = 5,
    Crashed = 6,
    PmSuspended = 7,
    Unknown,
}

impl From<u32> for VirDomainState {
    fn from(value: u32) -> Self {
        match value {
            0 => VirDomainState::NoState,
            1 => VirDomainState::Running,
            2 => VirDomainState::Blocked,
            3 => VirDomainState::Paused,
            4 => VirDomainState::Shutdown,
            5 => VirDomainState::Shutoff,
            6 => VirDomainState::Crashed,
            7 => VirDomainState::PmSuspended,
            _ => VirDomainState::Unknown,
        }
    }
}

fn virsh_domstats_with_retry(cmd: &str) -> Result<String, Error> {
    const RETRY_DELAY: Duration = Duration::from_millis(500);

    loop {
        match bash_stdout(cmd.to_string()) {
            Ok(output) => return Ok(output),
            Err(Error::CommandError(_, stderr)) if stderr.contains("Connection reset by peer") 
                || stderr.contains("Broken pipe") => {
                thread::sleep(RETRY_DELAY);
                continue;
            }
            Err(e) => return Err(e),
        }
    }
}

pub fn virsh_destroy_forgiving(domain_name: &str) -> Result<(), Error> {
    let cmd = format!("virsh destroy {}", domain_name);
    match bash_stdout(cmd.clone()) {
        Ok(_) => Ok(()),
        Err(Error::CommandError(_, stderr)) if stderr.contains("error: failed to get domain") => {
            // Domain doesn't exist, which is fine for destroy operation
            Ok(())
        }
        Err(e) => Err(e),
    }
}

#[derive(Debug, Clone)]
pub struct KVMStats {
    pub block_paths: Vec<String>,
    pub mem_max: Option<u64>,     // balloon.maximum in KiB
    pub mem_current: Option<u64>, // balloon.rss in KiB
    pub state: VirDomainState,
}

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

    let output = virsh_domstats_with_retry(
        "virsh domstats --list-running --interface | grep -E 'Domain|\\.name'",
    )?;
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

// Returns a mapping between existing VMs and their comprehensive stats
pub fn get_all_stats() -> Result<HashMap<VmName, KVMStats>, Error> {
    let mut result = HashMap::new();

    let output = virsh_domstats_with_retry("virsh domstats")?;

    let mut current_domain = String::new();

    for line in output.lines() {
        let line = line.trim();

        // Parse domain line: Domain: 'vmname'
        if line.starts_with("Domain: '") && line.ends_with("'") {
            current_domain = line[9..line.len() - 1].to_string();
            // Initialize KVMStats for this domain
            result
                .entry(current_domain.clone())
                .or_insert_with(|| KVMStats {
                    block_paths: Vec::new(),
                    mem_max: None,
                    mem_current: None,
                    state: VirDomainState::NoState,
                });
            continue;
        }

        if current_domain.is_empty() {
            continue;
        }

        let stats = result.get_mut(&current_domain).unwrap();

        // Parse block device path: block.0.path=/var/lib/libvirt/images/mstest1.qcow2
        if line.starts_with("block.") && line.contains(".path=") {
            if let Some(eq_pos) = line.find('=') {
                let path = &line[eq_pos + 1..];
                if !path.is_empty() {
                    stats.block_paths.push(path.to_string());
                }
            }
        }
        // Parse balloon memory maximum: balloon.maximum=8388608
        else if line.starts_with("balloon.maximum=") {
            if let Some(eq_pos) = line.find('=') {
                let value_str = &line[eq_pos + 1..];
                if let Ok(value) = value_str.parse::<u64>() {
                    stats.mem_max = Some(value);
                }
            }
        }
        // Parse balloon memory current: balloon.rss=2097152
        else if line.starts_with("balloon.rss=") {
            if let Some(eq_pos) = line.find('=') {
                let value_str = &line[eq_pos + 1..];
                if let Ok(value) = value_str.parse::<u64>() {
                    stats.mem_current = Some(value);
                }
            }
        }
        // Parse domain state: state.state=1
        else if line.starts_with("state.state=") {
            if let Some(eq_pos) = line.find('=') {
                let value_str = &line[eq_pos + 1..];
                if let Ok(value) = value_str.parse::<u32>() {
                    stats.state = VirDomainState::from(value);
                }
            }
        }
    }

    Ok(result)
}
