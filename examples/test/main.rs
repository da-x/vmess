use anyhow::{ensure, Result};
use log::info;
use std::path::PathBuf;
use std::process::Command;
use structopt::StructOpt;

use crate::infra::{
    copy_template, copy_vm_image, create_test_config, create_test_directory, parse_ssh_config, Args,
};

mod infra;

fn list_images(vmess: &mut vmess::VMess) -> Result<()> {
    use vmess::List;

    log::info!("Running vmess list");

    // Create list command
    let list_params = List {
        fields: None,
        no_headers: false,
        all: false,
        filter: vec![],
    };

    vmess.list(list_params)?;

    Ok(())
}

fn cleanup_vms_in_test_dir(test_dir: &PathBuf) -> Result<()> {
    use vmess::virsh::get_batch_block_info;

    log::info!("Cleaning up VMs with drives under test directory");

    let block_info = get_batch_block_info()?;
    let mut vms_to_cleanup = Vec::new();

    // Find VMs that have block devices under our test directory
    for (vm_name, paths) in block_info {
        for path in paths {
            if PathBuf::from(&path).starts_with(test_dir) {
                log::info!(
                    "Found VM '{}' with drive in test directory: {}",
                    vm_name,
                    path
                );
                vms_to_cleanup.push(vm_name.clone());
                break; // Only add each VM once
            }
        }
    }

    if vms_to_cleanup.is_empty() {
        log::info!("No VMs found with drives under test directory");
        return Ok(());
    }

    // Stop and undefine VMs
    for vm_name in &vms_to_cleanup {
        log::info!("Stopping VM: {}", vm_name);
        let _ = Command::new("virsh").args(&["destroy", vm_name]).output(); // Ignore errors as VM might not be running
    }

    for vm_name in &vms_to_cleanup {
        log::info!("Undefining VM: {}", vm_name);
        let output = Command::new("virsh")
            .args(&["undefine", "--nvram", vm_name])
            .output()?;

        if !output.status.success() {
            log::warn!(
                "Failed to undefine VM {}: {}",
                vm_name,
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    Ok(())
}

fn main_wrap() -> Result<()> {
    let args = Args::from_args();

    let log_level = if args.verbose {
        log::LevelFilter::Debug
    } else if args.quiet {
        log::LevelFilter::Error
    } else {
        log::LevelFilter::Info
    };

    infra::init_log(log_level)?;

    log::info!("VMess test rig starting");

    // Create test directory structure
    let test_dir = create_test_directory()?;
    cleanup_vms_in_test_dir(&test_dir)?;

    let ssh_config = parse_ssh_config(&args.config_path)?;
    create_test_config(&test_dir, &ssh_config)?;

    copy_vm_image(&args.vm_image, &test_dir)?;
    copy_template(&args.template_path, &test_dir)?;

    // Create VMess instance once and reuse
    let config_path = test_dir.join("config.dev");
    let mut vmess = vmess::VMess::new(Some(config_path), None)?;

    list_images(&mut vmess)?;
    fork_with_modification(&mut vmess)?;
    try_freeze_rocky_8(&mut vmess)?;
    squash_modified_to_rocky_8_s(&mut vmess)?;
    tree_images(&mut vmess)?;
    cleanup_vms_in_test_dir(&test_dir)?;

    Ok(())
}

fn fork_with_modification(vmess: &mut vmess::VMess) -> Result<()> {
    use vmess::Fork;

    log::info!("Running vmess fork with rpm-sign installation");

    let fork_params = Fork {
        name: "modified".to_string(),
        base_template: Some("main".to_string()),
        force: true,
        parent: Some("rocky-8".to_string()),
        script: Some(
            "echo 'This is some modification' | sudo tee /usr/bin/empty-binay".to_string(),
        ),
        changes: Some("I've done some modification".to_string()),
        cached: true,
        ..Default::default()
    };

    vmess.fork(fork_params)?;

    Ok(())
}

fn try_freeze_rocky_8(vmess: &mut vmess::VMess) -> Result<()> {
    use vmess::Freeze;

    log::info!("Trying to freeze rocky-8 after it has a subimage");

    let freeze_params = Freeze {
        name: "rocky-8".to_string(),
        force: None,
    };

    ensure!(
        vmess.freeze(freeze_params).is_err(),
        "should not be able to freeze images with subs"
    );

    info!("All good, it failed");

    Ok(())
}

fn squash_modified_to_rocky_8_s(vmess: &mut vmess::VMess) -> Result<()> {
    use vmess::Squash;

    log::info!("Squashing 'modified' image to create 'rocky-8-s'");

    let squash_params = Squash {
        source: "modified".to_string(),
        destination: "rocky-8-s".to_string(),
    };

    vmess.squash(squash_params)?;

    log::info!("Successfully created rocky-8-s from modified");
    Ok(())
}

fn tree_images(vmess: &mut vmess::VMess) -> Result<()> {
    use vmess::Tree;

    log::info!("Running vmess tree");

    let tree_params = Tree {
        filter: vec![],
    };

    vmess.tree(tree_params)?;

    Ok(())
}

fn main() {
    match main_wrap() {
        Ok(()) => {}
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(-1);
        }
    }
}
