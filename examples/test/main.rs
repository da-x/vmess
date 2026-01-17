use ansi_term::Style;
use anyhow::{bail, ensure, Result};
use log::info;
use std::process::Command;
use std::{path::PathBuf, time::Instant};
use structopt::StructOpt;
use vmess::{Fork, Freeze, Squash, Tree};

use crate::infra::{
    copy_template, copy_vm_image, create_test_config, create_test_directory, parse_ssh_config, Args,
};

mod infra;

fn get_terminal_width() -> usize {
    if let Some(size) = termsize::get() {
        size.cols as usize
    } else {
        80 // default fallback
    }
}

macro_rules! test_title {
    ($title:expr) => {
        let width = get_terminal_width();
        println!("{}", Style::new().bold().paint("⎯".repeat(width)));
        info!(
            "{}",
            Style::new().bold().paint(format!("=== {} ===", $title))
        );
        info!("{}", Style::new().bold().paint(format!("::")));
    };
}

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
    use vmess::virsh::get_all_stats;

    log::info!("Cleaning up VMs with drives under test directory");

    let block_info = get_all_stats()?;
    let mut vms_to_cleanup = Vec::new();

    // Find VMs that have block devices under our test directory
    for (vm_name, stats) in block_info {
        for path in &stats.block_paths {
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

    test_title!("Basic parent freeze test");

    fork_with_modification(&mut vmess)?;
    check_inability_to_freeze_parent(&mut vmess)?;
    squash_modified_to_rocky_8_s(&mut vmess)?;
    tree_images(&mut vmess)?;

    test_title!("Check cached freezing");

    freeze_parent(&mut vmess)?;
    fork_modified(&mut vmess, "modified-b", "Modification for B")?;
    tree_images(&mut vmess)?;

    freeze(&mut vmess, "modified-b")?;
    check_cached(|| fork_modified(&mut vmess, "modified-b", "Modification for B"))?;
    check_uncached(|| fork_modified(&mut vmess, "modified-b", "Override modification for B"))?;
    tree_images(&mut vmess)?;

    test_title!("Freeze the second one");
    freeze(&mut vmess, "modified-b")?;
    tree_images(&mut vmess)?;

    test_title!("Retargeting the symlink");
    check_cached(|| fork_modified(&mut vmess, "modified-b", "Modification for B"))?;
    tree_images(&mut vmess)?;
    check_cached(|| fork_modified(&mut vmess, "modified-b", "Override modification for B"))?;
    tree_images(&mut vmess)?;

    test_title!("Move to shared");

    // Test that moving modified-b fails because its parent (rocky-8-s) is not in the shared pool
    info!("Testing move validation - should fail because parent not in shared pool");
    ensure!(
        vmess.move_to("modified-b", "shared").is_err(),
        "Moving modified-b should fail because its parent rocky-8-s is not in shared pool"
    );
    info!("✅ Move validation working correctly - failed as expected");

    // Move rocky-8-s to shared pool first
    info!("Moving rocky-8-s to shared pool");
    vmess.move_to("rocky-8-s", "shared")?;
    info!("✅ Successfully moved rocky-8-s to shared pool");

    // Now move modified-b to shared pool (should work now)
    info!("Moving modified-b to shared pool");
    vmess.move_to("modified-b", "shared")?;
    info!("✅ Successfully moved modified-b to shared pool");

    tree_images(&mut vmess)?;

    test_title!("Forking in main after move to shared");
    fork_modified(&mut vmess, "modified-b", "Third Modification for B")?;
    tree_images(&mut vmess)?;

    cleanup_vms_in_test_dir(&test_dir)?;

    Ok(())
}

fn fork_with_modification(vmess: &mut vmess::VMess) -> Result<()> {
    log::info!("Running vmess fork with modifications");

    let fork_params = Fork {
        name: "modified".to_string(),
        base_template: Some("main".to_string()),
        force: true,
        parent: Some("rocky-8".to_string()),
        script: Some(
            "echo 'This is some modification' | sudo tee /usr/bin/empty-binary".to_string(),
        ),
        changes: Some("I've done some modification".to_string()),
        cached: true,
        ..Default::default()
    };

    vmess.fork(fork_params)?;

    Ok(())
}

fn check_inability_to_freeze_parent(vmess: &mut vmess::VMess) -> Result<()> {
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
    log::info!("Running vmess tree");

    let tree_params = Tree { filter: vec![] };

    vmess.tree(tree_params)?;

    Ok(())
}

fn freeze_parent(vmess: &mut vmess::VMess) -> Result<()> {
    log::info!("Freezing rocky-8-s image");

    let freeze_params = Freeze {
        name: "rocky-8-s".to_string(),
        force: None,
    };

    vmess.freeze(freeze_params)?;

    log::info!("Successfully froze rocky-8-s");
    Ok(())
}

fn fork_modified(vmess: &mut vmess::VMess, target: &str, modtext: &str) -> Result<()> {
    log::info!("Forking '{target}' from 'rocky-8-s', modtext: {modtext}");

    let fork_params = Fork {
        name: target.to_string(),
        base_template: Some("main".to_string()),
        force: true,
        parent: Some("rocky-8-s".to_string()),
        script: Some(
            "echo 'Additional modification in B' | sudo tee /usr/bin/mod-b > /dev/null".to_string(),
        ),
        changes: Some(modtext.to_string()),
        cached: true,
        ..Default::default()
    };

    vmess.fork(fork_params)?;

    log::info!("Successfully created {target} from rocky-8-s");
    Ok(())
}

fn freeze(vmess: &mut vmess::VMess, target: &str) -> Result<()> {
    log::info!("Freezing {target} image");

    let freeze_params = Freeze {
        name: target.to_string(),
        force: Some("stop-undefine".to_string()),
    };

    vmess.freeze(freeze_params)?;

    log::info!("Successfully froze {target}");
    Ok(())
}

fn check_cached<F>(operation: F) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    let start_time = Instant::now();

    let result = operation()?;

    let elapsed = start_time.elapsed();
    let elapsed_secs = elapsed.as_secs_f64();

    log::info!("Operation completed in {:.3} seconds", elapsed_secs);

    if elapsed_secs < 0.3 {
        log::info!("✅ Fast operation confirmed - cached result used");
    } else {
        bail!("⚠️  Operation took longer than expected - may not have used cache");
    }

    Ok(result)
}

fn check_uncached<F>(operation: F) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    let start_time = Instant::now();

    let result = operation()?;

    let elapsed = start_time.elapsed();
    let elapsed_secs = elapsed.as_secs_f64();

    log::info!("Operation completed in {:.3} seconds", elapsed_secs);

    if elapsed_secs >= 1.0 {
        log::info!("✅ Slow operation confirmed - cached result used");
    } else {
        bail!("⚠️  Operation took way shortedr than expected");
    }

    Ok(result)
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
