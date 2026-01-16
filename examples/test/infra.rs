use anyhow::Result;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
pub struct Args {
    #[structopt(long, short = "v", help = "Verbose logging (debug level)")]
    pub verbose: bool,

    #[structopt(long, short = "q", help = "Quiet logging (error level only)")]
    pub quiet: bool,

    #[structopt(help = "Path to pre-made installed VM image (Rocky Linux 8)")]
    pub vm_image: PathBuf,

    #[structopt(help = "Path to existing vmess config to extract ssh-config from")]
    pub config_path: PathBuf,

    #[structopt(help = "Path to template file to copy as templates/main.xml")]
    pub template_path: PathBuf,
}

pub fn init_log(level: log::LevelFilter) -> Result<()> {
    use fern::colors::{Color, ColoredLevelConfig};

    let colors_level = ColoredLevelConfig::new()
        .info(Color::Green)
        .warn(Color::Magenta);

    fern::Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "{} | {} | {}{}\x1B[0m | {}\x1B[0m",
                chrono::Local::now().format("-- %Y-%m-%d %H:%M:%S"),
                record.target(),
                colors_level.color(record.level()),
                format_args!(
                    "\x1B[{}m",
                    colors_level.get_color(&record.level()).to_fg_str()
                ),
                message
            ))
        })
        .level(level)
        .level_for("vmess", log::LevelFilter::Debug)
        .chain(std::io::stdout())
        .apply()?;

    Ok(())
}

pub fn create_test_directory() -> Result<PathBuf> {
    let user = std::env::var("USER").unwrap_or_else(|_| "unknown".to_string());
    let test_dir = PathBuf::from(format!("/tmp/{}/vmess-testing", user));

    // Remove existing test directory if it exists
    if test_dir.exists() {
        log::info!("Removing existing test directory: {}", test_dir.display());
        fs::remove_dir_all(&test_dir)?;
    }

    log::info!("Creating test directory: {}", test_dir.display());

    // Create main directories
    fs::create_dir_all(&test_dir)?;
    fs::create_dir_all(test_dir.join("main"))?;
    fs::create_dir_all(test_dir.join("main/templates"))?;
    fs::create_dir_all(test_dir.join("tmp"))?;
    fs::create_dir_all(test_dir.join("shared"))?;

    Ok(test_dir)
}

pub fn parse_ssh_config(config_path: &PathBuf) -> Result<String> {
    log::info!("Reading existing config from: {}", config_path.display());

    let config_content = fs::read_to_string(config_path)?;
    let config: toml::Value = toml::from_str(&config_content)?;

    // Extract ssh-config section
    let ssh_config = config
        .get("ssh-config")
        .ok_or_else(|| anyhow::anyhow!("No ssh-config section found"))?;

    Ok(toml::to_string(ssh_config)?)
}

pub fn create_test_config(test_dir: &PathBuf, ssh_config: &str) -> Result<()> {
    let user = std::env::var("USER").unwrap_or_else(|_| "unknown".to_string());

    let config_content = format!(
        r#"pool-path = "/tmp/{}/vmess-testing/main"
tmp-path = "/tmp/{}/vmess-testing/tmp"

[[pool]]
name = "shared"
path = "/tmp/{}/vmess-testing/shared"
shared = true

[ssh-config]
{}"#,
        user,
        user,
        user,
        ssh_config.trim()
    );

    let config_path = test_dir.join("config.dev");
    log::info!("Creating test config: {}", config_path.display());

    let mut file = fs::File::create(config_path)?;
    file.write_all(config_content.as_bytes())?;

    Ok(())
}

pub fn copy_vm_image(vm_image: &PathBuf, test_dir: &PathBuf) -> Result<()> {
    let target_path = test_dir.join("main/rocky-8.qcow2");

    log::info!(
        "Copying VM image from {} to {}",
        vm_image.display(),
        target_path.display()
    );

    fs::copy(vm_image, target_path)?;

    Ok(())
}

pub fn copy_template(template_path: &PathBuf, test_dir: &PathBuf) -> Result<()> {
    let target_path = test_dir.join("main/templates/main.xml");

    log::info!(
        "Copying template from {} to {}",
        template_path.display(),
        target_path.display()
    );

    fs::copy(template_path, target_path)?;

    Ok(())
}
