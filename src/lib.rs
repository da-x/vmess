#[macro_use]
extern crate lalrpop_util;

use std::borrow::Cow;
use std::collections::{btree_map, BTreeMap, HashMap};
use std::convert::TryFrom;
use std::fmt::Write;
use std::fs::OpenOptions;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Read;
use std::io::{BufWriter, Write as OtherWrite};
use std::os::unix::prelude::MetadataExt;
use std::path::PathBuf;
use std::process::Command;

use lazy_static::lazy_static;
use log::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use structopt::StructOpt;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use thiserror::Error;
use users::get_current_uid;
use xmltree::{Element, XMLNode};

mod utils;

#[allow(unused_parens)]
mod query;
pub mod virsh;

use crate::utils::calculate_hash;
use crate::utils::get_qcow2_backing_chain;
use crate::utils::is_version_at_least;
use crate::utils::read_json_path;
use crate::utils::write_json_path;
use crate::utils::AddExtension;
use crate::utils::{adjust_path_by_env, make_ssh, remote_shell_no_stderr};
use crate::virsh::{get_all_stats, get_batch_network_info, VirDomainState};
use fstrings::*;

use crate::query::{MatchInfo, VMState};

#[derive(Error, Debug)]
pub enum Error {
    #[error("Io error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Var error: {0}")]
    VarError(#[from] std::env::VarError),

    #[error("Format error: {0}")]
    FmtError(#[from] std::fmt::Error),

    #[error("Config error: {0}")]
    ConfigError(#[from] config::ConfigError),

    #[error("{0}: {1}")]
    Context(String, Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("Serde error: {0}")]
    Serderror(#[from] serde_json::Error),

    #[error("Command error: {0}, stderr: {1}")]
    CommandError(String, String),

    #[error("UTF8 error: {0}")]
    UTF8Error(#[from] std::string::FromUtf8Error),

    #[error("XML error: {0}")]
    XMLError(#[from] xmltree::ParseError),

    #[error("XML write error: {0}")]
    XMLWriteError(#[from] xmltree::Error),

    #[error("Regex error: {0}")]
    Regex(#[from] regex::Error),

    #[error("No default config file")]
    ConfigFile,

    #[error("Image not found: {0}")]
    NotFound(String),

    #[error("Already exists")]
    AlreadyExists,

    #[error("VM currently defined, operation aborted")]
    CurrentlyDefined,

    #[error("Parsing PCI spec {0}")]
    ParsePCISpec(String),

    #[error("Template {0} doesn't exist")]
    TemplateDoesntExist(String),

    #[error("Cannot {1} image {0} - has sub images")]
    HasSubImages(String, &'static str),

    #[error("No VM defined for {0}")]
    NoVMDefined(String),

    #[error("Filter parse error: {0}")]
    FilterParseError(String),

    #[error("{0}")]
    FreeText(String),

    #[error("{0}")]
    CallBack(anyhow::Error),

    #[error("Invalid pool name: {0}")]
    InvalidPoolName(String),
}

pub trait AddContext<T> {
    fn with_context(self, f: impl FnOnce() -> String) -> Result<T, Error>;
}

impl<T, E> AddContext<T> for Result<T, E>
where
    E: Into<Error>,
{
    fn with_context(self, f: impl FnOnce() -> String) -> Result<T, Error> {
        match self {
            Ok(v) => Ok(v),
            Err(_) => self.map_err(|e| Error::Context(f(), Box::new(e.into()))),
        }
    }
}

#[derive(Debug, StructOpt, Clone, Default)]
pub struct Fork {
    /// Full name of the domain
    pub name: String,

    /// Enable volatile VM execution - the domain definition will not be saved, and
    /// the definition will be removed when stopped.
    #[structopt(long = "volatile", short = "v")]
    pub volatile: bool,

    /// Store image in the temp pool, implies 'volatile'
    #[structopt(long = "temp", short = "t")]
    pub temp: bool,

    /// Store image in the given pool
    #[structopt(long = "pool")]
    pub pool: Option<String>,

    /// Base template used for actual VM execution
    #[structopt(long = "base-template", short = "b")]
    pub base_template: Option<String>,

    /// Start as paused
    #[structopt(long = "paused", short = "p")]
    pub paused: bool,

    /// Wait for VM to finish booting and then exit
    #[structopt(long = "wait", short = "w")]
    pub wait: bool,

    /// Force operation (will kill the VM if it exists)
    #[structopt(long = "force", short = "f")]
    pub force: bool,

    #[structopt(long = "print-parent")]
    pub print_parent: bool,

    /// Explicitly specify the parent image name instead of using longest prefix matching
    #[structopt(long = "parent")]
    pub parent: Option<String>,

    /// Script to execute on the VM after boot
    #[structopt(long = "script")]
    pub script: Option<String>,

    /// Text to be written to the changes JSON file
    #[structopt(long = "changes")]
    pub changes: Option<String>,

    /// Skip creation if sub-image with same name and changes already exists
    #[structopt(long = "cached")]
    pub cached: bool,

    /// Freeze and move the created image to a shared pool if one exists
    #[structopt(long = "publish")]
    pub publish: bool,

    #[structopt(flatten)]
    pub overrides: Overrides,
}

#[derive(Debug, StructOpt, Clone, Default)]
pub struct Wait {
    /// Full name of the domain
    pub name: String,
}

#[derive(Debug, StructOpt, Clone, Default)]
pub struct New {
    /// Full name of the domain
    pub name: String,

    /// Store image in the temp pool, implies 'volatile'
    #[structopt(name = "temp", short = "t")]
    pub temp: bool,

    /// Main image size
    #[structopt(long)]
    pub size: byte_unit::Byte,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VMInfo {
    // Override default username for VM access
    #[serde(default)]
    pub username: Option<String>,

    #[serde(default)]
    pub changes: Vec<String>,
}

#[derive(Debug, StructOpt, Clone, Default)]
pub struct Exists {
    /// Full name of the domain
    pub name: String,
}

#[derive(Debug, StructOpt, Clone, Default)]
pub struct Kill {
    /// List of the full names of the domains to kill
    pub names: Vec<String>,

    /// Use regex matching for the given names
    #[structopt(name = "regex", short = "E")]
    pub regex: bool,

    /// Do not remove, just print the matching names
    #[structopt(name = "dry_run", short = "n")]
    pub dry_run: bool,

    /// Force operation (kill the VM even if it is running)
    #[structopt(name = "force", short = "f")]
    pub force: bool,
}

#[derive(Debug, StructOpt, Clone)]
pub struct Start {
    /// Full name of the domain
    pub name: String,
}

#[derive(Debug, StructOpt, Clone)]
pub struct Stop {
    /// Full name of the domain
    pub name: String,
}

#[derive(Debug, StructOpt, Clone, Default)]
pub struct ShutdownWait {
    /// Full name of the domain
    pub name: String,
}

#[derive(Debug, StructOpt, Clone)]
pub struct Rename {
    /// Full name of the domain
    pub name: String,

    /// New full name of the domain
    pub new_name: String,

    /// Force rename even for images in shared pools
    #[structopt(long = "force", short = "f")]
    pub force: bool,
}

#[derive(Debug, StructOpt, Clone, Default)]
pub struct Console {
    /// Full name of the domain
    name: String,
}

#[derive(Debug, StructOpt, Clone, Default)]
pub struct Overrides {
    /// Override GB of memory
    #[structopt(name = "memory", short = "m", long = "mem")]
    pub memory_gb: Option<u32>,

    /// Override number of CPUs
    #[structopt(name = "cpus", short = "c", long = "cpus")]
    pub nr_cpus: Option<u32>,

    /// Host devices from VF pools
    #[structopt(name = "netdevs", long = "netdev")]
    pub netdevs: Vec<String>,

    /// Host devices from VF pools
    #[structopt(long)]
    pub cdrom: Option<PathBuf>,

    #[structopt(long)]
    pub usb: Option<PathBuf>,

    #[structopt(long)]
    pub uefi: bool,

    #[structopt(long)]
    pub secure_boot: bool,

    #[structopt(long)]
    pub stop_on_reboot: bool,

    /// Increase main image size to this amount
    #[structopt(long)]
    pub image_size: Option<byte_unit::Byte>,
}

#[derive(Debug, StructOpt, Clone)]
pub struct Spawn {
    /// Full name of the domain
    pub full: String,

    /// Base template XML to use
    #[structopt(name = "base-template", short = "b")]
    pub base_template: String,

    /// Volatile VM
    #[structopt(name = "volatile", short = "v")]
    pub volatile: bool,

    /// Store image in the temp pool, implies 'volatile'
    #[structopt(name = "temp", short = "t")]
    pub temp: bool,

    /// Don't start the VM after creation
    #[structopt(name = "paused", short = "s")]
    pub paused: bool,

    /// Wait for VM to boot after spawn
    #[structopt(name = "wait", short = "w")]
    pub wait: bool,

    #[structopt(flatten)]
    pub overrides: Overrides,

    /// Optional size for new image creation if image doesn't exist
    #[structopt(skip)]
    pub new_size: Option<byte_unit::Byte>,
}

#[derive(Debug, StructOpt, Clone)]
pub struct Modify {
    /// Full name of the domain
    full: String,

    #[structopt(flatten)]
    overrides: Overrides,
}

#[derive(Debug, StructOpt, Clone)]
pub struct Undefine {
    /// List of the full names of the domains to kill
    pub names: Vec<String>,
}

#[derive(Debug, StructOpt, Clone)]
pub struct UpdateSshParams {
    #[structopt(name = "quiet", short = "q")]
    pub quiet: bool,
}

#[derive(Debug, StructOpt, Clone)]
pub struct List {
    #[structopt(short = "f", long = "fields")]
    pub fields: Option<String>,

    #[structopt(short = "n", long = "no-headers")]
    pub no_headers: bool,

    #[structopt(long = "all")]
    pub all: bool,

    #[structopt(name = "filter")]
    pub filter: Vec<String>,
}

#[derive(Debug, StructOpt, Clone)]
pub struct Tree {
    #[structopt(name = "filter")]
    pub filter: Vec<String>,
}

#[derive(Debug, StructOpt, Clone)]
pub struct Freeze {
    /// Full name of the domain
    pub name: String,

    /// Force freezing behavior
    #[structopt(long = "force")]
    pub force: Option<String>,
}

#[derive(Debug, StructOpt, Clone, Default)]
pub struct Squash {
    /// Source image name to squash
    pub source: String,

    /// Destination image name
    pub destination: String,
}

#[derive(Debug, StructOpt, Clone)]
pub struct Move {
    /// Name of the shared pool to move the image to
    pub pool: String,

    /// Full name of the image to move
    pub image: String,
}

#[derive(Debug, StructOpt, Clone)]
pub enum CommandMode {
    New(New),

    /// Fork a new VM out of a suspended VM image and optionally spawn it
    /// if a template definition is provided
    Fork(Fork),

    /// Wait a VM to become available
    Wait(Wait),

    /// Check for an existence of a VM image
    Exists(Exists),

    /// Spawn an image into a running VM based on template
    Spawn(Spawn),

    /// Start console on a VM
    Console(Console),

    /// Stop a running VM but don't remove its definition
    Stop(Stop),

    /// Clean shutdown and wait for VM to be off
    ShutdownWait(ShutdownWait),

    /// Rename a VM that stopped
    Rename(Rename),

    /// Start a VM that was shutdown
    Start(Start),

    /// Remove a VM and its image file
    Kill(Kill),

    /// Remove a VM definition (but not its image file)
    Undefine(Undefine),

    /// Modify an existing VM definition
    Modify(Modify),

    /// List image files and VMs
    List(List),

    /// Show tree structure of VM images and images
    Tree(Tree),

    /// Freeze a VM image by adding SHA256 hash to filename
    Freeze(Freeze),

    /// Move an image and its backing chain to a shared pool
    Move(Move),

    /// Squash an image into a new independent qcow2
    Squash(Squash),

    /// Update SSH config based on DHCP of client VMs
    UpdateSsh(UpdateSshParams),

    /// No command
    Nop,
}

enum UpdateSshDisposition {
    NotConfigured,
    Updated,
    NotNeeded,
}

#[derive(Debug, StructOpt, Clone)]
pub struct CommandArgs {
    #[structopt(name = "config-file", short = "c")]
    config: Option<PathBuf>,

    #[structopt(subcommand)]
    command: CommandMode,
}

impl Default for CommandArgs {
    fn default() -> Self {
        Self {
            config: Default::default(),
            command: CommandMode::Nop,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    #[serde(rename = "pool-path")]
    pub pool_path: PathBuf,

    #[serde(rename = "tmp-path")]
    pub tmp_path: PathBuf,

    #[serde(default)]
    #[serde(rename = "multi-user")]
    pub multi_user: bool,

    #[serde(default)]
    #[serde(rename = "pool")]
    pub pools: Vec<NamedPoolPath>,

    #[serde(default)]
    #[serde(rename = "ssh-config")]
    pub ssh_config: Option<SSHConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NamedPoolPath {
    pub name: String,
    pub path: PathBuf,

    #[serde(default)]
    pub shared: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SSHConfig {
    #[serde(rename = "identity-file")]
    pub identity_file: String,

    #[serde(rename = "pubkey-file")]
    pub pubkey_file: String,

    #[serde(rename = "config-file")]
    pub config_file: PathBuf,

    #[serde(rename = "user", default)]
    pub user: Option<String>,
}

pub struct VMess {
    config: Config,
    command: Option<CommandMode>,
}

lazy_static::lazy_static! {
    static ref FROZEN_SUFFIX: Regex = Regex::new(r"@@[a-f0-9]+$").unwrap();
    static ref PARSE_QCOW2: Regex = Regex::new("[.]qcow2$").unwrap();
}

pub(crate) fn is_frozen_image(filename: &str) -> bool {
    FROZEN_SUFFIX.is_match(filename)
}

pub(crate) fn strip_frozen_suffix(filename: &str) -> String {
    FROZEN_SUFFIX.replace(filename, "").to_string()
}

pub(crate) fn strip_qcow2_suffix(filename: &str) -> String {
    PARSE_QCOW2.replace(filename, "").to_string()
}

#[derive(Debug, Default)]
pub struct ImageCollection {
    images: BTreeMap<String, Image>,
}

impl ImageCollection {
    fn get(&self, key: &str) -> Option<&Image> {
        self.images.get(key)
    }

    fn iter_direct_sub(&self) -> std::collections::btree_map::Iter<'_, String, Image> {
        self.images.iter()
    }

    fn is_empty(&self) -> bool {
        self.images.is_empty()
    }

    fn find_by_name(&self, name: &str) -> Option<&Image> {
        // First check direct match at this level
        if let Some(image) = self.images.get(name) {
            return Some(image);
        }

        // Then search recursively in sub-collections
        for (_, image) in self.images.iter() {
            if let Some(found) = image.sub.find_by_name(name) {
                return Some(found);
            }
        }

        None
    }

    fn find_by_name_with_parents<'a>(&'a self, name: &str, v: &mut Vec<&'a Image>) -> bool {
        // First check direct match at this level
        if let Some(image) = self.images.get(name) {
            v.push(image);
            return true;
        }

        // Then search recursively in sub-collections
        for (_, image) in self.images.iter() {
            v.push(image);
            if image.sub.find_by_name_with_parents(name, v) {
                return true;
            }
            v.pop();
        }

        false
    }

    fn collect_all_images(&self) -> Vec<&Image> {
        let mut result = Vec::new();

        // Add all images at this level
        for (_, image) in self.images.iter() {
            result.push(image);

            // Recursively add images from sub-collections
            let mut sub_images = image.sub.collect_all_images();
            result.append(&mut sub_images);
        }

        result
    }
}

#[derive(Debug)]
pub struct Image {
    rel_path: PathBuf,
    pool_directory: PathBuf,
    vm_info: VMInfo,
    merged_vm_info: VMInfo,
    size_mb: u64,
    vm_using: Option<String>,
    sub: ImageCollection,
    frozen: bool,
}

impl VMInfo {
    fn merge(&mut self, vm_info: &VMInfo) {
        if let Some(username) = &vm_info.username {
            self.username = Some(username.clone())
        }

        self.changes.extend(vm_info.changes.clone());
    }
}

#[derive(Debug)]
struct VM {
    name: String,
    stats: crate::virsh::KVMStats,
}

#[derive(Debug, Clone)]
pub struct TagInfo {
    pub image_name: String,
    pub pool_name: String,
    pub shared: bool,
}

#[derive(Debug)]
pub struct Pool {
    images: ImageCollection,
    vms: BTreeMap<String, VM>,

    // Tag are just name aliases and they are managed by having
    // symlinks in the pool directory. See 'load_tags'.
    tags: HashMap<String, TagInfo>,    // tag_name -> TagInfo
    rev_tags: HashMap<String, String>, // image_name -> tag_name
}

pub struct GetInfo<'a> {
    image: &'a Image,
    vm: Option<&'a VM>,
}

impl Pool {
    pub fn get_by_name<'a>(&'a self, name: &str) -> Result<GetInfo<'a>, Error> {
        // Check if name is a tag, and use the image name if it is
        let lookup_name = if let Some(tag_info) = self.tags.get(name) {
            tag_info.image_name.as_str()
        } else {
            name
        };

        for try_name in [lookup_name.to_owned(), lookup_name.replace(".", "%")] {
            if let Some(image) = self.images.find_by_name(&try_name) {
                return Ok(GetInfo {
                    image,
                    vm: if let Some(vm_name) = &image.vm_using {
                        self.vms.get(vm_name)
                    } else {
                        None
                    },
                });
            }
        }

        return Err(Error::NotFound(name.to_owned()));
    }

    fn get_all_images(&self) -> Vec<&Image> {
        self.images.collect_all_images()
    }

    fn get_backing_chain_by_name(&self, name: &str) -> Result<Vec<&Image>, Error> {
        // Check if name is a tag, and use the image name if it is
        let lookup_name = if let Some(tag_info) = self.tags.get(name) {
            tag_info.image_name.as_str()
        } else {
            name
        };

        for try_name in [lookup_name.to_owned(), lookup_name.replace(".", "%")] {
            let mut chain = Vec::new();
            if self.images.find_by_name_with_parents(&try_name, &mut chain) {
                return Ok(chain);
            }
        }

        Err(Error::NotFound(name.to_owned()))
    }

    fn name_from_tag(&self, image: &Image) -> String {
        if image.frozen {
            let image_stem = image.rel_path.file_stem().unwrap().to_string_lossy();
            if let Some(tag_name) = self.rev_tags.get(&image_stem.to_string()) {
                return tag_name.clone();
            }
        }

        return strip_qcow2_suffix(&image.rel_path.to_string_lossy().into_owned());
    }
}

impl Image {
    fn get_filename(root_path: &PathBuf, path: &PathBuf) -> PathBuf {
        return root_path.join(path);
    }

    fn new(
        pool_directory: &PathBuf,
        path: &PathBuf,
        files_to_domains: &HashMap<PathBuf, String>,
    ) -> Result<Self, Error> {
        let abs_path = Self::get_filename(pool_directory, &path);

        // Check if this is a frozen image based on filename
        let filename = path.file_stem().unwrap_or_default().to_string_lossy();
        let is_frozen = is_frozen_image(&filename);

        let vm_using = files_to_domains.get(&abs_path).map(|x| (*x).to_owned());

        Ok(Image {
            sub: Default::default(),
            vm_using,
            size_mb: (std::fs::metadata(&abs_path)?.blocks() * 512) / (1024 * 1024),
            vm_info: Default::default(),
            merged_vm_info: Default::default(),
            rel_path: path.clone(),
            pool_directory: pool_directory.clone(),
            frozen: is_frozen,
        })
    }

    fn get_absolute_path(&self) -> PathBuf {
        self.pool_directory.join(&self.rel_path)
    }

    fn get_pool_name(&self, config: &Config) -> String {
        if self.pool_directory == config.pool_path {
            "main".to_string()
        } else if self.pool_directory == config.tmp_path {
            "tmp".to_string()
        } else {
            // Check named pools
            for pool in &config.pools {
                if self.pool_directory == pool.path {
                    return pool.name.clone();
                }
            }
            // Fallback to directory name if not found
            self.pool_directory
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string()
        }
    }
}

impl VMess {
    pub fn command(opt: &CommandArgs) -> Result<Self, Error> {
        let opt = (*opt).clone();
        Self::new(opt.config, Some(opt.command))
    }

    pub fn default() -> Result<Self, Error> {
        Self::new(None, None)
    }

    pub fn new(config_path: Option<PathBuf>, command: Option<CommandMode>) -> Result<Self, Error> {
        let config_path = if let Some(config) = &config_path {
            config.clone()
        } else {
            if let Ok(path) = std::env::var("VMESS_CONFIG_PATH") {
                PathBuf::from(path)
            } else {
                if let Some(dir) = dirs::config_dir() {
                    let fp = dir.join("vmess").join("config.toml");
                    let fp_2 = dir.join("vmess").join("config-0.2.toml"); // Transition period
                    if fp_2.exists() {
                        fp_2
                    } else {
                        fp
                    }
                } else {
                    return Err(Error::ConfigFile);
                }
            }
        };

        let mut settings = config::Config::default();
        settings
            .merge(config::File::new(config_path.to_str()
                    .ok_or_else(|| Error::ConfigFile)?,
                    config::FileFormat::Toml))?
            // Add in settings from the environment (with a prefix of APP)
            // Eg.. `APP_DEBUG=1 ./target/app` would set the `debug` key
            .merge(config::Environment::with_prefix("VMESS_ENV_CONFIG"))?;

        let mut config = settings.try_into::<Config>()?;

        config.pool_path = adjust_path_by_env(config.pool_path);

        config.tmp_path = PathBuf::try_from(
            config
                .tmp_path
                .into_os_string()
                .into_string()
                .unwrap()
                .replace("$USER", &std::env::var("USER").expect("USER not defined")),
        )
        .unwrap();

        let mut pools = vec![];
        for pool in config.pools {
            let path = PathBuf::try_from(
                pool.path
                    .into_os_string()
                    .into_string()
                    .unwrap()
                    .replace("$USER", &std::env::var("USER").expect("USER not defined")),
            )
            .unwrap();
            pools.push(NamedPoolPath {
                path,
                name: pool.name,
                shared: pool.shared,
            })
        }
        config.pools = pools;

        Ok(Self { command, config })
    }

    fn get_vm_prefix(&self) -> String {
        match self.config.multi_user {
            true => format!("{}-", std::env::var("USER").expect("USER not defined")),
            false => "".to_owned(),
        }
    }

    pub fn run(&mut self) -> Result<(), Error> {
        let command = match &self.command {
            Some(command) => command.clone(),
            None => return Ok(()),
        };

        match command {
            CommandMode::List(params) => {
                self.list(params)?;
            }
            CommandMode::Tree(params) => {
                self.tree(params)?;
            }
            CommandMode::Freeze(params) => {
                self.freeze(params)?;
            }
            CommandMode::Move(params) => {
                self.move_image(params)?;
            }
            CommandMode::Fork(params) => {
                self.fork(params)?;
            }
            CommandMode::Wait(params) => {
                self.wait(params)?;
            }
            CommandMode::New(params) => {
                self.new_image(params)?;
            }
            CommandMode::Exists(params) => {
                self.exists(params)?;
            }
            CommandMode::Kill(params) => {
                self.kill(params)?;
            }
            CommandMode::Start(params) => {
                self.start(params)?;
            }
            CommandMode::Stop(params) => {
                self.stop(params)?;
            }
            CommandMode::ShutdownWait(params) => {
                self.shutdown_wait(params)?;
            }
            CommandMode::Rename(params) => {
                self.rename(params)?;
            }
            CommandMode::Console(params) => {
                self.console(params)?;
            }
            CommandMode::Spawn(params) => {
                self.spawn(params)?;
            }
            CommandMode::Modify(params) => {
                self.modify(params)?;
            }
            CommandMode::Undefine(params) => {
                self.undefine(params)?;
            }
            CommandMode::Squash(params) => {
                self.squash(params)?;
            }
            CommandMode::UpdateSsh(params) => {
                self.update_ssh(params)?;
            }
            CommandMode::Nop => {}
        }

        Ok(())
    }

    pub fn image_full_basename(&self, full_name: impl AsRef<str>) -> PathBuf {
        let basename = full_name.as_ref().to_owned().replace(".", "%");
        self.config.pool_path.join(basename)
    }

    pub fn get_config(&self) -> &Config {
        &self.config
    }

    pub fn get_pool(&self) -> Result<Pool, Error> {
        self.get_pool_detailed(true)
    }

    pub fn get_pool_no_vms(&self) -> Result<Pool, Error> {
        self.get_pool_detailed(false)
    }

    /// Ensure all images in the backing chain have symlinks in pool_path
    fn ensure_backing_chain_symlinks(&self, backing_chain: &[&Image]) -> Result<(), Error> {
        for image in backing_chain.iter() {
            if image.pool_directory != self.config.pool_path {
                let target_path = image.get_absolute_path();
                let symlink_path = self.config.pool_path.join(&image.rel_path);

                let needs_creation = if symlink_path.is_symlink() {
                    // Check if it's a symlink and if it points to the correct target
                    match std::fs::read_link(&symlink_path) {
                        Ok(current_target) => current_target != target_path,
                        Err(_) => {
                            // Not a symlink or can't read it, remove and recreate
                            std::fs::remove_file(&symlink_path).ok();
                            true
                        }
                    }
                } else {
                    true
                };

                if needs_creation {
                    std::fs::create_dir_all(&image.pool_directory)?;
                    std::os::unix::fs::symlink(&target_path, &symlink_path).with_context(|| {
                        format!(
                            "Failed to create symlink from {} to {}",
                            target_path.display(),
                            symlink_path.display()
                        )
                    })?;
                    info!(
                        "Created symlink: {} -> {}",
                        symlink_path.display(),
                        target_path.display()
                    );
                }
            }
        }
        Ok(())
    }

    pub fn get_image_prep_lock_path(&self, image: &str) -> Result<PathBuf, Error> {
        // The VM image does not need to exist. This is used for lock coordination.
        //
        // We will create <image>.lock in the shared pool if it is defined, otherwise
        // we will create it in the main pool.

        // Use the first shared pool if available, otherwise use main pool
        let lock_dir = if let Some(shared_pool) = self.config.pools.iter().find(|p| p.shared) {
            &shared_pool.path
        } else {
            &self.config.pool_path
        };

        let lock_filename = format!("{}.lock", image);
        Ok(lock_dir.join(lock_filename))
    }

    pub fn get_pool_detailed(&self, with_vm_list: bool) -> Result<Pool, Error> {
        let mut pool = Pool {
            images: Default::default(),
            vms: Default::default(),
            tags: HashMap::new(),
            rev_tags: HashMap::new(),
        };

        let mut files_to_domains = HashMap::new();
        let vmname_prefix = self.get_vm_prefix();

        if with_vm_list {
            // First, collect all VM names that match our prefix
            let mut vm_names = Vec::new();
            for line in ibash_stdout!("virsh list --all --name")
                .with_context(|| format!("during virsh list"))?
                .lines()
            {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                let vmname = line;
                if vmname.starts_with(&vmname_prefix) {
                    vm_names.push(vmname.to_string());
                }
            }

            // Get comprehensive stats for all VMs in one call
            let all_stats = get_all_stats()?;

            // Now process each VM with the pre-collected stats
            for vmname in vm_names {
                let short_vmname = &vmname[vmname_prefix.len()..];

                if let Some(stats) = all_stats.get(&vmname) {
                    // Add block device paths to files_to_domains mapping
                    for path_str in &stats.block_paths {
                        let path = PathBuf::from(path_str);
                        files_to_domains.insert(path.clone(), short_vmname.to_owned());

                        // If this is a symlink, also add the target path
                        if let Ok(target) = std::fs::canonicalize(&path) {
                            if target != path {
                                files_to_domains.insert(target, short_vmname.to_owned());
                            }
                        }
                    }

                    // Create VM with stats
                    let vm = VM {
                        name: short_vmname.to_owned(),
                        stats: stats.clone(),
                    };

                    pool.vms.insert(short_vmname.to_owned(), vm);
                }
            }
        }

        let pool_path = &self.config.pool_path;

        // Collect all lookup paths: pool_path, tmp_path, and pools
        let mut lookup_paths = vec![pool_path.clone(), self.config.tmp_path.clone()];
        for shared_pool in &self.config.pools {
            lookup_paths.push(shared_pool.path.clone());
        }

        // First, collect all qcow2 files and build backing chains
        let mut backing_chains: Vec<_> = Vec::new();

        for lookup_path in &lookup_paths {
            for entry in std::fs::read_dir(&lookup_path)
                .with_context(|| format!("reading directory {}", lookup_path.display()))?
            {
                let entry = entry.with_context(|| format!("during entry resolve"))?;
                let name = entry.file_name();
                let name = name.to_string_lossy();
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }

                // Check if it's a qcow2 file
                if name.ends_with(".qcow2") || name.ends_with(".qcow") {
                    // Get the backing chain for this file
                    match get_qcow2_backing_chain(&path, &lookup_paths) {
                        Ok(chain_info) => {
                            backing_chains.push(chain_info);
                        }
                        Err(_) => {
                            // If we can't read the backing chain, skip this image entirely
                        }
                    }
                }
            }
        }

        // Now build the image hierarchy based on actual backing relationships
        for chain_info in backing_chains.iter() {
            // Build locations map from the new chain structure for compatibility
            let mut locations_map: std::collections::HashMap<PathBuf, Vec<PathBuf>> =
                std::collections::HashMap::new();
            for layer in &chain_info.chain {
                let abs_path = layer.real_location.join(&layer.basename);
                locations_map.insert(layer.basename.clone(), vec![abs_path.clone()]);
                locations_map.insert(
                    abs_path.clone(),
                    vec![layer.real_location.join(&layer.basename)],
                );
            }

            // Process entire chain uniformly, from root (last) to leaf (first)
            let mut merged_vm_info = VMInfo::default();

            let mut current_image = &mut pool.images;
            for layer in chain_info.chain.iter().rev() {
                let current_name_raw = layer.basename.file_stem().unwrap().to_string_lossy();
                let current_name_full = current_name_raw.to_string();
                let json_base = &current_name_full;
                let json_path = layer
                    .real_location
                    .join(PathBuf::from(format!("{}.json", json_base)));

                let current_vm_info;
                if json_path.exists() {
                    current_vm_info = read_json_path(&json_path).with_context(|| {
                        format!("during merging of json {}", json_path.display())
                    })?;
                    merged_vm_info.merge(&current_vm_info);
                } else {
                    current_vm_info = Default::default();
                };

                let key = layer.basename.to_string_lossy().into_owned();
                let key = strip_qcow2_suffix(&key);

                // Create or update the image
                let ret = match current_image.images.entry(key.to_owned()) {
                    btree_map::Entry::Vacant(v) => {
                        let image_res =
                            Image::new(&layer.real_location, &layer.basename, &files_to_domains);
                        let mut image = match image_res {
                            Ok(image) => image,
                            Err(err) => {
                                warn!(
                                    "error {} during image resolve of path {}",
                                    err,
                                    layer.real_location.join(&layer.basename).display()
                                );
                                break;
                            }
                        };
                        image.vm_info = current_vm_info;
                        image.merged_vm_info = merged_vm_info.clone();
                        v.insert(image)
                    }
                    btree_map::Entry::Occupied(o) => o.into_mut(),
                };

                current_image = &mut ret.sub;
            }
        }

        // Build a mapping from path to pool name for load_tags
        let mut path_to_pool = std::collections::HashMap::new();
        path_to_pool.insert(self.config.pool_path.clone(), ("main".to_string(), false));
        path_to_pool.insert(self.config.tmp_path.clone(), ("tmp".to_string(), false));
        for pool in &self.config.pools {
            path_to_pool.insert(pool.path.clone(), (pool.name.clone(), pool.shared));
        }

        pool.load_tags(lookup_paths, path_to_pool)?;

        Ok(pool)
    }

    pub fn list(&mut self, params: List) -> Result<(), Error> {
        let pool = self
            .get_pool()
            .with_context(|| format!("during get_pool"))?;

        use indexmap::IndexSet;
        use prettytable::{format, Cell, Row, Table};
        let filter_expr =
            query::Expr::parse_cmd(&params.filter).with_context(|| format!("during parse cmd"))?;

        let mut table = Table::new();
        table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);

        #[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Debug, EnumIter)]
        enum Column {
            Name,
            Pool,
            State,
            MemUsage,
            DiskUsage,
        }

        let mut hm = HashMap::new();
        for field in Column::iter() {
            hm.insert(format!("{:?}", field), field);
        }

        let mut columns = indexmap::IndexSet::new();
        match params.fields {
            Some(s) => {
                for s in s.split(",") {
                    match hm.remove(s) {
                        Some(x) => {
                            columns.insert(x);
                        }
                        None => {}
                    }
                }
            }
            None => {
                columns.insert(Column::Name);
                columns.insert(Column::Pool);
                columns.insert(Column::State);
                columns.insert(Column::MemUsage);
                columns.insert(Column::DiskUsage);
            }
        }

        if !params.no_headers {
            table.set_titles(Row::new(
                columns
                    .iter()
                    .map(|x| Cell::new(&ron::ser::to_string(x).expect("serialization")))
                    .collect(),
            ));
        }

        fn by_image(
            columns: &IndexSet<Column>,
            config: &Config,
            table: &mut Table,
            pool: &Pool,
            image: &Image,
            path: String,
            filter_expr: &query::Expr,
        ) {
            let pool_name = image.get_pool_name(config);

            let (vm_state, mem_size) = if let Some(vm_using) = &image.vm_using {
                if let Some(vm) = pool.vms.get(vm_using) {
                    use crate::virsh::VirDomainState;
                    let state = &vm.stats.state;

                    let mem_size = if *state == VirDomainState::Running {
                        vm.stats
                            .mem_current
                            .map(|mem_kib| {
                                Cow::from(format!("{:.2} GB", mem_kib as f32 / 1024.0 / 1024.0))
                            })
                            .unwrap_or(Cow::from(""))
                    } else {
                        Cow::from("")
                    };
                    (
                        match state {
                            VirDomainState::Running => "running",
                            VirDomainState::Shutoff => "shut off",
                            VirDomainState::Paused => "paused",
                            VirDomainState::Shutdown => "shutting down",
                            VirDomainState::Crashed => "crashed",
                            VirDomainState::Blocked => "blocked",
                            VirDomainState::PmSuspended => "suspended",
                            VirDomainState::NoState => "",
                            VirDomainState::Unknown => "unknown",
                        },
                        mem_size,
                    )
                } else {
                    ("", Cow::from(""))
                }
            } else {
                ("", Cow::from(""))
            };

            let disk_size = format!("{:.2} GB", image.size_mb as f32 / 1024.0);

            let mut row = Row::empty();
            for column in columns {
                let s = match column {
                    Column::Name => path.as_str(),
                    Column::Pool => pool_name.as_str(),
                    Column::State => vm_state,
                    Column::MemUsage => mem_size.as_ref(),
                    Column::DiskUsage => disk_size.as_str(),
                };
                row.add_cell(Cell::new(s));
            }

            let mi = MatchInfo {
                vm_state: match vm_state {
                    "running" => Some(VMState::Running),
                    "shut off" => Some(VMState::Stopped),
                    _ => None,
                },
                name: &path,
            };

            if filter_expr.match_info(&mi) {
                table.add_row(row);
            }

            // Don't recurse into sub-images to avoid duplicates
            // Each image in pool.images represents a complete image chain
        }

        for image in pool.get_all_images() {
            // Generate display name for this image (remove .qcow2 extension)
            let image_stem = image.rel_path.file_stem().unwrap().to_string_lossy();
            let image_name = strip_frozen_suffix(&image_stem).replace('%', ".");

            // Skip frozen images that have no tags pointing to them unless --all is specified
            if image.frozen && !params.all {
                if !pool.rev_tags.contains_key(&image_stem.to_string()) {
                    continue;
                }
            }

            // For frozen images, use the tag name if available, otherwise use the image name
            let display_name = if image.frozen {
                if let Some(tag_name) = pool.rev_tags.get(&image_stem.to_string()) {
                    tag_name.clone()
                } else {
                    image_name
                }
            } else {
                image_name
            };

            by_image(
                &columns,
                &self.config,
                &mut table,
                &pool,
                image,
                display_name,
                &filter_expr,
            );
        }

        table.print_tty(false)?;

        Ok(())
    }

    pub fn tree(&mut self, params: Tree) -> Result<(), Error> {
        let pool = self
            .get_pool()
            .with_context(|| format!("during get_pool"))?;

        let filter_expr =
            query::Expr::parse_cmd(&params.filter).with_context(|| format!("during parse cmd"))?;

        fn print_image_tree(
            image_collection: &ImageCollection,
            pool: &Pool,
            config: &Config,
            filter_expr: &query::Expr,
            prefix: &str,
            _is_last: bool,
        ) {
            let images: Vec<_> = image_collection.iter_direct_sub().collect();

            for (i, (_name, image)) in images.iter().enumerate() {
                let is_last_item = i == images.len() - 1;

                // Generate display name for this image
                let image_name = image.rel_path.file_stem().unwrap().to_string_lossy();

                // Check if this image matches the filter
                let (vm_state, vm_info) = if let Some(vm_using) = &image.vm_using {
                    if let Some(vm) = pool.vms.get(vm_using) {
                        let vm_state = match vm.stats.state {
                            VirDomainState::Running => Some(crate::query::VMState::Running),
                            VirDomainState::Shutoff => Some(crate::query::VMState::Stopped),
                            _ => None,
                        };
                        let state_str = match vm.stats.state {
                            VirDomainState::Running => "running",
                            VirDomainState::Shutoff => "shut off",
                            VirDomainState::Paused => "paused",
                            VirDomainState::Shutdown => "shutting down",
                            VirDomainState::Crashed => "crashed",
                            VirDomainState::Blocked => "blocked",
                            VirDomainState::PmSuspended => "suspended",
                            VirDomainState::NoState => "",
                            VirDomainState::Unknown => "unknown",
                        };
                        (vm_state, format!(" ({})", state_str))
                    } else {
                        (None, String::new())
                    }
                } else {
                    (None, String::new())
                };

                let mi = crate::query::MatchInfo {
                    vm_state,
                    name: &image_name,
                };

                if filter_expr.match_info(&mi) {
                    // Print tree structure symbols
                    let current_prefix = if is_last_item {
                        format!("{}└── ", prefix)
                    } else {
                        format!("{}├── ", prefix)
                    };

                    // Print image info
                    let frozen_indicator = if image.frozen { " [FROZEN]" } else { "" };
                    let disk_size = format!("{:.2} GB", image.size_mb as f32 / 1024.0);
                    let pool_name = image.get_pool_name(config);
                    let tag_info = if let Some(tag) = pool.rev_tags.get(&image_name.to_string()) {
                        format!(" [tag: {}]", tag)
                    } else {
                        String::new()
                    };

                    let changes_info = if !image.vm_info.changes.is_empty() {
                        format!(" [changes: {}]", image.vm_info.changes.join(", "))
                    } else {
                        String::new()
                    };

                    println!(
                        "{}{}{}{}{}{}{}{}",
                        current_prefix,
                        image_name,
                        tag_info,
                        format!(" ({})", disk_size),
                        format!(" [pool: {}]", pool_name),
                        vm_info,
                        changes_info,
                        frozen_indicator
                    );
                }

                // Recursively print sub-images
                if !image.sub.is_empty() {
                    let next_prefix = if is_last_item {
                        format!("{}    ", prefix)
                    } else {
                        format!("{}│   ", prefix)
                    };

                    print_image_tree(&image.sub, pool, config, filter_expr, &next_prefix, true);
                }
            }
        }

        println!("VM Image Tree:");
        print_image_tree(&pool.images, &pool, &self.config, &filter_expr, "", true);

        // Display loaded tags
        if !pool.tags.is_empty() {
            println!("\nLoaded Tags:");
            for (tag_name, tag_info) in &pool.tags {
                println!(
                    "  {} -> {} [pool: {}]",
                    tag_name, tag_info.image_name, tag_info.pool_name
                );
            }
        }

        Ok(())
    }

    pub fn freeze(&self, params: Freeze) -> Result<(), Error> {
        use sha2::{Digest, Sha256};
        use std::io::Read;

        let pool = self
            .get_pool()
            .with_context(|| format!("during get_pool"))?;

        let existing = pool.get_by_name(&params.name)?;

        // Check if already frozen
        if existing.image.frozen {
            info!("Image {} is already frozen", params.name);
            return Ok(());
        }

        // Check if there are subimages
        if !existing.image.sub.is_empty() {
            return Err(Error::HasSubImages(params.name.clone(), "freeze"));
        }

        // Check VM state - must be undefined for freezing
        if let Some(vm) = &existing.vm {
            let vm_is_running = vm.stats.state == VirDomainState::Running;

            match params.force.as_deref() {
                Some("stop") => {
                    if vm_is_running {
                        info!("Stopping VM {} before freeze", params.name);
                        self.stop(Stop {
                            name: params.name.clone(),
                        })?;
                    }
                    info!("Undefining VM {} before freeze", params.name);
                    self.undefine(Undefine {
                        names: vec![params.name.clone()],
                    })?;
                }
                Some("while-running") => {
                    info!(
                        "Freezing while VM {} is running (VM will remain defined)",
                        params.name
                    );
                    // Continue with freeze process
                }
                None => {
                    if vm_is_running {
                        return Err(Error::FreeText(format!(
                            "Cannot freeze {} - VM is running. Use --force=stop-undefine or --force=while-running",
                            params.name
                        )));
                    } else {
                        return Err(Error::FreeText(format!(
                            "Cannot freeze {} - VM is defined but not running. Use --force=stop-undefine to undefine it first, or --force=while-running to freeze anyway",
                            params.name
                        )));
                    }
                }
                Some(other) => {
                    return Err(Error::FreeText(format!(
                        "Invalid force option '{}'. Use 'stop-undefine' or 'while-running'",
                        other
                    )));
                }
            }
        }

        let image_path = existing.image.get_absolute_path();
        let image_name_stem = existing
            .image
            .rel_path
            .file_stem()
            .unwrap()
            .to_string_lossy();

        // Calculate SHA256 hash
        let should_copy_while_running = if let Some(vm) = &existing.vm {
            vm.stats.state == VirDomainState::Running
                && params.force.as_deref() == Some("while-running")
        } else {
            false
        };

        let hash_hex = if should_copy_while_running {
            // Copy image to temporary file first
            let temp_path = existing
                .image
                .pool_directory
                .join(format!(".tmp-freeze.{}.qcow2.tmp", image_name_stem));
            info!("Creating temporary copy for running VM");

            std::fs::copy(&image_path, &temp_path)
                .with_context(|| format!("Failed to copy image to temp file"))?;

            // Calculate hash of the temporary copy
            let mut file = std::fs::File::open(&temp_path)?;
            let mut hasher = Sha256::new();
            let mut buffer = [0; 8192];
            loop {
                let bytes_read = file.read(&mut buffer)?;
                if bytes_read == 0 {
                    break;
                }
                hasher.update(&buffer[..bytes_read]);
            }
            let hash = hasher.finalize();
            let hash_hex = format!("{:x}", hash);

            // Remove temp file after hashing
            std::fs::remove_file(&temp_path)?;

            hash_hex
        } else {
            // Calculate hash of the original file
            let mut file = std::fs::File::open(&image_path)?;
            let mut hasher = Sha256::new();
            let mut buffer = [0; 8192];
            loop {
                let bytes_read = file.read(&mut buffer)?;
                if bytes_read == 0 {
                    break;
                }
                hasher.update(&buffer[..bytes_read]);
            }
            let hash = hasher.finalize();
            format!("{:x}", hash)
        };

        // Create new frozen filename
        let frozen_name = format!("{}@@{}.qcow2", image_name_stem, hash_hex);
        let frozen_path = existing.image.pool_directory.join(&frozen_name);

        info!("Freezing {} -> {}", params.name, frozen_name);

        // Rename the image file
        std::fs::rename(&image_path, &frozen_path)
            .with_context(|| format!("Failed to rename image to frozen filename"))?;

        // Also rename the corresponding JSON file if it exists
        let json_name = format!("{}.json", image_name_stem);
        let json_path = existing.image.pool_directory.join(&json_name);
        if json_path.exists() {
            let frozen_json_name = format!("{}@@{}.json", image_name_stem, hash_hex);
            let frozen_json_path = existing.image.pool_directory.join(&frozen_json_name);
            std::fs::rename(&json_path, &frozen_json_path)
                .with_context(|| format!("Failed to rename JSON file to frozen filename"))?;
        }

        // Create a tag symlink to the frozen image
        let tag_symlink_path = existing
            .image
            .pool_directory
            .join(format!("{}.qcow2", params.name));
        if let Err(e) = std::os::unix::fs::symlink(&frozen_name, &tag_symlink_path) {
            warn!("Failed to create tag symlink: {}", e);
        } else {
            info!("Created tag '{}' pointing to frozen image", params.name);
        }

        info!(
            "Successfully frozen image {} with hash {}",
            params.name,
            &hash_hex[..8]
        );
        Ok(())
    }

    pub fn squash(&mut self, params: Squash) -> Result<(), Error> {
        use crate::utils::get_qcow2_backing_chain;
        use log::{info, warn};

        let pool = self.get_pool()?;

        // Check that the source image exists
        let source_info = pool.get_by_name(&params.source)?;

        // Check that destination doesn't already exist
        if pool.get_by_name(&params.destination).is_ok() {
            return Err(Error::FreeText(format!(
                "Destination image '{}' already exists",
                params.destination
            )));
        }

        // Check that there's no tag with the destination name
        if pool.tags.contains_key(&params.destination) {
            return Err(Error::FreeText(format!(
                "Tag '{}' already exists",
                params.destination
            )));
        }

        let source_path = source_info.image.get_absolute_path();
        let dest_path = source_info
            .image
            .pool_directory
            .join(format!("{}.qcow2", params.destination));

        info!(
            "Squashing {} to {}",
            source_path.display(),
            dest_path.display()
        );

        // Use qemu-img convert to create independent qcow2
        let output = std::process::Command::new("qemu-img")
            .args(&[
                "convert",
                "-m",
                "16",
                "-p",
                "-c",
                "-W",
                "-O",
                "qcow2",
                &source_path.to_string_lossy(),
                &dest_path.to_string_lossy(),
            ])
            .output()
            .with_context(|| "Failed to execute qemu-img convert".to_string())?;

        if !output.status.success() {
            return Err(Error::FreeText(format!(
                "qemu-img convert failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        // Merge VMInfo from entire backing chain
        let lookup_paths = vec![source_info.image.pool_directory.clone()];
        let mut merged_vm_info = VMInfo::default();

        match get_qcow2_backing_chain(&source_path, &lookup_paths) {
            Ok(chain_info) => {
                info!(
                    "Merging VMInfo from {} layers in backing chain",
                    chain_info.chain.len()
                );

                // Merge VMInfo from each layer in the chain (starting from the root)
                for layer in chain_info.chain.iter().rev() {
                    let layer_name_raw = layer.basename.file_stem().unwrap().to_string_lossy();
                    let json_path = layer.real_location.join(format!("{}.json", layer_name_raw));

                    if json_path.exists() {
                        match read_json_path(&json_path) {
                            Ok(layer_vm_info) => {
                                info!("Merging VMInfo from layer: {}", layer.basename.display());
                                merged_vm_info.merge(&layer_vm_info);
                            }
                            Err(e) => {
                                warn!("Failed to read VMInfo from {}: {}", json_path.display(), e);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                warn!(
                    "Failed to get backing chain for {}: {}",
                    source_path.display(),
                    e
                );
            }
        }

        // Write merged VMInfo to the new squashed image's JSON file
        let dest_json_path = source_info
            .image
            .pool_directory
            .join(format!("{}.json", params.destination));
        write_json_path(&dest_json_path, &merged_vm_info)
            .with_context(|| format!("writing VMInfo to {}", dest_json_path.display()))?;

        info!(
            "Successfully squashed {} to {} with merged VMInfo",
            params.source, params.destination
        );
        Ok(())
    }

    pub fn move_image(&self, params: Move) -> Result<(), Error> {
        use std::process;

        let pool = self.get_pool()?;

        // Check that the source image exists
        let existing = pool.get_by_name(&params.image)?;

        // Validate the target pool exists and is shared
        let target_pool = self
            .config
            .pools
            .iter()
            .find(|p| p.name == params.pool)
            .ok_or_else(|| Error::InvalidPoolName(params.pool.clone()))?;

        if !target_pool.shared {
            return Err(Error::FreeText(format!(
                "Target pool '{}' should be a shared one.",
                params.pool
            )));
        }

        // Check that the image is in the main pool or tmp pool (not in a shared pool)
        let is_in_main_pool = existing.image.pool_directory == self.config.pool_path;
        let is_in_tmp_pool = existing.image.pool_directory == self.config.tmp_path;

        if !is_in_main_pool && !is_in_tmp_pool {
            return Err(Error::FreeText(format!(
                "Image '{}' is in a shared pool. Only images from the main pool or tmp pool can be moved.",
                params.image
            )));
        }

        // Check that the image is frozen before moving to shared pool
        if !existing.image.frozen {
            return Err(Error::FreeText(format!(
                "Image '{}' is not frozen. Only frozen images can be moved to shared pools.",
                params.image
            )));
        }

        // Get the backing chain and validate all images are in the target shared pool
        let backing_chain = pool.get_backing_chain_by_name(&params.image)?;

        for image in &backing_chain {
            // Skip the first image (the one we're moving)
            if image.rel_path == existing.image.rel_path {
                continue;
            }

            // Check if this backing image is already in the target shared pool
            if image.pool_directory != target_pool.path {
                return Err(Error::FreeText(format!(
                    "Cannot move image '{}' because its backing chain image '{}' is not in the target shared pool '{}'. All backing chain images must be in the target shared pool before moving.",
                    params.image,
                    image.rel_path.display(),
                    params.pool
                )));
            }
        }

        info!(
            "Moving image '{}' to shared pool '{}'",
            params.image, params.pool
        );

        // Create temporary directory with PID and hostname
        let hostname = std::env::var("HOSTNAME")
            .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
            .unwrap_or_else(|_| "unknown".to_string());
        let pid = process::id();
        let tmp_dir_name = format!(".tmp.{}.{}", pid, hostname);
        let tmp_dir = target_pool.path.join(&tmp_dir_name);

        // Create temporary directory
        std::fs::create_dir_all(&tmp_dir).with_context(|| {
            format!("Failed to create temporary directory {}", tmp_dir.display())
        })?;

        info!("Created temporary directory: {}", tmp_dir.display());

        // Move the specific image to temporary directory
        let source_path = existing.image.get_absolute_path();
        let tmp_path = tmp_dir.join(&existing.image.rel_path);

        info!("Moving {} to temporary location", source_path.display());

        // Try hard link first, fallback to copy
        if let Err(_) = std::fs::hard_link(&source_path, &tmp_path) {
            info!("Hard link failed, copying file instead");
            std::fs::copy(&source_path, &tmp_path).with_context(|| {
                format!(
                    "Failed to copy {} to {}",
                    source_path.display(),
                    tmp_path.display()
                )
            })?;
        } else {
            info!("Successfully hard linked file");
        }

        // Move file from temporary directory to final location
        let final_path = target_pool.path.join(&existing.image.rel_path);

        // Ensure parent directory exists
        if let Some(parent) = final_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::rename(&tmp_path, &final_path).with_context(|| {
            format!(
                "Failed to move {} to final location {}",
                tmp_path.display(),
                final_path.display()
            )
        })?;

        info!("Moved {} to {}", tmp_path.display(), final_path.display());

        // Move the corresponding JSON file if it exists
        let image_stem = existing
            .image
            .rel_path
            .file_stem()
            .unwrap()
            .to_string_lossy();
        let source_json_path = existing
            .image
            .pool_directory
            .join(format!("{}.json", image_stem));

        if source_json_path.exists() {
            let target_json_path = target_pool.path.join(format!("{}.json", image_stem));

            // Ensure parent directory exists for JSON file
            if let Some(parent) = target_json_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            // Try hard link first for JSON file, fallback to copy
            if let Err(_) = std::fs::hard_link(&source_json_path, &target_json_path) {
                info!("Hard link failed for JSON file, copying instead");
                std::fs::copy(&source_json_path, &target_json_path).with_context(|| {
                    format!(
                        "Failed to copy JSON file {} to {}",
                        source_json_path.display(),
                        target_json_path.display()
                    )
                })?;
            } else {
                info!("Successfully hard linked JSON file");
            }

            // Remove source JSON file after successful copy/link
            std::fs::remove_file(&source_json_path).with_context(|| {
                format!(
                    "Failed to remove source JSON file {}",
                    source_json_path.display()
                )
            })?;

            info!(
                "Moved JSON file {} to {}",
                source_json_path.display(),
                target_json_path.display()
            );
        } else {
            info!("No JSON file found for image '{}'", image_stem);
        }

        // Recreate tag symlinks in target pool if they exist
        if let Some(tag_name) = pool.rev_tags.get(&image_stem.to_string()) {
            let new_tag_path = target_pool.path.join(format!("{}.qcow2", tag_name));

            // Create symlink in target pool
            if let Err(e) = std::os::unix::fs::symlink(&existing.image.rel_path, &new_tag_path) {
                warn!("Failed to create tag symlink in target pool: {}", e);
            } else {
                info!("Created tag '{}' in target pool", tag_name);
            }
        }

        // Remove original file
        std::fs::remove_file(&source_path)
            .with_context(|| format!("Failed to remove original file {}", source_path.display()))?;
        info!("Removed original file: {}", source_path.display());

        // Remove original tag symlink
        if let Some(tag_name) = pool.rev_tags.get(&image_stem.to_string()) {
            let old_tag_path = existing
                .image
                .pool_directory
                .join(format!("{}.qcow2", tag_name));
            if old_tag_path.is_symlink() {
                if let Err(e) = std::fs::remove_file(&old_tag_path) {
                    warn!("Failed to remove original tag symlink: {}", e);
                } else {
                    info!("Removed original tag symlink: {}", old_tag_path.display());
                }
            }
        }

        // Try to remove temporary directory
        if let Err(e) = std::fs::remove_dir(&tmp_dir) {
            warn!(
                "Failed to remove temporary directory {}: {}",
                tmp_dir.display(),
                e
            );
        } else {
            info!("Removed temporary directory: {}", tmp_dir.display());
        }

        info!(
            "Successfully moved image '{}' to shared pool '{}'",
            params.image, params.pool
        );

        Ok(())
    }

    pub fn move_to(&mut self, image: &str, pool: &str) -> Result<(), Error> {
        self.move_image(Move {
            image: image.to_string(),
            pool: pool.to_string(),
        })
    }

    fn get_template(&self, name: &str) -> Result<Element, Error> {
        let filename = self
            .config
            .pool_path
            .join(format!("templates/{}.xml", name));
        if !filename.exists() {
            return Err(Error::TemplateDoesntExist(name.to_owned()));
        }

        let mut file = std::fs::File::open(filename)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        Ok(Element::parse(contents.as_bytes())?)
    }

    fn modify_xml_using_overrides(
        xml: &mut Element,
        overrides: &Overrides,
        fullname: &str,
    ) -> Result<(), Error> {
        if let Some(given_memory) = overrides.memory_gb {
            if let Some(memory) = xml.get_mut_child("memory") {
                memory
                    .attributes
                    .insert("unit".to_owned(), "KiB".to_owned());
                memory.children[0] =
                    XMLNode::Text(format!("{}", given_memory as u64 * 0x100000u64));
            }
            if let Some(memory) = xml.get_mut_child("currentMemory") {
                memory
                    .attributes
                    .insert("unit".to_owned(), "KiB".to_owned());
                memory.children[0] =
                    XMLNode::Text(format!("{}", given_memory as u64 * 0x100000u64));
            }
        }

        if let Some(nr_cpus) = overrides.nr_cpus {
            if let Some(vcpu) = xml.get_mut_child("vcpu") {
                vcpu.children[0] = XMLNode::Text(format!("{}", nr_cpus));
            }
        }

        if let Some(_) = &overrides.cdrom {
            if let Some(os) = xml.get_mut_child("os") {
                if let Some(boot) = os.get_mut_child("boot") {
                    boot.attributes.insert("dev".to_owned(), "cdrom".to_owned());
                }
            }
        }

        if let Some(_) = &overrides.usb {
            if let Some(os) = xml.get_mut_child("os") {
                if let Some(_boot) = os.take_child("boot") {
                    // So we use the boot order.
                }
            }
        }

        if overrides.uefi {
            if let Some(os) = xml.get_mut_child("os") {
                let code = if overrides.secure_boot {
                    ".secboot"
                } else {
                    ".cc"
                };
                let vars = if overrides.secure_boot {
                    ".secboot."
                } else {
                    "."
                };
                let attr = if overrides.secure_boot {
                    " secure='yes' "
                } else {
                    " "
                };
                let sb = if overrides.secure_boot { "yes" } else { "no" };
                let autoselection =
                    is_version_at_least(&ibash_stdout!("virsh --version")?, &[8, 6]);
                let new_elem = if autoselection {
                    format!(
                        r#"
    <os>
        <firmware>
          <feature enabled="{sb}" name="enrolled-keys"/>
          <feature enabled="{sb}" name="secure-boot"/>
        </firmware>
        <bootmenu enable='yes'/>
    </os>
    "#
                    )
                } else {
                    format!(
                        r#"
    <os>
        <firmware>
          <feature enabled='yes' name='enrolled-keys'/>
          <feature enabled='yes' name='secure-boot'/>
        </firmware>
        <loader readonly='yes' {attr} type='pflash'>/usr/share/edk2/ovmf/OVMF_CODE{code}.fd</loader>
        <nvram template='/usr/share/edk2/ovmf/OVMF_VARS{vars}fd'>/var/lib/libvirt/qemu/nvram/{fullname}_VARS.fd</nvram>
        <bootmenu enable='yes'/>
    </os>
    "#
                    )
                };
                let elem = Element::parse(new_elem.as_bytes())?;
                for child in elem.children.into_iter() {
                    os.children.push(child);
                }

                if autoselection {
                    os.attributes
                        .insert("firmware".to_owned(), "efi".to_owned());
                }
            }
            if let Some(features) = xml.get_mut_child("features") {
                let new_elem = format!(
                    r#"
                    <smm state='on'/>
    "#,
                );
                let elem = Element::parse(new_elem.as_bytes())?;
                features.children.push(XMLNode::Element(elem));
            }
        }

        if overrides.stop_on_reboot {
            let _ = xml.take_child("on_reboot");

            let new_elem = format!(r#"<on_reboot>destroy</on_reboot>"#,);
            let elem = Element::parse(new_elem.as_bytes())?;
            xml.children.push(XMLNode::Element(elem));
        }

        if let Some(devices) = xml.get_mut_child("devices") {
            // Remove existing host devices
            while let Some(_netdev) = devices.take_child("netdevs") {}

            if let Some(cdrom) = &overrides.cdrom {
                let cdrom = cdrom.display();
                let new_elem = format!(
                    r#"
    <disk type="file" device="cdrom">
      <driver name="qemu" type="raw"/>
      <source file="{cdrom}"/>
      <target dev="sda" bus="sata"/>
      <readonly/>
      <address type="drive" controller="0" bus="0" target="0" unit="0"/>
    </disk>
    "#,
                );
                let elem = Element::parse(new_elem.as_bytes())?;
                devices.children.push(XMLNode::Element(elem));
            }

            if let Some(usb) = &overrides.usb {
                let usb = usb.display();
                let new_elem = format!(
                    r#"
    <disk type="file" device="disk">
      <driver name="qemu" type="raw"/>
      <source file="{usb}"/>
      <target dev="sda" bus="usb"/>
      <address type='usb' bus='0' port='4'/>
      <boot order='1'/>
    </disk>
    "#,
                );
                let elem = Element::parse(new_elem.as_bytes())?;
                devices.children.push(XMLNode::Element(elem));
            }

            for netdev in &overrides.netdevs {
                if netdev.starts_with("pool:") {
                    let netdev = &netdev[5..];
                    let mut model = "".to_owned();
                    let mut mac_address = "".to_owned();
                    let mut network = "";

                    for part in netdev.split(",") {
                        if part.starts_with("model:") {
                            let model_type = &part[6..];
                            model = format!("<model type='{model_type}'/>");
                        } else if part.starts_with("mac:") {
                            let part_mac_address = &part[4..];
                            mac_address = format!("<mac address='{part_mac_address}'/>");
                        } else {
                            network = part;
                        }
                    }
                    let new_elem = format!(
                        r#"
  <interface type='network'>
    {model}
    {mac_address}
    <source network='{network}' />
  </interface>
    "#,
                    );
                    let elem = Element::parse(new_elem.as_bytes())?;
                    devices.children.push(XMLNode::Element(elem));
                } else if let Some((host, guest)) = netdev.split_once("/") {
                    lazy_static! {
                        static ref BUS_SLOT: Regex =
                            Regex::new(r"^([0-9a-f]+):([0-9a-f]+)[.]([0-9a-f]+)$").unwrap();
                    }

                    if let (Some(cap_host), Some(cap_guest)) =
                        (BUS_SLOT.captures(&host), BUS_SLOT.captures(&guest))
                    {
                        let new_elem = format!(
                            r#"
    <hostdev mode='subsystem' type='pci' managed='yes'>
      <source>
        <address domain='0x0000' bus='0x{}' slot='0x{}' function='0x{}'/>
      </source>
      <address type='pci' domain='0x0000' bus='0x{}' slot='0x{}' function='0x{}'/>
    </hostdev>"#,
                            cap_host.get(1).unwrap().as_str(),
                            cap_host.get(2).unwrap().as_str(),
                            cap_host.get(3).unwrap().as_str(),
                            cap_guest.get(1).unwrap().as_str(),
                            cap_guest.get(2).unwrap().as_str(),
                            cap_guest.get(3).unwrap().as_str(),
                        );

                        let elem = Element::parse(new_elem.as_bytes())?;
                        devices.children.push(XMLNode::Element(elem));
                    } else {
                        return Err(Error::ParsePCISpec(netdev.to_owned()));
                    }
                } else {
                    return Err(Error::ParsePCISpec(netdev.to_owned()));
                }
            }
        }

        Ok(())
    }

    fn spawn(&self, params: Spawn) -> Result<(), Error> {
        let mut pool = self.get_pool()?;

        let to_bring_up = match pool.get_by_name(&params.full) {
            Ok(image) => image,
            Err(Error::NotFound(_)) if params.new_size.is_some() => {
                // Image doesn't exist, create it with the specified size
                let new_params = New {
                    name: params.full.clone(),
                    temp: params.temp,
                    size: params.new_size.unwrap(),
                };
                self.new_image(new_params)?;

                // Re-read the pool after creating the new image
                pool = self.get_pool()?;
                pool.get_by_name(&params.full)?
            }
            Err(e) => return Err(e),
        };
        if !to_bring_up.image.sub.is_empty() {
            return Err(Error::HasSubImages(params.full.clone(), ""));
        }

        // Check if image is frozen - cannot spawn frozen (read-only) images
        if to_bring_up.image.frozen {
            return Err(Error::FreeText(format!(
                "Cannot spawn {} - image is frozen (read-only)",
                params.full
            )));
        }

        info!("Preparing to spawn VM {}", params.full);

        let mut xml = self.get_template(&params.base_template)?;

        // Get the complete backing chain for this image
        let backing_chain = pool
            .get_backing_chain_by_name(&params.full)
            .with_context(|| format!("Failed to get backing chain for {}", params.full))?;

        // Ensure all images in the backing chain have symlinks in pool_path
        self.ensure_backing_chain_symlinks(&backing_chain)?;

        // Use the symlink path in pool_path for the VM configuration
        let vm_disk_path = self.config.pool_path.join(&to_bring_up.image.rel_path);
        let to_bring_up_image_path = vm_disk_path.display();

        if vm_disk_path.metadata()?.permissions().readonly() {
            info!("Setting image to read-write");
            if vm_disk_path.metadata()?.uid() != get_current_uid() {
                ibash_stdout!("sudo -u qemu chmod u+w {to_bring_up_image_path}")?;
            } else {
                ibash_stdout!("chmod u+w {to_bring_up_image_path}")?;
            }
        }

        let vmname_prefix = self.get_vm_prefix();
        let hash: u64 = calculate_hash(&format!("{}-{}", vmname_prefix, &params.full));
        let new_mac = format!(
            "52:52:{:02x}:{:02x}:{:02x}:{:02x}",
            (hash >> 32) & 0xff,
            (hash >> 40) & 0xff,
            (hash >> 48) & 0xff,
            (hash >> 56) & 0xff,
        );

        if let Some(uuid) = xml.get_mut_child("uuid") {
            uuid.children[0] = XMLNode::Text(format!("{}", uuid::Uuid::new_v4()));
        }

        if let Some(name) = xml.get_mut_child("name") {
            let vm = params.full.clone();
            let prefixed_vm_name = format!("{}{}", vmname_prefix, vm);
            name.children[0] = XMLNode::Text(prefixed_vm_name);
        }

        if let Some(devices) = xml.get_mut_child("devices") {
            if let Some(interface) = devices.get_mut_child("interface") {
                if let Some(mac) = interface.get_mut_child("mac") {
                    mac.attributes.insert("address".to_owned(), new_mac);
                }
            }

            if let Some(disk) = devices.get_mut_child("disk") {
                if let Some(source) = disk.get_mut_child("source") {
                    source
                        .attributes
                        .insert("file".to_owned(), format!("{}", to_bring_up_image_path));
                }
            }
        }

        let full_name = format!("{vmname_prefix}{}", params.full);

        Self::modify_xml_using_overrides(&mut xml, &params.overrides, full_name.as_str())?;

        info!("Writing VM definition");

        let dir = tempdir::TempDir::new("vmess")?;
        let file_path = dir.path().join("domain.xml");
        let f = std::fs::File::create(&file_path)?;
        let file_path = file_path.display();
        xml.write_with_config(
            &f,
            xmltree::EmitterConfig {
                perform_indent: true,
                ..Default::default()
            },
        )?;
        f.sync_all()?;
        drop(f);

        let volatile = if params.temp { true } else { params.volatile };

        let v = if volatile {
            info!("Creating volatile VM");
            if params.paused {
                ibash_stdout!("virsh create {file_path} --paused")?
            } else {
                ibash_stdout!("virsh create {file_path} ")?
            }
        } else {
            info!("Defining VM");
            ibash_stdout!("virsh define {file_path}")?
        };

        info!("Result: {}", v.trim());

        if !volatile && !params.paused {
            ibash_stdout!("virsh start {full_name}")?;
        }

        dir.close()?;

        // Wait for VM to boot if requested
        if params.wait {
            self.wait(Wait {
                name: params.full.clone(),
            })?;
        }

        Ok(())
    }

    fn modify(&mut self, params: Modify) -> Result<(), Error> {
        let pool = self.get_pool()?;

        let existing = pool.get_by_name(&params.full)?;

        if let Some(vm) = &existing.vm {
            let vmname_prefix = self.get_vm_prefix();
            let contents = ibash_stdout!("virsh dumpxml {vmname_prefix}{vm.name}")?;
            let mut xml = Element::parse(contents.as_bytes())?;
            let full_name = format!("{vmname_prefix}{}", params.full);

            Self::modify_xml_using_overrides(&mut xml, &params.overrides, full_name.as_str())?;

            let dir = tempdir::TempDir::new("vmess")?;
            let file_path = dir.path().join("domain.xml");
            let f = std::fs::File::create(&file_path)?;
            xml.write_with_config(
                &f,
                xmltree::EmitterConfig {
                    perform_indent: true,
                    ..Default::default()
                },
            )?;
            f.sync_all()?;
            drop(f);

            let file_path = file_path.display();
            ibash_stdout!("virsh define {file_path}")?;

            dir.close()?;
        }

        Ok(())
    }

    fn undefine(&self, params: Undefine) -> Result<(), Error> {
        let vmname_prefix = self.get_vm_prefix();

        for name in &params.names {
            ibash_stdout!("virsh undefine --nvram {vmname_prefix}{name}")?;
        }

        Ok(())
    }

    fn wait(&self, params: Wait) -> Result<(), Error> {
        info!("Waiting boot of {}", params.name);

        while let Err(_) = remote_shell_no_stderr(&params.name, format!("echo -n")) {
            std::thread::sleep(std::time::Duration::from_millis(1000));
            self.update_ssh(UpdateSshParams { quiet: true })?;
        }

        info!("Wait done");

        Ok(())
    }

    pub fn fork(&mut self, params: Fork) -> Result<(), Error> {
        // Validate script/changes parameters
        if params.script.is_some() && params.changes.is_none() {
            return Err(Error::FreeText(
                "When --script is specified, --changes must also be specified".to_string(),
            ));
        }

        self.fork_with(params.clone(), move |vm_name: &str| -> anyhow::Result<()> {
            // Execute script if provided
            if let Some(script) = &params.script {
                // Write script to temporary file on VM via stdin
                let temp_script_path = "/tmp/vmess_script.sh";
                let write_script_cmd = format!("cat > {}", temp_script_path);

                let mut ssh_cmd = make_ssh();
                let mut child = ssh_cmd
                    .arg(vm_name)
                    .arg(&write_script_cmd)
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .with_context(|| "Failed to spawn SSH process".to_string())?;

                if let Some(stdin) = child.stdin.as_mut() {
                    std::io::Write::write_all(stdin, script.as_bytes()).with_context(|| {
                        "Failed to write script content to SSH stdin".to_string()
                    })?;
                }

                let output = child
                    .wait_with_output()
                    .with_context(|| "Failed to complete script write to VM".to_string())?;

                if !output.status.success() {
                    return Err(Error::FreeText(format!(
                        "Failed to write script to VM: {}",
                        String::from_utf8_lossy(&output.stderr)
                    ))
                    .into());
                }

                // Make script executable and run it
                let exec_cmd = format!("chmod +x {} && {}", temp_script_path, temp_script_path);
                let mut ssh_cmd = make_ssh();
                let status = ssh_cmd
                    .arg(vm_name)
                    .arg(&exec_cmd)
                    .status()
                    .with_context(|| "Failed to execute script on VM".to_string())?;

                if !status.success() {
                    return Err(Error::FreeText(format!(
                        "Script execution failed with exit code: {:?}",
                        status.code()
                    ))
                    .into());
                }
            }

            Ok(())
        })?;

        Ok(())
    }

    pub fn fork_with(
        &self,
        params: Fork,
        f: impl FnOnce(&str) -> anyhow::Result<()>,
    ) -> Result<(), Error> {
        let pool = self
            .get_pool()
            .with_context(|| "Failed to get pool in fork".to_string())?;

        if let Some(base_template) = &params.base_template {
            let _xml = self
                .get_template(&base_template)
                .with_context(|| format!("Failed to get template '{}'", base_template))?;
        }

        let new_full_name = params.name.clone();

        // Find the parent image: either explicitly specified or longest prefix match
        let parent = if let Some(parent_name) = &params.parent {
            // Use explicitly specified parent
            pool.get_by_name(parent_name)
                .with_context(|| format!("Failed to find parent image '{}'", parent_name))?
                .image
        } else {
            // Find the longest existing image for which the new name is a prefix
            let mut longest_match: Option<&Image> = None;
            let mut longest_length = 0;

            for image in pool.get_all_images() {
                let prefix_name = format!("{}.", pool.name_from_tag(image).replace("%", "."));
                if new_full_name.starts_with(&prefix_name) {
                    if prefix_name.len() > longest_length {
                        longest_length = prefix_name.len();
                        longest_match = Some(image);
                    }
                }
            }

            longest_match
                .ok_or_else(|| Error::NotFound(format!("No matching parent for {}", params.name)))?
        };

        if params.print_parent {
            println!("Parent: {:?}", parent.rel_path);
            return Ok(());
        }

        let new_base_name = PathBuf::from(format!("{}.qcow2", params.name));
        let new_main_pool_image = self.config.pool_path.join(&new_base_name);

        // Verify parent is not currently running
        if let Some(vm_using) = &parent.vm_using {
            if let Some(vm) = pool.vms.get(vm_using) {
                use crate::virsh::VirDomainState;
                if vm.stats.state != VirDomainState::NoState {
                    return Err(Error::FreeText(format!(
                        "Cannot fork from parent '{}' - VM '{}' is in state {:?}.",
                        pool.name_from_tag(parent),
                        vm_using,
                        vm.stats.state,
                    )));
                }
            }
        }

        // Check for frozen sub-image with same changes before checking existing images
        if let Some(changes_text) = &params.changes {
            // Search in parent's sub-images for a frozen image with same changes
            for (sub_name, sub_image) in &parent.sub.images {
                if params.cached
                    && sub_image.frozen
                    && sub_image.vm_info.changes == vec![changes_text.clone()]
                {
                    // Found a frozen sub-image with same changes
                    let image_name = strip_frozen_suffix(&sub_name).replace('%', ".");
                    if image_name != params.name {
                        continue;
                    }

                    info!(
                        "Found existing frozen sub-image '{}' with same changes, creating tag '{}' -> '{}'",
                        sub_name, params.name, sub_name
                    );

                    // Create tag symlink pointing to the frozen image
                    let tag_symlink_path =
                        self.config.pool_path.join(format!("{}.qcow2", params.name));
                    let frozen_path = format!("{}.qcow2", sub_name);

                    let _ = std::fs::remove_file(&tag_symlink_path);
                    std::os::unix::fs::symlink(&frozen_path, &tag_symlink_path).with_context(
                        || {
                            format!(
                                "Failed to create tag symlink {} -> {}",
                                tag_symlink_path.display(),
                                frozen_path
                            )
                        },
                    )?;

                    return Ok(());
                }
            }
        }

        if let Ok(existing) = pool.get_by_name(&new_full_name) {
            if params.cached {
                // Check if existing image has the same changes
                if let Some(changes_text) = &params.changes {
                    if existing.image.vm_info.changes == vec![changes_text.clone()] {
                        info!(
                            "Image {} already exists with the same changes, skipping creation",
                            new_full_name
                        );
                        return Ok(());
                    }
                }
            }

            if params.force {
                if let Some(vm) = &existing.vm {
                    info!("Removing VM (state {:?})", existing.image.sub.get("State"));
                    let vmname_prefix = self.get_vm_prefix();
                    let r1 = ibash_stdout!("virsh destroy {vmname_prefix}{vm.name}");
                    let r2 = ibash_stdout!("virsh undefine --nvram {vmname_prefix}{vm.name}");

                    if r1.is_err() && r2.is_err() {
                        r2?;
                    }
                }

                if new_main_pool_image.exists() {
                    std::fs::remove_file(&new_main_pool_image).with_context(|| {
                        format!(
                            "Failed to remove existing file '{}'",
                            new_main_pool_image.display()
                        )
                    })?;
                }
            } else {
                return Err(Error::AlreadyExists);
            }
        }

        let new = 'x: {
            if let Some(pool_name) = &params.pool {
                for pool in &self.config.pools {
                    if &pool.name == pool_name {
                        break 'x &pool.path;
                    }
                }
                return Err(Error::InvalidPoolName(pool_name.clone()));
            } else if !params.temp {
                &self.config.pool_path
            } else {
                std::fs::create_dir_all(&self.config.tmp_path)?;
                &self.config.tmp_path
            }
        }
        .join(&new_base_name);

        let _ = std::fs::remove_file(&new);

        let new_disp = new.display();
        if params.temp || params.pool.is_some() {
            let _ = std::fs::remove_file(&new_main_pool_image);
            std::os::unix::fs::symlink(&new, &new_main_pool_image)
                .with_context(|| format!("symlink {} creation", new_main_pool_image.display()))?;
        }

        let pool_path = &self.config.pool_path;
        let backing = pool_path.join(&parent.rel_path);
        let backing_basename = backing.file_name().unwrap().to_str().unwrap();
        let backing_disp = backing.display();

        info!(
            "Creating new image: {} -> {}",
            parent.rel_path.display(),
            new_full_name
        );

        // Get the complete backing chain for the parent image
        let backing_chain = pool
            .get_backing_chain_by_name(&parent.rel_path.file_stem().unwrap().to_string_lossy())
            .with_context(|| {
                format!(
                    "Failed to get backing chain for parent {}",
                    parent.rel_path.display()
                )
            })?;

        // Ensure all images in the backing chain have symlinks in pool_path
        self.ensure_backing_chain_symlinks(&backing_chain)
            .with_context(|| {
                format!(
                    "Failed to ensure backing chain symlinks for parent '{}'",
                    parent.rel_path.display()
                )
            })?;

        if params.temp {
            std::fs::create_dir_all(&self.config.tmp_path).with_context(|| {
                format!(
                    "Failed to create temp directory '{}'",
                    self.config.tmp_path.display()
                )
            })?;
        }

        if !backing
            .metadata()
            .with_context(|| format!("Failed to get metadata for backing file '{}'", backing_disp))?
            .permissions()
            .readonly()
        {
            info!("Setting parent image to read-only");
            if backing.metadata()?.uid() != get_current_uid() {
                ibash_stdout!("sudo -u qemu chmod u-w {backing_disp}")?;
            } else {
                ibash_stdout!("chmod u-w {backing_disp}")?;
            }
        }

        // Ensure JSON file doesn't exist before creating the new image
        let new_json_path = new.with_extension("json");
        if new_json_path.exists() {
            std::fs::remove_file(&new_json_path)?;
            info!(
                "Removed existing JSON file before fork: {}",
                new_json_path.display()
            );
        }

        // Also remove JSON file symlink from main pool if creating in temp/other pool
        if params.temp || params.pool.is_some() {
            let main_json_path = new_main_pool_image.with_extension("json");
            if main_json_path.exists() {
                std::fs::remove_file(&main_json_path)?;
                info!(
                    "Removed existing JSON file symlink from main pool before fork: {}",
                    main_json_path.display()
                );
            }
        }

        let cmd = format!("qemu-img create -f qcow2 {new_disp} -F qcow2 -b {backing_disp}");
        let v = ibash_stdout!("{}", cmd).with_context(|| {
            format!(
                "Failed to create qcow2 image '{}' with backing file '{}'. \
                Make sure the backing file exists and is accessible.",
                new_disp, backing_disp
            )
        })?;
        info!("qemu-image create result: {:?}", v);

        // Make sure the backing store pathname is relative.
        let cmd = format!("qemu-img rebase -F qcow2 -u {new_disp} -b {backing_basename}");
        let v = ibash_stdout!("{}", cmd)?;
        if v != "" {
            info!("qemu-image rebase result: {:?}", v);
        }

        // Resize the image if requested
        if let Some(image_size) = params.overrides.image_size {
            let image_size = format!("{}", image_size).replace(" ", "");
            let cmd = format!("qemu-img resize {new_disp} {image_size}");
            println!("{}", cmd);

            let v = ibash_stdout!("{}", cmd)?;
            if v != "" {
                info!("qemu-image rebase result: {:?}", v);
            }
        }

        let base_template_provided = params.base_template.is_some();
        if let Some(template) = params.base_template {
            self.spawn(Spawn {
                full: params.name.clone(),
                base_template: template,
                temp: params.temp,
                volatile: params.volatile,
                paused: params.paused,
                wait: false,
                overrides: params.overrides.clone(),
                new_size: None,
            })?;
        }

        // Execute script if provided
        if let Some(_) = &params.script {
            let changes_text = params.changes.as_ref().unwrap(); // Safe because we validated this above

            if !base_template_provided {
                return Err(Error::FreeText(
                    "Script execution requires --base-template to be specified".to_string(),
                ));
            }

            let json_path = new.with_extension("json");

            let vm_name: &str = &params.name;
            let changes_text: &str = changes_text;

            // Wait for VM to boot
            self.wait(Wait {
                name: vm_name.to_string(),
            })?;

            if params.wait {
                return Ok(());
            }

            f(vm_name).map_err(Error::CallBack)?;

            // Shutdown VM and wait for it to stop
            self.shutdown_wait(ShutdownWait {
                name: vm_name.to_string(),
            })?;

            if !params.volatile {
                // Undefine the VM after shutdown
                self.undefine(Undefine {
                    names: vec![vm_name.to_string()],
                })?;
            }

            // Write changes JSON file
            let vm_info = VMInfo {
                username: None,
                changes: vec![changes_text.to_string()],
            };

            write_json_path(json_path.clone(), &vm_info).with_context(|| {
                format!("Failed to write changes JSON file: {}", json_path.display())
            })?;
        } else {
            if params.publish {
                return Err(Error::FreeText(
                    "When --wait is specified, --publish cannot be used".to_string(),
                ));
            }

            self.wait(Wait {
                name: params.name.to_string(),
            })?;

            return Ok(());
        }

        // Handle publish flag - freeze and move to shared pool if one exists
        if params.publish {
            if let Some(shared_pool) = self.config.pools.iter().find(|p| p.shared) {
                let shared_pool_name = shared_pool.name.clone();
                info!(
                    "Publishing image '{}' to shared pool '{}'",
                    params.name, shared_pool_name
                );

                // Freeze the image first
                self.freeze(Freeze {
                    name: params.name.clone(),
                    force: Some("stop-undefine".to_string()),
                })?;

                // Move to the shared pool
                self.move_image(Move {
                    image: params.name.clone(),
                    pool: shared_pool_name.clone(),
                })?;

                info!(
                    "Successfully published '{}' to shared pool '{}'",
                    params.name, shared_pool_name
                );
            } else {
                info!("Publish requested but no shared pool available - skipping publish");
            }
        }

        Ok(())
    }

    fn new_image(&self, params: New) -> Result<(), Error> {
        let pool = self.get_pool()?;
        let name = &params.name;

        let new_base_name = { PathBuf::from(format!("{name}.qcow2")) };

        if let Ok(_) = pool.get_by_name(&name) {
            return Err(Error::AlreadyExists);
        }

        let new = if !params.temp {
            &self.config.pool_path
        } else {
            &self.config.tmp_path
        }
        .join(&new_base_name);

        let _ = std::fs::remove_file(&new);

        // Also remove any existing JSON file since New doesn't populate it with content
        let json_path = if !params.temp {
            self.config.pool_path.join(format!("{}.json", name))
        } else {
            self.config.tmp_path.join(format!("{}.json", name))
        };

        if json_path.exists() {
            let _ = std::fs::remove_file(&json_path);
            info!("Removed existing JSON file: {}", json_path.display());
        }

        let new_disp = new.display();

        let image_size = format!("{}", params.size).replace(" ", "");
        let cmd = format!("qemu-img create -f qcow2 {new_disp} {image_size}");
        let v = ibash_stdout!("{}", cmd)?;
        info!("qemu-image create result: {:?}", v);

        if params.temp {
            let new_link_path = self.config.pool_path.join(&new_base_name);
            std::os::unix::fs::symlink(&new, &new_link_path).map_err(|e| {
                Error::Context(
                    format!("symlink {} creation", new_link_path.display()),
                    Box::new(e),
                )
            })?;
        }

        Ok(())
    }

    fn exists(&mut self, params: Exists) -> Result<(), Error> {
        let pool = self.get_pool_no_vms()?;

        pool.get_by_name(&params.name).map(|_| ())
    }

    fn start(&mut self, params: Start) -> Result<(), Error> {
        let pool = self.get_pool()?;

        let existing = pool.get_by_name(&params.name)?;
        if !existing.image.sub.is_empty() {
            return Err(Error::HasSubImages(params.name.clone(), "start"));
        }

        let vmname_prefix = self.get_vm_prefix();
        if let Some(vm) = &existing.vm {
            ibash_stdout!("virsh start {vmname_prefix}{vm.name}")?;
        } else {
            return Err(Error::NoVMDefined(params.name));
        }

        Ok(())
    }

    fn stop(&self, params: Stop) -> Result<(), Error> {
        let pool = self.get_pool()?;

        let vmname_prefix = self.get_vm_prefix();
        let existing = pool.get_by_name(&params.name)?;
        if let Some(vm) = &existing.vm {
            ibash_stdout!("virsh shutdown {vmname_prefix}{vm.name}")?;
        } else {
            return Err(Error::NoVMDefined(params.name));
        }

        Ok(())
    }

    fn shutdown_wait(&self, params: ShutdownWait) -> Result<(), Error> {
        let pool = self.get_pool()?;

        let existing = pool.get_by_name(&params.name)?;
        if let Some(vm) = &existing.vm {
            let vmname_prefix = self.get_vm_prefix();

            ibash_stdout!("virsh shutdown {vmname_prefix}{vm.name}")?;

            while let Err(_) = ibash_stdout!(
                "virsh list --state-shutoff --name | grep -E '^{vmname_prefix}{vm.name}$'"
            ) {
                if let Err(_) = ibash_stdout!(
                    "virsh list --name | grep -E '^{vmname_prefix}{vmname}$'",
                    vmname = vm.name
                ) {
                    // Volatile VMs disappear
                    break;
                }

                std::thread::sleep(std::time::Duration::from_millis(1000));
            }
        } else {
            return Err(Error::NoVMDefined(params.name));
        }

        Ok(())
    }

    fn rename(&mut self, params: Rename) -> Result<(), Error> {
        let pool = self.get_pool()?;

        // Check that the source image exists
        let existing = pool.get_by_name(&params.name)?;
        if let Some(_) = &existing.vm {
            // FIXME: this can have a workaround
            return Err(Error::CurrentlyDefined);
        }

        // Check that the destination does not exist
        if let Err(Error::NotFound(_)) = pool.get_by_name(&params.new_name) {
        } else {
            return Err(Error::AlreadyExists);
        };

        // Check if image is in a shared pool and force is not specified
        let is_in_shared_pool = self
            .config
            .pools
            .iter()
            .any(|pool| pool.shared && existing.image.pool_directory == pool.path);

        if is_in_shared_pool && !params.force {
            return Err(Error::FreeText(format!(
                "Cannot rename {} - image is in a shared pool. Use --force to override",
                params.name
            )));
        }

        // Check if this is a frozen image accessed via a tag
        if existing.image.frozen {
            if let Some(_) = pool.tags.get(&params.name) {
                // Find and rename the tag symlink
                let old_tag_path = existing
                    .image
                    .pool_directory
                    .join(format!("{}.qcow2", params.name));
                let new_tag_path = existing
                    .image
                    .pool_directory
                    .join(format!("{}.qcow2", params.new_name));

                if old_tag_path.exists() && old_tag_path.is_symlink() {
                    // Read the symlink target
                    let target = std::fs::read_link(&old_tag_path).map_err(|e| {
                        Error::Context(
                            format!("read symlink {}", old_tag_path.display()),
                            Box::new(e),
                        )
                    })?;

                    // Remove old symlink
                    std::fs::remove_file(&old_tag_path).map_err(|e| {
                        Error::Context(
                            format!("remove tag symlink {}", old_tag_path.display()),
                            Box::new(e),
                        )
                    })?;

                    // Create new symlink
                    std::os::unix::fs::symlink(&target, &new_tag_path).map_err(|e| {
                        Error::Context(
                            format!("create new tag symlink {}", new_tag_path.display()),
                            Box::new(e),
                        )
                    })?;

                    info!(
                        "Renamed tag '{}' to '{}' for frozen image",
                        params.name, params.new_name
                    );
                    return Ok(());
                } else {
                    return Err(Error::FreeText(format!(
                        "Cannot rename frozen image {} - no tag symlink found",
                        params.name
                    )));
                }
            } else {
                return Err(Error::FreeText(format!(
                    "Cannot rename frozen image {} directly. Frozen images can only have their tags renamed",
                    params.name
                )));
            }
        }

        // Handle non-frozen images
        let existing_image_path = existing.image.get_absolute_path();
        let new_base_name = format!("{}.qcow2", params.new_name);
        let new_image_path = existing_image_path.with_file_name(&new_base_name);

        // Rename the actual image file
        std::fs::rename(&existing_image_path, &new_image_path).map_err(|e| {
            Error::Context(
                format!(
                    "rename image: {} -> {}",
                    existing_image_path.display(),
                    new_image_path.display()
                ),
                Box::new(e),
            )
        })?;

        // Handle symlink in main pool
        if existing.image.pool_directory != self.config.pool_path {
            let old_link_path = self.config.pool_path.join(&existing.image.rel_path);
            let new_link_path = self.config.pool_path.join(&new_base_name);

            // Remove old symlink if it exists
            if old_link_path.exists() {
                std::fs::remove_file(&old_link_path).map_err(|e| {
                    Error::Context(
                        format!("remove old symlink {}", old_link_path.display()),
                        Box::new(e),
                    )
                })?;
            }

            // Create new symlink
            let _ = std::fs::remove_file(&new_link_path); // Remove if exists
            std::os::unix::fs::symlink(&new_image_path, &new_link_path).map_err(|e| {
                Error::Context(
                    format!("create new symlink {}", new_link_path.display()),
                    Box::new(e),
                )
            })?;
        }

        // Handle JSON file renaming (unified logic)
        let old_json_path = existing_image_path.with_extension("json");
        let new_json_path = new_image_path.with_extension("json");
        if old_json_path.exists() {
            std::fs::rename(&old_json_path, &new_json_path).map_err(|e| {
                Error::Context(
                    format!(
                        "rename JSON file: {} -> {}",
                        old_json_path.display(),
                        new_json_path.display()
                    ),
                    Box::new(e),
                )
            })?;
        }

        Ok(())
    }

    fn console(&mut self, params: Console) -> Result<(), Error> {
        let pool = self.get_pool()?;

        let existing = pool.get_by_name(&params.name)?;
        if let Some(vm) = &existing.vm {
            let vmname_prefix = self.get_vm_prefix();
            let vm = format!("{vmname_prefix}{}", vm.name);
            let mut v = Command::new("virsh").arg("console").arg(&vm).spawn()?;
            let _status = v.wait()?;
        } else {
            return Err(Error::NoVMDefined(params.name));
        }

        Ok(())
    }

    pub fn background_console(&self, fullname: &str) -> Result<Command, Error> {
        let pool = self.get_pool()?;

        let existing = pool.get_by_name(&fullname)?;
        if let Some(vm) = &existing.vm {
            let vmname_prefix = self.get_vm_prefix();
            let vm = format!("{vmname_prefix}{}", vm.name);
            let mut command = Command::new("virsh");
            command.arg("console").arg(&vm);
            return Ok(command);
        } else {
            return Err(Error::NoVMDefined(fullname.to_owned()));
        }
    }

    fn kill(&mut self, params: Kill) -> Result<(), Error> {
        let pool = self.get_pool()?;

        // Collect images to kill - handle regex and exact match differently
        let mut images_to_kill = Vec::new();

        if params.regex {
            // For regex mode, match against display names
            for image in pool.get_all_images() {
                let image_stem = image.rel_path.file_stem().unwrap().to_string_lossy();
                let image_name_rep = image_stem.replace('%', ".");
                for pattern in params.names.iter() {
                    let regex = Regex::new(pattern)?;
                    if regex.is_match(&image_name_rep) || regex.is_match(&image_stem) {
                        images_to_kill.push(image);
                        break;
                    }
                }
            }
        } else {
            // Exact match mode
            for name in params.names.iter() {
                let image_name_rep = name.replace('%', ".");
                for name in [name, &image_name_rep] {
                    match pool.images.find_by_name(name) {
                        Some(image) => {
                            images_to_kill.push(image);
                        }
                        None => {
                            return Err(Error::NotFound(name.to_string()));
                        }
                    }
                }
            }
        }

        // Process the found images
        for image in images_to_kill {
            // Generate display name for output
            let image_path_str = image.rel_path.to_string_lossy();
            let image_name = strip_frozen_suffix(&image_path_str).replace('%', ".");

            let vm = if let Some(name) = &image.vm_using {
                pool.vms.get(name)
            } else {
                None
            };

            if params.dry_run {
                println!("{}", image_name);
                continue;
            }

            info!("About to remove VM and image files for {}", image_name);

            let image_path = &image.rel_path;
            if let Some(vm) = &vm {
                if !params.force {
                    return Err(Error::CurrentlyDefined);
                }

                let state_str = match vm.stats.state {
                    VirDomainState::Running => "running",
                    VirDomainState::Shutoff => "shut off",
                    VirDomainState::Paused => "paused",
                    VirDomainState::Shutdown => "shutting down",
                    VirDomainState::Crashed => "crashed",
                    VirDomainState::Blocked => "blocked",
                    VirDomainState::PmSuspended => "suspended",
                    VirDomainState::NoState => "",
                    VirDomainState::Unknown => "unknown",
                };

                info!("Stopping VM for {}, state: {}", image_name, state_str);

                let vmname_prefix = self.get_vm_prefix();
                match vm.stats.state {
                    VirDomainState::Shutoff => {
                        ibash_stdout!("virsh undefine --nvram {vmname_prefix}{vm.name}")?;
                    }
                    _ => {
                        ibash_stdout!("virsh destroy {vmname_prefix}{vm.name}")?;
                    }
                }
            }

            info!("Remove image files for {}", image_name);

            let pool_image_path = self.config.pool_path.join(&image_path);
            std::fs::remove_file(&pool_image_path)?;
            let tmp_image_path = self.config.tmp_path.join(&image_path);
            if tmp_image_path.exists() {
                std::fs::remove_file(&tmp_image_path)?;
            }

            // Remove corresponding JSON file from the image's actual pool directory
            let image_stem = image_path.file_stem().unwrap().to_string_lossy();
            let actual_json_path = image.pool_directory.join(format!("{}.json", image_stem));
            if actual_json_path.exists() {
                std::fs::remove_file(&actual_json_path)?;
                info!("Removed JSON file: {}", actual_json_path.display());
            }
        }

        Ok(())
    }

    fn update_ssh(&self, params: UpdateSshParams) -> Result<UpdateSshDisposition, Error> {
        let mut ssh_config = if let Some(ssh_config) = &self.config.ssh_config {
            ssh_config.clone()
        } else {
            return Ok(UpdateSshDisposition::NotConfigured);
        };

        let pool = self.get_pool()?;
        ssh_config.config_file = adjust_path_by_env(ssh_config.config_file);

        #[derive(Default)]
        struct HostEntry {
            hostname: Option<String>,
            user: Option<String>,
        }

        let mut host_config = BTreeMap::new();
        let mut cur_host_str: Option<String> = None;
        let mut cur_host: Option<&mut HostEntry> = None;

        if ssh_config.config_file.exists() {
            lazy_static! {
                static ref HOST: Regex = Regex::new("^Host (.*)$").unwrap();
                static ref HOSTNAME: Regex = Regex::new("^Hostname (.*)$").unwrap();
                static ref USER: Regex = Regex::new("^User (.*)$").unwrap();
            }

            let file = std::fs::File::open(&ssh_config.config_file)?;
            for line in BufReader::new(file).lines() {
                let line = line?;

                if let Some(cap) = HOSTNAME.captures(&line) {
                    let hostname = cap.get(1).unwrap().as_str().to_owned();
                    if let Some(cur_host_str) = &cur_host_str {
                        if pool.get_by_name(cur_host_str).is_ok() {
                            if let Some(cur_host) = &mut cur_host {
                                cur_host.hostname = Some(hostname);
                            }
                        }
                    }
                } else if let Some(cap) = HOST.captures(&line) {
                    drop(cur_host);
                    let host = cap.get(1).unwrap().as_str().to_owned();
                    cur_host_str = Some(host.clone());
                    cur_host = Some(match host_config.entry(host) {
                        btree_map::Entry::Vacant(v) => v.insert(Default::default()),
                        btree_map::Entry::Occupied(o) => o.into_mut(),
                    });
                }
            }
        }

        let mut config = String::new();

        // Get network information for all VMs in batch
        let vm_to_ip = get_batch_network_info()?;

        let vmname_prefix = self.get_vm_prefix();
        for line in ibash_stdout!("virsh list --name")?.lines() {
            let vmname = line.trim();
            if vmname.is_empty() {
                continue;
            }
            let short_vmname = if vmname.starts_with(&vmname_prefix) {
                &vmname[vmname_prefix.len()..]
            } else {
                continue;
            };

            // Use pre-collected network information
            if let Some(address) = vm_to_ip.get(vmname) {
                let username = if let Ok(image) = pool.get_by_name(short_vmname) {
                    if let Some(username) = &image.image.vm_info.username {
                        Some(username.as_str())
                    } else {
                        None
                    }
                } else {
                    None
                }
                .unwrap_or("user");

                host_config.insert(
                    short_vmname.to_owned(),
                    HostEntry {
                        hostname: Some(address.clone()),
                        user: Some(username.to_owned()),
                    },
                );
            }
        }

        for (host, entry) in host_config.iter() {
            writeln!(&mut config, r#"Host {}"#, host)?;
            if let Some(user) = &entry.user {
                writeln!(&mut config, r#"User {}"#, user)?;
            } else {
                if let Some(user) = &ssh_config.user {
                    writeln!(&mut config, r#"User {}"#, user)?;
                }
            }
            if let Some(hostname) = &entry.hostname {
                writeln!(&mut config, r#"Hostname {}"#, hostname)?;
            }
            writeln!(&mut config, "IdentityFile {}\n\n", ssh_config.identity_file)?;
        }

        if ssh_config.config_file.exists() {
            let mut file = std::fs::File::open(&ssh_config.config_file)?;
            let mut contents = String::new();
            file.read_to_string(&mut contents)?;
            if contents == config {
                if !params.quiet {
                    // No need to rewrite
                    info!("no update needed for {}", ssh_config.config_file.display());
                }

                return Ok(UpdateSshDisposition::NotNeeded);
            }
        }

        let with_tmp = ssh_config
            .config_file
            .add_extension(format!("tmp.{}", std::process::id()));
        let file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(&with_tmp)?;
        let mut file = BufWriter::new(file);
        write!(&mut file, "{}", config)?;
        drop(file);

        use std::os::unix::fs::PermissionsExt;
        let metadata = with_tmp.metadata()?;
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(&with_tmp, permissions)?;
        std::fs::rename(with_tmp, &ssh_config.config_file)?;

        if !params.quiet {
            info!(
                "updated {} with {} hosts",
                ssh_config.config_file.display(),
                host_config.len()
            );
        }

        Ok(UpdateSshDisposition::Updated)
    }
}

impl Pool {
    fn load_tags(
        &mut self,
        lookup_paths: Vec<PathBuf>,
        path_to_pool: std::collections::HashMap<PathBuf, (String, bool)>,
    ) -> Result<(), Error> {
        for lookup_path in &lookup_paths {
            for entry in std::fs::read_dir(lookup_path)
                .with_context(|| format!("reading directory {} for tags", lookup_path.display()))?
            {
                let entry = entry.with_context(|| format!("during entry resolve for tags"))?;
                let path = entry.path();

                // Check if it's a symlink
                if !path.is_symlink() {
                    continue;
                }

                let target = match std::fs::read_link(&path) {
                    Ok(target) => target,
                    Err(_) => continue,
                };

                // Only target pointing inside the directory
                if target.to_string_lossy().contains("/") {
                    continue;
                }

                // Remove .qcow2 suffix from symlink name to get tag name
                let tag_name = path
                    .file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();

                // Remove .qcow2 suffix from target name to get image name
                let image_name = target
                    .file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();

                if self.images.find_by_name(&image_name).is_none() {
                    // Ignore tags that point to images that don't exist.
                    continue;
                }

                if self.images.find_by_name(&tag_name).is_some() {
                    // Ignore tags that are superseeded by actual images in some
                    // pools
                    continue;
                }

                if self.tags.contains_key(&tag_name) {
                    // We prioritize the first tag we see based on the pool
                    // lookup order and ignore the other tags as if they
                    // don't exist.
                    continue;
                }

                // Find the pool name for this lookup path
                let (pool_name, shared) = path_to_pool
                    .get(lookup_path)
                    .cloned()
                    .unwrap_or_else(|| ("unknown".to_string(), false));

                // Add to tags maps
                let tag_info = TagInfo {
                    image_name: image_name.clone(),
                    pool_name,
                    shared,
                };
                self.tags.insert(tag_name.clone(), tag_info);
                self.rev_tags.insert(image_name, tag_name);
            }
        }

        Ok(())
    }
}

pub fn get_vm_image_path(image: impl AsRef<str>) -> Result<PathBuf, Error> {
    let vm = CommandMode::Exists(Exists {
        name: image.as_ref().to_owned(),
    });
    let opt = CommandArgs {
        config: None,
        command: vm,
    };

    let vmess = VMess::command(&opt)?;
    let pool = vmess.get_pool_no_vms()?;
    let info = pool.get_by_name(image.as_ref())?;
    return Ok(info.image.get_absolute_path());
}

pub fn get_pool() -> Result<Pool, Error> {
    VMess::command(&Default::default())?.get_pool_no_vms()
}

pub fn command(command: CommandMode) -> Result<(), Error> {
    let opt = CommandArgs {
        config: None,
        command,
    };

    match VMess::command(&opt) {
        Err(err) => return Err(err),
        Ok(mut vmess) => {
            vmess.run()?;
        }
    }

    Ok(())
}
