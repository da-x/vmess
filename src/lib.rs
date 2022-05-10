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

use lazy_static::lazy_static;
use log::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use structopt::StructOpt;
use thiserror::Error;
use users::get_current_uid;
use xmltree::{Element, XMLNode};

mod utils;

#[allow(unused_parens)]
mod query;

use fstrings::*;
use utils::*;

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

    #[error("Config error: {0}")]
    BoxError(#[from] Box<dyn std::error::Error + Send>),

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

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Already exists")]
    AlreadyExists,

    #[error("VM currently defined, operation aborted")]
    CurrentlyDefined,

    #[error("Parsing PCI spec {0}")]
    ParsePCISpec(String),

    #[error("Template {0} doesn't exist")]
    TemplateDoesntExist(String),

    #[error("Renaming across parents not supported")]
    RenameAcrossParentsUnsupported,

    #[error("Cannot {1} snapshot {0} - has sub snapshots")]
    HasSubSnapshots(String, &'static str),

    #[error("No VM defined for {0}")]
    NoVMDefined(String),

    #[error("Filter parse error: {0}")]
    FilterParseError(String),

    #[error("Under {0}: {1}")]
    Context(String, Box<Error>),
}

#[derive(Debug, StructOpt, Clone, Default)]
pub struct Fork {
    /// Full name of the domain
    pub name: String,

    /// Enable volatile VM execution - the domain definition will not be saved, and
    /// the definition will be removed when stopped.
    #[structopt(name = "volatile", short = "v")]
    pub volatile: bool,

    /// Store image in the temp pool, implies 'volatile'
    #[structopt(name = "temp", short = "t")]
    pub temp: bool,

    /// Base template used for actual VM execution
    #[structopt(name = "base-template", short = "b")]
    pub base_template: Option<String>,

    /// Start as paused
    #[structopt(name = "paused", short = "p")]
    pub paused: bool,

    /// Force operation (will kill the VM if it exists)
    #[structopt(name = "force", short = "f")]
    pub force: bool,

    #[structopt(flatten)]
    pub overrides: Overrides,
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
    name: String,
}

#[derive(Debug, StructOpt, Clone)]
pub struct Stop {
    /// Full name of the domain
    name: String,
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
    memory_gb: Option<u32>,

    /// Override number of CPUs
    #[structopt(name = "cpus", short = "c", long = "cpus")]
    nr_cpus: Option<u32>,

    /// Host devices from VF pools
    #[structopt(name = "netdevs", long = "netdev")]
    netdevs: Vec<String>,
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

    #[structopt(flatten)]
    pub overrides: Overrides,
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
    pub full: String,
}

#[derive(Debug, StructOpt, Clone)]
pub struct UpdateSshParams {
    #[structopt(name = "quiet", short = "q")]
    pub quiet: bool,
}

#[derive(Debug, StructOpt, Clone)]
pub struct List {
    #[structopt(name = "quiet")]
    pub filter: Vec<String>,
}

#[derive(Debug, StructOpt, Clone)]
pub enum CommandMode {
    /// Fork a new VM out of a suspended VM image and optionally spawn it
    /// if a template definition is provided
    Fork(Fork),

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

    /// Update SSH config based on DHCP of client VMs
    UpdateSsh(UpdateSshParams),
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

    /// Non-interactive mode - print data and exit
    #[structopt(subcommand)]
    command: CommandMode,
}

#[derive(Debug, Deserialize, Clone)]
struct Config {
    #[serde(rename = "pool-path")]
    pool_path: PathBuf,

    #[serde(rename = "tmp-path")]
    tmp_path: PathBuf,

    #[serde(default)]
    #[serde(rename = "multi-user")]
    multi_user: bool,

    #[serde(default)]
    #[serde(rename = "ssh-config")]
    ssh_config: Option<SSHConfig>,
}

#[derive(Debug, Deserialize, Clone)]
struct SSHConfig {
    #[serde(rename = "identity-file")]
    identity_file: String,

    #[serde(rename = "config-file")]
    config_file: PathBuf,
}

pub struct Main {
    config: Config,
    opt: CommandArgs,
}

#[derive(Debug)]
struct Snapshot {
    rel_path: PathBuf,
    size_mb: u64,
    vm_using: Option<String>,
    sub: BTreeMap<String, Snapshot>,
}

lazy_static! {
    static ref PARSE_QCOW2: Regex = Regex::new("^([^%]+)([%]([^.]*))?[.]qcow2?$").unwrap();
}

impl Snapshot {
    fn join(&self, x: &str) -> PathBuf {
        let name = self.rel_path.file_name().unwrap().to_str().unwrap();
        if let Some(cap) = PARSE_QCOW2.captures(&name) {
            let name = cap.get(1).unwrap().as_str();
            let mut v = if let Some(snapshot_path) = cap.get(3) {
                snapshot_path.as_str().split("%").collect()
            } else {
                vec![]
            };
            v.push(x);
            self.rel_path
                .with_file_name(format!("{}%{}.qcow2", name, v.join("%")))
        } else {
            panic!();
        }
    }
}

#[derive(Debug)]
struct Image {
    root: Snapshot,
}

#[derive(Debug)]
struct VM {
    name: String,
    attrs: BTreeMap<String, String>,
}

#[derive(Debug)]
struct Pool {
    images: BTreeMap<String, Image>,
    vms: BTreeMap<String, VM>,
}

struct GetInfo<'a> {
    snap: &'a Snapshot,
    vm: Option<&'a VM>,
}

impl<'a> GetInfo<'a> {
    fn image_path(&self) -> &'a PathBuf {
        &self.snap.rel_path
    }
}

impl Pool {
    fn get_by_name<'a>(&'a self, name: &str) -> Result<GetInfo<'a>, Error> {
        fn by_snapshot<'a>(
            pool: &'a Pool,
            lookup: &str,
            image: &Image,
            snapshot: &'a Snapshot,
            level: usize,
            name_path: String,
        ) -> Option<GetInfo<'a>> {
            if lookup == &name_path {
                return Some(GetInfo {
                    snap: snapshot,
                    vm: if let Some(name) = &snapshot.vm_using {
                        pool.vms.get(name)
                    } else {
                        None
                    },
                });
            }

            for (key, snapshot) in snapshot.sub.iter() {
                if let Some(i) = by_snapshot(
                    pool,
                    lookup,
                    image,
                    &snapshot,
                    level + 1,
                    format!("{}.{}", name_path, key),
                ) {
                    return Some(i);
                }
            }

            None
        }

        fn by_image<'a>(
            lookup: &str,
            pool: &'a Pool,
            image: &'a Image,
            name_path: String,
        ) -> Option<GetInfo<'a>> {
            by_snapshot(pool, lookup, &image, &image.root, 0, name_path.clone())
        }

        for (key, image) in self.images.iter() {
            if let Some(i) = by_image(name, self, &image, key.clone()) {
                return Ok(i);
            }
        }

        Err(Error::NotFound(name.to_owned()))
    }
}

impl Snapshot {
    fn new(
        root_path: &PathBuf,
        path: PathBuf,
        files_to_domains: &HashMap<PathBuf, String>,
    ) -> Result<Self, Error> {
        let abs_path = root_path.join(&path);

        Ok(Snapshot {
            sub: Default::default(),
            vm_using: files_to_domains.get(&abs_path).map(|x| (*x).to_owned()),
            size_mb: (std::fs::metadata(&abs_path)?.blocks() * 512) / (1024 * 1024),
            rel_path: path,
        })
    }
}

impl Main {
    pub fn new(opt: &CommandArgs) -> Result<Self, Error> {
        let opt = (*opt).clone();
        let config_path = if let Some(config) = &opt.config {
            config.clone()
        } else {
            if let Ok(path) = std::env::var("VMESS_CONFIG_PATH") {
                PathBuf::from(path)
            } else {
                if let Some(dir) = dirs::config_dir() {
                    dir.join("vmess").join("config.toml")
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

        Ok(Self { opt, config })
    }

    fn get_vm_prefix(&self) -> String {
        match self.config.multi_user {
            true => format!("{}-", std::env::var("USER").expect("USER not defined")),
            false => "".to_owned(),
        }
    }

    pub fn run(&mut self) -> Result<(), Error> {
        match self.opt.command.clone() {
            CommandMode::List(params) => {
                self.list(params)?;
            }
            CommandMode::Fork(params) => {
                self.fork(params)?;
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
            CommandMode::UpdateSsh(params) => {
                self.update_ssh(params)?;
            }
        }

        Ok(())
    }

    fn get_pool(&self) -> Result<Pool, Error> {
        lazy_static! {
            static ref SOURCE_FILE: Regex = Regex::new(r"^[\t ]+[^ ]+[\t ]+([^']+)$").unwrap();
            static ref DOM_PROP: Regex = Regex::new(r"^([^:]+):[ \t]*([^ \t]+.*)$").unwrap();
        }

        let mut pool = Pool {
            images: Default::default(),
            vms: Default::default(),
        };

        let mut files_to_domains = HashMap::new();
        let vmname_prefix = self.get_vm_prefix();

        for line in ibash_stdout!("virsh list --all --name")?.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let vmname = line;
            let short_vmname = if vmname.starts_with(&vmname_prefix) {
                &vmname[vmname_prefix.len()..]
            } else {
                continue;
            };

            for line in ibash_stdout!("virsh domblklist {vmname}")?.lines() {
                if let Some(cap) = SOURCE_FILE.captures(&line) {
                    let s = cap.get(1).unwrap().as_str();
                    files_to_domains.insert(PathBuf::from(s), short_vmname.to_owned());
                }
            }

            let mut vm = VM {
                attrs: Default::default(),
                name: short_vmname.to_owned(),
            };
            for line in ibash_stdout!("virsh dominfo {vmname}")?.lines() {
                if let Some(cap) = DOM_PROP.captures(&line) {
                    let key = cap.get(1).unwrap().as_str();
                    let value = cap.get(2).unwrap().as_str();
                    vm.attrs.insert(key.to_owned(), value.to_owned());
                }
            }

            pool.vms.insert(short_vmname.to_owned(), vm);
        }

        let pool_path = &self.config.pool_path;
        for entry in std::fs::read_dir(&self.config.pool_path)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            if let Some(cap) = PARSE_QCOW2.captures(&name) {
                let name = cap.get(1).unwrap().as_str();
                let v = if let Some(snapshot_path) = cap.get(3) {
                    snapshot_path.as_str().split("%").collect()
                } else {
                    vec![]
                };

                let image = match pool.images.entry(name.to_owned()) {
                    btree_map::Entry::Vacant(v) => {
                        let path = PathBuf::from(format!("{}.qcow2", name));
                        v.insert(Image {
                            root: Snapshot::new(&pool_path, path, &files_to_domains)?,
                        })
                    }
                    btree_map::Entry::Occupied(o) => o.into_mut(),
                };

                let mut node = &mut image.root;
                let mut r = vec![];
                for sub in v.into_iter() {
                    r.push(sub.clone());

                    let sub_path = if r.len() == 0 {
                        "".to_string()
                    } else {
                        format!("%{}", r.join("%"))
                    };
                    let image = match node.sub.entry(sub.to_owned()) {
                        btree_map::Entry::Vacant(v) => {
                            let path = PathBuf::from(format!("{}{}.qcow2", name, sub_path));
                            v.insert(Snapshot::new(&pool_path, path, &files_to_domains)?)
                        }
                        btree_map::Entry::Occupied(o) => o.into_mut(),
                    };

                    node = image;
                }
            }
        }

        Ok(pool)
    }

    fn list(&mut self, params: List) -> Result<(), Error> {
        let pool = self.get_pool()?;

        use indexmap::IndexSet;
        use prettytable::{format, Cell, Row, Table};
        let filter_expr = query::Expr::parse_cmd(&params.filter)?;

        let mut table = Table::new();
        table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);

        #[derive(Serialize, Deserialize, Hash, Eq, PartialEq)]
        enum Column {
            Name,
            Volatile,
            State,
            MemUsage,
            DiskUsage,
        }

        let mut columns = indexmap::IndexSet::new();
        columns.insert(Column::Name);
        columns.insert(Column::Volatile);
        columns.insert(Column::State);
        columns.insert(Column::MemUsage);
        columns.insert(Column::DiskUsage);

        table.set_titles(Row::new(
            columns
                .iter()
                .map(|x| Cell::new(&ron::ser::to_string(x).expect("serialization")))
                .collect(),
        ));

        fn by_snapshot(
            columns: &IndexSet<Column>,
            config: &Config,
            table: &mut Table,
            pool: &Pool,
            image: &Image,
            snapshot: &Snapshot,
            path: String,
            filter_expr: &query::Expr,
        ) {
            let abs_image = config.pool_path.join(&snapshot.rel_path);
            let tmp = if let Ok(link) = std::fs::read_link(abs_image) {
                if link.starts_with(&config.tmp_path) {
                    "Y"
                } else {
                    ""
                }
            } else {
                ""
            };

            let (vm_state, volatile, mem_size) = if let Some(vm_using) = &snapshot.vm_using {
                if let Some(vm) = pool.vms.get(vm_using) {
                    let state = vm.attrs.get("State").map(|x| x.as_str()).unwrap_or("");
                    let vol =
                        if vm.attrs.get("Persistent").map(|x| x.as_str()).unwrap_or("") == "no" {
                            "y"
                        } else {
                            tmp
                        };

                    let mem_size = if state == "running" {
                        vm.attrs
                            .get("Max memory")
                            .map(|x| {
                                Cow::from(format!(
                                    "{:.2} GB",
                                    (x.as_str()
                                        .split(" ")
                                        .nth(0)
                                        .unwrap()
                                        .parse::<i64>()
                                        .unwrap()
                                        / 1024) as f32
                                        / 1024.0
                                ))
                            })
                            .unwrap_or(Cow::from(""))
                    } else {
                        Cow::from("")
                    };
                    (state, vol, mem_size)
                } else {
                    ("", tmp, Cow::from(""))
                }
            } else {
                ("", tmp, Cow::from(""))
            };

            let disk_size = format!("{:.2} GB", snapshot.size_mb as f32 / 1024.0);

            let mut row = Row::empty();
            for column in columns {
                let s = match column {
                    Column::Name => &path,
                    Column::Volatile => volatile,
                    Column::State => &vm_state,
                    Column::MemUsage => &mem_size,
                    Column::DiskUsage => &disk_size,
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

            for (key, snapshot) in snapshot.sub.iter() {
                by_snapshot(
                    &columns,
                    config,
                    table,
                    pool,
                    image,
                    &snapshot,
                    format!("{}.{}", path, key),
                    filter_expr,
                );
            }
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
            by_snapshot(&columns, config, table, pool, &image, &image.root, path, filter_expr);
        }

        for (key, image) in pool.images.iter() {
            by_image(
                &columns,
                &self.config,
                &mut table,
                &pool,
                &image,
                key.clone(),
                &filter_expr,
            );
        }

        table.print_tty(false);

        Ok(())
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

    fn modify_xml_using_overrides(xml: &mut Element, overrides: &Overrides) -> Result<(), Error> {
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

        if let Some(devices) = xml.get_mut_child("devices") {
            // Remove existing host devices
            while let Some(_netdev) = devices.take_child("netdevs") {}

            for netdev in &overrides.netdevs {
                if netdev.starts_with("pool:") {
                    let netdev = &netdev[5..];
                    let mut model = "".to_owned();
                    let mut network = "";

                    for part in netdev.split(",") {
                        if part.starts_with("model:") {
                            let model_type = &part[6..];
                            model = format!("<model type='{model_type}'/>");
                        } else {
                            network = part;
                        }
                    }
                    let new_elem = format!(
                        r#"
  <interface type='network'>
    {model}
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

    fn spawn(&mut self, params: Spawn) -> Result<(), Error> {
        let pool = self.get_pool()?;

        let to_bring_up = pool.get_by_name(&params.full)?;
        if !to_bring_up.snap.sub.is_empty() {
            return Err(Error::HasSubSnapshots(params.full.clone(), ""));
        }

        info!("Preparing to spawn VM {}", params.full);

        let mut xml = self.get_template(&params.base_template)?;

        let to_bring_up_image = self.config.pool_path.join(&to_bring_up.image_path());
        let to_bring_up_image_path = to_bring_up_image.display();

        if to_bring_up_image.metadata()?.permissions().readonly() {
            info!("Setting image to read-write");
            if to_bring_up_image.metadata()?.uid() != get_current_uid() {
                ibash_stdout!("sudo -u qemu chmod u+w {to_bring_up_image_path}")?;
            } else {
                ibash_stdout!("chmod u+w {to_bring_up_image_path}")?;
            }
        }

        let hash: u64 = calculate_hash(&params.full);
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

        let vmname_prefix = self.get_vm_prefix();
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

        Self::modify_xml_using_overrides(&mut xml, &params.overrides)?;

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
            ibash_stdout!("virsh start {vmname_prefix}{params.full}")?;
        }

        dir.close()?;

        Ok(())
    }

    fn modify(&mut self, params: Modify) -> Result<(), Error> {
        let pool = self.get_pool()?;

        let existing = pool.get_by_name(&params.full)?;

        if let Some(vm) = &existing.vm {
            let vmname_prefix = self.get_vm_prefix();
            let contents = ibash_stdout!("virsh dumpxml {vmname_prefix}{vm.name}")?;
            let mut xml = Element::parse(contents.as_bytes())?;
            Self::modify_xml_using_overrides(&mut xml, &params.overrides)?;

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

    fn undefine(&mut self, params: Undefine) -> Result<(), Error> {
        let vmname_prefix = self.get_vm_prefix();
        ibash_stdout!("virsh undefine {vmname_prefix}{params.full}")?;

        Ok(())
    }

    fn fork(&mut self, params: Fork) -> Result<(), Error> {
        let pool = self.get_pool()?;

        if let Some(base_template) = &params.base_template {
            let _xml = self.get_template(&base_template)?;
        }

        let new_full_name = params.name.clone();
        let mut parts: Vec<_> = params.name.split(".").collect();
        let name = parts.pop().expect("name");
        let parent_name = parts.join(".");

        let parent = pool.get_by_name(&parent_name)?;

        let new_base_name = parent.snap.join(name);
        let new_adv = self.config.pool_path.join(&new_base_name);

        // TODO: verify parent is not running

        if let Ok(existing) = pool.get_by_name(&new_full_name) {
            if params.force {
                if let Some(vm) = &existing.vm {
                    info!("Removing VM (state {:?})", existing.snap.sub.get("State"));
                    let vmname_prefix = self.get_vm_prefix();
                    let r1 = ibash_stdout!("virsh destroy {vmname_prefix}{vm.name}");
                    let r2 = ibash_stdout!("virsh undefine {vmname_prefix}{vm.name}");

                    if r1.is_err() && r2.is_err() {
                        r2?;
                    }
                }
                std::fs::remove_file(&new_adv)?;
            } else {
                return Err(Error::AlreadyExists);
            }
        }

        if params.temp {
            std::fs::create_dir_all(&self.config.tmp_path)?;
        }

        let new = if !params.temp {
            &self.config.pool_path
        } else {
            &self.config.tmp_path
        }
        .join(&new_base_name);
        let _ = std::fs::remove_file(&new);

        let new_disp = new.display();
        if params.temp {
            let _ = std::fs::remove_file(&new_adv);
            std::os::unix::fs::symlink(&new, &new_adv).map_err(|e| {
                Error::Context(
                    format!("symlink {} creation", new_adv.display()),
                    Box::new(e.into()),
                )
            })?;
        }

        let backing = self.config.pool_path.join(&parent.image_path());
        let backing_disp = backing.display();

        info!(
            "Creating new snapshot: {} -> {}",
            parent_name, new_full_name
        );

        if params.temp {
            std::fs::create_dir_all(&self.config.tmp_path)?;
        }

        if !backing.metadata()?.permissions().readonly() {
            info!("Setting parent image to read-only");
            if backing.metadata()?.uid() != get_current_uid() {
                ibash_stdout!("sudo -u qemu chmod u-w {backing_disp}")?;
            } else {
                ibash_stdout!("chmod u-w {backing_disp}")?;
            }
        }

        let v = ibash_stdout!("qemu-img create -f qcow2 {new_disp} -F qcow2 -b {backing_disp}")?;
        info!("Result: {:?}", v);

        if let Some(template) = params.base_template {
            self.spawn(Spawn {
                full: params.name.clone(),
                base_template: template,
                temp: params.temp,
                volatile: params.volatile,
                paused: params.paused,
                overrides: params.overrides.clone(),
            })?;
        }

        Ok(())
    }

    fn exists(&mut self, params: Exists) -> Result<(), Error> {
        let pool = self.get_pool()?;

        pool.get_by_name(&params.name).map(|_| ())
    }

    fn start(&mut self, params: Start) -> Result<(), Error> {
        let pool = self.get_pool()?;

        let existing = pool.get_by_name(&params.name)?;
        if !existing.snap.sub.is_empty() {
            return Err(Error::HasSubSnapshots(params.name.clone(), "start"));
        }

        let vmname_prefix = self.get_vm_prefix();
        if let Some(vm) = &existing.vm {
            ibash_stdout!("virsh start {vmname_prefix}{vm.name}")?;
        } else {
            return Err(Error::NoVMDefined(params.name));
        }

        Ok(())
    }

    fn stop(&mut self, params: Stop) -> Result<(), Error> {
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

    fn shutdown_wait(&mut self, params: ShutdownWait) -> Result<(), Error> {
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

        // Check that the VM exists
        let existing = pool.get_by_name(&params.name)?;
        if let Some(_) = &existing.vm {
            // TODO: this can have a workaround
            return Err(Error::CurrentlyDefined);
        }

        let mut parts: Vec<_> = params.name.split(".").collect();
        let _name = parts.pop().expect("name");
        let existing_parent_name = parts.join(".");

        // Check that the destination does not exist
        if let Err(Error::NotFound(_)) = pool.get_by_name(&params.new_name) {
            let mut parts: Vec<_> = params.new_name.split(".").collect();
            let name = parts.pop().expect("name");
            let parent_name = parts.join(".");
            if parent_name != existing_parent_name {
                return Err(Error::RenameAcrossParentsUnsupported);
            }

            let parent = pool.get_by_name(&parent_name)?;
            let new_base_name = parent.snap.join(name);
            let new_adv = self.config.pool_path.join(&new_base_name);
            let image_path = self.config.pool_path.join(&existing.image_path());

            std::fs::rename(image_path, new_adv)?;
        } else {
            return Err(Error::AlreadyExists);
        }

        Ok(())
    }

    fn console(&mut self, params: Console) -> Result<(), Error> {
        let pool = self.get_pool()?;

        let existing = pool.get_by_name(&params.name)?;
        if let Some(vm) = &existing.vm {
            use std::process::Command;
            let vmname_prefix = self.get_vm_prefix();
            let vm = format!("{vmname_prefix}{}", vm.name);
            let mut v = Command::new("virsh").arg("console").arg(&vm).spawn()?;
            let _status = v.wait()?;
        } else {
            return Err(Error::NoVMDefined(params.name));
        }

        Ok(())
    }

    fn kill(&mut self, params: Kill) -> Result<(), Error> {
        let pool = self.get_pool()?;

        let check_match = &|s: &str| -> Result<bool, Error> {
            if params.regex {
                for name in params.names.iter() {
                    let regex = Regex::new(name)?;
                    if regex.is_match(s) {
                        return Ok(true);
                    }
                }
            } else {
                for name in params.names.iter() {
                    if name == s {
                        return Ok(true);
                    }
                }
            }

            Ok(false)
        };

        struct Closure<'a> {
            by_snapshot: &'a dyn Fn(&Closure, &Image, &Snapshot, String) -> Result<(), Error>,
            by_name: &'a dyn Fn(&Closure, &Image, String) -> Result<(), Error>,
        }

        let recursive = Closure {
            by_snapshot: &|closure, image, snapshot, name_path| {
                for (key, snapshot) in snapshot.sub.iter() {
                    (closure.by_snapshot)(
                        closure,
                        image,
                        &snapshot,
                        format!("{}.{}", name_path, key))?;
                }

                let vm = if let Some(name) = &snapshot.vm_using {
                    pool.vms.get(name)
                } else {
                    None
                };

                if !check_match(name_path.as_str())? {
                    return Ok(());
                }

                if params.dry_run {
                    println!("{}", name_path);
                    return Ok(());
                }

                info!("About to remove VM and image files for {}", name_path);

                let image_path = &snapshot.rel_path;
                if let Some(vm) = &vm {
                    if !params.force {
                        return Err(Error::CurrentlyDefined);
                    }

                    info!("Stopping VM for {}{}", name_path,
                        vm.attrs.get("State").map(|s| format!(", state: {s}"))
                        .unwrap_or("".to_owned()));

                    let vmname_prefix = self.get_vm_prefix();
                    match vm.attrs.get("State").as_ref().map(|x| x.as_str()) {
                        Some("shut off") => {
                            ibash_stdout!("virsh undefine {vmname_prefix}{vm.name}")?;
                        }
                        _ => {
                            ibash_stdout!("virsh destroy {vmname_prefix}{vm.name}")?;
                        }
                    }
                }

                info!("Remove image files for {}", name_path);

                let image_path = self.config.pool_path.join(&image_path);
                std::fs::remove_file(&image_path)?;
                let tmp_image_path = self.config.tmp_path.join(&image_path);
                if tmp_image_path.exists() {
                    std::fs::remove_file(&tmp_image_path)?;
                }

                Ok(())
            },
            by_name: &|closure, image, path| {
                (closure.by_snapshot)(closure, &image, &image.root, path)
            },
        };

        for (key, image) in pool.images.iter() {
            (recursive.by_name)(&recursive, &image, key.clone())?;
        }

        Ok(())
    }

    fn update_ssh(&mut self, params: UpdateSshParams) -> Result<UpdateSshDisposition, Error> {
        let mut ssh_config = if let Some(ssh_config) = &self.config.ssh_config {
            ssh_config.clone()
        } else {
            return Ok(UpdateSshDisposition::NotConfigured);
        };

        let pool = self.get_pool()?;
        ssh_config.config_file = adjust_path_by_env(ssh_config.config_file);

        let mut base = BTreeMap::new();

        if ssh_config.config_file.exists() {
            lazy_static! {
                static ref HOST: Regex = Regex::new("^Host (.*)$").unwrap();
                static ref HOSTNAME: Regex = Regex::new("^Hostname (.*)$").unwrap();
            }

            let mut host: Option<String> = None;
            let file = std::fs::File::open(&ssh_config.config_file)?;
            for line in BufReader::new(file).lines() {
                let line = line?;
                if let Some(cap) = HOSTNAME.captures(&line) {
                    let hostname = Some(cap.get(1).unwrap().as_str().to_owned());
                    if let (Some(host), Some(hostname)) = (&host, &hostname) {
                        if pool.get_by_name(host).is_ok() {
                            base.insert(host.clone(), hostname.clone());
                        }
                    }
                } else if let Some(cap) = HOST.captures(&line) {
                    host = Some(cap.get(1).unwrap().as_str().to_owned());
                }
            }
        }

        let mut config = String::new();

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

            let address = ibash_stdout!(
                r#"virsh domifaddr {vmname} | grep ipv4 \
                | awk '{{print $4}}' | awk -F/ '{{print $1}}' | tail -n 1"#
            )?;
            let address = address.trim().to_owned();
            if address.len() > 0 {
                base.insert(short_vmname.to_owned(), address.trim().to_owned());
            }
        }

        for (host, address) in base.iter() {
            writeln!(
                &mut config,
                r#"Host {}
User user
Hostname {}
IdentityFile {}

"#,
                host,
                address.trim(),
                ssh_config.identity_file
            )?;
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
                base.len()
            );
        }

        Ok(UpdateSshDisposition::Updated)
    }
}

pub fn command(command: CommandMode) -> Result<(), Error> {
    let opt = CommandArgs {
        config: None,
        command,
    };

    match Main::new(&opt) {
        Err(err) => return Err(err),
        Ok(mut vmess) => {
            vmess.run()?;
        }
    }

    Ok(())
}
