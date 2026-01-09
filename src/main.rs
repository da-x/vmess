use structopt::StructOpt;
use thiserror::Error;
use vmess::{CommandArgs, VMess};

#[derive(StructOpt, Debug)]
struct Args {
    #[structopt(flatten)]
    command_args: CommandArgs,

    #[structopt(long, short = "v", help = "Verbose logging (debug level)")]
    verbose: bool,

    #[structopt(long, short = "q", help = "Quiet logging (error level only)")]
    quiet: bool,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("VMess: {0}")]
    VMess(#[from] vmess::Error),

    #[error("Log: {0}")]
    LogSet(#[from] log::SetLoggerError),
}

fn init_log(level: log::LevelFilter) -> Result<(), Error> {
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
        .level_for("ops", log::LevelFilter::Debug)
        .chain(std::io::stdout())
        .apply()?;

    Ok(())
}

fn main_wrap() -> Result<(), Error> {
    let args = Args::from_args();

    let log_level = if args.verbose {
        log::LevelFilter::Debug
    } else if args.quiet {
        log::LevelFilter::Error
    } else {
        log::LevelFilter::Info
    };

    init_log(log_level)?;

    match VMess::command(&args.command_args) {
        Err(err) => return Err(err.into()),
        Ok(mut vmess) => {
            vmess.run()?;
        }
    }

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
