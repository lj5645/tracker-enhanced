use anyhow::Context;
use aquatic_toml_config::TomlConfig;
use git_testament::{git_testament, CommitKind};
use log::LevelFilter;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use simplelog::{ColorChoice, TermLogger, TerminalMode, ThreadLogMode};

/// Log level. Available values are off, error, warn, info, debug and trace.
#[derive(Debug, Clone, Copy, PartialEq, TomlConfig, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl Default for LogLevel {
    fn default() -> Self {
        Self::Warn
    }
}

pub trait Config: Default + TomlConfig + DeserializeOwned + std::fmt::Debug {
    fn get_log_level(&self) -> Option<LogLevel> {
        None
    }
}

#[derive(Debug, Default)]
pub struct Options {
    config_file: Option<String>,
    print_config: bool,
    print_parsed_config: bool,
    print_version: bool,
}

impl Options {
    pub fn parse_args<I>(mut arg_iter: I) -> Result<Options, Option<String>>
    where
        I: Iterator<Item = String>,
    {
        let mut options = Options::default();

        #[allow(clippy::while_let_loop)] // False positive
        loop {
            if let Some(arg) = arg_iter.next() {
                match arg.as_str() {
                    "-c" | "--config-file" => {
                        if let Some(path) = arg_iter.next() {
                            options.config_file = Some(path);
                        } else {
                            return Err(Some("No config file path given".to_string()));
                        }
                    }
                    "-p" | "--print-config" => {
                        options.print_config = true;
                    }
                    "-P" => {
                        options.print_parsed_config = true;
                    }
                    "-v" | "--version" => {
                        options.print_version = true;
                    }
                    "-h" | "--help" => {
                        return Err(None);
                    }
                    "" => (),
                    _ => {
                        return Err(Some("Unrecognized argument".to_string()));
                    }
                }
            } else {
                break;
            }
        }

        Ok(options)
    }
}

pub fn run_app_with_cli_and_config<T>(
    app_title: &str,
    crate_version: &str,
    // Function that takes config file and runs application
    app_fn: fn(T) -> anyhow::Result<()>,
    opts: Option<Options>,
) where
    T: Config,
{
    ::std::process::exit(match run_inner(app_title, crate_version, app_fn, opts) {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("Error: {:#}", err);

            1
        }
    })
}

fn run_inner<T>(
    app_title: &str,
    crate_version: &str,
    // Function that takes config file and runs application
    app_fn: fn(T) -> anyhow::Result<()>,
    // Possibly preparsed options
    options: Option<Options>,
) -> anyhow::Result<()>
where
    T: Config,
{
    let options = if let Some(options) = options {
        options
    } else {
        let mut arg_iter = ::std::env::args();

        let app_path = arg_iter.next().unwrap();

        match Options::parse_args(arg_iter) {
            Ok(options) => options,
            Err(opt_err) => {
                let gen_info = || format!("{}\n\nUsage: {} [OPTIONS]", app_title, app_path);

                // Print usage; for a genuine argument error, return it so the
                // process exits with a non-zero status. `--help` is not an
                // error and exits successfully.
                print_help(gen_info, None);

                return match opt_err {
                    Some(error) => Err(anyhow::anyhow!(error)),
                    None => Ok(()),
                };
            }
        }
    };

    if options.print_version {
        let commit_info = get_commit_info();

        println!("{}{}", crate_version, commit_info);

        Ok(())
    } else if options.print_config {
        print!("{}", default_config_as_toml::<T>());

        Ok(())
    } else {
        let config = if let Some(path) = options.config_file {
            config_from_toml_file(path)?
        } else {
            T::default()
        };

        if let Some(log_level) = config.get_log_level() {
            start_logger(log_level)?;
        }

        if options.print_parsed_config {
            println!("Running with configuration: {:#?}", config);
        }

        app_fn(config)
    }
}

pub fn print_help<F>(info_generator: F, opt_error: Option<String>)
where
    F: FnOnce() -> String,
{
    println!("{}", info_generator());

    println!("\nOptions:");
    println!("    -c, --config-file     Load config from this path");
    println!("    -h, --help            Print this help message");
    println!("    -p, --print-config    Print default config");
    println!("    -P                    Print parsed config");
    println!("    -v, --version         Print version information");

    if let Some(error) = opt_error {
        println!("\nError: {}.", error);
    }
}

fn config_from_toml_file<T>(path: String) -> anyhow::Result<T>
where
    T: DeserializeOwned,
{
    let bytes = std::fs::read(&path)
        .with_context(|| format!("Couldn't read config file {}", path.clone()))?;

    // Lossy decoding plus BOM stripping: config files are often edited on
    // Windows or contain a comment in a local code page. Neither should turn a
    // valid configuration into a startup failure.
    let data = String::from_utf8_lossy(&bytes);
    let data = data.strip_prefix('\u{feff}').unwrap_or(&data);

    toml::from_str(data).with_context(|| format!("Couldn't parse config file {}", path.clone()))
}

fn default_config_as_toml<T>() -> String
where
    T: Default + TomlConfig,
{
    <T as TomlConfig>::default_to_string()
}

fn start_logger(log_level: LogLevel) -> ::anyhow::Result<()> {
    let mut builder = simplelog::ConfigBuilder::new();

    builder
        .set_thread_mode(ThreadLogMode::Both)
        .set_thread_level(LevelFilter::Error)
        .set_target_level(LevelFilter::Error)
        .set_location_level(LevelFilter::Off);

    let config = match builder.set_time_offset_to_local() {
        Ok(builder) => builder.build(),
        Err(builder) => builder.build(),
    };

    let level_filter = match log_level {
        LogLevel::Off => LevelFilter::Off,
        LogLevel::Error => LevelFilter::Error,
        LogLevel::Warn => LevelFilter::Warn,
        LogLevel::Info => LevelFilter::Info,
        LogLevel::Debug => LevelFilter::Debug,
        LogLevel::Trace => LevelFilter::Trace,
    };

    TermLogger::init(
        level_filter,
        config,
        TerminalMode::Stderr,
        ColorChoice::Auto,
    )
    .context("Couldn't initialize logger")?;

    Ok(())
}

fn get_commit_info() -> String {
    git_testament!(TESTAMENT);

    match TESTAMENT.commit {
        CommitKind::NoTags(hash, date) => {
            format!(" ({} - {})", first_8_chars(hash), date)
        }
        CommitKind::FromTag(_tag, hash, date, _tag_distance) => {
            format!(" ({} - {})", first_8_chars(hash), date)
        }
        _ => String::new(),
    }
}

fn first_8_chars(input: &str) -> String {
    input.chars().take(8).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unknown_argument_is_an_error() {
        let result = Options::parse_args(["--definitely-not-an-option".to_string()].into_iter());

        assert!(matches!(result, Err(Some(_))));
    }

    #[test]
    fn test_help_is_not_an_error() {
        let result = Options::parse_args(["--help".to_string()].into_iter());

        assert!(matches!(result, Err(None)));
    }

    #[test]
    fn test_config_file_with_bom_and_non_utf8_comment() {
        #[derive(Deserialize)]
        struct TestConfig {
            value: u32,
        }

        let path = std::env::temp_dir().join("aquatic_cli_config_bom_test.toml");
        // BOM, a GBK comment and a valid value.
        std::fs::write(&path, b"\xef\xbb\xbf# \xc9\xa8\xc3\xe8\xc6\xf7\nvalue = 7\n").unwrap();

        let config: TestConfig = config_from_toml_file(path.to_string_lossy().into_owned()).unwrap();

        assert_eq!(config.value, 7);

        let _ = std::fs::remove_file(&path);
    }
}
