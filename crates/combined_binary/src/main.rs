use aquatic_common::cli::{
    print_help, print_version_info, run_app_with_cli_and_config, run_app_with_config, Config,
    Options,
};
use aquatic_toml_config::TomlConfig;

mod multiconfig;

use multiconfig::Resolved;

#[cfg(feature = "http")]
use aquatic_http::config::Config as HttpConfig;
#[cfg(feature = "udp")]
use aquatic_udp::config::Config as UdpConfig;
#[cfg(feature = "ws")]
use aquatic_ws::config::Config as WsConfig;

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

const APP_NAME: &str = "aquatic: BitTorrent tracker";

/// Where the configuration for the selected protocol comes from.
enum Source {
    /// No merged section: the regular CLI path loads the config file (or uses
    /// the protocol defaults when no file was given).
    Defaults,
    /// Merged config file: the protocol section, already extracted.
    Section(aquatic_toml_config::toml::Value),
}

fn main() {
    ::std::process::exit(match run() {
        Ok(()) => 0,
        Err(None) => {
            print_help(gen_info, None);

            0
        }
        Err(opt_err @ Some(_)) => {
            print_help(gen_info, opt_err);

            1
        }
    })
}

fn run() -> Result<(), Option<String>> {
    let mut arg_iter = ::std::env::args().skip(1).peekable();

    // The protocol is optional: when it is omitted, a merged config file
    // decides which protocol this process runs. Deciding with a separate
    // binding keeps the borrow of `peek` from overlapping `next`.
    let first_is_protocol = match arg_iter.peek() {
        Some(arg) => !arg.starts_with('-'),
        None => false,
    };

    let cli_protocol = if first_is_protocol {
        arg_iter.next()
    } else {
        None
    };

    let options = match Options::parse_args(arg_iter) {
        Ok(options) => options,
        Err(opt_err) => return Err(opt_err),
    };

    // Neither of these needs a protocol to be selected first.
    if options.print_version() {
        print_version_info(env!("CARGO_PKG_VERSION"));

        return Ok(());
    }

    if options.print_config() {
        match cli_protocol {
            // Unchanged behaviour: the protocol's own default configuration,
            // so `aquatic udp -p > udp.toml` keeps working as before.
            Some(ref protocol) => print_default_config(protocol)?,
            // Without a protocol there is no "the" default configuration, so a
            // merged template is the only useful answer.
            None => print!("{}", merged_template()),
        }

        return Ok(());
    }

    // From here on a protocol is mandatory: one process serves one protocol,
    // and the choice belongs to the startup command, not to the config file.
    let protocol = match cli_protocol {
        Some(protocol) => protocol,
        None => match options.config_file() {
            Some(_) => {
                return Err(Some(format!(
                    "No protocol given: pass one of {} along with --config-file, \
                     for example 'aquatic udp -c <path>'",
                    enabled_protocols().join(", ")
                )))
            }
            None => return Err(None),
        },
    };

    if !is_available(&protocol) {
        return Err(Some(format!(
            "Invalid or unavailable protocol '{}' (this build supports: {})",
            protocol,
            enabled_protocols().join(", ")
        )));
    }

    let source = match options.config_file() {
        Some(path) => match multiconfig::resolve(path, &protocol) {
            Ok(Resolved::Section(value)) => Source::Section(value),
            Ok(Resolved::Legacy) => Source::Defaults,
            Err(err) => return Err(Some(format!("{:#}", err))),
        },
        None => Source::Defaults,
    };

    let print_parsed_config = options.print_parsed_config();

    match protocol.as_str() {
        #[cfg(feature = "udp")]
        "udp" => dispatch(
            source,
            options,
            print_parsed_config,
            "udp",
            aquatic_udp::APP_NAME,
            aquatic_udp::APP_VERSION,
            aquatic_udp::run,
        ),
        #[cfg(feature = "http")]
        "http" => dispatch(
            source,
            options,
            print_parsed_config,
            "http",
            aquatic_http::APP_NAME,
            aquatic_http::APP_VERSION,
            aquatic_http::run,
        ),
        #[cfg(feature = "ws")]
        "ws" => dispatch(
            source,
            options,
            print_parsed_config,
            "ws",
            aquatic_ws::APP_NAME,
            aquatic_ws::APP_VERSION,
            aquatic_ws::run,
        ),
        other => Err(Some(format!(
            "Invalid or unavailable protocol '{}' (this build supports: {})",
            other,
            enabled_protocols().join(", ")
        ))),
    }
}

/// Run a protocol, either with a configuration extracted from a merged file or
/// through the regular single-protocol path.
fn dispatch<T>(
    source: Source,
    options: Options,
    print_parsed_config: bool,
    protocol: &str,
    app_name: &str,
    app_version: &str,
    app_fn: fn(T) -> ::anyhow::Result<()>,
) -> Result<(), Option<String>>
where
    T: Config,
{
    match source {
        Source::Section(value) => {
            // Re-serialize the section before deserializing it: this keeps the
            // parser's line/column diagnostics and does not depend on serde's
            // Value deserializer for a whole document.
            let text = match aquatic_toml_config::toml::to_string(&value) {
                Ok(text) => text,
                Err(err) => {
                    return Err(Some(format!(
                        "Couldn't read the [{}] section: {}",
                        protocol, err
                    )))
                }
            };

            let config: T = match aquatic_toml_config::toml::from_str(&text) {
                Ok(config) => config,
                Err(err) => {
                    return Err(Some(format!(
                        "Couldn't parse the [{}] section: {}",
                        protocol, err
                    )))
                }
            };

            run_app_with_config(app_fn, config, print_parsed_config)
        }
        Source::Defaults => {
            run_app_with_cli_and_config::<T>(app_name, app_version, app_fn, Some(options));

            Ok(())
        }
    }
}

/// Protocols compiled into this binary.
fn enabled_protocols() -> Vec<&'static str> {
    #[allow(unused_mut)]
    let mut protocols = Vec::new();

    #[cfg(feature = "udp")]
    protocols.push("udp");
    #[cfg(feature = "http")]
    protocols.push("http");
    #[cfg(feature = "ws")]
    protocols.push("ws");

    protocols
}

fn is_available(protocol: &str) -> bool {
    enabled_protocols()
        .iter()
        .any(|available| *available == protocol)
}

/// Print the default configuration of one protocol. The output is identical to
/// what `aquatic <protocol> -p` produced before merged config files existed, so
/// existing redirects (`aquatic udp -p > udp.toml`) keep working.
fn print_default_config(protocol: &str) -> Result<(), Option<String>> {
    match protocol {
        #[cfg(feature = "udp")]
        "udp" => print!("{}", UdpConfig::default_to_string()),
        #[cfg(feature = "http")]
        "http" => print!("{}", HttpConfig::default_to_string()),
        #[cfg(feature = "ws")]
        "ws" => print!("{}", WsConfig::default_to_string()),
        other => {
            return Err(Some(format!(
                "Invalid or unavailable protocol '{}' (this build supports: {})",
                other,
                enabled_protocols().join(", ")
            )))
        }
    }

    Ok(())
}

/// Header of the template printed by `-p` when no protocol was given.
const TEMPLATE_HEADER: &str = "\
# aquatic 合并配置文件（config.toml）
#
# 一个文件描述三种协议：每个协议一张表（[udp] / [http] / [ws]）。
# 启动哪个协议由命令行决定，配置只提供参数：
#
#   aquatic udp  -c config.toml
#   aquatic http -c config.toml
#   aquatic ws   -c config.toml
#
# 一个进程只运行一个协议，三个协议同时运行就是三条命令（或用 systemd 模板）：
#   ExecStart=/usr/local/bin/aquatic %i -c /etc/aquatic/config.toml
#
# 端口提示：HTTP 与 WebSocket 同为 TCP，不能共用同一端口。本模板已错开为
# UDP 6969 / HTTP 8080 / WS 8081，指标 9001-9003（仅监听本机）。
# 指标端点默认关闭，需要时把 run_prometheus_endpoint 设为 true。
";

/// Build the merged template, with ports staggered so that all three protocols
/// can run side by side on one host.
fn merged_template() -> String {
    #[allow(unused_mut)]
    let mut blocks: Vec<(&'static str, String)> = Vec::new();

    #[cfg(feature = "udp")]
    blocks.push((
        "udp",
        multiconfig::section(
            "udp",
            &UdpConfig::default_to_string(),
            &[
                (
                    "address_ipv4 = \"0.0.0.0:3000\"",
                    "address_ipv4 = \"0.0.0.0:6969\"",
                ),
                (
                    "address_ipv6 = \"[::]:3000\"",
                    "address_ipv6 = \"[::]:6969\"",
                ),
                (
                    "prometheus_endpoint_address = \"0.0.0.0:9000\"",
                    "prometheus_endpoint_address = \"127.0.0.1:9001\"",
                ),
            ],
        ),
    ));

    #[cfg(feature = "http")]
    blocks.push((
        "http",
        multiconfig::section(
            "http",
            &HttpConfig::default_to_string(),
            &[
                (
                    "address_ipv4 = \"0.0.0.0:3000\"",
                    "address_ipv4 = \"0.0.0.0:8080\"",
                ),
                (
                    "address_ipv6 = \"[::]:3000\"",
                    "address_ipv6 = \"[::]:8080\"",
                ),
                (
                    "prometheus_endpoint_address = \"0.0.0.0:9000\"",
                    "prometheus_endpoint_address = \"127.0.0.1:9002\"",
                ),
            ],
        ),
    ));

    #[cfg(feature = "ws")]
    blocks.push((
        "ws",
        multiconfig::section(
            "ws",
            &WsConfig::default_to_string(),
            &[
                (
                    "address = \"0.0.0.0:3000\"",
                    "address = \"0.0.0.0:8081\"",
                ),
                (
                    "prometheus_endpoint_address = \"0.0.0.0:9000\"",
                    "prometheus_endpoint_address = \"127.0.0.1:9003\"",
                ),
            ],
        ),
    ));

    multiconfig::merge_blocks(TEMPLATE_HEADER, &blocks)
}

fn gen_info() -> String {
    let mut info = String::new();

    info.push_str(APP_NAME);

    let app_path = ::std::env::args().next().unwrap();
    info.push_str(&format!("\n\nUsage: {} [PROTOCOL] [OPTIONS]", app_path));
    info.push_str("\n\nAvailable protocols:");

    #[cfg(feature = "udp")]
    info.push_str("\n    udp                   BitTorrent over UDP");
    #[cfg(feature = "http")]
    info.push_str("\n    http                  BitTorrent over HTTP");
    #[cfg(feature = "ws")]
    info.push_str("\n    ws                    WebTorrent");

    info.push_str(
        "\n\n--config-file may point at a merged file holding [udp], [http] and \
         [ws] tables;\nonly the table of the chosen protocol is used. One \
         process runs one protocol, so start\none process per protocol.\n\
         Use -p without a protocol to print a merged template.",
    );

    info
}
