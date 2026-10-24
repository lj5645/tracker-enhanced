use aquatic_common::cli::{print_help, run_app_with_cli_and_config, Options};
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
    let mut arg_iter = ::std::env::args().skip(1);

    let protocol = if let Some(protocol) = arg_iter.next() {
        protocol
    } else {
        return Err(None);
    };

    let options = match Options::parse_args(arg_iter) {
        Ok(options) => options,
        Err(opt_err) => {
            return Err(opt_err);
        }
    };

    match protocol.as_str() {
        #[cfg(feature = "udp")]
        "udp" => run_app_with_cli_and_config::<UdpConfig>(
            aquatic_udp::APP_NAME,
            aquatic_udp::APP_VERSION,
            aquatic_udp::run,
            Some(options),
        ),
        #[cfg(feature = "http")]
        "http" => run_app_with_cli_and_config::<HttpConfig>(
            aquatic_http::APP_NAME,
            aquatic_http::APP_VERSION,
            aquatic_http::run,
            Some(options),
        ),
        #[cfg(feature = "ws")]
        "ws" => run_app_with_cli_and_config::<WsConfig>(
            aquatic_ws::APP_NAME,
            aquatic_ws::APP_VERSION,
            aquatic_ws::run,
            Some(options),
        ),
        arg => {
            let opt_err = if arg == "-h" || arg == "--help" {
                None
            } else if arg.starts_with('-') {
                Some("First argument must be protocol".to_string())
            } else {
                Some(format!(
                    "Invalid or unavailable protocol '{}' (this build supports: {})",
                    arg,
                    enabled_protocols().join(", "),
                ))
            };

            return Err(opt_err);
        }
    }

    Ok(())
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

fn gen_info() -> String {
    let mut info = String::new();

    info.push_str(APP_NAME);

    let app_path = ::std::env::args().next().unwrap();
    info.push_str(&format!("\n\nUsage: {} PROTOCOL [OPTIONS]", app_path));
    info.push_str("\n\nAvailable protocols:");

    #[cfg(feature = "udp")]
    info.push_str("\n    udp                   BitTorrent over UDP");
    #[cfg(feature = "http")]
    info.push_str("\n    http                  BitTorrent over HTTP");
    #[cfg(feature = "ws")]
    info.push_str("\n    ws                    WebTorrent");

    info
}
