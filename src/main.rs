mod api;
mod config;
mod nftables;
mod types;

use clap::Parser;
use std::path::PathBuf;

use config::Config;
use nftables::NftManager;

#[derive(Parser)]
#[command(name = "internet-access-control")]
#[command(version)]
#[command(about = "Control internet access for network devices via nftables")]
struct Args {
    #[arg(
        short,
        long,
        default_value = "/etc/internet-access-control.yml",
        help = "YAML file with device aliases"
    )]
    config: PathBuf,

    #[arg(short, long, default_value_t = 8080, help = "HTTP server port")]
    port: u16,

    #[arg(
        short,
        long,
        default_value = "wan",
        help = "WAN interface name to block (internet access)"
    )]
    wan_interface: String,

    #[arg(
        short,
        long,
        default_value = "br-lan",
        help = "LAN bridge interface name for forwarding rules"
    )]
    lan_bridge: String,

    #[arg(
        short,
        long,
        default_value = "0.0.0.0",
        help = "Address to bind HTTP server"
    )]
    bind: String,
}

fn main() {
    let args = Args::parse();

    let config = Config::load(&args.config);

    eprintln!("Loaded {} device aliases", config.devices.len());

    let mut nft = match NftManager::new(&args.wan_interface, &args.lan_bridge) {
        Ok(nft) => nft,
        Err(error) => {
            eprintln!("Failed to initialize nftables: {error}");
            std::process::exit(1);
        }
    };

    let address = format!("{}:{}", args.bind, args.port);

    let server = match tiny_http::Server::http(&address) {
        Ok(server) => server,
        Err(error) => {
            eprintln!("Failed to start HTTP server on {address}: {error}");
            std::process::exit(1);
        }
    };

    eprintln!("Listening on http://{address}");
    eprintln!("WAN interface: {}", args.wan_interface);
    eprintln!("LAN bridge: {}", args.lan_bridge);

    if nftables::hardware_acceleration_present() {
        eprintln!(
            "NSS/ECM hardware acceleration detected: accelerated connections will be dropped back \
             to the slow path on each deny, so blocking also cuts established connections"
        );
    }

    if nftables::flow_offload_enabled() {
        eprintln!(
            "Warning: flow offloading is enabled. Offloaded connections skip the forward chain, \
             so blocking a device will not cut its established connections until they expire. \
             Disable it with: uci set firewall.@defaults[0].flow_offloading='0'"
        );
    }

    for mut request in server.incoming_requests() {
        let response = api::handle_request(&mut request, &config, &mut nft);

        if let Err(error) = request.respond(response) {
            eprintln!("Failed to send response: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::Args;

    #[test]
    fn command_exposes_package_version() {
        let command = Args::command();

        assert_eq!(command.get_version(), Some(env!("CARGO_PKG_VERSION")));
    }
}
