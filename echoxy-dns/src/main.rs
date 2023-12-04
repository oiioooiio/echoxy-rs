use std::net::{Ipv4Addr, Ipv6Addr};

use clap::Parser;
use serde::Deserialize;
use serde_json;
use serde_with::{
    base64::{Base64, Standard},
    formats::Padded,
    serde_as,
};

use hickory_server::{config::dnssec, config::Config as DnsServerConfig, ServerFuture};

use tokio::{
    net::{TcpListener, UdpSocket},
    runtime,
};

use tracing;
use tracing_subscriber;

use echoxy_dns::EchoxyDnsHandler;

#[derive(Parser, Debug)]
#[clap(version = "0.1.0", author = "oiioooiio")]
struct Opts {
    #[clap(short, long, default_value = "config.json")]
    config: String,
}

#[serde_as]
#[derive(Deserialize, Debug)]
struct ProxyConfig {
    #[serde_as(as = "Vec<Base64<Standard, Padded>>")]
    echconfigs: Vec<Vec<u8>>,
    listen_addrs_ipv4: Vec<Ipv4Addr>,
    listen_addrs_ipv6: Vec<Ipv6Addr>,
}

#[derive(Deserialize, Debug)]
struct Config {
    server: DnsServerConfig,
    proxy: ProxyConfig,
}

fn main() {
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let opts = Opts::parse();

    tracing::debug!("{:?}", opts);

    let config: Config = {
        let config = std::fs::read_to_string(&opts.config).unwrap_or_else(|e| {
            tracing::error!("failed to read {}: {}", opts.config, e);
            std::process::exit(1);
        });
        serde_json::from_str(&config).unwrap_or_else(|e| {
            tracing::error!("failed to parse config: {}", e);
            std::process::exit(1);
        })
    };

    tracing::debug!("{:?}", config);

    let directory = config.server.get_directory();

    let cert_config = config.server.get_tls_cert().unwrap_or_else(|| {
        tracing::error!("failed to get tls cert config");
        std::process::exit(1);
    });

    let cert = dnssec::load_cert(directory, cert_config).unwrap_or_else(|e| {
        tracing::error!("failed to load tls cert: {}", e);
        std::process::exit(1);
    });

    let runtime = runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(4)
        .thread_name("hickory-server-runtime")
        .build()
        .expect("failed to initialize Tokio Runtime");

    let handler = EchoxyDnsHandler {
        echconfigs: config
            .proxy
            .echconfigs
            .iter()
            .map(|echconfig| {
                // remove length because hickory-server will add it
                if echconfig[0..2] != [0xfe, 0x0d] {
                    echconfig[2..].to_vec()
                } else {
                    echconfig.clone()
                }
            })
            .collect(),
        ipv4s: config.proxy.listen_addrs_ipv4,
        ipv6s: config.proxy.listen_addrs_ipv6,
    };
    let mut server = ServerFuture::new(handler);

    for ipv4 in config
        .server
        .get_listen_addrs_ipv4()
        .expect("invalid listen_addrs_ipv4")
    {
        let udp = runtime
            .block_on(UdpSocket::bind((ipv4, config.server.get_listen_port())))
            .unwrap_or_else(|e| {
                tracing::error!("failed to bind: {}", e);
                std::process::exit(1);
            });

        let https = runtime
            .block_on(TcpListener::bind((
                ipv4,
                config.server.get_https_listen_port(),
            )))
            .unwrap_or_else(|e| {
                tracing::error!("failed to bind: {}", e);
                std::process::exit(1);
            });

        let _guard: runtime::EnterGuard<'_> = runtime.enter();

        server.register_socket(udp);

        server
            .register_https_listener(
                https,
                config.server.get_tcp_request_timeout(),
                cert.clone(),
                config
                    .server
                    .get_tls_cert()
                    .unwrap()
                    .get_endpoint_name()
                    .map(|s| s.to_string()),
            )
            .unwrap_or_else(|e| {
                tracing::error!("failed to register https listener: {}", e);
                std::process::exit(1);
            });
    }

    match runtime.block_on(server.block_until_done()) {
        Ok(_) => println!("server done"),
        Err(e) => println!("server error: {:?}", e),
    }
}
