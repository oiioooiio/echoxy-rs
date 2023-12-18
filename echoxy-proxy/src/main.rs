use std::net::IpAddr;

use echoxy_proxy::tls::{ClientHello, ECHClientHello, Handshake, TLSPlaintext};

use hpke_rs::{Hpke, HpkePrivateKey, Mode};
use hpke_rs_crypto::types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs_rust_crypto::HpkeRustCrypto;

use pkcs8::{
    der::{asn1::OctetStringRef, Decode},
    PrivateKeyInfo,
};

use tokio::{
    io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinSet,
};

use tracing;
use tracing_subscriber;

use clap::Parser;
use serde::Deserialize;
use serde_json;
use serde_with::{
    base64::{Base64, Standard},
    formats::Padded,
    serde_as,
};

#[derive(Parser, Debug)]
#[clap(version = "0.1.0", author = "oiioooiio")]
struct Opts {
    #[clap(short, long, default_value = "config.json")]
    config: String,
}

#[serde_as]
#[derive(Deserialize, Debug, Clone)]
struct ECH {
    #[serde_as(as = "Base64<Standard, Padded>")]
    key: Vec<u8>,
    #[serde_as(as = "Base64<Standard, Padded>")]
    config: Vec<u8>,
}

#[derive(Deserialize, Debug, Clone)]
struct Config {
    listen_addrs: Vec<IpAddr>,
    ech: Vec<ECH>,
}

#[tokio::main]
async fn main() {
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

    let mut join_set: JoinSet<_> = JoinSet::new();
    for addr in &config.listen_addrs {
        let addr = addr.clone();
        let config = config.clone();
        join_set.spawn(async move {
            let listener = TcpListener::bind((addr, 443)).await.expect("bind error");
            tracing::info!("listening: {}", addr);
            loop {
                let (stream, _remote_addr) = match listener.accept().await {
                    Ok((stream, _remote_addr)) => (stream, _remote_addr),
                    Err(e) => {
                        tracing::error!("accept error: {}", e);
                        continue;
                    }
                };
                let config = config.clone();
                tokio::spawn(async move {
                    handle_connection(stream, config).await;
                });
            }
        });
    }
    while let Some(result) = join_set.join_next().await {
        match result {
            Ok(_) => {}
            Err(e) => {
                tracing::error!("join error: {}", e);
            }
        }
    }
}

async fn handle_connection(mut stream: TcpStream, config: Config) {
    let mut buf = vec![0; 0x2000];
    match stream.read_exact(&mut buf[..5]).await {
        Ok(_) => {}
        Err(e) => {
            tracing::error!("read error: {}", e);
            return;
        }
    }

    if buf[0] != 22 {
        tracing::trace!("not tls handshake");
        return;
    }
    let len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    stream.read_exact(&mut buf[5..5 + len]).await.unwrap();

    let plaintext: TLSPlaintext = buf[..len + 5].try_into().unwrap();
    let handshake: Handshake = plaintext.payload.try_into().unwrap();
    let client_hello_outer: ClientHello = handshake.payload.try_into().unwrap();

    tracing::info!("out sni: {}", client_hello_outer.sni());

    if &client_hello_outer.sni() != "example.com" {
        tracing::trace!("not example.com");
        return;
    }

    let ech_extension = match client_hello_outer.ech_extension() {
        Some(ech_extension) => ech_extension,
        None => {
            tracing::trace!("no ech extension");
            return;
        }
    };
    let ech_client_hello: ECHClientHello = ech_extension.payload().try_into().unwrap();
    let offset =
        ech_client_hello.payload.as_ptr() as usize - client_hello_outer.raw.as_ptr() as usize;
    let length = ech_client_hello.payload.len();
    let mut aad = client_hello_outer.raw.to_vec();
    aad[offset..offset + length].fill(0);

    // try decrypt ech payload
    let encoded_client_hello_inner: Option<Vec<u8>> = config.ech.iter().find_map(|ech| {
        let config = match &ech.config {
            config if config.starts_with(&[0xfe, 0x0d]) => config.clone(),
            config => config[2..].to_vec(),
        };

        let mut info = Vec::with_capacity(config.len() + 8);
        info.extend_from_slice(b"tls ech\0");
        info.extend_from_slice(&config);

        let sk_r = PrivateKeyInfo::from_der(&ech.key).unwrap();
        let sk_r = OctetStringRef::from_der(sk_r.private_key).unwrap();
        let sk_r = HpkePrivateKey::new(sk_r.as_bytes().to_vec());
        let hpke = Hpke::<HpkeRustCrypto>::new(
            Mode::Base,
            KemAlgorithm::DhKem25519,
            KdfAlgorithm::HkdfSha256,
            AeadAlgorithm::Aes128Gcm,
        );
        match hpke.open(
            ech_client_hello.enc,
            &sk_r,
            &info,
            &aad,
            ech_client_hello.payload,
            None,
            None,
            None,
        ) {
            Ok(encoded_client_hello_inner) => Some(encoded_client_hello_inner),
            Err(_) => None,
        }
    });

    let encoded_client_hello_inner = match encoded_client_hello_inner {
        Some(inner) => inner,
        None => {
            tracing::trace!("decrypt failed");
            return;
        }
    };

    let encoded_client_hello_inner =
        ClientHello::try_from(encoded_client_hello_inner.as_ref()).unwrap();

    tracing::info!("inner sni: {}", encoded_client_hello_inner.sni());

    if encoded_client_hello_inner.sni().is_empty() {
        tracing::trace!("no inner sni");
        return;
    }

    let client_hello_inner = encoded_client_hello_inner.reconstruct(&client_hello_outer);
    let mut message = Vec::with_capacity(client_hello_inner.len() + 9);
    message.push(22);
    message.extend_from_slice(&[3, 1]);
    message.extend_from_slice(&(client_hello_inner.len() as u16 + 4).to_be_bytes());
    message.push(1);
    message.push(0);
    message.extend_from_slice(&(client_hello_inner.len() as u16).to_be_bytes());
    message.extend_from_slice(client_hello_inner.as_ref());
    let mut server = match TcpStream::connect((encoded_client_hello_inner.sni(), 443)).await {
        Ok(server) => server,
        Err(_e) => {
            tracing::error!("connect error: {}", encoded_client_hello_inner.sni());
            return;
        }
    };
    server.write_all(&message).await.expect("write error");
    server.flush().await.unwrap();
    match copy_bidirectional(&mut stream, &mut server).await {
        Ok(_) => {}
        Err(e) => {
            tracing::error!("copy error: {}", e);
        }
    }
}
