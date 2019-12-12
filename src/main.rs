
use async_std::task;
use async_std::net::{TcpListener, TcpStream};
use async_std::prelude::*;
use failure::{Fail, Error};
use log::*;

use std::fs::File;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

mod config;
//mod cipher;
//mod aes256cfb;
//mod chacha20poly1305;
mod shadowsocks;
mod utils;

use config::*;
use shadowsocks::{Socks5Host, Socks5Addr};
//use cipher::CipherBuilder;

#[derive(Debug, Fail)]
enum HandshakeError {
    #[fail(display = "VersionError")]
    VersionError,
    #[fail(display = "MethodListError")]
    MethodListError,
    #[fail(display = "MethodSelectError")]
    MethodSelectError,
}

async fn socks5_handshake(mut stream: TcpStream) -> Result<(TcpStream, Socks5Addr), Error> {
    stream.set_nodelay(true)?;

    // 1 byte version must be 0x05
    let mut buf = [0u8];
    stream.read_exact(&mut buf).await?;
    if buf[0] != 0x05 {
        return Err(HandshakeError::VersionError.into());
    }

    // 1 byte method length
    let mut buf = [0u8];
    stream.read_exact(&mut buf).await?;
    let method_len = buf[0] as usize;

    // read method list
    let mut buf = vec![0u8; method_len];
    stream.read_exact(&mut buf).await?;
    if !buf.contains(&0x00) {
        return Err(HandshakeError::MethodListError.into());
    }

    // write method select result
    stream.write(&[0x05, 0x00]).await?;

    // read response
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await?;
    if buf[0] != 0x05 || buf[1] != 0x01 && buf[2] != 0x00 {
        return Err(HandshakeError::MethodSelectError.into());
    }

    // read atyp
    let host = match buf[3] {
        // domain
        0x03 => {
            // read domain length
            let mut buf = [0u8];
            stream.read_exact(&mut buf).await?;

            // read domain
            let mut buf = vec![0u8, buf[0]];
            stream.read_exact(&mut buf).await?;

            let domain = std::str::from_utf8(&buf[..])?;
            Socks5Host::Domain(domain.to_string())
        },
        // Ipv4 Address
        0x01 => {
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await?;

            let ip = Ipv4Addr::from(buf);
            Socks5Host::Ip(IpAddr::V4(ip))
        },
        // Ipv6 Address
        0x04 => {
            let mut buf = [0u8; 16];
            stream.read_exact(&mut buf).await?;

            let ip = Ipv6Addr::from(buf);
            Socks5Host::Ip(IpAddr::V6(ip))
        },
        // Error
        _ => unreachable!(),
    };

    // read port
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;

    let port = u16::from_be_bytes(buf);

    // write local handshake data
    stream.write(&[0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await?;

    Ok((stream, Socks5Addr(host, port)))
}

async fn serve_shadowsocks(mut stream: TcpStream) -> Result<(), Error> {
    Ok(())
}

async fn connect_shadowsocks(mut stream: TcpStream, server: &ServerConfig) -> Result<TcpStream, Error> {
//    let mut cipher = CipherBuilder::new(config.clone()).build();

    Ok(stream)
}

async fn start_listener() -> Result<(), Error> {
    let config = ClientConfig::from_file(&mut File::open("example_config.toml")?)?;
    let server_1 = &config.server_list()[0];

    let listener = TcpListener::bind(config.bind_addr()).await?;
    let mut incoming = listener.incoming();

    while let Some(Ok(stream)) = incoming.next().await {
        // handshake with application
        let (mut stream, addr) = match socks5_handshake(stream).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Handshake Error: {:?}", e);
                continue;
            }
        };

        // handshake with remote ss server
        let stream = connect_shadowsocks(stream, server_1).await?;

        // serve
        serve_shadowsocks(stream).await?;
    }

    unreachable!()
}

fn main() -> Result<(), Error> {
    env_logger::builder()
        .filter_level(LevelFilter::Info)
        .init();

    task::block_on(async {
        start_listener().await
    })
}
