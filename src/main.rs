
use async_std::task;
use async_std::net::{TcpListener, TcpStream};
use async_std::prelude::*;
use failure::{Fail, Error};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Fail)]
enum HandshakeError {
    #[fail(display = "VersionError")]
    VersionError,
    #[fail(display = "MethodListError")]
    MethodListError,
    #[fail(display = "MethodSelectError")]
    MethodSelectError,
}

#[derive(Debug)]
pub enum Socks5Host {
    Ip(IpAddr),
    Domain(String),
}

#[derive(Debug)]
pub struct Socks5Addr(pub Socks5Host, pub u16);

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

async fn start_listener() -> Result<(), Error> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
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

        let mut buf = vec![];
        stream.read_to_end(&mut buf).await?;
        println!("{:?}", buf);
    }

    unreachable!()
}

fn main() -> Result<(), Error> {
    task::block_on(async {
        start_listener().await
    })
}
