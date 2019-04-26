use tokio::io::read_exact;
use tokio::net::TcpStream;
use tokio::prelude::*;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::shadowsocks::*;

pub fn nonce_plus_one(nonce: &mut [u8]) {
    for i in 0..nonce.len() {
        match nonce[i] {
            b'\xff' => nonce[i] = b'\x00',
            _ => {
                nonce[i] += 1;
                break;
            }
        }
    }
}

pub fn parse_addr(
    socket: TcpStream,
    atyp: u8,
) -> Box<Future<Item = (TcpStream, Socks5Host), Error = failure::Error> + Send> {
    match atyp {
        // domain
        0x03 => Box::new(
            read_exact(socket, [0u8])
                .map_err(Into::into)
                .and_then(|(sock, buf)| Ok((sock, buf[0] as usize)))
                .and_then(|(sock, len)| read_exact(sock, vec![0u8; len]).map_err(Into::into))
                .and_then(|(sock, buf)| {
                    let domain = std::str::from_utf8(&buf[..])?;

                    Ok((sock, Socks5Host::Domain(domain.to_string())))
                }),
        ),
        // Ipv4 Addr
        0x01 => Box::new(read_exact(socket, [0u8; 4]).map_err(Into::into).and_then(
            |(socket, buf)| {
                let ip = Ipv4Addr::from(buf);

                Ok((socket, Socks5Host::Ip(IpAddr::V4(ip))))
            },
        )),
        // Ipv6 Addr
        0x04 => Box::new(read_exact(socket, [0u8; 16]).map_err(Into::into).and_then(
            |(socket, buf)| {
                let ip = Ipv6Addr::from(buf);

                Ok((socket, Socks5Host::Ip(IpAddr::V6(ip))))
            },
        )),
        _ => unreachable!(),
    }
}
