use failure::Fail;
use futures::Future;
use log::*;
use ring::aead::*;
use tokio::io::{read_exact, write_all};
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::stream::Stream;
use tokio::prelude::*;

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

mod chacha20poly1305;
mod shadowsocks;
mod utils;

use chacha20poly1305::*;
use shadowsocks::*;
use utils::*;

#[derive(Debug, Fail)]
enum HandshakeError {
    #[fail(display = "Socks5 Version Error: 0x{:02x}", version)]
    VersionError { version: u8 },
    #[fail(
        display = "Only method type 0x00 is supported, server request one of {:x?}",
        supported
    )]
    MethodError { supported: Vec<u8> },
}

fn local_establish(
    sock: TcpStream,
) -> impl Future<Item = (TcpStream, Socks5Addr), Error = failure::Error> {
    trace!("Establish connection for {:?}", sock.peer_addr());

    // read socks version
    read_exact(sock, [0u8])
        .map_err(Into::into)
        .and_then(|(socket, buf)| {
            if buf[0] != 0x05 {
                Err(HandshakeError::VersionError { version: buf[0] }.into())
            } else {
                Ok(socket)
            }
        })
        // read method length
        .and_then(|socket| {
            read_exact(socket, [0u8])
                .map_err(Into::into)
                .and_then(|(socket, buf)| Ok((socket, buf[0] as usize)))
        })
        // read method list
        .and_then(|(socket, method_len)| {
            read_exact(socket, vec![0u8; method_len])
                .map_err(Into::into)
                .and_then(|(socket, buf)| {
                    if buf.contains(&0x00) {
                        Ok(socket)
                    } else {
                        Err(HandshakeError::MethodError { supported: buf }.into())
                    }
                })
        })
        // write method select response
        .and_then(|socket| write_all(socket, [0x05, 0x00]).map_err(Into::into))
        .and_then(|(socket, _)| {
            read_exact(socket, [0u8; 4])
                .map_err(Into::into)
                .and_then(|(socket, buf)| {
                    assert!(buf[0] == 0x05 && buf[1] == 0x01 && buf[2] == 0x00);
                    Ok((socket, buf[3]))
                })
        })
        .and_then(|(socket, atyp)| parse_addr(socket, atyp))
        .and_then(|(socket, addr)| {
            read_exact(socket, [0u8; 2])
                .map_err(Into::into)
                .and_then(move |(socket, buf)| {
                    let port = u16::from_be_bytes(buf);

                    Ok((socket, Socks5Addr(addr, port)))
                })
        })
}

fn remote_establish(
    config: Arc<ServerConfig>,
) -> impl Future<Item = TcpStream, Error = failure::Error> {
    TcpStream::connect(&config.addr).map_err(Into::into)
}

fn local_handshake(
    sock: TcpStream,
) -> impl Future<Item = (impl AsyncRead, impl AsyncWrite), Error = io::Error> {
    // fake data, client won't really use it!
    let buf = vec![0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    write_all(sock, buf).and_then(|(sock, _)| Ok(sock.split()))
}

fn remote_handshake(
    sock: TcpStream,
    config: Arc<ServerConfig>,
    request_addr: Socks5Addr,
) -> impl Future<Item = (impl AsyncRead, impl AsyncWrite), Error = io::Error> {
    // TODO: move to other place
    let salt = Arc::new(*b"01234567890123456789012345678901");
    let encrypt_skey = derivate_sub_key(config.password.as_bytes(), &*salt.clone());
    trace!("enc skey: {:x?}", encrypt_skey);
    // TODO: Error handling
    let sealing_key = SealingKey::new(&CHACHA20_POLY1305, &encrypt_skey[..]).unwrap();

    // write salt
    write_all(sock, *salt.clone())
        .and_then(|(sock, _)| Ok(sock.split()))
        .and_then(move |(r, w)| {
            // wrap remote writer into secure channel
            let encryptor = Chacha20Poly1305Encryptor::new(sealing_key);
            let secure_writer = ShadowsocksWriter::new(w, encryptor);

            // write request addr in secure channel
            write_all(secure_writer, request_addr.bytes()).and_then(move |(sw, _)| Ok((r, sw)))
        })
        .and_then(move |(r, sw)| {
            read_exact(r, [0u8; 32]).and_then(move |(r, salt)| {
                trace!("Got salt from remote server: {:x?}", salt);

                let decrypt_skey = derivate_sub_key(config.password.as_bytes(), &salt);
                trace!("dec skey: {:x?}", decrypt_skey);
                // TODO: Error handling
                let opening_key = OpeningKey::new(&CHACHA20_POLY1305, &decrypt_skey[..]).unwrap();

                // wrap remote reader into secure channel
                let decryptor = Chacha20Poly1305Decryptor::new(opening_key);
                let secure_reader = ShadowsocksReader::new(r, decryptor);

                Ok((secure_reader, sw))
            })
        })
}

fn parse_addr(
    socket: TcpStream,
    atyp: u8,
) -> Box<Future<Item = (TcpStream, Socks5Host), Error = failure::Error> + Send> {
    match atyp {
        // domain
        0x03 => Box::new(
            read_exact(socket, [0u8])
                .map_err(|e| e.into())
                .and_then(|(sock, buf)| Ok((sock, buf[0] as usize)))
                .and_then(|(sock, len)| read_exact(sock, vec![0u8; len]).map_err(|e| e.into()))
                .and_then(|(sock, buf)| {
                    let domain = std::str::from_utf8(&buf[..])?;

                    Ok((sock, Socks5Host::Domain(domain.to_string())))
                }),
        ),
        // Ipv4 Addr
        0x01 => Box::new(read_exact(socket, [0u8; 4]).map_err(|e| e.into()).and_then(
            |(socket, buf)| {
                let ip = Ipv4Addr::from(buf);

                Ok((socket, Socks5Host::Ip(IpAddr::V4(ip))))
            },
        )),
        // Ipv6 Addr
        0x04 => Box::new(
            read_exact(socket, [0u8; 16])
                .map_err(|e| e.into())
                .and_then(|(socket, buf)| {
                    let ip = Ipv6Addr::from(buf);

                    Ok((socket, Socks5Host::Ip(IpAddr::V6(ip))))
                }),
        ),
        _ => unreachable!(),
    }
}

struct ServerConfig {
    addr: SocketAddr,
    password: String,
}

impl ServerConfig {
    pub fn new() -> Self {
        Self {
            addr: "172.96.230.37:8100".parse().unwrap(),
            password: "nT9kz6aoxG".to_string(),
            //addr: "[::]:5001".parse().unwrap(),
            //password: "123456".to_string(),
        }
    }
}

fn main() {
    env_logger::builder()
        .default_format_timestamp(false)
        .default_format_module_path(false)
        .init();

    let config = Arc::new(ServerConfig::new());
    let addr: SocketAddr = "[::]:5002".parse().unwrap();
    let f = TcpListener::bind(&addr)
        .unwrap()
        .incoming()
        .map_err(|e| error!("Incoming Error: {:?}", e))
        .for_each(move |socket| {
            trace!("Incoming from {:?}", addr);

            let config = config.clone();
            let remote = remote_establish(config.clone())
                .map_err(|e| error!("Establish connection to server failed: {:?}", e));
            let local = local_establish(socket)
                .map_err(|e| error!("Establish connection from local failed: {:?}", e));

            let serv =
                remote
                    .join(local)
                    .and_then(move |(remote_sock, (local_sock, request_addr))| {
                        info!("Relay Connection Established");

                        let remote = remote_handshake(remote_sock, config.clone(), request_addr)
                            .map_err(|e| error!("Handshake with server failed: {:?}", e));
                        let local = local_handshake(local_sock)
                            .map_err(|e| error!("Handshake with local failed: {:?}", e));

                        remote.join(local).and_then(
                            |((remote_read, remote_write), (local_read, local_write))| {
                                trace!("Ready to transfer");
                                let download = tokio::io::copy(remote_read, local_write);
                                let upload = tokio::io::copy(local_read, remote_write);

                                upload
                                    .join(download)
                                    .map_err(|e| error!("Transfer error {:?}", e))
                                    .map(|((upload, _, _), (download, _, _))| {
                                        info!(
                                            "Relay finished, upload {} bytes, download {} bytes",
                                            upload, download
                                        );
                                    })
                            },
                        )
                    });
            tokio::spawn(serv)
        });

    tokio::run(f);
}
