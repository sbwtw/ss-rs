use clap::{App, Arg};
use failure::Fail;
use futures::Future;
use log::*;
use tokio::codec::{BytesCodec, Decoder};
use tokio::io::{read_exact, write_all};
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::stream::Stream;
use tokio::prelude::*;

use std::fs::File;
use std::io;
use std::sync::Arc;

mod aes256cfb;
mod chacha20poly1305;
mod cipher;
mod config;
mod shadowsocks;
mod utils;

use cipher::*;
use config::*;
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

fn remote_establish(config: ServerConfig) -> impl Future<Item = TcpStream, Error = io::Error> {
    TcpStream::connect(config.addr()).and_then(|sock| {
        sock.set_nodelay(true)?;

        Ok(sock)
    })
}

fn local_handshake(sock: TcpStream) -> impl Future<Item = TcpStream, Error = io::Error> {
    // fake data, client won't really use it!
    let buf = vec![0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    write_all(sock, buf).and_then(|(sock, _)| Ok(sock))
}

fn remote_handshake(
    sock: TcpStream,
    mut cipher: CipherWrapper,
    request_addr: Socks5Addr,
) -> impl Future<Item = (TcpStream, CipherWrapper), Error = io::Error> {
    let data = cipher.first_sending_block(&request_addr.bytes());
    let read_len = cipher.first_reply_length();
    trace!("first-block: {:?}", data);

    // write handshake data
    write_all(sock, data).and_then(move |(sock, _)| {
        // got first reply
        read_exact(sock, vec![0u8; read_len]).and_then(move |(sock, salt)| {
            trace!("recv-block: {:x?}", salt);

            cipher.set_opening_iv(&salt[..]);

            Ok((sock, cipher))
        })
    })
}

fn main() -> Result<(), failure::Error> {
    env_logger::builder()
        .default_format_timestamp(false)
        .default_format_module_path(false)
        .init();

    let matches = App::new("ss-rs")
        .version("0.1")
        .author("sbw <sbw@sbw.so>")
        .about("Keep your connection secure!")
        .arg(
            Arg::with_name("config")
                .long("--config")
                .short("-c")
                .value_name("FILE")
                .takes_value(true)
                .help("Configuration file"),
        )
        .get_matches();

    let config_file = matches.value_of("config").unwrap();
    let config = ClientConfig::from_file(&mut File::open(config_file)?)?;
    let config = Arc::new(config);

    info!("ss-rs client listening on: {}", config.bind_addr());
    let f = TcpListener::bind(config.bind_addr())
        .unwrap()
        .incoming()
        .map_err(|e| error!("Incoming Error: {:?}", e))
        .for_each(move |socket| {
            trace!("Incoming from {:?}", socket.peer_addr());

            socket.set_nodelay(true).unwrap();

            let config = config.clone();
            let server = Arc::new(config.server_list()[0].clone());
            let remote = remote_establish(config.server_list()[0].clone())
                .map_err(|e| error!("Establish connection to server failed: {:?}", e));
            let local = local_establish(socket)
                .map_err(|e| error!("Establish connection from local failed: {:?}", e));

            let serv =
                remote
                    .join(local)
                    .and_then(move |(remote_sock, (local_sock, request_addr))| {
                        let rpeer = remote_sock.peer_addr().unwrap();
                        let lpeer = local_sock.peer_addr().unwrap();
                        info!("Relay {} in {} -> {}", request_addr, lpeer, rpeer);

                        let cipher = CipherBuilder::new(server).build();
                        let remote = remote_handshake(remote_sock, cipher, request_addr)
                            .map_err(|e| error!("Handshake with server failed: {:?}", e));
                        let local = local_handshake(local_sock)
                            .map_err(|e| error!("Handshake with local failed: {:?}", e));

                        local
                            .join(remote)
                            .and_then(move |(local, (remote, mut cipher))| {
                                let (lsink, lstream) = BytesCodec::new().framed(local).split();
                                let (rr, rw) = remote.split();
                                let rsink = ShadowsocksSink::new(rw, cipher.take_encryptor());
                                let rstream = ShadowsocksStream::new(rr, cipher.take_decryptor());

                                let upload = lstream.forward(rsink);
                                let download = rstream.forward(lsink);

                                upload
                                    .join(download)
                                    .map_err(|e| error!("Transfer error: {:?}", e))
                                    .and_then(move |_| {
                                        info!("Relay END for {:?} -> {:?}", lpeer, rpeer);
                                        Ok(())
                                    })
                            })
                    });

            tokio::spawn(serv)
        });

    Ok(tokio::run(f))
}
