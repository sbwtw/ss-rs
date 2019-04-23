use clap::{App, Arg, ArgMatches};
use failure::Fail;
use futures::Future;
use log::*;
use ring::aead::*;
use tokio::codec::{BytesCodec, Decoder};
use tokio::io::{read_exact, write_all};
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::stream::Stream;
use tokio::prelude::*;

use std::io;
use std::net::SocketAddr;
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

fn remote_establish(config: Arc<Config>) -> impl Future<Item = TcpStream, Error = io::Error> {
    TcpStream::connect(&config.server_addr)
}

fn local_handshake(sock: TcpStream) -> impl Future<Item = TcpStream, Error = io::Error> {
    // fake data, client won't really use it!
    let buf = vec![0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    write_all(sock, buf).and_then(|(sock, _)| Ok(sock))
}

fn remote_handshake(
    sock: TcpStream,
    config: Arc<Config>,
    request_addr: Socks5Addr,
) -> impl Future<
    Item = (
        TcpStream,
        impl ShadowsocksEncryptor,
        impl ShadowsocksDecryptor,
    ),
    Error = io::Error,
> {
    // TODO: move to other place
    let salt = Arc::new(*b"01234567890123456789012345678901");
    let encrypt_skey = derivate_sub_key(config.password.as_bytes(), &*salt.clone());
    trace!("enc salt: {:x?}", salt);
    trace!("enc skey: {:x?}", encrypt_skey);
    // TODO: Error handling
    let sealing_key = SealingKey::new(&CHACHA20_POLY1305, &encrypt_skey[..]).unwrap();

    // write salt
    write_all(sock, *salt.clone())
        .and_then(move |(sock, _)| {
            // wrap remote writer into secure channel
            let mut encryptor = Chacha20Poly1305Encryptor::new(sealing_key);
            let encrypted_addr = encryptor.encrypt(&request_addr.bytes()).unwrap();
            //let secure_writer = ShadowsocksWriter::new(w, encryptor);

            // write request addr in secure channel
            write_all(sock, encrypted_addr).and_then(move |(sock, _)| Ok((sock, encryptor)))
        })
        .and_then(move |(sock, encryptor)| {
            read_exact(sock, [0u8; 32]).and_then(move |(sock, salt)| {
                trace!("dec salt: {:x?}", salt);

                let decrypt_skey = derivate_sub_key(config.password.as_bytes(), &salt);
                trace!("dec skey: {:x?}", decrypt_skey);
                // TODO: Error handling
                let opening_key = OpeningKey::new(&CHACHA20_POLY1305, &decrypt_skey[..]).unwrap();

                // wrap remote reader into secure channel
                let decryptor = Chacha20Poly1305Decryptor::new(opening_key);

                Ok((sock, encryptor, decryptor))
            })
        })
}

struct Config {
    server_addr: SocketAddr,
    listen_addr: SocketAddr,
    password: String,
}

impl Config {
    pub fn from_args(args: &ArgMatches) -> Option<Self> {
        let server_addr = args.value_of("server_addr")?;
        let listen_addr = args.value_of("listen_addr")?;
        let password = args.value_of("password")?;

        Some(Self {
            server_addr: server_addr.parse().ok()?,
            listen_addr: listen_addr.parse().ok()?,
            password: password.to_string(),
        })
    }
}

fn main() {
    env_logger::builder()
        .default_format_timestamp(false)
        .default_format_module_path(false)
        .init();

    let matches = App::new("ss-rs")
        .version("0.1")
        .author("sbw <sbw@sbw.so>")
        .about("Shadowsocks")
        .arg(
            Arg::with_name("password")
                .long("pwd")
                .takes_value(true)
                .required(true)
                .help("password"),
        )
        .arg(
            Arg::with_name("server_addr")
                .long("svr")
                .takes_value(true)
                .required(true)
                .help("server address"),
        )
        .arg(
            Arg::with_name("listen_addr")
                .long("listen")
                .takes_value(true)
                .required(true)
                .help("local address"),
        )
        .arg(
            Arg::with_name("encrypt_method")
                .long("cipher")
                .takes_value(true)
                .help("encrypt method"),
        )
        .get_matches();

    let config = Config::from_args(&matches).unwrap();
    let config = Arc::new(config);

    let f = TcpListener::bind(&config.listen_addr)
        .unwrap()
        .incoming()
        .map_err(|e| error!("Incoming Error: {:?}", e))
        .for_each(move |socket| {
            trace!("Incoming from {:?}", socket.peer_addr());

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

                        local.join(remote).and_then(|(local, (remote, enc, dec))| {
                            let (rr, rw) = remote.split();
                            let rsink = ShadowsocksSink::new(rw, enc);
                            let rstream = ShadowsocksStream::new(rr, dec);
                            let (lsink, lstream) = BytesCodec::new().framed(local).split();

                            let upload = lstream.forward(rsink);
                            let download = rstream.forward(lsink);

                            upload
                                .join(download)
                                .map_err(|e| error!("Transfer error: {:?}", e))
                                .and_then(|_| Ok(()))
                        })
                    });

            tokio::spawn(serv)
        });

    tokio::run(f);
}
